import asyncio
import subprocess
from types import SimpleNamespace

from backend.app import suricata_rules
from backend.app.api import rules as rules_api
from backend.app.pipeline import sensor_handlers


def test_list_suricata_rules_seeds_from_installed_rules(monkeypatch, tmp_path):
    rules_dir = tmp_path / "managed-rules"
    installed_rules = tmp_path / "installed" / "suricata.rules"
    installed_rules.parent.mkdir(parents=True)
    installed_rules.write_text('alert http any any -> any any (msg:"Seeded rule"; sid:1; rev:1;)\n')

    monkeypatch.setattr(
        suricata_rules,
        "INSTALLED_SURICATA_RULES_CANDIDATES",
        (installed_rules,),
    )

    items = asyncio.run(
        rules_api.list_suricata_rules(
            settings=SimpleNamespace(aipam_suricata_rules_dir=rules_dir),
        )
    )

    assert [item.filename for item in items] == ["suricata.rules"]
    assert (rules_dir / "suricata.rules").read_text() == installed_rules.read_text()


def test_build_runtime_suricata_bundle_combines_ui_rule_files(tmp_path):
    rules_dir = tmp_path / "managed-rules"
    rules_dir.mkdir()
    (rules_dir / "alpha.rules").write_text(
        'alert http any any -> any any (msg:"alpha"; sid:1; rev:1;)\n',
    )
    (rules_dir / "beta.rules").write_text(
        '# alert dns any any -> any any (msg:"beta"; sid:2; rev:1;)\n',
    )

    bundle_path = suricata_rules.build_runtime_suricata_bundle(rules_dir)

    assert bundle_path == rules_dir / ".runtime" / "aipam-ui.rules"
    bundle = bundle_path.read_text()
    assert "# Source: alpha.rules" in bundle
    assert "# Source: beta.rules" in bundle
    assert 'msg:"alpha"' in bundle
    assert 'msg:"beta"' in bundle


def test_rule_file_api_lifecycle_rebuilds_runtime_bundle(monkeypatch, tmp_path):
    rules_dir = tmp_path / "managed-rules"
    installed_rules = tmp_path / "installed" / "suricata.rules"
    installed_rules.parent.mkdir(parents=True)
    installed_rules.write_text('alert tcp any any -> any any (msg:"seeded"; sid:7; rev:1;)\n')

    monkeypatch.setattr(
        suricata_rules,
        "INSTALLED_SURICATA_RULES_CANDIDATES",
        (installed_rules,),
    )

    settings = SimpleNamespace(aipam_suricata_rules_dir=rules_dir)
    filename = "augment-runtime-check.rules"
    marker = "AIPAM temporary runtime verification rule"
    content = (
        f"# {marker}\n"
        f'alert ip any any -> 203.0.113.254 any (msg:"{marker}"; sid:9901001; rev:1; classtype:misc-activity;)\n'
    )

    seeded = asyncio.run(rules_api.list_suricata_rules(settings=settings))
    assert [item.filename for item in seeded] == ["suricata.rules"]

    created = asyncio.run(
        rules_api.update_suricata_rule(
            filename,
            rules_api.SuricataRuleUpdate(content=content),
            settings=settings,
        )
    )

    assert created.filename == filename
    assert created.content == content

    listed = asyncio.run(rules_api.list_suricata_rules(settings=settings))
    assert [item.filename for item in listed] == [filename, "suricata.rules"]

    fetched = asyncio.run(rules_api.get_suricata_rule(filename, settings=settings))
    assert fetched.content == content

    bundle_path = suricata_rules.build_runtime_suricata_bundle(rules_dir)
    assert bundle_path == rules_dir / ".runtime" / "aipam-ui.rules"
    bundle = bundle_path.read_text()
    assert "# Source: suricata.rules" in bundle
    assert f"# Source: {filename}" in bundle
    assert marker in bundle

    deleted = asyncio.run(rules_api.delete_suricata_rule(filename, settings=settings))
    assert deleted.status_code == 204

    remaining = asyncio.run(rules_api.list_suricata_rules(settings=settings))
    assert [item.filename for item in remaining] == ["suricata.rules"]

    rebuilt_bundle = suricata_rules.build_runtime_suricata_bundle(rules_dir).read_text()
    assert "# Source: suricata.rules" in rebuilt_bundle
    assert f"# Source: {filename}" not in rebuilt_bundle
    assert marker not in rebuilt_bundle


def test_handle_suricata_uses_explicit_managed_bundle(monkeypatch, tmp_path):
    job_dir = tmp_path / "job-1"
    input_dir = job_dir / "input"
    input_dir.mkdir(parents=True)
    pcap = input_dir / "capture.pcap"
    pcap.write_bytes(b"pcap")

    sensor_output_dir = job_dir / "sensors" / "suricata"
    sensor_output_dir.mkdir(parents=True)

    rules_dir = tmp_path / "managed-rules"
    installed_rules = tmp_path / "installed" / "suricata.rules"
    installed_rules.parent.mkdir(parents=True)
    installed_rules.write_text('alert tcp any any -> any any (msg:"runtime"; sid:7; rev:1;)\n')

    monkeypatch.setattr(
        suricata_rules,
        "INSTALLED_SURICATA_RULES_CANDIDATES",
        (installed_rules,),
    )
    monkeypatch.setattr(
        sensor_handlers,
        "get_settings",
        lambda: SimpleNamespace(aipam_suricata_rules_dir=rules_dir),
    )
    monkeypatch.setattr(sensor_handlers.shutil, "which", lambda name: "/usr/bin/suricata")
    monkeypatch.setattr(sensor_handlers, "_parse_suricata_results", lambda raw_dir: [])

    calls = []

    def fake_run(cmd, cwd, *, label, ceiling_seconds):
        calls.append((cmd, cwd, ceiling_seconds))
        return subprocess.CompletedProcess(cmd, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(sensor_handlers, "run_capture_tool", fake_run)

    sensor_handlers.handle_suricata(job_dir, sensor_output_dir, "job-1", "standard")

    bundle_path = rules_dir / ".runtime" / "aipam-ui.rules"
    raw_dir = sensor_output_dir / "raw"

    assert calls == [
        (
            [
                "/usr/bin/suricata",
                "-r",
                str(pcap),
                "-l",
                str(raw_dir),
                "--set",
                "community-id.enabled=true",
                "-S",
                str(bundle_path),
            ],
            raw_dir,
            # Ceiling comes from the sensor registry, not a hardcoded literal.
            sensor_handlers._sensor_timeout("suricata", 1800),
        )
    ]
    assert (rules_dir / "suricata.rules").exists()
    assert bundle_path.exists()