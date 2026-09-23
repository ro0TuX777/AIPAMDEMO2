import json
import subprocess

from backend.app.pipeline import sensor_handlers


def _write_file_triage_record(job_dir, data):
    results_file = job_dir / "sensors" / "file_triage" / "sensor.results.jsonl"
    results_file.parent.mkdir(parents=True, exist_ok=True)
    results_file.write_text(json.dumps({"type": "extracted_file", "data": data}) + "\n")


def _read_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_handle_capa_emits_finding_for_executable(monkeypatch, tmp_path):
    job_dir = tmp_path / "job-1"
    sensor_output_dir = job_dir / "sensors" / "capa"
    sensor_output_dir.mkdir(parents=True)

    extracted_dir = job_dir / "extracted_files" / "files"
    extracted_dir.mkdir(parents=True)
    extracted_file = extracted_dir / "sample.exe"
    extracted_file.write_bytes(b"MZ\x90\x00")

    _write_file_triage_record(job_dir, {
        "file_id": "sample.exe",
        "filename": "sample.exe",
        "mime": "application/x-dosexec",
        "file_type": "PE32 executable",
        "sha256": "abc123",
        "source": "zeek",
        "host_ip": "10.0.0.5",
        "src_ip": "10.0.0.5",
        "dst_ip": "8.8.8.8",
        "pcap_label": "capture-a",
        "ts": "2026-03-11T12:00:00Z",
    })

    rules_dir = tmp_path / "rules"
    signatures_dir = tmp_path / "signatures"
    rules_dir.mkdir()
    signatures_dir.mkdir()

    monkeypatch.setenv("AIPAM_CAPA_RULES_DIR", str(rules_dir))
    monkeypatch.setenv("AIPAM_CAPA_SIGNATURES_DIR", str(signatures_dir))
    monkeypatch.setattr(sensor_handlers.shutil, "which", lambda name: "/usr/bin/capa")

    calls = []

    def fake_run(cmd, timeout, capture_output, text):
        calls.append((cmd, timeout, capture_output, text))
        payload = {
            "rules": {
                "encrypt data using RC4 PRGA": {
                    "meta": {
                        "name": "encrypt data using RC4 PRGA",
                        "namespace": "data-manipulation/encryption",
                        "att&ck": [
                            {
                                "tactic": "Credential Access",
                                "technique": "Input Capture",
                                "id": "T1056",
                            }
                        ],
                    }
                },
                "allocate execute memory": {
                    "meta": {
                        "name": "allocate execute memory",
                        "namespace": "host-interaction/process",
                        "mbc": [
                            {
                                "objective": "Defense Evasion",
                                "behavior": "Executable Code",
                                "method": "Memory",
                                "id": "B0001",
                            }
                        ],
                    }
                },
            }
        }
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(sensor_handlers.subprocess, "run", fake_run)

    sensor_handlers.handle_capa(job_dir, sensor_output_dir, "job-1", "standard", run_output_dir=job_dir)

    assert len(calls) == 1
    cmd, timeout, capture_output, text = calls[0]
    assert cmd == [
        "/usr/bin/capa",
        "-r",
        str(rules_dir),
        "-s",
        str(signatures_dir),
        "-j",
        str(extracted_file),
    ]
    assert timeout == 300
    assert capture_output is True
    assert text is True

    results = _read_jsonl(sensor_output_dir / "sensor.results.jsonl")
    assert len(results) == 1

    finding = results[0]
    assert finding["event_type"] == "finding"
    assert finding["sensor"] == "capa"
    assert finding["severity"] == "high"
    assert finding["title"] == "CAPA identified capabilities in sample.exe"
    assert "capa identified 2 capability rule(s)" in finding["summary"]
    assert "ATT&CK: Credential Access / Input Capture (T1056)." in finding["summary"]
    assert finding["host_ip"] == "10.0.0.5"
    assert finding["pcap_label"] == "capture-a"

    evidence = finding["evidence"]
    assert evidence["file_id"] == "sample.exe"
    assert evidence["sha256"] == "abc123"
    assert evidence["capability_count"] == 2
    assert evidence["capabilities"] == [
        "encrypt data using RC4 PRGA",
        "allocate execute memory",
    ]
    assert evidence["attack"] == ["Credential Access / Input Capture (T1056)"]
    assert evidence["mbc"] == ["Executable Code / Defense Evasion / Memory (B0001)"]


def test_handle_capa_writes_empty_results_when_configured_rules_dir_missing(monkeypatch, tmp_path):
    job_dir = tmp_path / "job-2"
    sensor_output_dir = job_dir / "sensors" / "capa"
    sensor_output_dir.mkdir(parents=True)

    extracted_dir = job_dir / "extracted_files" / "files"
    extracted_dir.mkdir(parents=True)
    (extracted_dir / "sample.exe").write_bytes(b"MZ\x90\x00")

    _write_file_triage_record(job_dir, {
        "file_id": "sample.exe",
        "filename": "sample.exe",
        "mime": "application/x-dosexec",
    })

    monkeypatch.setenv("AIPAM_CAPA_RULES_DIR", str(tmp_path / "missing-rules"))
    monkeypatch.delenv("AIPAM_CAPA_SIGNATURES_DIR", raising=False)
    monkeypatch.setattr(sensor_handlers.shutil, "which", lambda name: "/usr/bin/capa")

    calls = []
    monkeypatch.setattr(sensor_handlers.subprocess, "run", lambda *args, **kwargs: calls.append((args, kwargs)))

    sensor_handlers.handle_capa(job_dir, sensor_output_dir, "job-2", "standard", run_output_dir=job_dir)

    assert calls == []
    assert (sensor_output_dir / "sensor.results.jsonl").read_text() == ""