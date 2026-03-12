"""Route-level tests for rules endpoints."""

from pathlib import Path

from backend.app import suricata_rules
from backend.app.config_v2 import Settings, get_settings

AUTH = {"Authorization": "Bearer test-token-v2"}


class TestSuricataRulesApi:
    def test_rule_file_lifecycle_rebuilds_runtime_bundle(self, app_client, monkeypatch, tmp_path):
        client, _db = app_client

        rules_dir = tmp_path / "managed-rules"
        installed_rules = tmp_path / "installed" / "suricata.rules"
        installed_rules.parent.mkdir(parents=True)
        installed_rules.write_text(
            'alert tcp any any -> any any (msg:"seeded"; sid:7; rev:1;)\n',
            encoding="utf-8",
        )

        monkeypatch.setattr(
            suricata_rules,
            "INSTALLED_SURICATA_RULES_CANDIDATES",
            (installed_rules,),
        )

        upload_root = tmp_path / "uploads"
        job_root = tmp_path / "jobs"
        upload_root.mkdir(exist_ok=True)
        job_root.mkdir(exist_ok=True)
        test_settings = Settings(
            aipam_api_token="test-token-v2",
            aipam_upload_root=upload_root,
            aipam_job_root=job_root,
            aipam_db_path=Path("/tmp/unused.db"),
            aipam_suricata_rules_dir=rules_dir,
        )
        monkeypatch.setitem(
            client.app.dependency_overrides,
            get_settings,
            lambda: test_settings,
        )

        listed = client.get("/api/v1/rules/suricata", headers=AUTH)
        assert listed.status_code == 200
        assert [item["filename"] for item in listed.json()] == ["suricata.rules"]

        filename = "augment-http-check.rules"
        marker = "AIPAM HTTP route verification rule"
        content = (
            f"# {marker}\n"
            f'alert ip any any -> 203.0.113.254 any (msg:"{marker}"; sid:9901002; rev:1; classtype:misc-activity;)\n'
        )

        updated = client.put(
            f"/api/v1/rules/suricata/{filename}",
            headers=AUTH,
            json={"content": content},
        )
        assert updated.status_code == 200
        assert updated.json()["filename"] == filename
        assert updated.json()["content"] == content

        listed_again = client.get("/api/v1/rules/suricata", headers=AUTH)
        assert listed_again.status_code == 200
        assert [item["filename"] for item in listed_again.json()] == [filename, "suricata.rules"]

        fetched = client.get(f"/api/v1/rules/suricata/{filename}/raw", headers=AUTH)
        assert fetched.status_code == 200
        assert fetched.json()["content"] == content

        bundle_path = suricata_rules.build_runtime_suricata_bundle(rules_dir)
        assert bundle_path == rules_dir / ".runtime" / "aipam-ui.rules"
        bundle = bundle_path.read_text(encoding="utf-8")
        assert "# Source: suricata.rules" in bundle
        assert f"# Source: {filename}" in bundle
        assert marker in bundle

        deleted = client.delete(f"/api/v1/rules/suricata/{filename}", headers=AUTH)
        assert deleted.status_code == 204

        remaining = client.get("/api/v1/rules/suricata", headers=AUTH)
        assert remaining.status_code == 200
        assert [item["filename"] for item in remaining.json()] == ["suricata.rules"]

        missing = client.get(f"/api/v1/rules/suricata/{filename}/raw", headers=AUTH)
        assert missing.status_code == 404

        rebuilt_bundle = suricata_rules.build_runtime_suricata_bundle(rules_dir).read_text(encoding="utf-8")
        assert "# Source: suricata.rules" in rebuilt_bundle
        assert f"# Source: {filename}" not in rebuilt_bundle
        assert marker not in rebuilt_bundle