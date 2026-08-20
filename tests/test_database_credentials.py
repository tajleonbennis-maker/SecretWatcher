from pathlib import Path

from app.database import Database


def test_credential_suffix_lookup(tmp_path: Path):
    db = Database(tmp_path / "watcher.db")
    db.initialize()
    asset_id, _ = db.upsert_asset({"host": "example.test", "domain": "example.test", "port": 443, "protocol": "https"})
    db.upsert_credential_finding(asset_id, {
        "provider": "DeepSeek",
        "product": "DeepTutor",
        "asset_name": "example.test",
        "source_path": "/assets/app.js",
        "model_names": "deepseek-chat",
        "key_suffix8": "1234abcd",
        "key_hmac": "a" * 64,
        "confidence": 0.95,
        "risk_level": "critical",
    })
    assert db.lookup_key_suffix4("abcd")[0]["provider"] == "DeepSeek"
    assert db.lookup_key_suffix4("abcd")[0]["model_names"] == "deepseek-chat"
    assert db.lookup_key_suffix4("zzzz") == []
    # 公开列表不再按 status 过滤，unverified 也直接返回。
    public = db.public_credential_findings()
    assert len(public) == 1
    assert public[0]["key_suffix8"] == "1234abcd"
    assert public[0]["model_names"] == "deepseek-chat"
    assert public[0]["status"] == "unverified"
    assert "key_hmac" not in public[0]
    assert "source_path" not in public[0]
    assert db.set_credential_status(asset_id, "a" * 64, "resolved") is True
    scheduled = db.asset_for_scan(10)
    assert scheduled[0]["id"] == asset_id
    db.finish_asset_scan(asset_id, files=3, bytes_scanned=100, findings=1)
    assert db.asset_for_scan(10)[0]["id"] == asset_id
    run_id = db.create_scan_run(1)
    db.mark_asset_scan(asset_id, "running")
    db.advance_scan_run(run_id, files=3, bytes_scanned=100, findings=1, failed=False)
    progress = db.admin_scan_progress()
    assert progress["status"] == "completed"
    assert progress["completed_assets"] == 1
    assert progress["recent_assets"][0]["status"] == "running"
    finding_id = public[0]["id"]
    assert db.delete_credential_finding(finding_id) is True
    assert db.delete_credential_finding(finding_id) is False
