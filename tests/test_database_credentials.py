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
        "key_suffix8": "1234abcd",
        "key_hmac": "a" * 64,
        "confidence": 0.95,
        "risk_level": "critical",
    })
    assert db.lookup_key_suffix4("abcd")[0]["provider"] == "DeepSeek"
    assert db.lookup_key_suffix4("zzzz") == []
    scheduled = db.asset_for_scan(10)
    assert scheduled[0]["id"] == asset_id
    db.finish_asset_scan(asset_id, files=3, bytes_scanned=100, findings=1)
    assert db.asset_for_scan(10)[0]["id"] == asset_id
