from app.main import _mask_asset, _public_finding


def test_public_asset_masks_last_ipv4_octet():
    assert _mask_asset("https://50.118.187.180/app") == "50.118.187.*"


def test_public_list_and_lookup_use_different_key_masks():
    finding = {
        "provider": "DeepSeek",
        "product": "DeepTutor",
        "asset_name": "50.118.187.180",
        "model_names": "deepseek-chat",
        "key_suffix8": "1234abcd",
        "risk_level": "critical",
        "first_seen": "2026-08-20T00:00:00+00:00",
        "last_seen": "2026-08-20T00:00:00+00:00",
        "status": "unverified",
    }
    public = _public_finding(finding)
    assert public["key_hint"] == "****abcd"
    assert public["models"] == "deepseek-chat"
    assert public["asset"] == "50.118.187.*"
    assert _public_finding(finding, key_visible_chars=8)["key_hint"] == "****1234abcd"
    assert public["provider"] == "DeepSeek"
