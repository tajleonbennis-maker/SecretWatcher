from app.credentials import extract_credential_findings


def test_extracts_deepseek_without_returning_full_key():
    raw = "sk-abcdefghijklmnopqrstuvwxyz123456"
    findings = extract_credential_findings(
        f'DEEPSEEK_API_KEY="{raw}"; baseURL="https://api.deepseek.com"',
        source_url="https://example.test/assets/app.js",
        asset_name="example.test",
        product="DeepTutor",
        fingerprint_key="test-fingerprint-secret",
    )
    assert len(findings) == 1
    assert findings[0]["provider"] == "DeepSeek"
    assert findings[0]["key_suffix8"] == raw[-8:]
    assert raw not in repr(findings)


def test_does_not_attribute_context_free_sk_key():
    assert extract_credential_findings(
        "const value = 'sk-abcdefghijklmnopqrstuvwxyz123456'",
        source_url="https://example.test/app.js",
        asset_name="example.test",
        product="",
        fingerprint_key="test-fingerprint-secret",
    ) == []


def test_ignores_documentation_placeholder():
    assert extract_credential_findings(
        "DEEPSEEK_API_KEY=sk-xxx",
        source_url="https://example.test/docs.js",
        asset_name="example.test",
        product="",
        fingerprint_key="test-fingerprint-secret",
    ) == []
