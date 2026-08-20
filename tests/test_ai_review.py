from app.ai_review import redact_for_ai


def test_redacts_keys_and_sensitive_assignments_before_ai():
    raw = "sk-abcdefghijklmnopqrstuvwxyz123456"
    text = f'const DEEPSEEK_API_KEY="{raw}"; Authorization: BearerVerySensitiveToken12345'
    safe = redact_for_ai(text)
    assert raw not in safe
    assert "BearerVerySensitiveToken12345" not in safe
    assert safe.count("[REDACTED_CREDENTIAL]") >= 2
