from app.detector import detect


def test_detects_deeptutor_from_title():
    findings = detect({"title": "DeepTutor - Personalized Learning", "header": ""})
    assert findings[0]["product"] == "DeepTutor"
    assert findings[0]["confidence"] >= 0.94


def test_does_not_treat_generic_ai_page_as_product():
    assert detect({"title": "My AI assistant", "header": "nginx"}) == []


def test_detects_gateway_from_header():
    findings = detect({"header": "X-App: LiteLLM Proxy", "title": "Gateway"})
    assert {finding["product"] for finding in findings} == {"LiteLLM Proxy"}

