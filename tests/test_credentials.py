from app.credentials import extract_credential_findings


def _findings(text: str, product: str = "") -> list[dict]:
    return extract_credential_findings(
        text,
        source_url="https://example.test/assets/app.js",
        asset_name="example.test",
        product=product,
        fingerprint_key="test-fingerprint-secret",
    )


def test_extracts_deepseek_without_returning_full_key():
    raw = "sk-abcdefghijklmnopqrstuvwxyz123456"
    findings = _findings(
        f'DEEPSEEK_API_KEY="{raw}"; model="deepseek-chat"; baseURL="https://api.deepseek.com"',
        product="DeepTutor",
    )
    assert len(findings) == 1
    assert findings[0]["provider"] == "DeepSeek"
    assert findings[0]["key_suffix8"] == raw[-8:]
    assert findings[0]["model_names"] == "deepseek-chat"
    assert set(findings[0]) >= {
        "provider", "product", "asset_name", "model_names", "key_suffix8", "key_hmac",
    }
    assert raw not in repr(findings)


def test_context_free_sk_key_is_kept_as_generic():
    findings = _findings("const value = 'sk-abcdefghijklmnopqrstuvwxyz123456'")
    assert len(findings) == 1
    assert findings[0]["provider"] == "sk- 前缀（厂商未定）"
    assert findings[0]["confidence"] < 0.8


def test_model_names_filter_embedding_and_generic():
    raw = "sk-abcdefghijklmnopqrstuvwxyz123456"
    findings = _findings(
        f'DEEPSEEK_API_KEY="{raw}"; model="deepseek-chat"; embedModel="bge-m3"; name="chat"'
    )
    assert len(findings) == 1
    # bge-m3（embedding）和 "chat"（误匹配）都应被过滤，只留 deepseek-chat
    assert findings[0]["model_names"] == "deepseek-chat"


def test_ignores_documentation_placeholder():
    assert _findings("DEEPSEEK_API_KEY=sk-xxx") == []


def test_ignores_long_placeholder_patterns():
    assert _findings('DEEPSEEK_API_KEY="sk-your-api-key-goes-here-abcdefgh"') == []


def test_extracts_qwen_model_near_dashscope_key():
    raw = "sk-qwenrealkeyvalue0123456789abcd"
    findings = _findings(f'window.__ENV={{DASHSCOPE_API_KEY:"{raw}",model:"qwen-plus"}};')
    assert len(findings) == 1
    assert findings[0]["provider"].startswith("阿里云")
    assert "qwen-plus" in findings[0]["model_names"]
    assert findings[0]["key_suffix8"] == raw[-8:]


def test_extracts_ark_uuid_only_with_context():
    uuid = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
    with_ctx = _findings(f'ARK_API_KEY="{uuid}"; endpoint="https://ark.cn-beijing.volces.com"')
    assert len(with_ctx) == 1
    assert with_ctx[0]["provider"].startswith("火山")
    # 无上下文的 UUID 应被丢弃，避免把普通 UUID 当密钥。
    assert _findings(f'const id = "{uuid}"') == []


def test_extracts_jwt_token():
    raw = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    findings = _findings(f'const token = "{raw}"')
    assert len(findings) == 1
    assert findings[0]["provider"].startswith("JWT")


def test_extracts_github_token():
    raw = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    findings = _findings(f'GITHUB_TOKEN="{raw}"')
    assert len(findings) == 1
    assert findings[0]["provider"] == "GitHub"


def test_entropy_catch_with_sensitive_context():
    raw = "qJ93nvu23hKma0xn8sLkX7pQ2wR9vT4yF6sA1cD5eG0hB"
    findings = _findings(f'const apiKey = "{raw}"')
    assert len(findings) == 1
    assert findings[0]["provider"] == "未识别（高熵凭据）"
    assert findings[0]["confidence"] < 0.6


def test_entropy_does_not_fire_without_sensitive_context():
    raw = "qJ93nvu23hKma0xn8sLkX7pQ2wR9vT4yF6sA1cD5eG0hB"
    assert _findings(f'const cacheKey = "{raw}"') == []
