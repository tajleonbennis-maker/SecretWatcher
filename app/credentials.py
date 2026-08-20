from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ProviderRule:
    name: str
    context: tuple[re.Pattern[str], ...]


def _rx(*values: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(value, re.I) for value in values)


PROVIDERS = (
    ProviderRule("DeepSeek", _rx(r"deepseek", r"api\.deepseek\.com", r"DEEPSEEK_API_KEY")),
    ProviderRule("阿里云百炼 / 通义千问", _rx(r"dashscope", r"aliyuncs\.com/compatible-mode", r"DASHSCOPE_API_KEY", r"\bqwen[-_]")),
    ProviderRule("火山引擎方舟 / 豆包", _rx(r"volces\.com/api/v3", r"ARK_API_KEY", r"doubao", r"volcengine")),
    ProviderRule("智谱 GLM", _rx(r"open\.bigmodel\.cn", r"ZHIPUAI_API_KEY", r"\bglm[-_]")),
    ProviderRule("月之暗面 Kimi", _rx(r"api\.moonshot\.cn", r"MOONSHOT_API_KEY", r"moonshot-v1", r"\bkimi\b")),
    ProviderRule("百度千帆 / 文心", _rx(r"qianfan", r"aip\.baidubce\.com", r"QIANFAN_(?:AK|SK)", r"ERNIE")),
    ProviderRule("腾讯混元", _rx(r"hunyuan", r"tencentcloudapi\.com", r"TENCENTCLOUD_SECRET")),
    ProviderRule("MiniMax", _rx(r"api\.minimax\.chat", r"MINIMAX_API_KEY", r"abab[0-9]")),
    ProviderRule("百川智能", _rx(r"api\.baichuan-ai\.com", r"BAICHUAN_API_KEY")),
    ProviderRule("零一万物", _rx(r"api\.lingyiwanwu\.com", r"YI_API_KEY", r"yi-large")),
    ProviderRule("硅基流动", _rx(r"api\.siliconflow\.cn", r"SILICONFLOW_API_KEY")),
    ProviderRule("OpenAI 兼容", _rx(r"api\.openai\.com", r"OPENAI_API_KEY", r"openai\.azure\.com")),
)

# Deliberately conservative: short examples such as sk-xxx never match.
KEY_PATTERNS = (
    re.compile(r"(?<![A-Za-z0-9_-])(sk-[A-Za-z0-9_-]{20,})(?![A-Za-z0-9_-])"),
    re.compile(r"(?<![A-Za-z0-9_-])([A-Za-z0-9]{8,}\.[A-Za-z0-9_-]{20,})(?![A-Za-z0-9_-])"),
)

# Common fake / docs strings that still satisfy length rules.
_PLACEHOLDER_FRAGMENTS = (
    "xxx", "your-", "your_", "example", "changeme", "placeholder",
    "insert", "replace", "todo", "sample", "dummy", "fake", "testkey",
)

_MODEL_ASSIGN = re.compile(
    r"""(?ix)
    (?:["']?(?:model|default[_-]?model|llm[_-]?model|chat[_-]?model|completion[_-]?model)["']?
    \s*[:=]\s*
    |models?\s*[\[:]\s*)
    ["']([A-Za-z0-9][A-Za-z0-9._:/-]{2,96})["']
    """
)

_KNOWN_MODELS = re.compile(
    r"""(?ix)\b(
        deepseek-(?:chat|coder|reasoner|v[0-9][a-z0-9.-]*)|
        qwen[-_][a-z0-9][a-z0-9._-]{1,40}|
        doubao[-_][a-z0-9][a-z0-9._-]{1,40}|
        glm-4[a-z0-9._-]{0,40}|
        moonshot-v1-[a-z0-9._-]{1,40}|
        kimi[-_][a-z0-9][a-z0-9._-]{1,40}|
        ernie[-_][a-z0-9][a-z0-9._-]{1,40}|
        hunyuan[-_][a-z0-9][a-z0-9._-]{1,40}|
        abab[0-9][a-z0-9._-]{0,40}|
        yi-(?:large|medium|spark)[a-z0-9._-]{0,40}|
        gpt-[0-9.o]{1,12}(?:-[a-z0-9._-]{1,30})?|
        o[1-9](?:-[a-z0-9._-]{1,20})?|
        claude-3[a-z0-9._-]{0,40}|
        gemini[-_][a-z0-9][a-z0-9._-]{1,40}
    )\b"""
)

_CONTEXT_WINDOW = 1600


def _is_placeholder_key(raw_key: str) -> bool:
    lowered = raw_key.lower()
    if any(fragment in lowered for fragment in _PLACEHOLDER_FRAGMENTS):
        return True
    body = raw_key[3:] if raw_key.startswith("sk-") else raw_key
    if len(set(body)) <= 3:
        return True
    return False


def _provider_for(text: str, start: int, end: int) -> tuple[str, float] | None:
    local = text[max(0, start - _CONTEXT_WINDOW): min(len(text), end + _CONTEXT_WINDOW)]
    scored: list[tuple[int, str]] = []
    for rule in PROVIDERS:
        score = sum(1 for pattern in rule.context if pattern.search(local))
        if score:
            scored.append((score, rule.name))
    if not scored:
        return None
    scored.sort(reverse=True)
    best_score, provider = scored[0]
    return provider, min(0.99, 0.78 + best_score * 0.07)


def _models_near(text: str, start: int, end: int) -> str:
    local = text[max(0, start - _CONTEXT_WINDOW): min(len(text), end + _CONTEXT_WINDOW)]
    found: list[str] = []
    seen: set[str] = set()
    for match in _MODEL_ASSIGN.finditer(local):
        name = match.group(1).strip()
        key = name.lower()
        if key in seen or len(name) < 3:
            continue
        seen.add(key)
        found.append(name)
    for match in _KNOWN_MODELS.finditer(local):
        name = match.group(1).strip()
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        found.append(name)
    return ",".join(found[:8])[:240]


def extract_credential_findings(
    text: str,
    *,
    source_url: str,
    asset_name: str,
    product: str,
    fingerprint_key: str,
) -> list[dict[str, object]]:
    """Find likely AI API keys; persist only asset + model + suffix8 (+ hmac for dedupe)."""
    if not fingerprint_key:
        raise ValueError("SECRETWATCHER_FINGERPRINT_KEY 未配置")
    results: list[dict[str, object]] = []
    seen: set[str] = set()
    for pattern in KEY_PATTERNS:
        for match in pattern.finditer(text):
            raw_key = match.group(1)
            if _is_placeholder_key(raw_key):
                continue
            attribution = _provider_for(text, match.start(), match.end())
            if not attribution:
                continue
            provider, confidence = attribution
            digest = hmac.new(fingerprint_key.encode(), raw_key.encode(), hashlib.sha256).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            path = urlsplit(source_url).path or "/"
            results.append(
                {
                    "provider": provider,
                    "product": product,
                    "asset_name": asset_name[:255],
                    "source_path": path[:1000],
                    "model_names": _models_near(text, match.start(), match.end()),
                    "key_suffix8": raw_key[-8:],
                    "key_hmac": digest,
                    "confidence": confidence,
                    "risk_level": "critical",
                }
            )
            # raw_key intentionally leaves scope; never returned or logged.
    return results
