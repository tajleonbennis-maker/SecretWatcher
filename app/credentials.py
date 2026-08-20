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
)

# Deliberately conservative: short examples such as sk-xxx never match.
KEY_PATTERNS = (
    re.compile(r"(?<![A-Za-z0-9_-])(sk-[A-Za-z0-9_-]{20,})(?![A-Za-z0-9_-])"),
    re.compile(r"(?<![A-Za-z0-9_-])([A-Za-z0-9]{8,}\.[A-Za-z0-9_-]{20,})(?![A-Za-z0-9_-])"),
)


def _provider_for(text: str, start: int, end: int) -> tuple[str, float] | None:
    local = text[max(0, start - 1200): min(len(text), end + 1200)]
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


def extract_credential_findings(
    text: str,
    *,
    source_url: str,
    asset_name: str,
    product: str,
    fingerprint_key: str,
) -> list[dict[str, object]]:
    if not fingerprint_key:
        raise ValueError("SECRETWATCHER_FINGERPRINT_KEY 未配置")
    results: list[dict[str, object]] = []
    seen: set[str] = set()
    for pattern in KEY_PATTERNS:
        for match in pattern.finditer(text):
            raw_key = match.group(1)
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
                    "key_suffix8": raw_key[-8:],
                    "key_hmac": digest,
                    "confidence": confidence,
                    "risk_level": "critical",
                }
            )
            # raw_key intentionally leaves scope here and is never returned or logged.
    return results
