from __future__ import annotations

import hashlib
import hmac
import re
from collections import Counter
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

# Common fake / docs strings that still satisfy length rules (expanded).
_PLACEHOLDER_FRAGMENTS = (
    "xxx", "your-", "your_", "example", "changeme", "placeholder",
    "insert", "replace", "todo", "sample", "dummy", "fake", "testkey",
    # New additions - common example keys in docs/tutorials
    "wxyz", "test-", "demo-", "sample-", "apikey",
)

# Known fake/example key suffixes that appear in tutorials and sample code.
_KNOWN_FAKE_SUFFIXES = (
    "wxyzwxyz", "test1234", "demodemo", "examplek", "sampleke",
    "aaaaaaa", "bbbbbbb", "ccccccc", "ddddddd",
)

# File path patterns that are HIGH RISK for false positives (frontend build artifacts).
_LOW_CONFIDENCE_PATHS = re.compile(
    r"""(?ix)
    /(?:assets|static|dist|build|js|_next|chunk)[-_.] |
    \.(?:js|mjs|css|map)$ |
    chunk[-_.] |
    [-_](?:vendor|chunk|module|runtime)[-_.]
    """
)

# File path patterns that are LOW RISK (likely to contain real configs).
_HIGH_CONFIDENCE_PATHS = re.compile(
    r"""(?ix)
    /(?:config|env|settings|api)[.-_] |
    ^/(?:config|env|settings)\.(?:js|json)$ |
    /(?:api|v1|v2|v3)/
    """
)

# Context patterns that indicate a key is in a legitimate assignment context.
# Must have one of these NEAR the matched key (within 200 chars).
_CONTEXT_ASSIGNMENT_PATTERNS = (
    # JSON key-value pairs
    re.compile(r"""(?ix)(?:["'])(api[_-]?key|token|secret|authorization|access[_-]?key|auth[_-]?key)["']\s*:"""),
    # JS/Python variable assignments
    re.compile(r"""(?ix)(?:const|let|var)\s+(?:api[_-]?key|token|secret|apiKey|API_KEY)\s*="""),
    # Object property assignments
    re.compile(r"""(?ix)(?:api[_-]?key|token|secret|apiKey|API_KEY)\s*[:=]\s*["']"""),
    # Environment variable references
    re.compile(r"""(?ix)(?:process\.env|os\.environ|getenv|ENV\[)\s*\(\s*["']?(?:api[_-]?key|token|secret)"""),
)

# Patterns that indicate the match is likely NOT a real key (exclusion contexts).
_EXCLUSION_PATTERNS = (
    # Code comments
    re.compile(r"""(?://|#|/\*|\*|<!--).{0,100}sk-[a-zA-Z0-9]"""),
    # Console logging
    re.compile(r"""(?ix)console\.(log|debug|info|warn|error)\s*\([^)]*sk-[a-zA-Z0-9]"""),
    # String examples in documentation/comments
    re.compile(r"""(?ix)(?:example|sample|demo|placeholder|todo|fixme|xxx).{0,50}sk-[a-zA-Z0-9]"""),
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

# Window size for context validation (chars before and after the match).
_VALIDATION_WINDOW = 200


def _is_placeholder_key(raw_key: str) -> bool:
    """Check if a matched key looks like a placeholder/fake value."""
    lowered = raw_key.lower()
    
    # Check against known placeholder fragments
    if any(fragment in lowered for fragment in _PLACEHOLDER_FRAGMENTS):
        return True
    
    body = raw_key[3:] if raw_key.startswith("sk-") else raw_key
    
    # Character diversity check (original logic)
    if len(set(body)) <= 3:
        return True
    
    # Check against known fake suffixes
    if any(body.endswith(suffix) for suffix in _KNOWN_FAKE_SUFFIXES):
        return True
    
    # Entropy-based checks
    if _has_low_entropy(body):
        return True
    
    # Repetitive pattern detection
    if _has_repetitive_pattern(body):
        return True
    
    return False


def _has_low_entropy(text: str) -> bool:
    """Check if text has suspiciously low character diversity."""
    if len(text) < 10:
        return False
    
    char_counts = Counter(text)
    most_common_count = char_counts.most_common(1)[0][1]
    
    # If one character makes up > 60% of the key, it's likely fake
    if most_common_count / len(text) > 0.6:
        return True
    
    return False


def _has_repetitive_pattern(text: str) -> bool:
    """Detect repetitive patterns like 'aaaa', 'abab', etc."""
    if len(text) < 8:
        return False
    
    # Check for runs of 4+ identical characters
    if re.search(r'(.)\1{3,}', text):
        return True
    
    # Check for short repeated patterns (e.g., 'abcdabcd')
    for pattern_len in range(2, min(6, len(text) // 2)):
        pattern = text[:pattern_len]
        repeats = len(text) // pattern_len
        if text == pattern * repeats or text.startswith(pattern * (repeats - 1)):
            return True
    
    return False


def _is_in_exclusion_context(text: str, start: int, end: int) -> bool:
    """Check if the match is in an exclusion context (comments, logs, etc.)."""
    local = text[max(0, start - 100):min(len(text), end + 100)]
    
    for pattern in _EXCLUSION_PATTERNS:
        if pattern.search(local):
            return True
    
    return False


def _has_valid_assignment_context(text: str, start: int, end: int) -> bool:
    """Check if the match is near a legitimate key assignment context."""
    local = text[max(0, start - _VALIDATION_WINDOW):min(len(text), end + _VALIDATION_WINDOW)]
    
    for pattern in _CONTEXT_ASSIGNMENT_PATTERNS:
        if pattern.search(local):
            return True
    
    return False


def _get_confidence_from_path(source_url: str) -> float:
    """Determine base confidence from file path."""
    path = urlsplit(source_url).path or "/"
    
    # High confidence paths (configs, APIs)
    if _HIGH_CONFIDENCE_PATHS.search(path):
        return 0.95
    
    # Low confidence paths (frontend JS, chunks, maps)
    if _LOW_CONFIDENCE_PATHS.search(path):
        return 0.55  # Reduced confidence for frontend files
    
    # Default confidence
    return 0.78


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
    """Find likely AI API keys; persist only asset + model + suffix8 (+ hmac for dedupe).

    Improved version with four-layer filtering:
    1. File type awareness (path-based confidence adjustment)
    2. Context validation (must be near legitimate assignment)
    3. Enhanced placeholder detection (entropy, repetition, expanded blacklist)
    4. Cross-file deduplication (via HMAC, unchanged)
    """
    if not fingerprint_key:
        raise ValueError("SECRETWATCHER_FINGERPRINT_KEY 未配置")
    
    results: list[dict[str, object]] = []
    seen: set[str] = set()
    
    # Get base confidence from file path
    path_confidence = _get_confidence_from_path(source_url)
    path = urlsplit(source_url).path or "/"
    
    # Determine if we need strict context validation (for low-confidence paths)
    require_strict_context = _LOW_CONFIDENCE_PATHS.search(path) is not None
    
    for pattern in KEY_PATTERNS:
        for match in pattern.finditer(text):
            raw_key = match.group(1)
            
            # Layer 3: Enhanced placeholder detection
            if _is_placeholder_key(raw_key):
                continue
            
            # Layer 2: Context validation (stricter for frontend files)
            if _is_in_exclusion_context(text, match.start(), match.end()):
                continue
            
            if require_strict_context:
                if not _has_valid_assignment_context(text, match.start(), match.end()):
                    continue
            
            attribution = _provider_for(text, match.start(), match.end())
            if not attribution:
                continue
            
            provider, confidence = attribution
            
            # Adjust confidence based on path and context
            final_confidence = min(confidence, path_confidence)
            
            # If confidence is too low, skip (likely false positive)
            if final_confidence < 0.5:
                continue
            
            digest = hmac.new(fingerprint_key.encode(), raw_key.encode(), hashlib.sha256).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            
            results.append(
                {
                    "provider": provider,
                    "product": product,
                    "asset_name": asset_name[:255],
                    "source_path": path[:1000],
                    "model_names": _models_near(text, match.start(), match.end()),
                    "key_suffix8": raw_key[-8:],
                    "key_hmac": digest,
                    "confidence": round(final_confidence, 2),
                    "risk_level": "critical" if final_confidence >= 0.75 else "medium",
                }
            )
            # raw_key intentionally leaves scope; never returned or logged.
    return results


# New function for cross-file frequency analysis (to be called from crawler.py)
def analyze_finding_frequency(findings: list[dict[str, object]]) -> dict[str, object]:
    """Analyze findings to detect potential false positives based on frequency.

    Returns statistics about finding distribution that can be used to
    identify suspicious patterns (same key across many files, high-frequency
    suffixes on same asset, etc.).
    """
    if not findings:
        return {"total": 0, "warnings": []}
    
    warnings: list[str] = []
    
    # Group by asset
    by_asset: dict[str, list[dict]] = {}
    for f in findings:
        asset = f.get("asset_name", "unknown")
        by_asset.setdefault(asset, []).append(f)
    
    # Check for assets with unusually many findings
    for asset, asset_findings in by_asset.items():
        if len(asset_findings) > 10:
            warnings.append(f"资产 {asset} 有 {len(asset_findings)} 条发现，可能存在误报")
        
        # Check for duplicate key suffixes on same asset
        suffixes = [f.get("key_suffix8", "") for f in asset_findings]
        suffix_counts = Counter(suffixes)
        for suffix, count in suffix_counts.most_common(3):
            if count >= 5:
                warnings.append(f"资产 {asset} 上 Key 后缀 ****{suffix} 出现 {count} 次，可能是示例值")
    
    return {
        "total": len(findings),
        "unique_assets": len(by_asset),
        "warnings": warnings[:10],  # Limit to top 10 warnings
    }
