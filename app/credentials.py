from __future__ import annotations

import hashlib
import hmac
import math
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlsplit


# ---------------------------------------------------------------------------
# 提供商上下文规则
#
# 这些规则用于「归属加分」，不再是「硬门槛」。候选密钥即使没有上下文，
# 只要格式本身足够特异，仍然会被记录（置信度略低），进入人工复核队列。
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProviderRule:
    name: str
    context: tuple[re.Pattern[str], ...]


def _rx(*values: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(value, re.I) for value in values)


PROVIDERS = (
    ProviderRule("DeepSeek", _rx(r"deepseek", r"api\.deepseek\.com", r"DEEPSEEK_API_KEY")),
    ProviderRule("阿里云百炼 / 通义千问", _rx(r"dashscope", r"aliyuncs\.com/compatible-mode", r"DASHSCOPE_API_KEY", r"\bqwen[-_]")),
    ProviderRule("火山引擎方舟 / 豆包", _rx(r"volces\.com/api/v3", r"ARK_API_KEY", r"doubao", r"volcengine", r"\bark\b")),
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


# ---------------------------------------------------------------------------
# 密钥格式库
#
# 每个提供商/通用凭据至少一条「精确格式」正则。捕获组 `key` 为完整密钥。
#   - `fixed`          格式本身即可确定提供商（如 AKID、ghp_、AIza、AKIA），
#                      上下文只用于提升置信度，不改变归属。
#   - `requires_context` 格式太常见（如 UUID），必须有上下文才记录，否则误报爆炸。
#   - `min_entropy`    对格式做熵下限约束，排除 aaaa、1234 这类低熵假密钥。
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class KeyFormat:
    provider: str
    pattern: re.Pattern[str]
    fixed: bool = False
    requires_context: bool = False
    min_entropy: float | None = None


def _fmt(
    provider: str,
    regex: str,
    *,
    fixed: bool = False,
    requires_context: bool = False,
    min_entropy: float | None = None,
    flags: int = re.I,
) -> KeyFormat:
    return KeyFormat(
        provider=provider,
        pattern=re.compile(regex, flags),
        fixed=fixed,
        requires_context=requires_context,
        min_entropy=min_entropy,
    )


KEY_FORMATS = (
    # --- 通用 sk- 前缀：OpenAI / DeepSeek / DashScope / Kimi / 硅基流动 / 零一万物 / 百川 ---
    _fmt(
        "sk- 前缀（厂商未定）",
        r"(?<![A-Za-z0-9_-])(?P<key>sk-[A-Za-z0-9_-]{20,})(?![A-Za-z0-9_-])",
        min_entropy=3.0,
    ),
    # --- 智谱 GLM 的 id.secret 形式 ---
    _fmt(
        "智谱 GLM 兼容（id.secret）",
        r"(?<![A-Za-z0-9_.-])(?P<key>[A-Za-z0-9]{8,}\.[A-Za-z0-9]{28,})(?![A-Za-z0-9_.-])",
        min_entropy=3.0,
    ),
    # --- 火山引擎方舟：UUID 形式，太常见，必须上下文 ---
    _fmt(
        "火山引擎方舟 / 豆包",
        r"(?<![0-9A-Fa-f-])(?P<key>[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})(?![0-9A-Fa-f-])",
        requires_context=True,
    ),
    # --- JWT：MiniMax 与各类 Bearer 令牌 ---
    _fmt(
        "JWT 令牌（MiniMax/通用）",
        r"(?<![A-Za-z0-9_-])(?P<key>eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})(?![A-Za-z0-9_-])",
    ),
    # --- 腾讯云 SecretId（AKID 前缀足够特异，可直接确定） ---
    _fmt(
        "腾讯云",
        r"(?<![A-Za-z0-9])(?P<key>AKID[A-Za-z0-9]{20,})(?![A-Za-z0-9])",
        fixed=True,
    ),
    # --- GitHub 令牌 ---
    _fmt(
        "GitHub",
        r"(?<![A-Za-z0-9])(?P<key>gh[pous]_[A-Za-z0-9]{36})(?![A-Za-z0-9])",
        fixed=True,
    ),
    _fmt(
        "GitHub",
        r"(?<![A-Za-z0-9])(?P<key>github_pat_[A-Za-z0-9_]{20,})(?![A-Za-z0-9])",
        fixed=True,
    ),
    # --- Google API Key ---
    _fmt(
        "Google",
        r"(?<![A-Za-z0-9])(?P<key>AIza[0-9A-Za-z_-]{35})(?![A-Za-z0-9])",
        fixed=True,
    ),
    # --- AWS Access Key ---
    _fmt(
        "AWS",
        r"(?<![A-Za-z0-9])(?P<key>(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})(?![A-Za-z0-9])",
        fixed=True,
    ),
    # --- Slack 令牌 ---
    _fmt(
        "Slack",
        r"(?<![A-Za-z0-9])(?P<key>xox[baprs]-[A-Za-z0-9-]{10,})(?![A-Za-z0-9])",
        fixed=True,
    ),
)

# 熵兜底候选：无法匹配已知格式、但随机性高的字符串。
# 只在与「敏感赋值」相邻时报警，避免把普通 hash、cache key 当密钥。
BASE64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/=])(?P<key>[A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])")
HEX_CANDIDATE = re.compile(r"(?<![0-9A-Fa-f])(?P<key>[0-9A-Fa-f]{32,})(?![0-9A-Fa-f])")

SENSITIVE_CONTEXT = re.compile(
    r"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?key|auth[_-]?token|"
    r"bearer|password|passwd|credential|private[_-]?key|client[_-]?secret|"
    r"authorization|token)"
)

# 用于 AI 复核前的脱敏：覆盖全部格式 + 熵兜底候选。
REDACTION_PATTERNS = tuple(fmt.pattern for fmt in KEY_FORMATS) + (BASE64_CANDIDATE, HEX_CANDIDATE)

# 常见占位符 / 文档示例字符串，即使长度满足也要排除。
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


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


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


def _context_scores(text: str, start: int, end: int) -> dict[str, int]:
    local = text[max(0, start - _CONTEXT_WINDOW): min(len(text), end + _CONTEXT_WINDOW)]
    scores: dict[str, int] = {}
    for rule in PROVIDERS:
        score = sum(1 for pattern in rule.context if pattern.search(local))
        if score:
            scores[rule.name] = score
    return scores


def _sensitive_context_near(text: str, start: int, end: int) -> bool:
    local = text[max(0, start - _CONTEXT_WINDOW): min(len(text), end + _CONTEXT_WINDOW)]
    return bool(SENSITIVE_CONTEXT.search(local))


def _resolve_provider(
    fmt: KeyFormat, text: str, start: int, end: int
) -> tuple[str, float] | None:
    scores = _context_scores(text, start, end)
    best = max(scores, key=scores.get) if scores else None

    if fmt.requires_context and best is None:
        return None  # UUID 等常见格式，无上下文直接丢弃

    if fmt.fixed:
        # 格式本身确定提供商，上下文只提置信度。
        confidence = 0.80 + (0.02 * scores.get(best, 0) if best else 0.0)
        return fmt.provider, min(0.99, confidence)

    if best is not None:
        return best, min(0.99, 0.82 + 0.05 * scores[best])

    # 无上下文：保留格式默认归属，但降置信度。
    return fmt.provider, 0.60


# 太笼统/误匹配的模型名（minified JS 里 "chat"、"model" 等常被误当模型）
_GENERIC_MODEL_NAME = re.compile(r"(?i)^(?:chat|model|default|llm|ai|assistant|completion|base|main)$")

# 非对话模型：embedding / rerank / 语音 / 图像等，混在配置里但不应算作对话模型
_NON_CHAT_MODEL = re.compile(
    r"(?i)(?:embed|rerank|re-rank|bge-|whisper|asr|tts|speech|voice|"
    r"vision|image|stable|diffusion|dall-|flux|audio|ocr|translat)"
)


def _models_near(text: str, start: int, end: int) -> str:
    # 紧邻窗口：直接 model="xxx" 赋值。远窗口：兜底。
    near = text[max(0, start - 200): min(len(text), end + 200)]
    far = text[max(0, start - 500): min(len(text), end + 500)]
    found: list[str] = []
    seen: set[str] = set()

    def keep(name: str) -> bool:
        if not name or len(name) < 3:
            return False
        if _GENERIC_MODEL_NAME.match(name):
            return False
        if _NON_CHAT_MODEL.search(name):
            return False
        return True

    def add(name: str) -> bool:
        key = name.lower()
        if key in seen or not keep(name):
            return False
        seen.add(key)
        found.append(name)
        return True

    # 1) 紧邻 model="..." 赋值（最相关）
    for match in _MODEL_ASSIGN.finditer(near):
        if add(match.group(1).strip()) and len(found) >= 2:
            break
    # 2) 远 _MODEL_ASSIGN（数组/多配置场景）
    if len(found) < 2:
        for match in _MODEL_ASSIGN.finditer(far):
            if add(match.group(1).strip()) and len(found) >= 2:
                break
    # 3) 紧邻裸词（_KNOWN_MODELS）兜底，仅前两步都无结果时
    if not found:
        for match in _KNOWN_MODELS.finditer(near):
            if add(match.group(1).strip()) and len(found) >= 2:
                break
    # 4) 远裸词兜底
    if not found:
        for match in _KNOWN_MODELS.finditer(far):
            if add(match.group(1).strip()) and len(found) >= 2:
                break
    return ",".join(found[:2])[:120]


def extract_credential_findings(
    text: str,
    *,
    source_url: str,
    asset_name: str,
    product: str,
    fingerprint_key: str,
) -> list[dict[str, object]]:
    """Find likely API keys; persist only asset + model + suffix8 (+ hmac for dedupe).

    与旧版不同：无提供商上下文的强格式密钥不再被丢弃，而是降级为通用归属，
    以人工复核兜底，从而显著降低漏报。
    """
    if not fingerprint_key:
        raise ValueError("SECRETWATCHER_FINGERPRINT_KEY 未配置")

    results: list[dict[str, object]] = []
    seen: set[str] = set()
    path = urlsplit(source_url).path or "/"
    path_confidence = _get_confidence_from_path(source_url)
    require_strict_context = _LOW_CONFIDENCE_PATHS.search(path) is not None
    covered: list[tuple[int, int]] = []

    def emit(raw_key: str, provider: str, confidence: float, start: int, end: int) -> None:
        raw_key = raw_key.strip()
        if not raw_key or _is_placeholder_key(raw_key):
            return
        if _is_in_exclusion_context(text, start, end):
            return
        if require_strict_context and not _has_valid_assignment_context(text, start, end):
            return
        confidence = min(confidence, path_confidence)
        if confidence < 0.5:
            return
        digest = hmac.new(fingerprint_key.encode(), raw_key.encode(), hashlib.sha256).hexdigest()
        if digest in seen:
            return
        seen.add(digest)
        results.append(
            {
                "provider": provider,
                "product": product,
                "asset_name": asset_name[:255],
                "source_path": path[:1000],
                "model_names": _models_near(text, start, end),
                "key_suffix8": raw_key[-8:],
                "key_hmac": digest,
                "confidence": round(confidence, 2),
                "risk_level": "critical" if confidence >= 0.75 else "medium",
            }
        )

    # 1. 精确格式库。
    for fmt in KEY_FORMATS:
        for match in fmt.pattern.finditer(text):
            raw_key = match.group("key")
            if fmt.min_entropy is not None and _shannon_entropy(raw_key) < fmt.min_entropy:
                continue
            resolved = _resolve_provider(fmt, text, match.start(), match.end())
            if resolved is None:
                continue
            provider, confidence = resolved
            covered.append((match.start(), match.end()))
            emit(raw_key, provider, confidence, match.start(), match.end())

    # 2. 熵兜底：只在敏感赋值语境中，对高熵 base64 / hex 串报警，
    #    并跳过格式库已覆盖的区间，避免同一密钥的子串被重复报告。
    def _overlaps(start: int, end: int) -> bool:
        return any(start < b and a < end for a, b in covered)

    for candidate, threshold, confidence in (
        (BASE64_CANDIDATE, 4.5, 0.45),
        (HEX_CANDIDATE, 3.2, 0.42),
    ):
        for match in candidate.finditer(text):
            if _overlaps(match.start(), match.end()):
                continue
            raw_key = match.group("key").rstrip("=")
            if _shannon_entropy(raw_key) < threshold:
                continue
            if not _sensitive_context_near(text, match.start(), match.end()):
                continue
            emit(raw_key, "未识别（高熵凭据）", confidence, match.start(), match.end())

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
