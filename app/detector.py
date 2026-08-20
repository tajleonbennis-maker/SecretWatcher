from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Signature:
    product: str
    category: str
    patterns: tuple[re.Pattern[str], ...]
    confidence: float


def _patterns(*values: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(value, re.I) for value in values)


SIGNATURES = (
    Signature("DeepTutor", "ai_application", _patterns(r"\bDeepTutor\b", r"/api/v1/settings/llm-options"), 0.94),
    Signature("Dify", "ai_application", _patterns(r"\bDify\b", r"/console/api/", r"langgenius"), 0.91),
    Signature("Open WebUI", "ai_application", _patterns(r"Open[ -]?WebUI", r"/api/v1/auths"), 0.93),
    Signature("AnythingLLM", "ai_application", _patterns(r"AnythingLLM", r"/api/system"), 0.94),
    Signature("LobeChat", "ai_application", _patterns(r"LobeChat", r"Lobe Chat"), 0.93),
    Signature("LibreChat", "ai_application", _patterns(r"LibreChat"), 0.93),
    Signature("FastGPT", "ai_application", _patterns(r"FastGPT"), 0.92),
    Signature("RAGFlow", "ai_application", _patterns(r"\bRAGFlow\b"), 0.94),
    Signature("New API", "ai_gateway", _patterns(r"\bNew API\b", r"new-api"), 0.82),
    Signature("One API", "ai_gateway", _patterns(r"\bOne API\b", r"one-api"), 0.82),
    Signature("LiteLLM Proxy", "ai_gateway", _patterns(r"LiteLLM", r"litellm-proxy"), 0.91),
    Signature("ChatGPT-Next-Web", "ai_application", _patterns(r"ChatGPT[- ]Next[- ]Web", r"NextChat"), 0.9),
    Signature("Ollama", "model_runtime", _patterns(r"\bOllama\b", r"/api/tags"), 0.84),
    Signature("vLLM", "model_runtime", _patterns(r"\bvLLM\b", r"vllm-project"), 0.84),
)


def detect(row: dict[str, object]) -> list[dict[str, object]]:
    fields = {
        "title": str(row.get("title") or ""),
        "server": str(row.get("server") or ""),
        "header": str(row.get("header") or ""),
        "link": str(row.get("link") or ""),
        "host": str(row.get("host") or ""),
    }
    results: list[dict[str, object]] = []
    for signature in SIGNATURES:
        for kind, value in fields.items():
            match = next((pattern.search(value) for pattern in signature.patterns if pattern.search(value)), None)
            if match:
                results.append(
                    {
                        "product": signature.product,
                        "category": signature.category,
                        "confidence": signature.confidence if kind != "title" else min(0.99, signature.confidence + 0.04),
                        "evidence_kind": kind,
                        "evidence_summary": f"{kind} 命中 {match.group(0)[:80]}",
                    }
                )
                break
    return results

