from __future__ import annotations

import json
import re
from typing import Any

import httpx

from .credentials import REDACTION_PATTERNS


SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(authorization|cookie|api[_-]?key|secret|token)(\s*[:=]\s*)"
    r"([\"']?)([^\s,;\"']{8,})([\"']?)"
)


def redact_for_ai(text: str, max_chars: int = 24_000) -> str:
    redacted = text[:max_chars]
    for pattern in REDACTION_PATTERNS:
        redacted = pattern.sub("[REDACTED_CREDENTIAL]", redacted)
    redacted = SENSITIVE_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED_CREDENTIAL]",
        redacted,
    )
    return redacted


class DeepSeekReviewer:
    def __init__(self, api_key: str, base_url: str, model: str, timeout: float = 30):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    async def review(self, javascript: str) -> dict[str, Any]:
        safe_text = redact_for_ai(javascript)
        prompt = (
            "你是公益安全项目的前端代码分析器。输入已经脱敏。"
            "识别其中的大模型供应商、可能返回配置或凭据的同源公开路径、构建系统。"
            "不要推测密钥内容，不建议绕过认证。只返回 JSON："
            '{"providers":[],"candidate_paths":[],"framework":"","reason":""}.\n\n'
            + safe_text
        )
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0,
                    "response_format": {"type": "json_object"},
                },
            )
        response.raise_for_status()
        payload = response.json()
        content = payload["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        paths = [str(path) for path in parsed.get("candidate_paths", []) if str(path).startswith("/")]
        return {
            "providers": [str(item)[:100] for item in parsed.get("providers", [])][:20],
            "candidate_paths": paths[:30],
            "framework": str(parsed.get("framework", ""))[:100],
            "reason": str(parsed.get("reason", ""))[:500],
        }
