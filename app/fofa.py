from __future__ import annotations

import base64

import httpx


FIELDS = ("host", "ip", "port", "protocol", "domain", "title", "server", "header", "link")


class FofaError(RuntimeError):
    pass


class FofaClient:
    def __init__(self, base_url: str, key: str, timeout: float = 20):
        if not key:
            raise FofaError("FOFA_KEY 未配置")
        self.base_url = base_url
        self.key = key
        self.timeout = timeout

    async def search(self, query: str, size: int = 100, page: int = 1) -> list[dict[str, object]]:
        if not 1 <= size <= 1000:
            raise FofaError("size 必须在 1 到 1000 之间")
        qbase64 = base64.b64encode(query.encode()).decode()
        params = {
            "key": self.key,
            "qbase64": qbase64,
            "fields": ",".join(FIELDS),
            "size": size,
            "page": page,
        }
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
            response = await client.get(f"{self.base_url}/api/v1/search/all", params=params)
        if response.status_code != 200:
            raise FofaError(f"FOFA 请求失败：HTTP {response.status_code}")
        payload = response.json()
        if payload.get("error"):
            raise FofaError(str(payload.get("errmsg") or "FOFA 返回错误"))
        rows = payload.get("results") or []
        return [dict(zip(FIELDS, row, strict=False)) for row in rows if isinstance(row, list)]

