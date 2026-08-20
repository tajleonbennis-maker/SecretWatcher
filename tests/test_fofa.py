import base64

import httpx
import pytest

from app.fofa import FIELDS, FofaClient


@pytest.mark.asyncio
async def test_fofa_normalizes_rows(monkeypatch):
    async def fake_get(self, url, params):
        assert base64.b64decode(params["qbase64"]).decode() == 'title="DeepTutor"'
        row = ["http://example.test", "203.0.113.5", "80", "http", "example.test", "DeepTutor", "nginx", "", "http://example.test"]
        return httpx.Response(200, json={"error": False, "results": [row]}, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    rows = await FofaClient("https://fofa.test", "test-key").search('title="DeepTutor"')
    assert set(rows[0]) == set(FIELDS)
    assert rows[0]["ip"] == "203.0.113.5"
    assert rows[0]["title"] == "DeepTutor"

