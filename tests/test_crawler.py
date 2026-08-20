import httpx
import json
import pytest

from app.crawler import CrawlLimits, asset_entry_urls, crawl_javascript_exposure


def test_builds_asset_entry_urls_from_fofa_fields():
    urls = asset_entry_urls({
        "host": "example.test:8443", "domain": "example.test", "ip": "203.0.113.8",
        "port": 8443, "protocol": "https", "link": "",
    })
    assert "https://example.test:8443/" in urls
    assert "https://203.0.113.8:8443/" in urls


@pytest.mark.asyncio
async def test_crawls_html_chunks_and_source_maps_without_returning_key():
    raw = "sk-abcdefghijklmnopqrstuvwxyz123456"
    responses = {
        "/": ("text/html", '<script src="/assets/app.js"></script>'),
        "/assets/app.js": ("application/javascript", 'import("/assets/chunk-7.js"); //# sourceMappingURL=app.js.map'),
        "/assets/chunk-7.js": (
            "application/javascript",
            f'const DEEPSEEK_API_KEY="{raw}"; const model="deepseek-chat"; const base="https://api.deepseek.com"',
        ),
        "/assets/app.js.map": (
            "application/json",
            '{"version":3,"sources":["src/secret.ts"],"sourcesContent":["const x=1"]}',
        ),
        "/config.js": ("application/javascript", "window.__CFG={}"),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        content_type, body = responses.get(request.url.path, ("text/plain", "missing"))
        return httpx.Response(
            200 if request.url.path in responses else 404,
            text=body,
            headers={"content-type": content_type},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        report = await crawl_javascript_exposure(
            "https://example.test/",
            asset_name="example.test",
            product="DeepTutor",
            fingerprint_key="test-fingerprint-secret",
            client=client,
            allow_private=True,
        )
    assert report["files_scanned"] >= 4
    assert len(report["findings"]) == 1
    assert report["findings"][0]["model_names"] == "deepseek-chat"
    assert report["findings"][0]["key_suffix8"] == raw[-8:]
    assert raw not in repr(report)


@pytest.mark.asyncio
async def test_scans_source_map_sources_content_for_keys():
    raw = "sk-mapembeddedkeyvalueabcdef123456"
    mapping = {
        "version": 3,
        "sources": ["src/cfg.ts"],
        "sourcesContent": [
            f'DEEPSEEK_API_KEY="{raw}"; model="deepseek-coder"; base="https://api.deepseek.com"',
        ],
    }
    responses = {
        "/": ("text/html", "<html></html>"),
        "/assets/app.js.map": ("application/json", json.dumps(mapping)),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/assets/app.js.map":
            return httpx.Response(200, text=responses["/assets/app.js.map"][1], headers={"content-type": "application/json"})
        if request.url.path == "/":
            return httpx.Response(200, text='<script src="/assets/app.js.map"></script>', headers={"content-type": "text/html"})
        return httpx.Response(404, text="missing")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        report = await crawl_javascript_exposure(
            "https://example.test/",
            asset_name="map.test",
            product="Open WebUI",
            fingerprint_key="test-fingerprint-secret",
            client=client,
            allow_private=True,
            limits=CrawlLimits(max_files=40),
        )
    assert len(report["findings"]) == 1
    assert report["findings"][0]["key_suffix8"] == raw[-8:]
    assert "deepseek-coder" in report["findings"][0]["model_names"]
    assert raw not in repr(report)


@pytest.mark.asyncio
async def test_deeptutor_scans_structured_settings_endpoint():
    raw = "sk-0123456789abcdef0123456789abcdef"
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request.url.path)
        if request.url.path == "/":
            return httpx.Response(200, text="<title>DeepTutor</title>", headers={"content-type": "text/html"})
        if request.url.path == "/api/v1/settings":
            payload = {
                "catalog": {"services": {"llm": {"profiles": [{
                    "provider": "deepseek",
                    "model": "deepseek-chat",
                    "base_url": "https://api.deepseek.com",
                    "api_key": raw,
                }]}}}
            }
            return httpx.Response(200, json=payload)
        return httpx.Response(404, text="missing")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        report = await crawl_javascript_exposure(
            "https://example.test/",
            asset_name="example.test",
            product="DeepTutor",
            fingerprint_key="test-fingerprint-secret",
            client=client,
            allow_private=True,
        )

    assert "/api/v1/settings" in requested
    assert len(report["findings"]) == 1
    assert report["findings"][0]["provider"] == "DeepSeek"
    assert report["findings"][0]["key_suffix8"] == raw[-8:]
    assert raw not in repr(report)
