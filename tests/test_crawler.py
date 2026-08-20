import httpx
import pytest

from app.crawler import crawl_javascript_exposure


@pytest.mark.asyncio
async def test_crawls_html_chunks_and_source_maps_without_returning_key():
    raw = "sk-abcdefghijklmnopqrstuvwxyz123456"
    responses = {
        "/": ("text/html", '<script src="/assets/app.js"></script>'),
        "/assets/app.js": ("application/javascript", 'import("/assets/chunk-7.js"); //# sourceMappingURL=app.js.map'),
        "/assets/chunk-7.js": ("application/javascript", f'const DEEPSEEK_API_KEY="{raw}"; const base="https://api.deepseek.com"'),
        "/assets/app.js.map": ("application/json", '{"version":3,"sources":[]}'),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        content_type, body = responses.get(request.url.path, ("text/plain", "missing"))
        return httpx.Response(200 if request.url.path in responses else 404, text=body, headers={"content-type": content_type})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        report = await crawl_javascript_exposure(
            "https://example.test/",
            asset_name="example.test",
            product="DeepTutor",
            fingerprint_key="test-fingerprint-secret",
            client=client,
            allow_private=True,
        )
    assert report["files_scanned"] == 4
    assert len(report["findings"]) == 1
    assert raw not in repr(report)
