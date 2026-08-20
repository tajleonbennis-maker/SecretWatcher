from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
from collections import deque
from dataclasses import dataclass
from collections.abc import Callable
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from .ai_review import DeepSeekReviewer
from .credentials import extract_credential_findings


HTML_ASSET = re.compile(r"<(?:script|link)\b[^>]+?(?:src|href)=[\"']([^\"']+)[\"']", re.I)
JS_ASSET = re.compile(r"[\"']([^\"']{1,500}\.(?:js|mjs|map)(?:\?[^\"']*)?)[\"']", re.I)
SOURCE_MAP = re.compile(r"sourceMappingURL=([^\s*]+)")
BUILD_MANIFEST = re.compile(
    r"[\"']((?:/_next/static/[^\"']+|_nuxt/[^\"']+|/(?:assets|static|dist|build|js)/[^\"']+\.(?:js|mjs|json))(?:\?[^\"']*)?)[\"']",
    re.I,
)
REDIRECT_CODES = {301, 302, 303, 307, 308}

# High-signal same-origin paths often containing runtime config / embedded keys.
PRIORITY_PATHS = (
    "/config.js",
    "/env.js",
    "/env-config.js",
    "/runtime-config.js",
    "/_app.config.js",
    "/settings.js",
    "/static/config.js",
    "/assets/config.js",
    "/config.json",
    "/env.json",
    "/manifest.json",
    "/_next/static/chunks/main.js",
    "/_next/static/chunks/webpack.js",
    "/_next/static/chunks/pages/_app.js",
)


@dataclass(frozen=True)
class CrawlLimits:
    max_files: int = 80
    max_bytes: int = 12_000_000
    max_file_bytes: int = 2_000_000
    concurrency: int = 4


def _same_origin(root: str, candidate: str) -> bool:
    a, b = urlsplit(root), urlsplit(candidate)
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)


async def _public_host(url: str) -> bool:
    host = urlsplit(url).hostname
    if not host:
        return False
    try:
        addresses = await asyncio.wait_for(
            asyncio.to_thread(socket.getaddrinfo, host, None), timeout=5
        )
    except (socket.gaierror, TimeoutError):
        return False
    for item in addresses:
        ip = ipaddress.ip_address(item[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return False
    return True


def _normalize(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))


def asset_entry_urls(asset: dict[str, object]) -> list[str]:
    """Build usable HTTP entry URLs from heterogeneous FOFA fields."""
    candidates: list[str] = []

    def add(value: str) -> None:
        value = value.strip()
        if not value:
            return
        if value.startswith("//"):
            value = "https:" + value
        if urlsplit(value).scheme in {"http", "https"}:
            candidates.append(_normalize(value))

    add(str(asset.get("link") or ""))
    raw_host = str(asset.get("host") or "").strip()
    add(raw_host)

    protocol = str(asset.get("protocol") or "").lower()
    port = int(asset.get("port") or 0)
    preferred = protocol if protocol in {"http", "https"} else ("https" if port == 443 else "http")
    schemes = (preferred, "http" if preferred == "https" else "https")
    names: list[str] = []
    for value in (asset.get("domain"), asset.get("ip"), raw_host):
        name = str(value or "").strip()
        if not name or name.lower().startswith(("http://", "https://")):
            continue
        # FOFA host may be host:port without a scheme.
        names.append(name.split("/", 1)[0])
    for name in names:
        host_part = name
        if ":" not in name and port and not ((preferred == "http" and port == 80) or (preferred == "https" and port == 443)):
            host_part = f"{name}:{port}"
        for scheme in schemes:
            add(f"{scheme}://{host_part}/")

    return list(dict.fromkeys(candidates))


def _response_bucket(status: int) -> str:
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if status in {401, 403}:
        return "auth_or_forbidden"
    if status == 404:
        return "not_found"
    if status == 429:
        return "rate_limited"
    if 400 <= status < 500:
        return "other_4xx"
    if status >= 500:
        return "5xx"
    return "other"


async def _resolve_root(
    http: httpx.AsyncClient, root_url: str, diagnostics: dict[str, int], *, allow_private: bool
) -> tuple[str, httpx.Response | None]:
    current = root_url
    for _ in range(6):
        if not allow_private and not await _public_host(current):
            diagnostics["blocked_address"] = diagnostics.get("blocked_address", 0) + 1
            return current, None
        try:
            response = await http.get(current)
        except httpx.TimeoutException:
            diagnostics["timeout"] = diagnostics.get("timeout", 0) + 1
            return current, None
        except httpx.HTTPError:
            diagnostics["network_or_tls"] = diagnostics.get("network_or_tls", 0) + 1
            return current, None
        bucket = _response_bucket(response.status_code)
        diagnostics[bucket] = diagnostics.get(bucket, 0) + 1
        if response.status_code not in REDIRECT_CODES or not response.headers.get("location"):
            return current, response
        current = _normalize(urljoin(current, response.headers["location"]))
        if urlsplit(current).scheme not in {"http", "https"}:
            return current, None
    diagnostics["redirect_limit"] = diagnostics.get("redirect_limit", 0) + 1
    return current, None


def _scan_text_for_credentials(
    text: str,
    *,
    source_url: str,
    asset_name: str,
    product: str,
    fingerprint_key: str,
) -> list[dict[str, object]]:
    return extract_credential_findings(
        text,
        source_url=source_url,
        asset_name=asset_name,
        product=product,
        fingerprint_key=fingerprint_key,
    )


def _texts_from_source_map(payload: str) -> list[str]:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return []
    contents = data.get("sourcesContent")
    if not isinstance(contents, list):
        return []
    return [item for item in contents if isinstance(item, str) and item]


def _enqueue_priority_paths(root_url: str, queue: deque[tuple[str, httpx.Response | None]], visited: set[str]) -> None:
    for path in PRIORITY_PATHS:
        candidate = _normalize(urljoin(root_url, path))
        if _same_origin(root_url, candidate) and candidate not in visited:
            queue.append((candidate, None))


async def crawl_javascript_exposure(
    root_url: str,
    *,
    asset_name: str,
    product: str,
    fingerprint_key: str,
    limits: CrawlLimits = CrawlLimits(),
    client: httpx.AsyncClient | None = None,
    allow_private: bool = False,
    reviewer: DeepSeekReviewer | None = None,
    on_file: Callable[[int], None] | None = None,
) -> dict[str, object]:
    root_url = _normalize(root_url)
    if urlsplit(root_url).scheme not in {"http", "https"}:
        raise ValueError("仅支持 HTTP/HTTPS")
    if not allow_private and not await _public_host(root_url):
        raise ValueError("拒绝访问非公网地址")

    own_client = client is None
    http = client or httpx.AsyncClient(
        timeout=httpx.Timeout(12, connect=5),
        follow_redirects=False,
        verify=False,
        headers={"User-Agent": "SecretWatcher/0.1 (+https://www.cyberstroll.top)"},
    )
    diagnostics: dict[str, int] = {}
    resolved_root, initial_response = await _resolve_root(
        http, root_url, diagnostics, allow_private=allow_private
    )
    root_url = resolved_root
    queue: deque[tuple[str, httpx.Response | None]] = deque([(root_url, initial_response)])
    visited: set[str] = set()
    _enqueue_priority_paths(root_url, queue, visited)
    successful_files = 0
    findings: list[dict[str, object]] = []
    ai_reviews: list[dict[str, object]] = []
    total_bytes = 0
    try:
        while queue and len(visited) < limits.max_files and total_bytes < limits.max_bytes:
            url, prefetched = queue.popleft()
            if url in visited or not _same_origin(root_url, url):
                continue
            visited.add(url)
            if prefetched is not None:
                response = prefetched
            else:
                try:
                    response = await http.get(url, headers={"Range": f"bytes=0-{limits.max_file_bytes - 1}"})
                except httpx.TimeoutException:
                    diagnostics["timeout"] = diagnostics.get("timeout", 0) + 1
                    continue
                except httpx.HTTPError:
                    diagnostics["network_or_tls"] = diagnostics.get("network_or_tls", 0) + 1
                    continue
                bucket = _response_bucket(response.status_code)
                diagnostics[bucket] = diagnostics.get(bucket, 0) + 1
            if not 200 <= response.status_code < 300:
                continue
            successful_files += 1
            content = response.content[: limits.max_file_bytes]
            total_bytes += len(content)
            if on_file:
                on_file(len(content))
            text = content.decode("utf-8", errors="ignore")
            findings.extend(
                _scan_text_for_credentials(
                    text, source_url=url, asset_name=asset_name, product=product,
                    fingerprint_key=fingerprint_key,
                )
            )
            path_lower = urlsplit(url).path.lower()
            if path_lower.endswith(".map"):
                for embedded in _texts_from_source_map(text):
                    findings.extend(
                        _scan_text_for_credentials(
                            embedded, source_url=url, asset_name=asset_name, product=product,
                            fingerprint_key=fingerprint_key,
                        )
                    )
            content_type = response.headers.get("content-type", "").lower()
            refs: list[str] = []
            looks_html = "html" in content_type or "<script" in text.lower() or "<html" in text.lower()
            if looks_html or url == root_url:
                refs.extend(HTML_ASSET.findall(text))
                refs.extend(BUILD_MANIFEST.findall(text))
            looks_js = (
                "javascript" in content_type
                or "json" in content_type
                or path_lower.endswith((".js", ".mjs", ".json", ".map"))
            )
            if looks_js:
                refs.extend(JS_ASSET.findall(text))
                refs.extend(SOURCE_MAP.findall(text))
                refs.extend(BUILD_MANIFEST.findall(text))
            if reviewer and len(ai_reviews) < 3 and (looks_js or looks_html) and re.search(
                    r"(?i)(api[_-]?key|authorization|base[_-]?url|deepseek|dashscope|bigmodel|moonshot|volces|openai)",
                    text,
                ):
                try:
                    review = await reviewer.review(text)
                    ai_reviews.append({"source_path": urlsplit(url).path, **review})
                    refs.extend(review["candidate_paths"])
                except (httpx.HTTPError, KeyError, ValueError, json.JSONDecodeError):
                    diagnostics["ai_review_error"] = diagnostics.get("ai_review_error", 0) + 1
            for ref in refs:
                candidate = _normalize(urljoin(url, ref.strip('"\'')))
                if _same_origin(root_url, candidate) and candidate not in visited:
                    queue.append((candidate, None))
    finally:
        if own_client:
            await http.aclose()

    unique = {str(item["key_hmac"]): item for item in findings}
    return {
        "requests_attempted": len(visited),
        "files_scanned": successful_files,
        "bytes_scanned": total_bytes,
        "findings": list(unique.values()),
        "ai_reviews": ai_reviews,
        "diagnostics": diagnostics,
    }
