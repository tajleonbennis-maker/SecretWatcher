from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
from collections import deque
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from .ai_review import DeepSeekReviewer
from .credentials import extract_credential_findings


HTML_ASSET = re.compile(r"<(?:script|link)\b[^>]+?(?:src|href)=[\"']([^\"']+)[\"']", re.I)
JS_ASSET = re.compile(r"[\"']([^\"']{1,500}\.(?:js|mjs|map)(?:\?[^\"']*)?)[\"']", re.I)
SOURCE_MAP = re.compile(r"sourceMappingURL=([^\s*]+)")


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
        addresses = await asyncio.to_thread(socket.getaddrinfo, host, None)
    except socket.gaierror:
        return False
    for item in addresses:
        ip = ipaddress.ip_address(item[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return False
    return True


def _normalize(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))


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
        headers={"User-Agent": "SecretWatcher/0.1 (+https://www.cyberstroll.top)"},
    )
    queue: deque[str] = deque([root_url])
    visited: set[str] = set()
    findings: list[dict[str, object]] = []
    ai_reviews: list[dict[str, object]] = []
    total_bytes = 0
    try:
        while queue and len(visited) < limits.max_files and total_bytes < limits.max_bytes:
            url = queue.popleft()
            if url in visited or not _same_origin(root_url, url):
                continue
            visited.add(url)
            try:
                response = await http.get(url, headers={"Range": f"bytes=0-{limits.max_file_bytes - 1}"})
            except httpx.HTTPError:
                continue
            if response.status_code != 200:
                continue
            content = response.content[: limits.max_file_bytes]
            total_bytes += len(content)
            text = content.decode("utf-8", errors="ignore")
            findings.extend(
                extract_credential_findings(
                    text, source_url=url, asset_name=asset_name, product=product,
                    fingerprint_key=fingerprint_key,
                )
            )
            content_type = response.headers.get("content-type", "").lower()
            refs: list[str] = []
            if "html" in content_type or url == root_url:
                refs.extend(HTML_ASSET.findall(text))
            if "javascript" in content_type or urlsplit(url).path.endswith((".js", ".mjs")):
                refs.extend(JS_ASSET.findall(text))
                refs.extend(SOURCE_MAP.findall(text))
                if reviewer and re.search(
                    r"(?i)(api[_-]?key|authorization|base[_-]?url|deepseek|dashscope|bigmodel|moonshot|volces)",
                    text,
                ):
                    try:
                        review = await reviewer.review(text)
                        ai_reviews.append({"source_path": urlsplit(url).path, **review})
                        refs.extend(review["candidate_paths"])
                    except (httpx.HTTPError, KeyError, ValueError, json.JSONDecodeError):
                        pass
            for ref in refs:
                candidate = _normalize(urljoin(url, ref.strip('"\'')))
                if _same_origin(root_url, candidate) and candidate not in visited:
                    queue.append(candidate)
    finally:
        if own_client:
            await http.aclose()

    unique = {str(item["key_hmac"]): item for item in findings}
    return {
        "files_scanned": len(visited),
        "bytes_scanned": total_bytes,
        "findings": list(unique.values()),
        "ai_reviews": ai_reviews,
    }
