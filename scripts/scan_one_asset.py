#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
from urllib.parse import urlsplit

from app.config import get_settings
from app.crawler import crawl_javascript_exposure
from app.database import Database
from app.product_adapters import adapter_for


async def run(url: str, product: str, confirm_exposure: bool) -> dict[str, object]:
    cfg = get_settings()
    if not cfg.fingerprint_key:
        raise SystemExit("SECRETWATCHER_FINGERPRINT_KEY 未配置")

    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SystemExit("资产必须是有效的 HTTP/HTTPS URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        ipaddress.ip_address(parsed.hostname)
        ip, domain = parsed.hostname, ""
    except ValueError:
        ip, domain = "", parsed.hostname

    db = Database(cfg.database_path)
    db.initialize()
    asset_id, inserted = db.upsert_asset({
        "host": parsed.hostname,
        "ip": ip,
        "port": port,
        "protocol": parsed.scheme,
        "domain": domain,
        "title": product,
        "link": url,
    })
    report = await crawl_javascript_exposure(
        url,
        asset_name=parsed.hostname,
        product=product,
        fingerprint_key=cfg.fingerprint_key,
    )

    adapter = adapter_for(product)
    confirmed = 0
    new_findings = 0
    for finding in report["findings"]:
        if db.upsert_credential_finding(asset_id, finding):
            new_findings += 1
        source_path = str(finding.get("source_path", ""))
        can_confirm = (
            confirm_exposure
            and adapter is not None
            and adapter.maturity == "verified"
            and source_path in adapter.public_paths
            and float(finding.get("confidence", 0)) >= 0.9
        )
        if can_confirm and db.set_credential_status(asset_id, str(finding["key_hmac"]), "confirmed"):
            confirmed += 1

    db.finish_asset_scan(
        asset_id,
        files=int(report["files_scanned"]),
        bytes_scanned=int(report["bytes_scanned"]),
        findings=len(report["findings"]),
    )
    return {
        "asset_id": asset_id,
        "asset_inserted": inserted,
        "files_scanned": report["files_scanned"],
        "bytes_scanned": report["bytes_scanned"],
        "findings": len(report["findings"]),
        "new_findings": new_findings,
        "confirmed_exposures": confirmed,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="扫描单个明确输入的公开资产并脱敏落库")
    parser.add_argument("url")
    parser.add_argument("--product", required=True)
    parser.add_argument("--confirm-exposure", action="store_true")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(run(args.url, args.product, args.confirm_exposure)), ensure_ascii=False))


if __name__ == "__main__":
    main()
