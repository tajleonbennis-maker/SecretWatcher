#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio

from app.config import get_settings
from app.ai_review import DeepSeekReviewer
from app.crawler import crawl_javascript_exposure
from app.database import Database


async def run(limit: int) -> dict[str, int]:
    cfg = get_settings()
    if not cfg.fingerprint_key:
        raise SystemExit("SECRETWATCHER_FINGERPRINT_KEY 未配置")
    db = Database(cfg.database_path)
    db.initialize()
    result = {"assets": 0, "files": 0, "findings": 0}
    reviewer = (
        DeepSeekReviewer(cfg.deepseek_api_key, cfg.deepseek_base_url, cfg.deepseek_model)
        if cfg.deepseek_api_key else None
    )
    for asset in db.asset_for_scan(limit):
        url = str(asset.get("link") or asset.get("host") or "")
        if not url:
            continue
        result["assets"] += 1
        try:
            report = await crawl_javascript_exposure(
                url,
                asset_name=str(asset.get("domain") or asset.get("title") or "未命名资产"),
                product=str(asset.get("product") or ""),
                fingerprint_key=cfg.fingerprint_key,
                reviewer=reviewer,
            )
        except (ValueError, OSError) as exc:
            db.finish_asset_scan(int(asset["id"]), files=0, bytes_scanned=0, findings=0, error=type(exc).__name__)
            continue
        result["files"] += int(report["files_scanned"])
        new_findings = 0
        for finding in report["findings"]:
            if db.upsert_credential_finding(int(asset["id"]), finding):
                result["findings"] += 1
                new_findings += 1
        db.finish_asset_scan(
            int(asset["id"]), files=int(report["files_scanned"]),
            bytes_scanned=int(report["bytes_scanned"]), findings=new_findings,
        )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="同源遍历公开 HTML/JS 并脱敏记录大模型凭据暴露")
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()
    print(asyncio.run(run(args.limit)))


if __name__ == "__main__":
    main()
