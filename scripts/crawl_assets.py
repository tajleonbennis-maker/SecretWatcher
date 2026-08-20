#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio

from app.config import get_settings
from app.ai_review import DeepSeekReviewer
from app.crawler import asset_entry_urls, crawl_javascript_exposure
from app.database import Database


async def _scan_one(asset: dict[str, object], cfg, reviewer, semaphore: asyncio.Semaphore, db: Database, run_id: int):
    urls = asset_entry_urls(asset)
    if not urls:
        return asset, None, {}, "NoCandidateURL"
    diagnostics: dict[str, int] = {}
    last_error = ""
    async with semaphore:
        asset_id = int(asset["id"])
        db.mark_asset_scan(asset_id, "running", run_id)
        for url in urls:
            try:
                report = await crawl_javascript_exposure(
                    url,
                    asset_name=str(asset.get("domain") or asset.get("title") or "未命名资产"),
                    product=str(asset.get("product") or ""),
                    fingerprint_key=cfg.fingerprint_key,
                    reviewer=reviewer,
                    on_file=lambda size: db.record_file_progress(run_id, asset_id, size),
                )
            except (ValueError, OSError) as exc:
                last_error = type(exc).__name__
                continue
            for kind, count in report["diagnostics"].items():
                diagnostics[kind] = diagnostics.get(kind, 0) + int(count)
            if int(report["files_scanned"]) > 0:
                return asset, report, diagnostics, ""
    return asset, None, diagnostics, last_error or "NoSuccessfulResponse"


async def run(limit: int, concurrency: int = 5) -> dict[str, object]:
    cfg = get_settings()
    if not cfg.fingerprint_key:
        raise SystemExit("SECRETWATCHER_FINGERPRINT_KEY 未配置")
    db = Database(cfg.database_path)
    db.initialize()
    result = {"assets": 0, "requests": 0, "files": 0, "bytes": 0, "findings": 0}
    diagnostics: dict[str, int] = {}
    reviewer = (
        DeepSeekReviewer(cfg.deepseek_api_key, cfg.deepseek_base_url, cfg.deepseek_model)
        if cfg.deepseek_api_key else None
    )
    assets = db.asset_for_scan(limit)
    result["assets"] = len(assets)
    run_id = db.create_scan_run(len(assets))
    for asset in assets:
        db.mark_asset_scan(int(asset["id"]), "queued", run_id)
    semaphore = asyncio.Semaphore(max(1, min(concurrency, 10)))
    tasks = [asyncio.create_task(_scan_one(asset, cfg, reviewer, semaphore, db, run_id)) for asset in assets]
    for task in asyncio.as_completed(tasks):
        asset, report, asset_diagnostics, scan_error = await task
        for kind, count in asset_diagnostics.items():
            diagnostics[kind] = diagnostics.get(kind, 0) + int(count)
        if report is None:
            db.finish_asset_scan(
                int(asset["id"]), files=0, bytes_scanned=0, findings=0,
                error=scan_error,
            )
            db.advance_scan_run(
                run_id, files=0, bytes_scanned=0, findings=0, failed=True
            )
            continue
        result["requests"] += int(report["requests_attempted"])
        result["files"] += int(report["files_scanned"])
        result["bytes"] += int(report["bytes_scanned"])
        new_findings = 0
        for finding in report["findings"]:
            if db.upsert_credential_finding(int(asset["id"]), finding):
                result["findings"] += 1
                new_findings += 1
        db.finish_asset_scan(
            int(asset["id"]), files=int(report["files_scanned"]),
            bytes_scanned=int(report["bytes_scanned"]), findings=new_findings,
        )
        db.advance_scan_run(
            run_id, files=0, bytes_scanned=0, findings=new_findings, failed=False,
        )
    result["diagnostics"] = diagnostics
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="同源遍历公开 HTML/JS 并脱敏记录大模型凭据暴露")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=5, choices=range(1, 11), metavar="1..10")
    args = parser.parse_args()
    print(asyncio.run(run(args.limit, args.concurrency)))


if __name__ == "__main__":
    main()
