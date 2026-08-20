#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio

from app.config import get_settings
from app.database import Database
from app.detector import detect
from app.fofa import FofaClient, FofaError


async def run(query: str, size: int, page: int) -> dict[str, int]:
    settings = get_settings()
    database = Database(settings.database_path)
    database.initialize()
    job_id = database.create_job(query, size)
    result = {"received": 0, "inserted": 0, "updated": 0, "detections": 0}
    try:
        rows = await FofaClient(settings.fofa_base_url, settings.fofa_key).search(query, size, page)
        result["received"] = len(rows)
        for row in rows:
            asset_id, inserted = database.upsert_asset(row)
            result["inserted" if inserted else "updated"] += 1
            for finding in detect(row):
                database.upsert_detection(asset_id, finding)
                result["detections"] += 1
        database.finish_job(job_id, result)
        return result
    except FofaError as exc:
        database.finish_job(job_id, result, str(exc))
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="被动导入 FOFA 资产数据，不访问目标站点")
    parser.add_argument("query", help="FOFA 查询语句")
    parser.add_argument("--size", type=int, default=100, choices=range(1, 1001), metavar="1..1000")
    parser.add_argument("--page", type=int, default=1)
    args = parser.parse_args()
    result = asyncio.run(run(args.query, args.size, args.page))
    print(
        "导入完成："
        f"收到 {result['received']}，新增 {result['inserted']}，"
        f"更新 {result['updated']}，指纹命中 {result['detections']}"
    )


if __name__ == "__main__":
    main()

