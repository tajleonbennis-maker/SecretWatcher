from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import Settings, get_settings
from .database import Database
from .detector import SIGNATURES, detect
from .fofa import FofaClient, FofaError


ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "web"


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    database = Database(settings.database_path)
    database.initialize()
    app.state.settings = settings
    app.state.database = database
    yield


app = FastAPI(title="秘钥守望者", version="0.1.0", docs_url=None, redoc_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC / "static"), name="static")


class ImportRequest(BaseModel):
    query: str = Field(min_length=3, max_length=500)
    size: int = Field(default=100, ge=1, le=1000)
    page: int = Field(default=1, ge=1, le=100)


class KeyLookupRequest(BaseModel):
    suffix4: str = Field(pattern=r"^[A-Za-z0-9_-]{4}$")


def settings() -> Settings:
    return app.state.settings


def database() -> Database:
    return app.state.database


def require_admin(
    authorization: str | None = Header(default=None),
    cfg: Settings = Depends(settings),
) -> None:
    if not cfg.admin_configured:
        raise HTTPException(status_code=503, detail="管理令牌尚未配置")
    expected = f"Bearer {cfg.admin_token}"
    if not authorization or not secrets.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="无效的管理凭据")


@app.get("/", include_in_schema=False)
def homepage() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health(cfg: Settings = Depends(settings)) -> dict[str, object]:
    return {"status": "ok", "fofa_configured": cfg.fofa_configured, "mode": "passive_observation"}


@app.get("/api/public/stats")
def public_stats(db: Database = Depends(database)) -> dict[str, object]:
    return db.public_stats()


@app.get("/api/public/coverage")
def public_coverage() -> dict[str, object]:
    return {
        "products": [item.product for item in SIGNATURES],
        "count": len(SIGNATURES),
        "method": "基于 FOFA 已有响应数据进行被动指纹识别",
    }


def _mask_asset(value: str) -> str:
    if "." in value:
        parts = value.split(".")
        parts[0] = (parts[0][:2] + "***") if parts[0] else "***"
        return ".".join(parts)
    return value[:2] + "***" if value else "未公开"


@app.post("/api/public/key-lookup")
def key_lookup(request: KeyLookupRequest, db: Database = Depends(database)) -> dict[str, object]:
    matches = db.lookup_key_suffix4(request.suffix4)
    return {
        "matches": [
            {
                "provider": item["provider"],
                "product": item["product"],
                "asset": _mask_asset(str(item["asset_name"])),
                "key_hint": "****" + str(item["key_suffix8"])[-4:],
                "first_seen": item["first_seen"],
                "last_seen": item["last_seen"],
                "status": item["status"],
            }
            for item in matches
        ],
        "count": len(matches),
        "notice": "末四位只能用于初步查询，查看完整处置信息前需验证资产所有权。",
    }


@app.post("/api/admin/fofa/import", dependencies=[Depends(require_admin)])
async def import_fofa(
    request: ImportRequest,
    cfg: Settings = Depends(settings),
    db: Database = Depends(database),
) -> dict[str, int]:
    if not cfg.fofa_configured:
        raise HTTPException(status_code=503, detail="FOFA_KEY 未配置")
    job_id = db.create_job(request.query, request.size)
    result = {"job_id": job_id, "received": 0, "inserted": 0, "updated": 0, "detections": 0}
    try:
        rows = await FofaClient(cfg.fofa_base_url, cfg.fofa_key).search(request.query, request.size, request.page)
        result["received"] = len(rows)
        for row in rows:
            asset_id, inserted = db.upsert_asset(row)
            result["inserted" if inserted else "updated"] += 1
            for finding in detect(row):
                db.upsert_detection(asset_id, finding)
                result["detections"] += 1
        db.finish_job(job_id, result)
        return result
    except FofaError as exc:
        db.finish_job(job_id, result, str(exc))
        raise HTTPException(status_code=502, detail=str(exc)) from exc
