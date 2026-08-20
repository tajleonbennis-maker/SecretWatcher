from __future__ import annotations

import secrets
import asyncio
import json
import ipaddress
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import Settings, get_settings
from .database import Database
from .detector import SIGNATURES, detect
from .fofa import FofaClient, FofaError
from .product_adapters import public_adapter_summary


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


@app.get("/owner", include_in_schema=False)
def owner_dashboard() -> FileResponse:
    return FileResponse(STATIC / "owner.html")


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
        "adapters": public_adapter_summary(),
        "method": "基于 FOFA 已有响应数据进行被动指纹识别",
    }


def _mask_asset(value: str) -> str:
    candidate = value.strip()
    hostname = urlsplit(candidate if "://" in candidate else f"//{candidate}").hostname or candidate
    try:
        address = ipaddress.ip_address(hostname)
        if address.version == 4:
            octets = hostname.split(".")
            return ".".join(octets[:3] + ["*"])
        groups = address.exploded.split(":")
        return ":".join(groups[:3]) + ":*"
    except ValueError:
        pass
    labels = hostname.split(".")
    if len(labels) >= 2:
        return (labels[0][:2] or "*") + "***." + labels[-1]
    return hostname[:2] + "***" if hostname else "未公开"


def _public_finding(item: dict[str, object], *, key_visible_chars: int = 4) -> dict[str, object]:
    """Public surface: masked asset, model info, and key suffix only."""
    models = str(item.get("model_names") or "").strip()
    return {
        "provider": item["provider"],
        "product": item.get("product") or "未识别应用",
        "asset": _mask_asset(str(item["asset_name"])),
        "models": models or "未识别模型",
        "key_hint": "****" + str(item["key_suffix8"])[-key_visible_chars:],
        "risk_level": item.get("risk_level", "unknown"),
        "first_seen": item["first_seen"],
        "last_seen": item["last_seen"],
        "status": item["status"],
    }


@app.get("/api/public/findings")
def public_findings(db: Database = Depends(database)) -> dict[str, object]:
    findings = [_public_finding(item) for item in db.public_credential_findings()]
    return {
        "findings": findings,
        "count": len(findings),
        "privacy_note": "仅展示脱敏资产、模型信息与 Key 后缀；不公开完整密钥或源码路径。",
    }


@app.post("/api/public/key-lookup")
def key_lookup(request: KeyLookupRequest, db: Database = Depends(database)) -> dict[str, object]:
    matches = db.lookup_key_suffix4(request.suffix4)
    return {
        "matches": [_public_finding(item, key_visible_chars=8) for item in matches],
        "count": len(matches),
        "notice": "末四位只能用于初步查询；命中后仅展示后八位，查看处置信息前仍需验证资产所有权。",
    }


@app.get("/api/admin/scan/progress", dependencies=[Depends(require_admin)])
def scan_progress(db: Database = Depends(database)) -> dict[str, object]:
    return db.admin_scan_progress()


@app.get("/api/admin/scan/stream", dependencies=[Depends(require_admin)])
async def scan_stream(db: Database = Depends(database)) -> StreamingResponse:
    async def events():
        event_id = 0
        while True:
            rows = db.scan_events_after(event_id)
            if rows:
                event_id = int(rows[-1]["id"])
                payload = {"event_id": event_id, "progress": db.admin_scan_progress()}
                yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
            else:
                yield ": keepalive\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(
        events(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


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
