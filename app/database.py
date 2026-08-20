from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_key TEXT NOT NULL UNIQUE,
    host TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    port INTEGER NOT NULL DEFAULT 0,
    protocol TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    server TEXT NOT NULL DEFAULT '',
    link TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL,
    product TEXT NOT NULL,
    category TEXT NOT NULL,
    confidence REAL NOT NULL,
    evidence_kind TEXT NOT NULL,
    evidence_summary TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    UNIQUE(asset_id, product),
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS import_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    query_hash TEXT NOT NULL,
    requested_size INTEGER NOT NULL,
    received INTEGER NOT NULL DEFAULT 0,
    inserted INTEGER NOT NULL DEFAULT 0,
    updated INTEGER NOT NULL DEFAULT 0,
    detections INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS credential_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    product TEXT NOT NULL DEFAULT '',
    asset_name TEXT NOT NULL,
    source_path TEXT NOT NULL,
    key_suffix8 TEXT NOT NULL,
    key_hmac TEXT NOT NULL,
    confidence REAL NOT NULL,
    risk_level TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unverified',
    UNIQUE(asset_id, provider, key_hmac),
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_credential_suffix8
ON credential_findings(key_suffix8);

CREATE TABLE IF NOT EXISTS asset_scans (
    asset_id INTEGER PRIMARY KEY,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    bytes_scanned INTEGER NOT NULL DEFAULT 0,
    findings INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    error TEXT NOT NULL DEFAULT '',
    scanned_at TEXT NOT NULL,
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);
"""


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class Database:
    def __init__(self, path: Path):
        self.path = path

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        try:
            yield db
            db.commit()
        finally:
            db.close()

    def upsert_asset(self, row: dict[str, object]) -> tuple[int, bool]:
        now = utc_now()
        identity = "|".join(str(row.get(key, "")) for key in ("host", "ip", "port", "protocol"))
        asset_key = hashlib.sha256(identity.encode()).hexdigest()
        values = {
            "asset_key": asset_key,
            "host": str(row.get("host") or ""),
            "ip": str(row.get("ip") or ""),
            "port": int(row.get("port") or 0),
            "protocol": str(row.get("protocol") or ""),
            "domain": str(row.get("domain") or ""),
            "title": str(row.get("title") or "")[:500],
            "server": str(row.get("server") or "")[:500],
            "link": str(row.get("link") or "")[:1000],
        }
        with self.connect() as db:
            existing = db.execute("SELECT id FROM assets WHERE asset_key = ?", (asset_key,)).fetchone()
            if existing:
                db.execute(
                    """UPDATE assets SET host=:host, ip=:ip, port=:port, protocol=:protocol,
                    domain=:domain, title=:title, server=:server, link=:link, last_seen=:now
                    WHERE asset_key=:asset_key""",
                    values | {"now": now},
                )
                return int(existing["id"]), False
            cursor = db.execute(
                """INSERT INTO assets
                (asset_key, host, ip, port, protocol, domain, title, server, link, first_seen, last_seen)
                VALUES (:asset_key, :host, :ip, :port, :protocol, :domain, :title, :server, :link, :now, :now)""",
                values | {"now": now},
            )
            return int(cursor.lastrowid), True

    def upsert_detection(self, asset_id: int, detection: dict[str, object]) -> bool:
        with self.connect() as db:
            before = db.total_changes
            db.execute(
                """INSERT INTO detections
                (asset_id, product, category, confidence, evidence_kind, evidence_summary, detected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id, product) DO UPDATE SET
                  confidence=MAX(confidence, excluded.confidence),
                  evidence_kind=excluded.evidence_kind,
                  evidence_summary=excluded.evidence_summary,
                  detected_at=excluded.detected_at""",
                (
                    asset_id,
                    detection["product"],
                    detection["category"],
                    detection["confidence"],
                    detection["evidence_kind"],
                    detection["evidence_summary"],
                    utc_now(),
                ),
            )
            return db.total_changes > before

    def create_job(self, query: str, requested_size: int) -> int:
        query_hash = hashlib.sha256(query.encode()).hexdigest()
        with self.connect() as db:
            cursor = db.execute(
                "INSERT INTO import_jobs (query_hash, requested_size, status, created_at) VALUES (?, ?, 'running', ?)",
                (query_hash, requested_size, utc_now()),
            )
            return int(cursor.lastrowid)

    def finish_job(self, job_id: int, result: dict[str, int], error: str = "") -> None:
        with self.connect() as db:
            db.execute(
                """UPDATE import_jobs SET received=?, inserted=?, updated=?, detections=?,
                status=?, error=?, completed_at=? WHERE id=?""",
                (
                    result.get("received", 0),
                    result.get("inserted", 0),
                    result.get("updated", 0),
                    result.get("detections", 0),
                    "failed" if error else "completed",
                    error[:500],
                    utc_now(),
                    job_id,
                ),
            )

    def public_stats(self) -> dict[str, object]:
        with self.connect() as db:
            asset_count = db.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
            detection_count = db.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
            product_count = db.execute("SELECT COUNT(DISTINCT product) FROM detections").fetchone()[0]
            jobs = db.execute("SELECT COUNT(*) FROM import_jobs WHERE status='completed'").fetchone()[0]
            credentials = db.execute("SELECT COUNT(*) FROM credential_findings").fetchone()[0]
            credential_providers = db.execute(
                "SELECT COUNT(DISTINCT provider) FROM credential_findings"
            ).fetchone()[0]
            products = [
                dict(row)
                for row in db.execute(
                    """SELECT product, COUNT(*) AS count FROM detections
                    GROUP BY product ORDER BY count DESC, product LIMIT 12"""
                ).fetchall()
            ]
        return {
            "assets_observed": asset_count,
            "detections": detection_count,
            "products": product_count,
            "completed_imports": jobs,
            "credential_findings": credentials,
            "credential_providers": credential_providers,
            "top_products": products,
            "privacy_note": "仅展示汇总数据，不公开目标地址或凭据。",
        }

    def upsert_credential_finding(self, asset_id: int, finding: dict[str, object]) -> bool:
        now = utc_now()
        with self.connect() as db:
            existing = db.execute(
                "SELECT id FROM credential_findings WHERE asset_id=? AND provider=? AND key_hmac=?",
                (asset_id, finding["provider"], finding["key_hmac"]),
            ).fetchone()
            if existing:
                db.execute(
                    """UPDATE credential_findings SET product=?, asset_name=?, source_path=?,
                    key_suffix8=?, confidence=MAX(confidence, ?), risk_level=?, last_seen=? WHERE id=?""",
                    (
                        finding.get("product", ""), finding["asset_name"], finding["source_path"],
                        finding["key_suffix8"], finding["confidence"], finding["risk_level"], now,
                        existing["id"],
                    ),
                )
                return False
            db.execute(
                """INSERT INTO credential_findings
                (asset_id, provider, product, asset_name, source_path, key_suffix8, key_hmac,
                 confidence, risk_level, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    asset_id, finding["provider"], finding.get("product", ""), finding["asset_name"],
                    finding["source_path"], finding["key_suffix8"], finding["key_hmac"],
                    finding["confidence"], finding["risk_level"], now, now,
                ),
            )
            return True

    def lookup_key_suffix4(self, suffix4: str) -> list[dict[str, object]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT provider, product, asset_name, key_suffix8, first_seen, last_seen, status
                FROM credential_findings WHERE substr(key_suffix8, -4)=?
                ORDER BY last_seen DESC LIMIT 50""",
                (suffix4,),
            ).fetchall()
        return [dict(row) for row in rows]

    def asset_for_scan(self, limit: int = 100) -> list[dict[str, object]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT a.id, a.host, a.link, a.domain, a.title,
                COALESCE((SELECT product FROM detections d WHERE d.asset_id=a.id
                          ORDER BY confidence DESC LIMIT 1), '') AS product
                FROM assets a
                LEFT JOIN asset_scans s ON s.asset_id=a.id
                ORDER BY s.scanned_at IS NOT NULL, s.scanned_at, a.last_seen DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def finish_asset_scan(
        self, asset_id: int, *, files: int, bytes_scanned: int, findings: int, error: str = ""
    ) -> None:
        with self.connect() as db:
            db.execute(
                """INSERT INTO asset_scans
                (asset_id, files_scanned, bytes_scanned, findings, status, error, scanned_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                  files_scanned=excluded.files_scanned,
                  bytes_scanned=excluded.bytes_scanned,
                  findings=excluded.findings,
                  status=excluded.status,
                  error=excluded.error,
                  scanned_at=excluded.scanned_at""",
                (
                    asset_id, files, bytes_scanned, findings,
                    "failed" if error else "completed", error[:300], utc_now(),
                ),
            )
