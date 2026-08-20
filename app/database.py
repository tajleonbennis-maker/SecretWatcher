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
    source_path TEXT NOT NULL DEFAULT '',
    model_names TEXT NOT NULL DEFAULT '',
    key_suffix8 TEXT NOT NULL,
    key_hmac TEXT NOT NULL,
    confidence REAL NOT NULL,
    risk_level TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unverified',
    evidence_path TEXT NOT NULL DEFAULT '',
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

CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    total_assets INTEGER NOT NULL,
    completed_assets INTEGER NOT NULL DEFAULT 0,
    successful_assets INTEGER NOT NULL DEFAULT 0,
    failed_assets INTEGER NOT NULL DEFAULT 0,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    bytes_scanned INTEGER NOT NULL DEFAULT 0,
    findings INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS scan_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    asset_id INTEGER,
    event_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_events_run_id ON scan_events(run_id, id);
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
            self._migrate_schema(db)

    @staticmethod
    def _migrate_schema(db: sqlite3.Connection) -> None:
        columns = {row[1] for row in db.execute("PRAGMA table_info(credential_findings)")}
        if columns and "model_names" not in columns:
            db.execute(
                "ALTER TABLE credential_findings ADD COLUMN model_names TEXT NOT NULL DEFAULT ''"
            )
        if columns and "evidence_path" not in columns:
            db.execute(
                "ALTER TABLE credential_findings ADD COLUMN evidence_path TEXT NOT NULL DEFAULT ''"
            )

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
                    model_names=CASE WHEN length(?)>length(model_names) THEN ? ELSE model_names END,
                    key_suffix8=?, confidence=MAX(confidence, ?), risk_level=?, last_seen=?,
                    evidence_path=CASE WHEN ? != '' THEN ? ELSE evidence_path END
                    WHERE id=?""",
                    (
                        finding.get("product", ""), finding["asset_name"], finding.get("source_path", ""),
                        finding.get("model_names", ""), finding.get("model_names", ""),
                        finding["key_suffix8"], finding["confidence"], finding["risk_level"], now,
                        finding.get("evidence_path", ""), finding.get("evidence_path", ""),
                        existing["id"],
                    ),
                )
                return False
            db.execute(
                """INSERT INTO credential_findings
                (asset_id, provider, product, asset_name, source_path, model_names, key_suffix8, key_hmac,
                 confidence, risk_level, first_seen, last_seen, evidence_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    asset_id, finding["provider"], finding.get("product", ""), finding["asset_name"],
                    finding.get("source_path", ""), finding.get("model_names", ""),
                    finding["key_suffix8"], finding["key_hmac"],
                    finding["confidence"], finding["risk_level"], now, now,
                    finding.get("evidence_path", ""),
                ),
            )
            return True

    def set_credential_status(self, asset_id: int, key_hmac: str, status: str) -> bool:
        allowed = {"unverified", "confirmed", "notified", "resolved", "false_positive"}
        if status not in allowed:
            raise ValueError("不支持的凭据状态")
        with self.connect() as db:
            cursor = db.execute(
                "UPDATE credential_findings SET status=?, last_seen=? WHERE asset_id=? AND key_hmac=?",
                (status, utc_now(), asset_id, key_hmac),
            )
            return cursor.rowcount > 0

    def lookup_key_suffix4(self, suffix4: str) -> list[dict[str, object]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT provider, product, asset_name, model_names, key_suffix8,
                first_seen, last_seen, status
                FROM credential_findings WHERE substr(key_suffix8, -4)=?
                ORDER BY last_seen DESC LIMIT 50""",
                (suffix4,),
            ).fetchall()
        return [dict(row) for row in rows]

    def public_credential_findings(self, limit: int = 200) -> list[dict[str, object]]:
        """Return public-safe fields for all findings (id kept for admin deletion)."""
        with self.connect() as db:
            rows = db.execute(
                """SELECT id, provider, product, asset_name, model_names, key_suffix8, confidence, risk_level,
                first_seen, last_seen, status, evidence_path
                FROM credential_findings
                ORDER BY last_seen DESC, id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def delete_credential_finding(self, finding_id: int) -> bool:
        with self.connect() as db:
            cursor = db.execute("DELETE FROM credential_findings WHERE id=?", (finding_id,))
            return cursor.rowcount > 0

    def asset_for_scan(self, limit: int = 100) -> list[dict[str, object]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT a.id, a.host, a.ip, a.port, a.protocol, a.link, a.domain, a.title,
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

    def create_scan_run(self, total_assets: int) -> int:
        now = utc_now()
        with self.connect() as db:
            db.execute(
                "UPDATE scan_runs SET status='interrupted', completed_at=?, updated_at=? WHERE status='running'",
                (now, now),
            )
            cursor = db.execute(
                """INSERT INTO scan_runs (total_assets, status, started_at, updated_at)
                VALUES (?, 'running', ?, ?)""",
                (total_assets, now, now),
            )
            run_id = int(cursor.lastrowid)
            db.execute(
                "INSERT INTO scan_events (run_id, event_type, created_at) VALUES (?, 'run_started', ?)",
                (run_id, now),
            )
            return run_id

    def mark_asset_scan(self, asset_id: int, status: str, run_id: int | None = None) -> None:
        with self.connect() as db:
            db.execute(
                """INSERT INTO asset_scans
                (asset_id, status, scanned_at) VALUES (?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET status=excluded.status,
                  error='', scanned_at=excluded.scanned_at""",
                (asset_id, status, utc_now()),
            )
            if status == "queued":
                db.execute(
                    """UPDATE asset_scans SET files_scanned=0, bytes_scanned=0,
                    findings=0, error='' WHERE asset_id=?""",
                    (asset_id,),
                )
            if run_id is not None:
                db.execute(
                    "INSERT INTO scan_events (run_id, asset_id, event_type, created_at) VALUES (?, ?, ?, ?)",
                    (run_id, asset_id, f"asset_{status}", utc_now()),
                )

    def record_file_progress(self, run_id: int, asset_id: int, byte_count: int) -> None:
        now = utc_now()
        with self.connect() as db:
            db.execute(
                """UPDATE asset_scans SET files_scanned=files_scanned+1,
                bytes_scanned=bytes_scanned+?, scanned_at=? WHERE asset_id=?""",
                (byte_count, now, asset_id),
            )
            db.execute(
                """UPDATE scan_runs SET files_scanned=files_scanned+1,
                bytes_scanned=bytes_scanned+?, updated_at=? WHERE id=?""",
                (byte_count, now, run_id),
            )
            count = db.execute(
                "SELECT files_scanned FROM asset_scans WHERE asset_id=?", (asset_id,)
            ).fetchone()[0]
            if count == 1 or count % 5 == 0:
                db.execute(
                    "INSERT INTO scan_events (run_id, asset_id, event_type, created_at) VALUES (?, ?, 'file_progress', ?)",
                    (run_id, asset_id, now),
                )

    def advance_scan_run(
        self, run_id: int, *, files: int, bytes_scanned: int, findings: int, failed: bool
    ) -> None:
        now = utc_now()
        with self.connect() as db:
            db.execute(
                """UPDATE scan_runs SET
                  completed_assets=completed_assets+1,
                  successful_assets=successful_assets+?,
                  failed_assets=failed_assets+?,
                  files_scanned=files_scanned+?,
                  bytes_scanned=bytes_scanned+?,
                  findings=findings+?,
                  status=CASE WHEN completed_assets+1 >= total_assets THEN 'completed' ELSE 'running' END,
                  completed_at=CASE WHEN completed_assets+1 >= total_assets THEN ? ELSE NULL END,
                  updated_at=?
                WHERE id=?""",
                (0 if failed else 1, 1 if failed else 0, files, bytes_scanned, findings, now, now, run_id),
            )
            db.execute(
                "INSERT INTO scan_events (run_id, event_type, created_at) VALUES (?, ?, ?)",
                (run_id, "asset_failed" if failed else "asset_completed", now),
            )
            run = db.execute(
                "SELECT status FROM scan_runs WHERE id=?", (run_id,)
            ).fetchone()
            if run and run["status"] == "completed":
                db.execute(
                    "INSERT INTO scan_events (run_id, event_type, created_at) VALUES (?, 'run_completed', ?)",
                    (run_id, now),
                )

    def admin_scan_progress(self) -> dict[str, object]:
        with self.connect() as db:
            run = db.execute("SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1").fetchone()
            recent = db.execute(
                """SELECT COALESCE(NULLIF(a.domain,''), NULLIF(a.title,''), a.host) AS asset_name,
                s.status, s.files_scanned, s.bytes_scanned, s.findings, s.error, s.scanned_at,
                COALESCE((SELECT product FROM detections d WHERE d.asset_id=a.id
                          ORDER BY confidence DESC LIMIT 1), '') AS product
                FROM asset_scans s JOIN assets a ON a.id=s.asset_id
                ORDER BY s.scanned_at DESC LIMIT 30"""
            ).fetchall()
        payload = dict(run) if run else {
            "total_assets": 0, "completed_assets": 0, "successful_assets": 0,
            "failed_assets": 0, "files_scanned": 0, "bytes_scanned": 0,
            "findings": 0, "status": "idle",
        }
        payload["recent_assets"] = [dict(row) for row in recent]
        return payload

    def scan_events_after(self, event_id: int, limit: int = 100) -> list[dict[str, object]]:
        with self.connect() as db:
            rows = db.execute(
                """SELECT id, run_id, asset_id, event_type, created_at FROM scan_events
                WHERE id>? ORDER BY id LIMIT ?""",
                (event_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]
