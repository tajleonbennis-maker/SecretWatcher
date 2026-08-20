from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database_path: Path
    fofa_base_url: str
    fofa_key: str
    admin_token: str
    public_site_url: str
    fingerprint_key: str
    deepseek_api_key: str
    deepseek_base_url: str
    deepseek_model: str

    @property
    def fofa_configured(self) -> bool:
        return bool(self.fofa_key)

    @property
    def admin_configured(self) -> bool:
        return bool(self.admin_token)


def get_settings() -> Settings:
    return Settings(
        database_path=Path(os.getenv("SECRETWATCHER_DB", "data/secretwatcher.db")),
        fofa_base_url=os.getenv("FOFA_BASE_URL", "https://fofa.info").rstrip("/"),
        fofa_key=os.getenv("FOFA_KEY", "").strip(),
        admin_token=os.getenv("SECRETWATCHER_ADMIN_TOKEN", "").strip(),
        public_site_url=os.getenv("PUBLIC_SITE_URL", "https://www.cyberstroll.top").rstrip("/"),
        fingerprint_key=os.getenv("SECRETWATCHER_FINGERPRINT_KEY", "").strip(),
        deepseek_api_key=os.getenv("DEEPSEEK_API_KEY", "").strip(),
        deepseek_base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/"),
        deepseek_model=os.getenv("DEEPSEEK_MODEL", "deepseek-v4-flash").strip(),
    )
