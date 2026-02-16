from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    # Only scan explicitly allowed public demo targets.
    ALLOWED_HOSTNAMES: set[str] = frozenset({"scanme.nmap.org", "localhost"})

    # Nmap settings (safe scanning only; no scripts/exploitation).
    DEFAULT_PORT_RANGE: str = os.getenv("SCAN_PORT_RANGE", "1-1024")
    NMAP_TIMING: str = os.getenv("NMAP_TIMING", "-T3")
    HOST_TIMEOUT: str = os.getenv("NMAP_HOST_TIMEOUT", "30s")
    VERSION_DETECTION: str = os.getenv("NMAP_VERSION_DETECTION", "--version-light")

    # API
    ETHICAL_DISCLAIMER: str = "This tool is for educational purposes only."

    # CORS (dev-friendly default)
    CORS_ORIGINS: str = os.getenv("CORS_ORIGINS", "*")

    # If you want to allow scanning any valid domain, set this to "0".
    ENFORCE_ALLOWLIST: bool = os.getenv("ENFORCE_ALLOWLIST", "1") != "0"


def get_settings() -> Settings:
    return Settings()

