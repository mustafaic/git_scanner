"""Yapilandirilmis JSON loglama + secret maskeleme (master_prompt.md kural 8,
bolum 3.4 "Gozlemlenebilirlik").

Asil kontrol secret'i hic log cagrisina yazmamaktir (ornegin github_auth.py
token'i asla logger.info(...) icine koymaz). Bu modul ikinci bir guvence
katmanidir: kaydi bilinen secret degerleri olup olmadigina karsi tarar.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from datetime import datetime, timezone
from typing import Optional

_secret_lock = threading.Lock()
_registered_secrets: list[str] = []


def register_secret(value: Optional[str]) -> None:
    """Bilinen bir secret degerini maskeleme listesine ekler."""
    if not value:
        return
    with _secret_lock:
        if value not in _registered_secrets:
            _registered_secrets.append(value)


def _redact(text: str) -> str:
    with _secret_lock:
        secrets = list(_registered_secrets)
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***REDACTED***")
    return text


class JsonFormatter(logging.Formatter):
    def __init__(self, service_name: str) -> None:
        super().__init__()
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        message = _redact(record.getMessage())
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "service": self.service_name,
            "logger": record.name,
            "message": message,
        }
        if record.exc_info:
            payload["exc_info"] = _redact(self.formatException(record.exc_info))
        extra = getattr(record, "extra_fields", None)
        if isinstance(extra, dict):
            for key, value in extra.items():
                payload[key] = _redact(value) if isinstance(value, str) else value
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(service_name: str, level: str = "INFO") -> None:
    root = logging.getLogger()
    root.setLevel(level.upper())
    for handler in list(root.handlers):
        root.removeHandler(handler)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(service_name))
    root.addHandler(handler)
