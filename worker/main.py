"""Worker ana loop'u (master_prompt.md 5 "Worker izolasyonu", 3.4).

network_mode: none icinde calisir; SADECE staging dizinini okur/yazar ve
pinli osv-scanner binary'sini calistirir. Baska hicbir ag/islem yoktur.
Repo icerigi/scanner ciktisi guvenilmeyen girdidir -- bu yuzden burada
SADECE run() cagrilir, parse/dogrulama orchestrator'da (ingest) yapilir.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from adapters.osv_scanner import run as run_osv_scanner
from core.logging_setup import configure_logging
from core.worker_protocol import (
    INPUT_DIRNAME,
    is_job_ready,
    read_job,
    write_result,
)

LOG = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = float(os.environ.get("WORKER_POLL_INTERVAL_SECONDS", "0.5"))
SCAN_TIMEOUT_SECONDS = int(os.environ.get("WORKER_SCAN_TIMEOUT_SECONDS", "120"))


def process_one_job(staging_dir: Path, binary_path: str, db_cache_dir: str) -> None:
    job = read_job(staging_dir)
    LOG.info("Is alindi: job_id=%s job_kind=%s", job.job_id, job.job_kind)

    if job.job_kind != "osv_scan":
        LOG.error("Bilinmeyen job_kind: %s", job.job_kind)
        write_result(staging_dir, exit_code=-2, stdout=b"", stderr=f"unknown job_kind: {job.job_kind}".encode())
        return

    target_path = staging_dir / INPUT_DIRNAME / job.input_filename
    if not target_path.is_file():
        LOG.error("Girdi dosyasi bulunamadi: %s", target_path)
        write_result(staging_dir, exit_code=-3, stdout=b"", stderr=b"input file missing")
        return

    result = run_osv_scanner(
        binary_path=binary_path,
        target_path=str(target_path),
        db_cache_dir=db_cache_dir,
        timeout_seconds=SCAN_TIMEOUT_SECONDS,
    )
    LOG.info("Is tamamlandi: job_id=%s exit_code=%s", job.job_id, result.exit_code)
    write_result(staging_dir, exit_code=result.exit_code, stdout=result.stdout, stderr=result.stderr)


def main() -> None:
    configure_logging("worker", os.environ.get("LOG_LEVEL", "INFO"))

    staging_dir = Path(os.environ.get("STAGING_DIR", "/staging"))
    db_cache_dir = os.environ.get("DB_CACHE_DIR", "/dbs")
    binary_path = os.environ.get("OSV_SCANNER_BINARY", "/usr/local/bin/osv-scanner")

    LOG.info("Worker basladi (staging=%s, db_cache=%s)", staging_dir, db_cache_dir)
    while True:
        try:
            if is_job_ready(staging_dir):
                process_one_job(staging_dir, binary_path, db_cache_dir)
        except Exception:  # noqa: BLE001 - bir is'in hatasi worker'i durdurmamali
            LOG.exception("Is islenirken beklenmeyen hata")
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
