"""Orchestrator <-> worker dosya tabanli IPC protokolu (master_prompt.md
3.4: "Worker ile iletisim dosya tabanli... network_mode: none").

Worker'in agi olmadigi icin orchestrator ve worker SADECE paylasilan bir
volume (STAGING_DIR) uzerinden dosya yazip/okuyarak konusur. Tek seferde
bu dizinde en fazla BIR is durur (just-in-time staging, master_prompt.md
3.4: "Orchestrator ayni anda yalnizca bir job'u worker'in gorebildigi
dizine hazirlar").

Dosya duzeni:
  <staging>/job.json          -- orchestrator yazar (ready sinyali, SON yazilan)
  <staging>/input/<dosya>     -- orchestrator yazar (job.json'dan ONCE)
  <staging>/output/stdout.raw -- worker yazar (scanner'in ham stdout'u)
  <staging>/output/meta.json  -- worker yazar ({"exit_code", "stderr_tail"})
  <staging>/done              -- worker yazar (SON, "cikti hazir" sinyali)
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

JOB_FILENAME = "job.json"
DONE_FILENAME = "done"
META_FILENAME = "meta.json"
STDOUT_FILENAME = "stdout.raw"
INPUT_DIRNAME = "input"
OUTPUT_DIRNAME = "output"

STDERR_TAIL_MAX_BYTES = 4096


@dataclass
class WorkerJob:
    job_id: str
    # 'osv_scan' (Hat B) | 'lockfile_parse' (Hat A) | 'secret_scan' (Asama 3).
    job_kind: str
    # job_kind in ('osv_scan','lockfile_parse') icin: staging/input/ altindaki dosya adi.
    input_filename: str = ""
    # job_kind == 'lockfile_parse' icin zorunlu: core.lockfile_parser.PARSERS anahtari.
    lockfile_type: Optional[str] = None
    # job_kind == 'secret_scan' icin zorunlu: GIT_MIRRORS_DIR altindaki
    # (read-only mount) repo mirror dizininin adi (bkz. orchestrator/secret_scan.py).
    mirror_subdir: Optional[str] = None
    # job_kind == 'secret_scan' icin opsiyonel: "sha1..sha2" (incremental);
    # bos ise TAM tarama (ilk tarama/force-push/ruleset degisimi, 4.4).
    log_opts: Optional[str] = None


def write_job(staging_dir: Path, job: WorkerJob) -> None:
    """ONEMLI: cagiran taraf once input/ dosyalarini yazmis olmali; bu
    fonksiyon job.json'u YAZAR YAZMAZ worker is'i gormeye baslar."""
    (staging_dir / JOB_FILENAME).write_text(
        json.dumps(
            {
                "job_id": job.job_id,
                "job_kind": job.job_kind,
                "input_filename": job.input_filename,
                "lockfile_type": job.lockfile_type,
                "mirror_subdir": job.mirror_subdir,
                "log_opts": job.log_opts,
            }
        ),
        encoding="utf-8",
    )


def read_job(staging_dir: Path) -> WorkerJob:
    data = json.loads((staging_dir / JOB_FILENAME).read_text(encoding="utf-8"))
    return WorkerJob(
        job_id=data["job_id"],
        job_kind=data["job_kind"],
        input_filename=data.get("input_filename", ""),
        lockfile_type=data.get("lockfile_type"),
        mirror_subdir=data.get("mirror_subdir"),
        log_opts=data.get("log_opts"),
    )


def is_job_ready(staging_dir: Path) -> bool:
    return (staging_dir / JOB_FILENAME).exists() and not (staging_dir / DONE_FILENAME).exists()


def is_result_ready(staging_dir: Path) -> bool:
    return (staging_dir / DONE_FILENAME).exists()


def _mkdir_shared(path: Path) -> None:
    """orchestrator (root) ve worker (non-root UID) AYNI paylasilan Docker
    volume'una yazar; hangisi dizini once olusturursa, digeri de yazabilsin
    diye 0o777 verilir (tek makine icinde paylasilan staging volume'u,
    gercek bir guvenlik siniri degil -- asil izolasyon network_mode:none +
    cap_drop + read_only rootfs'tir, bkz. master_prompt.md 5)."""
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o777)
    except OSError:
        pass  # bazi platformlarda (ör. Windows bind mount) chmod no-op olabilir


def write_result(staging_dir: Path, exit_code: int, stdout: bytes, stderr: bytes) -> None:
    output_dir = staging_dir / OUTPUT_DIRNAME
    _mkdir_shared(output_dir)
    (output_dir / STDOUT_FILENAME).write_bytes(stdout)
    stderr_tail = stderr[-STDERR_TAIL_MAX_BYTES:].decode("utf-8", errors="replace")
    (output_dir / META_FILENAME).write_text(json.dumps({"exit_code": exit_code, "stderr_tail": stderr_tail}), encoding="utf-8")
    # "done" SON yazilir: orchestrator bunu gorene kadar cikti TAMAMLANMAMIS sayilir.
    (staging_dir / DONE_FILENAME).write_text("1", encoding="utf-8")


@dataclass
class WorkerResult:
    exit_code: int
    stdout: bytes
    stderr_tail: str


def read_result(staging_dir: Path) -> WorkerResult:
    output_dir = staging_dir / OUTPUT_DIRNAME
    meta = json.loads((output_dir / META_FILENAME).read_text(encoding="utf-8"))
    stdout = (output_dir / STDOUT_FILENAME).read_bytes()
    return WorkerResult(exit_code=meta["exit_code"], stdout=stdout, stderr_tail=meta["stderr_tail"])


def clear_staging(staging_dir: Path) -> None:
    for name in (JOB_FILENAME, DONE_FILENAME):
        path = staging_dir / name
        if path.exists():
            path.unlink()
    for dirname in (INPUT_DIRNAME, OUTPUT_DIRNAME):
        dir_path = staging_dir / dirname
        if dir_path.exists():
            shutil.rmtree(dir_path)
    _mkdir_shared(staging_dir / INPUT_DIRNAME)
    _mkdir_shared(staging_dir / OUTPUT_DIRNAME)


def stage_input_file(staging_dir: Path, filename: str, content: bytes) -> None:
    input_dir = staging_dir / INPUT_DIRNAME
    _mkdir_shared(input_dir)
    (input_dir / filename).write_bytes(content)
