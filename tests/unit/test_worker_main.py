"""worker/main.py process_one_job() testleri (lockfile_parse yolu).
osv_scan yolu gercek binary ile Docker'da canli test edildi (bkz.
docs/VERIFIED_FACTS.md); burada sadece dosya-tabanli protokol + dispatch
mantigi test edilir, subprocess cagrilmaz."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.worker_protocol import (  # noqa: E402
    WorkerJob,
    clear_staging,
    read_result,
    stage_input_file,
    write_job,
)
from worker.main import process_one_job  # noqa: E402


def test_lockfile_parse_job_real_npm_fixture(tmp_path):
    clear_staging(tmp_path)
    fixture = (
        Path(__file__).resolve().parents[1] / "fixtures" / "osv_scanner" / "npm_lodash_package-lock.json"
    ).read_bytes()
    stage_input_file(tmp_path, "package-lock.json", fixture)
    write_job(tmp_path, WorkerJob(job_id="1", job_kind="lockfile_parse", input_filename="package-lock.json", lockfile_type="npm"))

    process_one_job(tmp_path, binary_path="/does/not/matter", db_cache_dir="/does/not/matter")

    result = read_result(tmp_path)
    assert result.exit_code == 0
    components = json.loads(result.stdout)
    assert len(components) == 1
    assert components[0]["name"] == "lodash"
    assert components[0]["version"] == "4.17.15"


def test_lockfile_parse_job_unknown_lockfile_type(tmp_path):
    clear_staging(tmp_path)
    stage_input_file(tmp_path, "x.lock", b"irrelevant")
    write_job(tmp_path, WorkerJob(job_id="1", job_kind="lockfile_parse", input_filename="x.lock", lockfile_type="not-a-real-type"))

    process_one_job(tmp_path, binary_path="/x", db_cache_dir="/x")

    result = read_result(tmp_path)
    assert result.exit_code == -4


def test_unknown_job_kind(tmp_path):
    clear_staging(tmp_path)
    stage_input_file(tmp_path, "x", b"irrelevant")
    write_job(tmp_path, WorkerJob(job_id="1", job_kind="something_else", input_filename="x"))

    process_one_job(tmp_path, binary_path="/x", db_cache_dir="/x")

    result = read_result(tmp_path)
    assert result.exit_code == -2


def test_missing_input_file(tmp_path):
    clear_staging(tmp_path)
    write_job(tmp_path, WorkerJob(job_id="1", job_kind="osv_scan", input_filename="missing.json"))

    process_one_job(tmp_path, binary_path="/x", db_cache_dir="/x")

    result = read_result(tmp_path)
    assert result.exit_code == -3


def test_lockfile_parse_handles_malformed_content_gracefully(tmp_path):
    clear_staging(tmp_path)
    stage_input_file(tmp_path, "package-lock.json", b"{not valid json")
    write_job(tmp_path, WorkerJob(job_id="1", job_kind="lockfile_parse", input_filename="package-lock.json", lockfile_type="npm"))

    process_one_job(tmp_path, binary_path="/x", db_cache_dir="/x")

    result = read_result(tmp_path)
    # parse_npm_lock malformed JSON'da exception FIRLATMAZ, bos liste doner
    # (bkz. core/lockfile_parser.py) -> exit_code 0, bos liste.
    assert result.exit_code == 0
    assert json.loads(result.stdout) == []


def test_secret_scan_job_missing_mirror_dir(tmp_path):
    clear_staging(tmp_path)
    write_job(tmp_path, WorkerJob(job_id="1", job_kind="secret_scan", mirror_subdir="nonexistent-repo.git"))

    process_one_job(
        tmp_path, binary_path="/x", db_cache_dir="/x",
        gitleaks_binary_path="/x", git_mirrors_dir=str(tmp_path / "mirrors_root"),
    )

    result = read_result(tmp_path)
    assert result.exit_code == -5
