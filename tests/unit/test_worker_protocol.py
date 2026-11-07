import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.worker_protocol import (  # noqa: E402
    WorkerJob,
    clear_staging,
    is_job_ready,
    is_result_ready,
    read_job,
    read_result,
    stage_input_file,
    write_job,
    write_result,
)


def test_fresh_staging_has_no_job_or_result_ready(tmp_path):
    clear_staging(tmp_path)
    assert is_job_ready(tmp_path) is False
    assert is_result_ready(tmp_path) is False


def test_write_and_read_job_round_trip(tmp_path):
    clear_staging(tmp_path)
    stage_input_file(tmp_path, "package-lock.json", b'{"fake": true}')
    write_job(tmp_path, WorkerJob(job_id="123", job_kind="osv_scan", input_filename="package-lock.json"))

    assert is_job_ready(tmp_path) is True
    job = read_job(tmp_path)
    assert job.job_id == "123"
    assert job.job_kind == "osv_scan"
    assert (tmp_path / "input" / "package-lock.json").read_bytes() == b'{"fake": true}'


def test_job_not_ready_once_done_marker_written(tmp_path):
    clear_staging(tmp_path)
    write_job(tmp_path, WorkerJob(job_id="1", job_kind="osv_scan", input_filename="x"))
    assert is_job_ready(tmp_path) is True

    write_result(tmp_path, exit_code=0, stdout=b"{}", stderr=b"")
    assert is_job_ready(tmp_path) is False  # done yazildi, tekrar islenmesin
    assert is_result_ready(tmp_path) is True


def test_write_and_read_result_round_trip(tmp_path):
    clear_staging(tmp_path)
    write_result(tmp_path, exit_code=1, stdout=b'{"results": []}', stderr=b"some warning on stderr")

    result = read_result(tmp_path)
    assert result.exit_code == 1
    assert result.stdout == b'{"results": []}'
    assert result.stderr_tail == "some warning on stderr"


def test_stderr_tail_is_truncated_to_max_bytes(tmp_path):
    clear_staging(tmp_path)
    big_stderr = b"x" * 10_000
    write_result(tmp_path, exit_code=0, stdout=b"{}", stderr=big_stderr)
    result = read_result(tmp_path)
    assert len(result.stderr_tail) == 4096


def test_clear_staging_removes_previous_job_and_output(tmp_path):
    clear_staging(tmp_path)
    stage_input_file(tmp_path, "a.json", b"x")
    write_job(tmp_path, WorkerJob(job_id="1", job_kind="osv_scan", input_filename="a.json"))
    write_result(tmp_path, exit_code=0, stdout=b"{}", stderr=b"")

    clear_staging(tmp_path)

    assert not (tmp_path / "job.json").exists()
    assert not (tmp_path / "done").exists()
    assert list((tmp_path / "input").iterdir()) == []
    assert list((tmp_path / "output").iterdir()) == []
