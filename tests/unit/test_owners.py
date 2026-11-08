"""core/owners.py parse_owners_csv() testleri -- DB gerektirmez (master_prompt.md 6 A5)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.owners import parse_owners_csv  # noqa: E402


def test_parses_simple_two_column_csv():
    result = parse_owners_csv("acme/repo1,team-a\nacme/repo2,team-b\n")
    assert result.errors == []
    assert [r.full_name for r in result.rows] == ["acme/repo1", "acme/repo2"]
    assert [r.owner_identifier for r in result.rows] == ["team-a", "team-b"]


def test_skips_recognized_header_row():
    result = parse_owners_csv("full_name,owner_identifier\nacme/repo1,team-a\n")
    assert len(result.rows) == 1
    assert result.rows[0].full_name == "acme/repo1"


def test_skips_blank_lines():
    result = parse_owners_csv("acme/repo1,team-a\n\n\nacme/repo2,team-b\n")
    assert len(result.rows) == 2


def test_reports_error_for_row_with_too_few_columns():
    result = parse_owners_csv("acme/repo1,team-a\nacme/repo2\n")
    assert len(result.rows) == 1
    assert len(result.errors) == 1
    assert "satir 2" in result.errors[0]


def test_reports_error_for_empty_owner_value():
    result = parse_owners_csv("acme/repo1,\n")
    assert result.rows == []
    assert len(result.errors) == 1


def test_strips_whitespace_around_values():
    result = parse_owners_csv(" acme/repo1 , team-a \n")
    assert result.rows[0].full_name == "acme/repo1"
    assert result.rows[0].owner_identifier == "team-a"


def test_empty_content_yields_no_rows_no_errors():
    result = parse_owners_csv("")
    assert result.rows == []
    assert result.errors == []
