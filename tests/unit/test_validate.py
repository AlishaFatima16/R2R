import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pipeline.validate.osv import validate_osv_page
from pipeline.validate.pypi import validate_pypi_project, validate_pypi_version

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
PYPI_FIXTURES = sorted((FIXTURES / "pypi_json").glob("*.json"))
OSV_FIXTURES = sorted((FIXTURES / "osv").glob("*.json"))


def good_vuln(**changes) -> dict:
    vuln = {
        "id": "PYSEC-2021-1",
        "modified": "2021-02-01T00:00:00Z",
        "published": "2021-01-01T00:00:00Z",
        "aliases": ["CVE-2021-1"],
        "affected": [
            {
                "package": {"name": "pkg", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1"}]}
                ],
                "versions": ["1.0"],
            }
        ],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
    }
    vuln.update(changes)
    return vuln


def reasons(rows) -> list[tuple[str, str]]:
    return [(row["reason_code"], row["field_path"]) for row in rows]


@pytest.mark.parametrize("path", PYPI_FIXTURES, ids=lambda p: p.name)
def test_every_real_pypi_fixture_validates(path):
    result = validate_pypi_project(json.loads(path.read_text(encoding="utf-8")), 1)
    assert result.value is not None, result.quarantine[:3]
    assert result.quarantine == []


@pytest.mark.parametrize("path", OSV_FIXTURES, ids=lambda p: p.name)
def test_every_real_osv_fixture_validates(path):
    result = validate_osv_page(json.loads(path.read_text(encoding="utf-8")), 1)
    assert result.quarantine == [], result.quarantine[:3]


def test_a_good_pypi_project_is_parsed_with_utc_times():
    body = {
        "info": {"name": "pkg", "version": "1.0", "requires_dist": ["a>=1"]},
        "last_serial": 5,
        "releases": {"1.0": [{"upload_time_iso_8601": "2010-06-29T19:56:36"}]},
    }
    result = validate_pypi_project(body, 1)
    stamp = result.value.releases["1.0"][0].upload_time_iso_8601
    assert stamp == datetime(2010, 6, 29, 19, 56, 36, tzinfo=UTC)  # naive means UTC
    assert result.value.info.requires_dist == ["a>=1"]


def test_a_missing_name_is_quarantined_with_the_field_path():
    result = validate_pypi_project({"info": {"version": "1.0"}}, 42)
    assert result.value is None
    assert reasons(result.quarantine) == [("missing_field", "info.name")]
    row = result.quarantine[0]
    assert (row["raw_object_id"], row["stage"]) == (42, "validate")


def test_requires_dist_as_a_string_is_a_type_error():
    body = {"info": {"name": "pkg", "version": "1.0", "requires_dist": "a>=1"}}
    result = validate_pypi_version(body, 1)
    assert reasons(result.quarantine) == [("type_error", "info.requires_dist")]


def test_an_unparseable_upload_time_is_quarantined():
    info = {"name": "p", "version": "1"}
    body = {"info": info, "releases": {"1": [{"upload_time_iso_8601": "x"}]}}
    result = validate_pypi_project(body, 1)
    expected = [("invalid_timestamp", "releases.1[0].upload_time_iso_8601")]
    assert reasons(result.quarantine) == expected


def test_a_body_that_is_not_an_object_is_quarantined():
    assert reasons(validate_pypi_project(["x"], 1).quarantine) == [("type_error", "")]
    assert reasons(validate_osv_page("x", 1).quarantine) == [("type_error", "")]


def test_extra_fields_are_ignored():
    result = validate_pypi_project({"info": {"name": "p", "version": "1", "new_field": 1}}, 1)
    assert result.value is not None


def test_a_page_with_no_advisories_is_fine():
    result = validate_osv_page({}, 1)
    assert result.vulns == [] and result.quarantine == []


def test_a_good_advisory_is_parsed():
    [vuln] = validate_osv_page({"vulns": [good_vuln()]}, 1).vulns
    event = vuln.affected[0].ranges[0].events[1]
    assert (event.event_type, event.version_string) == ("fixed", "1.1")
    assert vuln.modified.tzinfo is not None and not vuln.dates_out_of_order


def test_nanosecond_timestamps_are_accepted():
    body = {"vulns": [good_vuln(modified="2026-09-10T03:50:24.238504042Z")]}
    assert validate_osv_page(body, 1).quarantine == []


def test_modified_before_published_is_a_soft_flag_not_a_failure():
    body = {"vulns": [good_vuln(modified="2020-01-01T00:00:00Z")]}
    [vuln] = validate_osv_page(body, 1).vulns
    assert vuln.dates_out_of_order


def test_one_bad_advisory_does_not_block_the_others():
    body = {"vulns": [good_vuln(), good_vuln(id="bad id"), good_vuln(id="GHSA-x-y")]}
    result = validate_osv_page(body, 9)
    assert [v.id for v in result.vulns] == ["PYSEC-2021-1", "GHSA-x-y"]
    assert reasons(result.quarantine) == [("invalid_value", "vulns[1].id")]
    assert result.quarantine[0]["message"].startswith("bad id:")


def test_an_advisory_without_modified_is_quarantined():
    vuln = good_vuln()
    del vuln["modified"]
    result = validate_osv_page({"vulns": [vuln]}, 1)
    assert reasons(result.quarantine) == [("missing_field", "vulns[0].modified")]


def test_an_event_with_two_kinds_is_invalid():
    event = {"introduced": "0", "fixed": "1"}
    affected = [{"ranges": [{"type": "ECOSYSTEM", "events": [event]}]}]
    result = validate_osv_page({"vulns": [good_vuln(affected=affected)]}, 1)
    assert len(result.quarantine) == 1 and result.quarantine[0]["reason_code"] == "invalid_value"


def test_a_git_range_needs_a_repo():
    affected = [{"ranges": [{"type": "GIT", "events": [{"introduced": "0"}]}]}]
    result = validate_osv_page({"vulns": [good_vuln(affected=affected)]}, 1)
    assert len(result.quarantine) == 1


def test_an_unknown_range_type_is_invalid():
    affected = [{"ranges": [{"type": "MAGIC", "events": [{"introduced": "0"}]}]}]
    result = validate_osv_page({"vulns": [good_vuln(affected=affected)]}, 1)
    assert reasons(result.quarantine)[0][0] == "invalid_value"


def test_aliases_as_a_string_is_a_type_error():
    result = validate_osv_page({"vulns": [good_vuln(aliases="CVE-1")]}, 1)
    assert reasons(result.quarantine) == [("type_error", "vulns[0].aliases")]
