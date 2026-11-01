import pytest

from pipeline.extract import pypi_json
from pipeline.extract.http import HttpClient
from pipeline.extract.raw_writer import read_lines
from pipeline.extract.run import extract_packages
from pipeline.extract.select_versions import select_versions, versions_named_by_osv


def project(times: dict[str, str | None]) -> dict:
    """A project body whose releases have one file each, uploaded at the given times."""
    releases = {}
    for version, stamp in times.items():
        releases[version] = [] if stamp is None else [{"upload_time_iso_8601": stamp}]
    return {"info": {"name": "pkg", "version": "3.0"}, "releases": releases}


def osv_body(*events: dict, range_type: str = "ECOSYSTEM") -> dict:
    return {"vulns": [{"affected": [{"ranges": [{"type": range_type, "events": list(events)}]}]}]}


TIMES = {
    "1.0": "2020-01-01T00:00:00Z",
    "2.0": "2021-01-01T00:00:00Z",
    "3.0": "2022-01-01T00:00:00Z",
    "0.5": None,
}


def test_the_most_recent_releases_are_chosen_oldest_first():
    assert select_versions(project(TIMES), [], limit=2) == ["2.0", "3.0"]


def test_a_release_named_by_an_advisory_is_added():
    bodies = [osv_body({"introduced": "0"}, {"fixed": "1.0"})]
    assert select_versions(project(TIMES), bodies, limit=1) == ["1.0", "3.0"]


def test_names_that_are_not_real_releases_are_ignored():
    bodies = [osv_body({"introduced": "0"}, {"fixed": "9.9"}, {"last_affected": "2.0"})]
    assert select_versions(project(TIMES), bodies, limit=1) == ["2.0", "3.0"]


def test_git_ranges_name_no_releases():
    body = osv_body({"fixed": "abc123"}, range_type="GIT")
    assert versions_named_by_osv([body]) == set()


def test_a_project_without_a_releases_map_selects_nothing():
    assert select_versions({"info": {}}, []) == []


def test_version_file_names_are_path_safe():
    assert pypi_json.version_file_name("pkg", "1!2.0+local") == "pkg@1%212.0%2Blocal"


class FakeResponse:
    def __init__(self, status=200, data=None):
        self.status_code = status
        self._data = data
        self.headers = {}

    def json(self):
        return self._data


class RoutingSession:
    """Answers by URL, and remembers every URL asked for."""

    def __init__(self, routes):
        self.routes = routes
        self.urls = []

    def request(self, method, url, **kwargs):
        self.urls.append(url)
        for part, data in self.routes.items():
            if url.endswith(part):
                return FakeResponse(200, data)
        raise AssertionError(f"unexpected request {url}")


def make_routes():
    return {
        "/pypi/pkg/json": project(TIMES),
        "https://api.osv.dev/v1/query": osv_body({"introduced": "0"}, {"fixed": "1.0"}),
        "/pypi/pkg/3.0/json": {"info": {"name": "pkg", "version": "3.0"}},
        "/pypi/pkg/2.0/json": {"info": {"name": "pkg", "version": "2.0"}},
        "/pypi/pkg/1.0/json": {"info": {"name": "pkg", "version": "1.0"}},
    }


def test_extract_fetches_recent_and_advisory_releases_and_resumes(tmp_path):
    session = RoutingSession(make_routes())
    client = HttpClient(session=session, sleep=lambda _: None)
    first = extract_packages(["Pkg"], client, tmp_path, "run1", release_limit=2, log=lambda _: None)
    assert not first.failed
    fetched = [url.rsplit("/", 2)[-2] for url in session.urls if "/pkg/" in url][1:]
    assert sorted(fetched) == ["1.0", "2.0", "3.0"]
    file_names = sorted({r.file_path.rsplit("/", 1)[-1] for r in first.records})
    assert "pkg@1.0.jsonl.gz" in file_names and "pkg.jsonl.gz" in file_names
    saved = read_lines(tmp_path, "data/raw/pypi_json/run1/pkg@3.0.jsonl.gz")
    assert saved[0]["body"]["info"]["version"] == "3.0"

    again = extract_packages(["pkg"], client, tmp_path, "run1", release_limit=2, log=lambda _: None)
    assert not again.records and len(again.skipped) == 5
    assert len(session.urls) == 5  # nothing new was requested


def test_release_limit_none_skips_the_per_release_step(tmp_path):
    session = RoutingSession(make_routes())
    client = HttpClient(session=session, sleep=lambda _: None)
    result = extract_packages(["pkg"], client, tmp_path, "run1", release_limit=None, log=print)
    assert len(result.records) == 2 and len(session.urls) == 2


def test_dots_in_a_run_label_cannot_escape_the_data_folder(tmp_path):
    session = RoutingSession(make_routes())
    client = HttpClient(session=session, sleep=lambda _: None)
    with pytest.raises(ValueError):
        extract_packages(["pkg"], client, tmp_path, "..", release_limit=None, log=print)
