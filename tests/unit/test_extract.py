import gzip

import pytest
import requests

from pipeline.extract import osv, pypi_json
from pipeline.extract.http import HttpClient, HttpError
from pipeline.extract.names import canonical_name
from pipeline.extract.raw_writer import body_sha256, raw_file_path, read_lines, write_line
from pipeline.extract.run import extract_packages


class FakeResponse:
    def __init__(self, status=200, data=None, headers=None, bad_json=False):
        self.status_code = status
        self._data = data
        self.headers = headers or {}
        self._bad_json = bad_json

    def json(self):
        if self._bad_json:
            raise ValueError("truncated")
        return self._data


class FakeSession:
    """Replays a list of responses (or exceptions) in order and records the calls."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs.get("json")))
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def client(replies, retries=3):
    sleeps = []
    session = FakeSession(replies)
    return HttpClient(session=session, retries=retries, sleep=sleeps.append), session, sleeps


def test_names_are_normalized():
    assert canonical_name("Flask_SQLAlchemy.Ext") == "flask-sqlalchemy-ext"


def test_a_good_response_is_returned_as_parsed_json():
    c, _, _ = client([FakeResponse(200, {"info": {"name": "x"}})])
    result = c.request("GET", "https://example.com/x")
    assert (result.status, result.body) == (200, {"info": {"name": "x"}})


def test_a_404_is_a_normal_result_and_is_not_retried():
    c, session, _ = client([FakeResponse(404)])
    result = c.request("GET", "https://example.com/x")
    assert (result.status, result.body, len(session.calls)) == (404, None, 1)


def test_a_server_error_is_retried_then_succeeds_with_growing_waits():
    c, session, sleeps = client([FakeResponse(500), FakeResponse(503), FakeResponse(200, {})])
    assert c.request("GET", "https://example.com/x").status == 200
    assert len(session.calls) == 3 and sleeps == [1.0, 2.0]


def test_a_network_error_is_retried():
    c, session, _ = client([requests.ConnectionError("down"), FakeResponse(200, {})])
    assert c.request("GET", "https://example.com/x").status == 200
    assert len(session.calls) == 2


def test_a_truncated_body_is_retried():
    c, _, _ = client([FakeResponse(200, bad_json=True), FakeResponse(200, {"ok": 1})])
    assert c.request("GET", "https://example.com/x").body == {"ok": 1}


def test_retry_after_is_respected_for_429():
    c, _, sleeps = client([FakeResponse(429, headers={"Retry-After": "7"}), FakeResponse(200, {})])
    c.request("GET", "https://example.com/x")
    assert sleeps == [7.0]


def test_it_gives_up_after_the_last_try():
    c, session, _ = client([FakeResponse(500)] * 3)
    with pytest.raises(HttpError, match="gave up after 3 tries"):
        c.request("GET", "https://example.com/x")
    assert len(session.calls) == 3


def test_other_client_errors_are_not_retried():
    c, session, _ = client([FakeResponse(403)])
    with pytest.raises(HttpError, match="HTTP 403"):
        c.request("GET", "https://example.com/x")
    assert len(session.calls) == 1


def test_the_body_hash_ignores_key_order():
    assert body_sha256({"a": 1, "b": 2}) == body_sha256({"b": 2, "a": 1})
    assert body_sha256({"a": 1}) != body_sha256({"a": 2})


def test_unsafe_names_cannot_become_file_paths():
    with pytest.raises(ValueError):
        raw_file_path("osv", "run1", "../evil")
    assert raw_file_path("osv", "run1", "flask") == "data/raw/osv/run1/flask.jsonl.gz"


def test_lines_are_appended_and_numbered(tmp_path):
    first = write_line(tmp_path, "osv", "run1", "flask", {"body": {"page": 1}})
    second = write_line(tmp_path, "osv", "run1", "flask", {"body": {"page": 2}})
    assert (first.line_number, second.line_number) == (1, 2)
    assert first.file_path == second.file_path
    lines = read_lines(tmp_path, first.file_path)
    assert [line["body"]["page"] for line in lines] == [1, 2]
    with gzip.open(tmp_path / first.file_path, "rt") as handle:
        assert len(handle.read().splitlines()) == 2


def test_a_pypi_package_is_saved_and_described(tmp_path):
    c, session, _ = client([FakeResponse(200, {"info": {"name": "flask"}, "releases": {}})])
    [record] = pypi_json.fetch_package(c, tmp_path, "run1", "flask")
    assert session.calls[0][:2] == ("GET", "https://pypi.org/pypi/flask/json")
    assert record.source == "pypi_json" and record.http_status == 200
    assert record.file_path == "data/raw/pypi_json/run1/flask.jsonl.gz"
    assert record.line_number == 1 and len(record.sha256) == 64
    saved = read_lines(tmp_path, record.file_path)[0]
    assert saved["body"]["info"]["name"] == "flask"
    assert set(record.as_kwargs()) == {
        "source", "request_url", "request_params", "http_status",
        "fetched_at", "sha256", "file_path", "line_number",
    }


def test_a_missing_pypi_package_is_saved_with_status_404(tmp_path):
    c, _, _ = client([FakeResponse(404)])
    [record] = pypi_json.fetch_package(c, tmp_path, "run1", "nope")
    assert record.http_status == 404
    assert read_lines(tmp_path, record.file_path)[0]["body"] is None


def test_osv_follows_every_page_and_sends_the_token(tmp_path):
    pages = [
        FakeResponse(200, {"vulns": [{"id": "A"}], "next_page_token": "t1"}),
        FakeResponse(200, {"vulns": [{"id": "B"}]}),
    ]
    c, session, _ = client(pages)
    records = osv.fetch_package(c, tmp_path, "run1", "flask")
    assert [r.line_number for r in records] == [1, 2]
    assert records[0].sha256 != records[1].sha256
    assert "page_token" not in session.calls[0][2]
    assert session.calls[1][2]["page_token"] == "t1"
    assert records[1].request_params["page_token"] == "t1"


def test_osv_saves_nothing_if_a_later_page_fails(tmp_path):
    pages = [FakeResponse(200, {"vulns": [], "next_page_token": "t1"})] + [FakeResponse(500)] * 3
    c, _, _ = client(pages)
    with pytest.raises(HttpError):
        osv.fetch_package(c, tmp_path, "run1", "flask")
    assert not (tmp_path / "data").exists()


def test_a_failed_package_does_not_stop_the_run_and_resume_skips_saved_ones(tmp_path):
    replies = [
        FakeResponse(200, {"info": {}}),  # a: pypi
        FakeResponse(200, {"vulns": []}),  # a: osv
        FakeResponse(500), FakeResponse(500), FakeResponse(500),  # b: pypi fails
        FakeResponse(200, {"vulns": []}),  # b: osv
    ]
    c, _, _ = client(replies)
    logs = []
    first = extract_packages(["A", "b"], c, tmp_path, "run1", log=logs.append)
    assert [r.source for r in first.records] == ["pypi_json", "osv", "osv"]
    assert list(first.failed) == ["pypi_json:b"]

    c2, session2, _ = client([FakeResponse(200, {"info": {}})])
    second = extract_packages(["a", "b"], c2, tmp_path, "run1", log=logs.append)
    assert sorted(second.skipped) == ["osv:a", "osv:b", "pypi_json:a"]
    assert [r.source for r in second.records] == ["pypi_json"]
    assert len(session2.calls) == 1


def test_packages_file_ignores_comments_and_blank_lines(tmp_path):
    from pipeline.extract.cli import read_packages_file

    path = tmp_path / "seed.txt"
    path.write_text("# seed\nrequests\n\nFlask  # web\n", encoding="utf-8")
    assert read_packages_file(path) == ["requests", "Flask"]
