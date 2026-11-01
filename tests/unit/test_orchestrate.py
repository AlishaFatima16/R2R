from datetime import UTC, datetime

import pandas as pd
import pytest

from pipeline.extract.http import HttpClient
from pipeline.extract.raw_writer import write_line
from pipeline.load.loader import TableResult
from pipeline.orchestrate import (
    Ops,
    TransformResult,
    build_batch,
    config_hash,
    no_transform,
    parse_seed,
    run_pipeline,
    scan_raw,
    split_file_name,
)

NOW = datetime(2026, 11, 1, tzinfo=UTC).isoformat()


def save(root, source, label, name, body, status=200):
    record = {
        "source": source,
        "request_url": f"https://example.com/{name}",
        "request_params": None,
        "http_status": status,
        "fetched_at": NOW,
        "body": body,
    }
    return write_line(root, source, label, name, record)


def good_vuln(**changes):
    vuln = {"id": "PYSEC-1", "modified": "2021-02-01T00:00:00Z", "aliases": []}
    vuln.update(changes)
    return vuln


def write_sample_run(root, label="run1"):
    project = {"info": {"name": "pkg", "version": "2.0"}, "releases": {}}
    release = {"info": {"name": "pkg", "version": "1!2.0"}}
    page = {"vulns": [good_vuln(), good_vuln(id="bad id")]}
    save(root, "pypi_json", label, "pkg", project)
    save(root, "pypi_json", label, "pkg@1%212.0", release)
    save(root, "osv", label, "pkg", page)
    save(root, "pypi_json", label, "ghost", None, status=404)


class FakeDb:
    """Stands in for the database functions and records every call, in order."""

    def __init__(self):
        self.calls = []
        self.raw_ids = {}

    def ops(self) -> Ops:
        return Ops(self.start_run, self.finish_run, self.register, self.load)

    def start_run(self, conn, commit, config, notes=None):
        self.calls.append(("start_run", notes))
        return 7

    def finish_run(self, conn, run_id, status, notes=None):
        self.calls.append(("finish_run", status))

    def register(self, conn, run_id, **kwargs):
        key = (kwargs["file_path"], kwargs["line_number"])
        created = key not in self.raw_ids
        self.raw_ids.setdefault(key, 100 + len(self.raw_ids))
        return self.raw_ids[key], created

    def load(self, frames, conn, run_id=None):
        self.calls.append(("load", sorted(frames), run_id))
        return {t: TableResult(t, len(f), 0, 0) for t, f in frames.items()}


def test_seed_entries_need_a_tier_and_names_are_normalized():
    seed = parse_seed(["Flask_X,a", "requests:B", "# note", ""])
    assert seed == {"flask-x": "A", "requests": "B"}
    with pytest.raises(ValueError, match="needs a tier"):
        parse_seed(["requests"])
    with pytest.raises(ValueError, match="needs a tier"):
        parse_seed(["requests,Z"])


def test_config_hash_is_stable_and_changes_with_the_seed():
    one = config_hash({"a": "A"}, 30, ["osv", "pypi_json"])
    assert one == config_hash({"a": "A"}, 30, ["pypi_json", "osv"])
    assert len(one) == 64 and one != config_hash({"a": "B"}, 30, ["osv", "pypi_json"])


def test_file_names_are_split_into_package_and_version():
    assert split_file_name("data/raw/pypi_json/r/pkg.jsonl.gz") == ("pkg", None)
    assert split_file_name("data/raw/pypi_json/r/pkg@1%212.0.jsonl.gz") == ("pkg", "1!2.0")


def test_scan_raw_rebuilds_every_line(tmp_path):
    write_sample_run(tmp_path)
    records = scan_raw(tmp_path, "run1")
    assert len(records) == 4
    assert {r.http_status for r in records} == {200, 404}
    assert all(len(r.sha256) == 64 and r.line_number == 1 for r in records)
    assert scan_raw(tmp_path, "other-run") == []


def test_build_batch_validates_and_quarantines_with_raw_ids(tmp_path):
    write_sample_run(tmp_path)
    records = scan_raw(tmp_path, "run1")
    ids = {(r.file_path, r.line_number): 500 + i for i, r in enumerate(records)}
    batch, quarantine, stats = build_batch(tmp_path, records, ids, 7, {"pkg": "A"})
    assert [p.name for p in batch.projects] == ["pkg"]
    assert [(v.name, v.version) for v in batch.versions] == [("pkg", "1!2.0")]
    assert len(batch.osv_pages) == 1 and [v.id for v in batch.osv_pages[0].vulns] == ["PYSEC-1"]
    assert stats.lines == 4 and stats.not_found == 1 and stats.quarantined == 1
    [row] = quarantine
    osv_id = ids[("data/raw/osv/run1/pkg.jsonl.gz", 1)]
    assert row["raw_object_id"] == osv_id and row["field_path"] == "vulns[1].id"
    assert row["stage"] == "validate" and batch.run_id == 7 and batch.seed == {"pkg": "A"}


def test_replay_without_fetching_loads_quarantine_before_data(tmp_path):
    write_sample_run(tmp_path)
    db = FakeDb()

    def transform(batch):
        assert len(batch.projects) == 1
        return TransformResult(frames={"package": pd.DataFrame({"x": [1]})})

    summary = run_pipeline(
        None, {"pkg": "A"}, tmp_path, "run1", transform=transform, fetch=False,
        ops=db.ops(), log=lambda _: None,
    )
    assert db.calls == [
        ("start_run", "run1"),
        ("load", ["quarantine"], 7),
        ("load", ["package"], 7),
        ("finish_run", "succeeded"),
    ]
    assert summary.raw_lines == 4 and summary.raw_registered_new == 4
    assert summary.stats.quarantined == 1 and summary.transform_connected


def test_without_a_transform_only_quarantine_is_loaded(tmp_path):
    write_sample_run(tmp_path)
    db = FakeDb()
    summary = run_pipeline(
        None, {"pkg": "A"}, tmp_path, "run1", transform=no_transform, fetch=False,
        ops=db.ops(), log=lambda _: None,
    )
    assert [c[:2] for c in db.calls if c[0] == "load"] == [("load", ["quarantine"])]
    assert not summary.transform_connected


def test_running_again_registers_nothing_new(tmp_path):
    write_sample_run(tmp_path)
    db = FakeDb()
    for _ in range(2):
        summary = run_pipeline(
            None, {"pkg": "A"}, tmp_path, "run1", fetch=False, ops=db.ops(), log=lambda _: None
        )
    assert summary.raw_registered_new == 0


def test_a_failing_transform_marks_the_run_failed_and_raises(tmp_path):
    write_sample_run(tmp_path)
    db = FakeDb()

    def broken(batch):
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        run_pipeline(
            None, {"pkg": "A"}, tmp_path, "run1", transform=broken, fetch=False,
            ops=db.ops(), log=lambda _: None,
        )
    assert db.calls[-1] == ("finish_run", "failed")
    assert ("load", ["quarantine"], 7) in db.calls  # quarantine was already kept


class Reply:
    def __init__(self, status, data=None):
        self.status_code, self._data, self.headers = status, data, {}

    def json(self):
        return self._data


class Session:
    def request(self, method, url, **kwargs):
        return Reply(404) if "pypi.org" in url else Reply(200, {})


def test_a_full_run_with_fetching_saves_registers_and_finishes(tmp_path):
    db = FakeDb()
    summary = run_pipeline(
        None, {"ghost": "A"}, tmp_path, None, client=HttpClient(session=Session()),
        ops=db.ops(), log=lambda _: None,
    )
    assert summary.run_label == "run-7"
    assert summary.raw_lines == 2 and summary.stats.not_found == 1
    assert db.calls[0][0] == "start_run" and db.calls[-1] == ("finish_run", "succeeded")
    assert (tmp_path / "data/raw/pypi_json/run-7/ghost.jsonl.gz").exists()
