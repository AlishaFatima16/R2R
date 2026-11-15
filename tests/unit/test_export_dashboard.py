"""Tests for the dashboard exporter. No database: rows are plain dicts, the connection is a stub."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


export = load_script("export_dashboard_data")
AS_OF = datetime(2026, 11, 1, tzinfo=UTC)


def d(text: str) -> datetime:
    return datetime.fromisoformat(text).replace(tzinfo=UTC)


def tiny_dataset() -> dict:
    """One tier A package with an advisory fixed in 2.0, plus a tier B package with its own."""
    return {
        "as_of": AS_OF,
        "run": {"run_id": 7, "status": "succeeded", "started_at": d("2026-10-31T10:00:00"),
                "finished_at": d("2026-10-31T10:05:00"), "git_commit": "abcdef1234567890",
                "config_hash": "f" * 64, "notes": "run-7"},
        "run_latest": {"run_id": 7, "status": "succeeded", "started_at": d("2026-10-31T10:00:00"),
                       "finished_at": d("2026-10-31T10:05:00"), "git_commit": "abcdef1234567890",
                       "config_hash": "f" * 64, "notes": "run-7"},
        "recent_runs": [],
        "packages": [
            {"package_id": 1, "canonical_name": "demo", "display_name": "Demo", "seed_tier": "A",
             "summary": "A demo package", "repo_url": None, "license_raw": "MIT",
             "latest_version": "2.0", "last_serial": 1},
            {"package_id": 2, "canonical_name": "other", "display_name": "other", "seed_tier": "B",
             "summary": None, "repo_url": None, "license_raw": None, "latest_version": "1.0",
             "last_serial": 2},
        ],
        "releases": [
            {"package_id": 1, "release_id": 10, "version": "1.0", "version_valid": True,
             "version_rank": 1, "is_prerelease": False, "is_dev": False,
             "uploaded_at": d("2020-01-01T00:00:00"), "yanked": False, "requires_python": None,
             "deps_fetched": False},
            {"package_id": 1, "release_id": 11, "version": "1.1", "version_valid": True,
             "version_rank": 2, "is_prerelease": False, "is_dev": False,
             "uploaded_at": d("2020-03-01T00:00:00"), "yanked": False, "requires_python": None,
             "deps_fetched": False},
            {"package_id": 1, "release_id": 12, "version": "2.0", "version_valid": True,
             "version_rank": 3, "is_prerelease": False, "is_dev": False,
             "uploaded_at": d("2021-01-01T00:00:00"), "yanked": False, "requires_python": None,
             "deps_fetched": True},
            {"package_id": 1, "release_id": 13, "version": "1.0-foo", "version_valid": False,
             "version_rank": None, "is_prerelease": False, "is_dev": False,
             "uploaded_at": None, "yanked": False, "requires_python": None,
             "deps_fetched": False},
            {"package_id": 2, "release_id": 20, "version": "1.0", "version_valid": True,
             "version_rank": 1, "is_prerelease": False, "is_dev": False,
             "uploaded_at": d("2022-01-01T00:00:00"), "yanked": False, "requires_python": None,
             "deps_fetched": False},
        ],
        "advisories": [
            {"package_id": 1, "package_name": "demo", "entry_index": 0,
             "vulnerability_id": "GHSA-aaaa-bbbb-cccc", "published_at": d("2020-06-01T00:00:00"),
             "modified_at": d("2020-07-01T00:00:00"), "withdrawn_at": None, "summary": "Bad bug",
             "dates_out_of_order": False},
            {"package_id": 1, "package_name": "demo", "entry_index": 0,
             "vulnerability_id": "PYSEC-2020-1", "published_at": d("2020-06-02T00:00:00"),
             "modified_at": d("2020-07-01T00:00:00"), "withdrawn_at": None, "summary": "Bad bug",
             "dates_out_of_order": False},
            {"package_id": 2, "package_name": "other", "entry_index": 0,
             "vulnerability_id": "PYSEC-2022-9", "published_at": d("2022-06-01T00:00:00"),
             "modified_at": d("2022-07-01T00:00:00"), "withdrawn_at": None, "summary": "Tier B bug",
             "dates_out_of_order": False},
        ],
        "advisories_excluded": 2,
        "aliases": [
            {"vulnerability_id": "GHSA-aaaa-bbbb-cccc", "alias": "CVE-2020-0001"},
            {"vulnerability_id": "PYSEC-2020-1", "alias": "CVE-2020-0001"},
        ],
        "severities": [
            {"vulnerability_id": "GHSA-aaaa-bbbb-cccc", "severity_type": "CVSS_V3",
             "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "origin": None},
        ],
        "events": [
            {"vulnerability_id": vid, "package_id": 1, "entry_index": 0, "range_index": 0,
             "range_type": "ECOSYSTEM", "event_order": order, "event_type": kind,
             "version_string": version}
            for vid in ("GHSA-aaaa-bbbb-cccc", "PYSEC-2020-1")
            for order, (kind, version) in enumerate([("introduced", "1.1"), ("fixed", "2.0")])
        ] + [
            {"vulnerability_id": "PYSEC-2022-9", "package_id": 2, "entry_index": 0,
             "range_index": 0, "range_type": "ECOSYSTEM", "event_order": 0,
             "event_type": "introduced", "version_string": "0"},
        ],
        "exposure": [
            {"release_id": 11, "package_id": 1, "vulnerability_id": "GHSA-aaaa-bbbb-cccc",
             "in_range": True, "in_enumerated": None},
            {"release_id": 11, "package_id": 1, "vulnerability_id": "PYSEC-2020-1",
             "in_range": True, "in_enumerated": True},
            {"release_id": 10, "package_id": 1, "vulnerability_id": "PYSEC-2020-1",
             "in_range": False, "in_enumerated": None},
            {"release_id": 20, "package_id": 2, "vulnerability_id": "PYSEC-2022-9",
             "in_range": True, "in_enumerated": None},
        ],
        "dependencies": [
            {"release_id": 12, "package_id": 1, "target_package_name": "requests",
             "raw_requirement": "requests>=2", "requirement_valid": True, "specifier": ">=2",
             "marker": None, "extras": None, "is_extra_only": False, "is_conditional": False},
            {"release_id": 12, "package_id": 1, "target_package_name": None,
             "raw_requirement": "not a requirement", "requirement_valid": False,
             "specifier": None, "marker": None, "extras": None, "is_extra_only": False,
             "is_conditional": False},
        ],
        "resolved": [],
        "pipeline": {
            "run_id": 7,
            "table_counts": [{"table_name": "package", "n": 2}, {"table_name": "release", "n": 5}],
            "raw_by_source": [{"source": "pypi_json", "responses": 3, "ok": 2, "not_found": 1,
                               "other_status": 0}],
            "quarantine_counts": [{"stage": "validate", "reason_code": "missing_field", "n": 2}],
            "quarantine_distinct": 1,
            "quarantine_samples": [{"quarantine_id": 1, "raw_object_id": 5, "stage": "validate",
                                    "reason_code": "missing_field", "field_path": "info.name",
                                    "message": "Field required"}],
            "dq_results": [{"check_name": "release_natural_key_unique", "dimension": "uniqueness",
                            "table_name": "release", "metric_value": 0, "threshold": 0,
                            "passed": True}],
        },
    }


# ------------------------------------------------------------------------------ pure helpers


def test_cvss3_scores_match_published_examples():
    assert export.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert export.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert export.cvss3_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N") == 5.5
    assert export.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0


def test_cvss3_rejects_other_or_broken_vectors():
    assert export.cvss3_score(None) is None
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    assert export.cvss3_score(v4) is None
    assert export.cvss3_score("CVSS:3.1/AV:N") is None


def test_levels_use_standard_cvss_bands():
    assert export.level_for(0.0) is None
    assert [export.level_for(s) for s in (3.9, 4.0, 6.9, 7.0, 8.9, 9.0)] == [
        "low", "medium", "medium", "high", "high", "critical"]


def test_alias_groups_merge_records_that_share_a_cve():
    groups = export.alias_groups(
        ["GHSA-1", "PYSEC-1", "GHSA-2"],
        {"GHSA-1": ["CVE-1"], "PYSEC-1": ["CVE-1", "GHSA-1"], "GHSA-2": []})
    assert groups["GHSA-1"] is groups["PYSEC-1"]
    assert groups["GHSA-1"]["label"] == "CVE-1"
    assert groups["GHSA-1"]["ids"] == ["GHSA-1", "PYSEC-1"]
    assert groups["GHSA-2"]["label"] == "GHSA-2"


def test_runs_are_run_length_encoded():
    assert export._runs([5, 1, 2, 3, 7, 8]) == [[1, 3], [5, 5], [7, 8]]
    assert export._runs([]) == []


def test_numbers_and_dates_become_plain_json_values():
    from decimal import Decimal

    assert export.num(Decimal(3)) == 3 and export.num(Decimal("0.25")) == 0.25
    assert export.num(float("nan")) is None
    assert export.iso(datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)) == "2026-01-02T03:04:05Z"
    assert export.iso("2026-01-02T03:04:05Z") == "2026-01-02T03:04:05Z"
    assert export.iso(None) is None


# ------------------------------------------------------------------------------- shaping


def test_files_carry_generated_at_run_id_and_sample_flag():
    files = export.build_files(tiny_dataset(), is_sample=False)
    assert {"overview.json", "packages.json", "advisories.json", "pipeline.json",
            "packages/demo.json", "packages/other.json"} <= set(files)
    for payload in files.values():
        assert payload["generated_at"] == "2026-11-01T00:00:00Z"
        assert payload["run_id"] == 7
        assert payload["is_sample"] is False
    assert export.build_files(tiny_dataset(), is_sample=True)["overview.json"]["is_sample"] is True


def test_exposure_window_and_time_to_fix():
    files = export.build_files(tiny_dataset(), is_sample=False)
    demo = files["packages/demo.json"]
    assert len(demo["advisories"]) == 1  # GHSA and PYSEC merge into one issue
    group = demo["advisories"][0]
    assert group["id"] == "CVE-2020-0001"
    assert group["ids"] == ["GHSA-aaaa-bbbb-cccc", "PYSEC-2020-1"]
    assert group["level"] == "critical" and group["score"] == 9.8
    window = group["windows"][0]
    assert (window["from"], window["to"], window["kind"]) == ("1.1", "2.0", "fixed")
    assert window["start"] == "2020-03-01T00:00:00Z" and window["end"] == "2021-01-01T00:00:00Z"
    assert window["days"] == 306.0
    assert group["exposed"] == [[1, 1]] and group["fixed_in"] == ["2.0"]
    assert demo["stats"]["affected_releases"] == 1
    assert demo["stats"]["share_affected"] == pytest.approx(0.25)  # 1 of 4 releases
    assert demo["stats"]["median_fix_days"] == 306.0


def test_records_of_one_issue_share_the_best_severity():
    index = export.build_files(tiny_dataset(), is_sample=False)["advisories.json"]["advisories"]
    by_id = {item["id"]: item for item in index}
    assert by_id["PYSEC-2020-1"]["l"] == by_id["GHSA-aaaa-bbbb-cccc"]["l"] == "critical"
    assert by_id["PYSEC-2020-1"]["s"] == 9.8
    assert by_id["PYSEC-2020-1"]["aliases"] == ["CVE-2020-0001", "GHSA-aaaa-bbbb-cccc"]
    assert by_id["PYSEC-2022-9"]["l"] is None  # no vector anywhere: stays unrated


def test_invalid_versions_are_kept_not_dropped():
    demo = export.build_files(tiny_dataset(), is_sample=False)["packages/demo.json"]
    versions = [r["v"] for r in demo["releases"]]
    assert "1.0-foo" in versions and len(versions) == 4
    bad = next(r for r in demo["releases"] if r["v"] == "1.0-foo")
    assert bad["t"] is None and bad["a"] == 0


def test_prevalence_numbers_use_tier_a_only():
    overview = export.build_files(tiny_dataset(), is_sample=False)["overview.json"]
    head = overview["headline"]
    assert head["packages"] == 2 and head["packages_tier_a"] == 1 and head["packages_tier_b"] == 1
    assert head["releases"] == 5 and head["releases_tier_a"] == 4
    assert head["advisories"] == 1 and head["advisory_records"] == 2  # tier B advisory excluded
    assert head["affected_releases"] == 1
    assert head["share_affected"] == pytest.approx(0.25)
    assert head["median_fix_days"] == 306.0 and head["fix_windows"] == 1
    assert head["excluded_advisories"] == 2
    assert overview["time_to_fix"]["median_days"] == 306.0
    assert [r["name"] for r in overview["top_packages"]] == ["demo"]


def test_origin_windows_are_not_counted_in_time_to_fix():
    data = tiny_dataset()
    for event in data["events"]:
        if event["event_type"] == "introduced" and event["package_id"] == 1:
            event["version_string"] = "0"
    overview = export.build_files(data, is_sample=False)["overview.json"]
    assert overview["headline"]["fix_windows"] == 0
    assert overview["headline"]["median_fix_days"] is None
    assert overview["time_to_fix"]["excluded"]["since_first_release"] == 1


def test_open_window_runs_to_the_export_time():
    data = tiny_dataset()
    data["events"] = [e for e in data["events"] if e["event_type"] != "fixed"]
    group = export.build_files(data, is_sample=False)["packages/demo.json"]["advisories"][0]
    window = group["windows"][0]
    assert window["kind"] == "open" and window["end"] == "2026-11-01T00:00:00Z"
    assert window["days"] is None and group["fixed_in"] == []


def test_dependencies_keep_invalid_requirements():
    deps = export.build_files(tiny_dataset(), is_sample=False)["packages/demo.json"]["dependencies"]
    assert deps["release"] == "2.0" and deps["source"] == "direct" and deps["total"] == 2
    invalid = next(i for i in deps["items"] if not i["valid"])
    assert invalid["raw"] == "not a requirement"


def test_pipeline_page_data_reports_stage_counts_and_reasons():
    pipe = export.build_files(tiny_dataset(), is_sample=False)["pipeline.json"]
    assert pipe["run"]["id"] == 7 and pipe["run"]["duration_s"] == 300.0
    assert pipe["run"]["git_commit"] == "abcdef1234" and pipe["run"]["config_hash"] == "f" * 12
    stages = {s["key"]: s for s in pipe["stages"]}
    assert stages["extract"]["metrics"][0]["value"] == 3
    assert stages["validate"]["metrics"][0]["value"] == 1  # 2 ok minus 1 rejected
    reasons = {r["reason"]: r["count"] for r in pipe["quarantine"]["by_reason"]}
    assert reasons["missing_field"] == 2 and reasons["empty_body"] == 0
    assert pipe["quality"] == {"passed": 1, "failed": 0, "results": pipe["quality"]["results"]}


def test_empty_database_still_produces_valid_files():
    data = {"as_of": AS_OF, "run": None, "run_latest": None, "recent_runs": [], "packages": [],
            "releases": [], "advisories": [], "advisories_excluded": 0, "aliases": [],
            "severities": [], "events": [], "exposure": [], "dependencies": [], "resolved": [],
            "pipeline": {"run_id": None, "table_counts": []}}
    files = export.build_files(data, is_sample=False)
    assert files["overview.json"]["headline"]["packages"] == 0
    assert files["overview.json"]["headline"]["share_affected"] is None
    assert files["packages.json"]["packages"] == []
    json.dumps(files)


# ---------------------------------------------------------------------- stub database


class StubCursor:
    def __init__(self, rows: list[dict]):
        self.description = [(name,) for name in (rows[0] if rows else {"n": 0})]
        self._rows = [tuple(row.values()) for row in rows] if rows else []

    def fetchall(self):
        return self._rows


class StubConnection:
    """Answers each exporter query from the tiny dataset. Records the SQL it was asked."""

    def __init__(self, data: dict):
        pipe = data["pipeline"]
        self.answers = {
            "run_latest": [data["run_latest"]], "run_data": [data["run"]],
            "recent_runs": [], "packages": data["packages"], "releases": data["releases"],
            "advisories": data["advisories"], "advisories_excluded": [{"n": 2}],
            "aliases": data["aliases"], "severities": data["severities"],
            "events": data["events"], "exposure": data["exposure"],
            "dependencies": data["dependencies"], "resolved": [],
            "raw_by_source": pipe["raw_by_source"], "quarantine_counts": pipe["quarantine_counts"],
            "quarantine_distinct": [{"n": 1}], "quarantine_samples": pipe["quarantine_samples"],
            "dq_results": pipe["dq_results"], "table_counts": pipe["table_counts"],
        }
        self.asked: list[str] = []
        self.read_only = False

    def execute(self, sql, params=None):
        name = next(key for key, text in export.QUERIES.items() if text == sql)
        self.asked.append(name)
        return StubCursor(self.answers[name])

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_main_exports_from_a_stub_connection_without_leaking_the_url(tmp_path, monkeypatch):
    secret_url = "postgresql://r2r_user:very-secret-pw@db.example:5432/r2r"
    monkeypatch.setenv("DATABASE_URL", secret_url)
    monkeypatch.setattr(export, "load_env_file", lambda path: None)
    conn = StubConnection(tiny_dataset())
    seen = []

    def connect(dsn):
        seen.append(dsn)
        return conn

    out = tmp_path / "data"
    assert export.main(["--out", str(out), "--as-of", "2026-11-01T00:00:00Z"], connect=connect) == 0
    assert seen == [secret_url] and conn.read_only is True
    assert {"run_latest", "packages", "releases", "advisories", "exposure"} <= set(conn.asked)

    overview = json.loads((out / "overview.json").read_text(encoding="utf-8"))
    assert overview["is_sample"] is False and overview["run_id"] == 7
    assert (out / "packages" / "demo.json").exists() and (out / "pipeline.json").exists()
    for path in out.rglob("*.json"):
        text = path.read_text(encoding="utf-8")
        assert "very-secret-pw" not in text and "postgresql://" not in text
        json.loads(text)


def test_main_refuses_to_run_without_database_url(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setattr(export, "load_env_file", lambda path: None)
    assert export.main(["--out", str(tmp_path)], connect=lambda dsn: None) == 2
    assert "DATABASE_URL" in capsys.readouterr().err
    assert not list(tmp_path.iterdir())


def test_write_files_replaces_stale_package_files(tmp_path):
    (tmp_path / "packages").mkdir()
    (tmp_path / "packages" / "old.json").write_text("{}")
    export.write_files({"packages/new.json": {"a": 1}, "overview.json": {"b": 2}}, tmp_path)
    assert sorted(p.name for p in (tmp_path / "packages").iterdir()) == ["new.json"]
    assert json.loads((tmp_path / "overview.json").read_text(encoding="utf-8")) == {"b": 2}


# ------------------------------------------------------------------ shipped sample data


DATA_DIR = ROOT / "dashboard" / "data"


@pytest.mark.skipif(not (DATA_DIR / "overview.json").exists(), reason="no dashboard/data yet")
def test_shipped_data_files_are_consistent_and_small():
    overview = json.loads((DATA_DIR / "overview.json").read_text(encoding="utf-8"))
    for key in ("generated_at", "run_id", "is_sample", "headline", "time_to_fix"):
        assert key in overview
    listed = json.loads((DATA_DIR / "packages.json").read_text(encoding="utf-8"))["packages"]
    for row in listed:
        package = json.loads((DATA_DIR / "packages" / f"{row['n']}.json").read_text(encoding="utf-8"))
        assert package["is_sample"] == overview["is_sample"]
        assert package["stats"]["releases"] == row["releases"] == len(package["releases"])
        assert package["stats"]["advisories"] == row["advisories"] == len(package["advisories"])
    index = json.loads((DATA_DIR / "advisories.json").read_text(encoding="utf-8"))["advisories"]
    assert all(set(item["pk"]) <= {r["n"] for r in listed} for item in index)
    total = sum(p.stat().st_size for p in DATA_DIR.rglob("*") if p.is_file())
    assert total < 5 * 1024 * 1024
    assert "postgresql://" not in "".join(p.read_text(encoding="utf-8") for p in DATA_DIR.rglob("*.json"))


# ------------------------------------------------------ real fixtures, no database


def test_sample_builder_runs_the_pipeline_on_the_real_fixtures(tmp_path):
    pytest.importorskip("pandas")
    pytest.importorskip("pipeline.transform")
    if not list((ROOT / "fixtures" / "pypi_json").glob("*.json")):
        pytest.skip("no fixtures")
    sample = load_script("build_sample_dashboard_data")
    out = tmp_path / "data"
    assert sample.main(["--out", str(out)]) == 0
    overview = json.loads((out / "overview.json").read_text(encoding="utf-8"))
    assert overview["is_sample"] is True and overview["run_id"] is None
    assert overview["headline"]["packages"] >= 1 and overview["headline"]["releases"] > 0
    pipe = json.loads((out / "pipeline.json").read_text(encoding="utf-8"))
    assert pipe["run"]["status"] == "sample"
    assert {s["key"] for s in pipe["stages"]} == {"extract", "validate", "transform", "load"}
    assert next(s for s in pipe["stages"] if s["key"] == "load")["status"] == "skipped"
    assert pipe["quarantine"]["total"] > 0  # fixtures/bad/ goes through the real validators
