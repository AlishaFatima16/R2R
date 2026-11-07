"""Unit tests for the affected_* transform (no database needed)."""

import pandas as pd

from pipeline.transform.affected import transform_affected
from pipeline.validate.osv import OsvVuln


def _vuln(affected):
    return OsvVuln.model_validate(
        {"id": "PYSEC-1", "modified": "2024-01-01T00:00:00Z", "affected": affected}
    )


def _releases(name, versions):
    return pd.DataFrame({"canonical_name": [name] * len(versions), "version": versions})


RANGE = {"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.2"}]}


def test_package_range_event_and_release_rows():
    vuln = _vuln([{"package": {"name": "Flask", "ecosystem": "PyPI"}, "ranges": [RANGE]}])
    frames = transform_affected([vuln], _releases("flask", ["0.9", "1.0", "1.1", "1.2"]))
    assert frames["affected_package"].to_dict("records") == [
        {"vulnerability_id": "PYSEC-1", "entry_index": 0, "package_name": "flask"}
    ]
    assert list(frames["affected_range"]["range_type"]) == ["ECOSYSTEM"]
    assert list(frames["affected_event"]["event_type"]) == ["introduced", "fixed"]
    rel = frames["affected_release"].set_index("version")
    assert rel["in_range"].to_dict() == {"0.9": False, "1.0": True, "1.1": True, "1.2": False}
    assert rel["in_enumerated"].isna().all()


def test_enumerated_versions_and_both_flags():
    entry = {"package": {"name": "six", "ecosystem": "PyPI"}, "ranges": [RANGE],
             "versions": ["1.1", "1.5"]}
    frames = transform_affected([_vuln([entry])], _releases("six", ["1.1", "1.5"]))
    assert sorted(frames["affected_version"]["version"]) == ["1.1", "1.5"]
    rel = frames["affected_release"].set_index("version")
    assert rel.loc["1.1", "in_range"] and rel.loc["1.1", "in_enumerated"]
    assert not rel.loc["1.5", "in_range"] and rel.loc["1.5", "in_enumerated"]


def test_other_ecosystems_and_missing_package_are_skipped():
    vuln = _vuln([
        {"package": {"name": "x", "ecosystem": "npm"}, "ranges": [RANGE]},
        {"ranges": [RANGE]},
    ])
    assert transform_affected([vuln], _releases("x", ["1.0"])) == {}


def test_git_range_kept_but_not_evaluated():
    git = {"type": "GIT", "repo": "https://example.org/r.git",
           "events": [{"introduced": "0"}, {"fixed": "abc123"}]}
    vuln = _vuln([{"package": {"name": "p", "ecosystem": "PyPI"}, "ranges": [git]}])
    frames = transform_affected([vuln], _releases("p", ["1.0"]))
    assert frames["affected_range"].iloc[0]["repo"] == "https://example.org/r.git"
    assert "affected_release" not in frames  # no usable range, no enumerated list


def test_release_with_unparseable_version_is_skipped_when_nothing_known():
    vuln = _vuln([{"package": {"name": "p", "ecosystem": "PyPI"}, "ranges": [RANGE]}])
    frames = transform_affected([vuln], _releases("p", ["not-a-version", "1.1"]))
    assert list(frames["affected_release"]["version"]) == ["1.1"]


def test_duplicate_advisories_do_not_duplicate_rows():
    vuln = _vuln([{"package": {"name": "p", "ecosystem": "PyPI"}, "ranges": [RANGE]}])
    frames = transform_affected([vuln, vuln], _releases("p", ["1.1"]))
    assert len(frames["affected_package"]) == 1
    assert len(frames["affected_release"]) == 1
