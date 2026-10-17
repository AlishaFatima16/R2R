import pandas as pd
import pytest

from pipeline.load.loader import LoadError
from pipeline.load.tables import DEPENDENCY, load

HASH = "d" * 64


def seed_packages_and_release(conn) -> None:
    packages = pd.DataFrame(
        {
            "canonical_name": ["app", "lib"],
            "display_name": ["App", "Lib"],
            "in_seed": [True, False],
            "seed_tier": ["A", None],
            "summary": [None, None],
            "repo_url": [None, None],
            "license_raw": [None, None],
            "latest_version": ["1.0", None],
            "last_serial": [None, None],
            "raw_object_id": [None, None],
            "content_hash": [HASH, HASH],
        }
    )
    releases = pd.DataFrame(
        {
            "canonical_name": ["app"],
            "version": ["1.0"],
            "version_valid": [True],
            "version_rank": [1],
            "is_prerelease": [False],
            "is_dev": [False],
            "uploaded_at": [pd.Timestamp("2024-01-02T03:04:05Z")],
            "yanked": [False],
            "yanked_reason": [None],
            "requires_python": [None],
            "deps_fetched": [True],
            "raw_object_id": [None],
            "content_hash": [HASH],
        }
    )
    load({"package": packages, "release": releases}, conn)


def dependency_frame() -> pd.DataFrame:
    rows = [
        ("app", "1.0", "lib[x]>=2,<3", True, "lib", ["x"], ">=2,<3", None, False, False),
        ("app", "1.0", "!!bad", False, None, None, None, None, False, False),
    ]
    return pd.DataFrame(rows, columns=[name for name, _ in DEPENDENCY.columns])


def test_dependencies_load_and_resolve_ids(conn):
    seed_packages_and_release(conn)
    result = load({"dependency": dependency_frame()}, conn)
    assert result["dependency"].inserted == 2
    row = conn.execute(
        "SELECT p.canonical_name, d.extras, d.specifier FROM dependency d "
        "JOIN package p ON p.package_id = d.target_package_id"
    ).fetchone()
    assert row == ("lib", ["x"], ">=2,<3")


def test_loading_the_same_dependencies_twice_changes_nothing(conn):
    seed_packages_and_release(conn)
    load({"dependency": dependency_frame()}, conn)
    again = load({"dependency": dependency_frame()}, conn)["dependency"]
    assert (again.inserted, again.updated, again.unchanged) == (0, 0, 2)


def test_a_changed_specifier_is_updated(conn):
    seed_packages_and_release(conn)
    load({"dependency": dependency_frame()}, conn)
    changed = dependency_frame()
    changed.loc[0, "specifier"] = ">=2.1,<3"
    result = load({"dependency": changed}, conn)["dependency"]
    assert (result.inserted, result.updated, result.unchanged) == (0, 1, 1)


def test_unknown_release_is_rejected(conn):
    seed_packages_and_release(conn)
    frame = dependency_frame().assign(version="9.9")
    with pytest.raises(LoadError, match="release app==9.9"):
        load({"dependency": frame}, conn)


def test_unknown_target_package_is_rejected(conn):
    seed_packages_and_release(conn)
    frame = dependency_frame()
    frame.loc[0, "target_name"] = "ghost"
    with pytest.raises(LoadError, match="target package ghost"):
        load({"dependency": frame}, conn)


def test_valid_requirement_without_target_is_rejected(conn):
    seed_packages_and_release(conn)
    frame = dependency_frame()
    frame.loc[0, "target_name"] = None
    with pytest.raises(LoadError, match="without target_name"):
        load({"dependency": frame}, conn)