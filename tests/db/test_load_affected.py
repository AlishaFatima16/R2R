import pandas as pd
import psycopg
import pytest

from pipeline.load.loader import LoadError
from pipeline.load.tables import (
    AFFECTED_EVENT,
    AFFECTED_PACKAGE,
    AFFECTED_RANGE,
    AFFECTED_RELEASE,
    AFFECTED_VERSION,
    PACKAGE,
    RELEASE,
    VULNERABILITY,
    load,
)

HASH = "a" * 64


def frame(spec, rows) -> pd.DataFrame:
    return pd.DataFrame(rows, columns=spec.column_names)


def seed(conn) -> None:
    """One package with two releases, and one vulnerability."""
    packages = frame(
        PACKAGE,
        [("app", "App", True, "A", None, None, None, "1.1", None, None, HASH)],
    )
    ts = pd.Timestamp("2024-01-02T03:04:05Z")
    releases = frame(
        RELEASE,
        [
            ("app", "1.0", True, 1, False, False, ts, False, None, None, True, None, HASH),
            ("app", "1.1", True, 2, False, False, ts, False, None, None, True, None, HASH),
        ],
    )
    vulnerabilities = frame(
        VULNERABILITY,
        [("V-1", None, ts, None, "s", None, "1.6.0", False, None, HASH)],
    )
    load({"package": packages, "release": releases, "vulnerability": vulnerabilities}, conn)


def packages_frame() -> pd.DataFrame:
    return frame(AFFECTED_PACKAGE, [("V-1", 0, "app"), ("V-1", 1, "outside-pkg")])


def ranges_frame() -> pd.DataFrame:
    return frame(
        AFFECTED_RANGE,
        [("V-1", 0, 0, "ECOSYSTEM", None), ("V-1", 0, 1, "GIT", "https://example.com/r.git")],
    )


def events_frame() -> pd.DataFrame:
    return frame(
        AFFECTED_EVENT,
        [("V-1", 0, 0, 0, "introduced", "0"), ("V-1", 0, 0, 1, "fixed", "1.1")],
    )


def versions_frame() -> pd.DataFrame:
    return frame(AFFECTED_VERSION, [("V-1", 0, "1.0"), ("V-1", 0, "0.9")])


def releases_frame() -> pd.DataFrame:
    return frame(
        AFFECTED_RELEASE,
        [("app", "1.0", "V-1", 0, True, None), ("app", "1.1", "V-1", 0, False, True)],
    )


def load_all(conn):
    return load(
        {
            "affected_release": releases_frame(),
            "affected_version": versions_frame(),
            "affected_event": events_frame(),
            "affected_range": ranges_frame(),
            "affected_package": packages_frame(),
        },
        conn,
    )


def counts(result) -> dict[str, tuple[int, int, int]]:
    return {t: (r.inserted, r.updated, r.unchanged) for t, r in result.items()}


def test_everything_loads_in_one_call(conn):
    seed(conn)
    assert counts(load_all(conn)) == {
        "affected_package": (2, 0, 0),
        "affected_range": (2, 0, 0),
        "affected_event": (2, 0, 0),
        "affected_version": (2, 0, 0),
        "affected_release": (2, 0, 0),
    }


def test_loading_everything_twice_changes_nothing(conn):
    seed(conn)
    load_all(conn)
    assert all(c == (0, 0, 2) for c in counts(load_all(conn)).values())


def test_package_id_is_filled_only_for_packages_we_loaded(conn):
    seed(conn)
    load({"affected_package": packages_frame()}, conn)
    rows = conn.execute(
        "SELECT entry_index, package_id IS NOT NULL FROM affected_package ORDER BY 1"
    ).fetchall()
    assert rows == [(0, True), (1, False)]


def test_a_changed_fixed_version_is_updated(conn):
    seed(conn)
    load_all(conn)
    changed = events_frame()
    changed.loc[1, "version_string"] = "1.2"
    result = load({"affected_event": changed}, conn)["affected_event"]
    assert (result.inserted, result.updated, result.unchanged) == (0, 1, 1)


def test_a_changed_range_flag_is_updated(conn):
    seed(conn)
    load_all(conn)
    changed = releases_frame()
    changed.loc[1, "in_range"] = True
    result = load({"affected_release": changed}, conn)["affected_release"]
    assert (result.inserted, result.updated, result.unchanged) == (0, 1, 1)


def test_range_for_unknown_affected_entry_is_rejected(conn):
    seed(conn)
    with pytest.raises(LoadError, match="affected entry V-1#0"):
        load({"affected_range": ranges_frame()}, conn)


def test_event_for_unknown_range_is_rejected(conn):
    seed(conn)
    load({"affected_package": packages_frame()}, conn)
    with pytest.raises(LoadError, match="range V-1#0/0"):
        load({"affected_event": events_frame()}, conn)


def test_affected_package_for_unknown_vulnerability_is_rejected(conn):
    seed(conn)
    bad = frame(AFFECTED_PACKAGE, [("V-404", 0, "app")])
    with pytest.raises(LoadError, match="no parent row"):
        load({"affected_package": bad}, conn)


def test_affected_release_for_unknown_release_is_rejected(conn):
    seed(conn)
    load({"affected_package": packages_frame()}, conn)
    bad = frame(AFFECTED_RELEASE, [("app", "9.9", "V-1", 0, True, None)])
    with pytest.raises(LoadError, match="release app==9.9"):
        load({"affected_release": bad}, conn)


def test_a_git_range_without_a_repo_is_refused_by_the_database(conn):
    seed(conn)
    load({"affected_package": packages_frame()}, conn)
    bad = frame(AFFECTED_RANGE, [("V-1", 0, 0, "GIT", None)])
    with pytest.raises(psycopg.errors.CheckViolation, match="affected_range_check"):
        load({"affected_range": bad}, conn)
