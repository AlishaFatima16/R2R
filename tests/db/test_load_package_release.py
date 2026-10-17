import hashlib
from datetime import UTC, datetime

import pandas as pd
import pytest

from pipeline.load.loader import LoadError
from pipeline.load.tables import PACKAGE, RELEASE, load

UPLOADED = pd.Timestamp("2024-01-02T03:04:05Z")


def h(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def package_frame(requests_summary: str = "HTTP library") -> pd.DataFrame:
    columns = [name for name, _ in PACKAGE.columns]
    rows = [
        ("requests", "requests", True, "A", requests_summary, None, None,
         "2.32.0", 100, None, h("requests" + requests_summary)),
        ("flask", "Flask", True, "A", "Web framework", None, None,
         "3.0.0", 200, None, h("flask")),
    ]
    return pd.DataFrame(rows, columns=columns)


def release_frame() -> pd.DataFrame:
    columns = [name for name, _ in RELEASE.columns]
    rows = [
        ("requests", "2.31.0", True, 1, False, False, UPLOADED,
         False, None, ">=3.7", True, None, h("r1")),
        ("requests", "2.32.0", True, 2, False, False, UPLOADED,
         False, None, ">=3.8", True, None, h("r2")),
        ("flask", "not-a-version", False, None, False, False, pd.NaT,
         False, None, None, False, None, h("f1")),
    ]
    return pd.DataFrame(rows, columns=columns)


def both() -> dict[str, pd.DataFrame]:
    return {"package": package_frame(), "release": release_frame()}


def count(conn, table: str) -> int:
    return conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


def numbers(result) -> tuple[int, int, int]:
    return result.inserted, result.updated, result.unchanged


def test_first_load_inserts_everything(conn):
    result = load(both(), conn)
    assert numbers(result["package"]) == (2, 0, 0)
    assert numbers(result["release"]) == (3, 0, 0)
    assert count(conn, "package") == 2
    assert count(conn, "release") == 3


def test_second_load_of_the_same_data_changes_nothing(conn):
    load(both(), conn)
    result = load(both(), conn)
    assert numbers(result["package"]) == (0, 0, 2)
    assert numbers(result["release"]) == (0, 0, 3)
    assert count(conn, "package") == 2
    assert count(conn, "release") == 3


def test_changed_row_updates_only_that_row(conn):
    load(both(), conn)
    result = load({"package": package_frame("A better summary")}, conn)
    assert numbers(result["package"]) == (0, 1, 1)
    summary = conn.execute(
        "SELECT summary FROM package WHERE canonical_name = 'requests'"
    ).fetchone()[0]
    assert summary == "A better summary"


def test_missing_values_are_stored_as_null(conn):
    load(both(), conn)
    rank, uploaded = conn.execute(
        "SELECT version_rank, uploaded_at FROM release WHERE version = 'not-a-version'"
    ).fetchone()
    assert rank is None
    assert uploaded is None


def test_timestamps_keep_their_timezone(conn):
    load(both(), conn)
    uploaded = conn.execute(
        "SELECT uploaded_at FROM release WHERE version = '2.31.0'"
    ).fetchone()[0]
    assert uploaded == datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)

def test_release_without_its_package_is_rejected(conn):
    with pytest.raises(LoadError, match="no parent row"):
        load({"release": release_frame()}, conn)
    assert count(conn, "release") == 0


def test_duplicate_keys_in_one_batch_are_rejected(conn):
    frame = package_frame()
    with pytest.raises(LoadError, match="duplicate natural keys"):
        load({"package": pd.concat([frame, frame.iloc[[0]]])}, conn)


def test_tables_without_a_loader_are_rejected(conn):
    with pytest.raises(LoadError, match="No loader yet"):
        load({"vulnerability": pd.DataFrame()}, conn)