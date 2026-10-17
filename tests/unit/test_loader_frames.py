import pandas as pd
import pytest

from pipeline.load.loader import LoadError, check_frame, to_rows
from pipeline.load.tables import PACKAGE, RELEASE


def release_frame() -> pd.DataFrame:
    columns = [name for name, _ in RELEASE.columns]
    rows = [
        ("requests", "2.0", True, 1, False, False, pd.Timestamp("2024-01-02T03:04:05Z"),
         False, None, ">=3.8", True, None, "a" * 64),
        ("requests", "bad", False, None, False, False, pd.NaT,
         False, None, None, False, None, "b" * 64),
    ]
    return pd.DataFrame(rows, columns=columns)


def test_to_rows_turns_missing_values_into_none():
    rows = to_rows(RELEASE, release_frame())
    assert rows[1][3] is None  # version_rank
    assert rows[1][6] is None  # uploaded_at (NaT)
    assert rows[1][9] is None  # requires_python


def test_to_rows_gives_plain_ints_even_when_pandas_made_floats():
    frame = release_frame()
    assert frame["version_rank"].dtype == "float64"  # 1.0 and NaN
    rows = to_rows(RELEASE, frame)
    assert rows[0][3] == 1
    assert isinstance(rows[0][3], int)


def test_to_rows_gives_plain_datetimes():
    rows = to_rows(RELEASE, release_frame())
    assert type(rows[0][6]).__name__ == "datetime"


def test_check_frame_accepts_a_valid_frame():
    check_frame(RELEASE, release_frame())


def test_check_frame_rejects_missing_column():
    with pytest.raises(LoadError, match="missing"):
        check_frame(RELEASE, release_frame().drop(columns=["is_dev"]))


def test_check_frame_rejects_unexpected_column():
    with pytest.raises(LoadError, match="unexpected"):
        check_frame(RELEASE, release_frame().assign(extra=1))


def test_check_frame_rejects_duplicate_keys():
    frame = release_frame()
    doubled = pd.concat([frame, frame.iloc[[0]]])
    with pytest.raises(LoadError, match="duplicate natural keys"):
        check_frame(RELEASE, doubled)


def test_package_spec_key_is_canonical_name():
    assert PACKAGE.key == ("canonical_name",)