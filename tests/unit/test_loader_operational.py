import pandas as pd
import pytest

from pipeline.load.loader import LoadError, check_frame, to_rows, upsert
from pipeline.load.tables import DATA_QUALITY_RESULT, QUARANTINE


def quality_frame() -> pd.DataFrame:
    columns = [name for name, _ in DATA_QUALITY_RESULT.columns if name != "run_id"]
    rows = [
        ("raw_fetch_rate", "completeness", "release", 0.995, 0.99, True, {"fetched": 199}),
        ("version_validity", "validity", None, 0.97, None, True, None),
    ]
    return pd.DataFrame(rows, columns=columns)


def test_dicts_in_jsonb_columns_become_json_text():
    frame = quality_frame().assign(run_id=1)
    rows = to_rows(DATA_QUALITY_RESULT, frame)
    details = [row[7] for row in rows]
    assert details == ['{"fetched": 199}', None]


def test_lists_in_jsonb_columns_do_not_break_missing_value_check():
    frame = quality_frame().assign(run_id=1)
    frame["details"] = [[1, 2], None]
    rows = to_rows(DATA_QUALITY_RESULT, frame)
    assert rows[0][7] == "[1, 2]"
    assert rows[1][7] is None


def test_append_only_tables_skip_the_duplicate_key_check():
    frame = pd.DataFrame(
        {
            "run_id": [1, 1],
            "raw_object_id": [5, 5],
            "stage": ["validate", "validate"],
            "reason_code": ["missing_field", "missing_field"],
            "field_path": ["info.version", "info.version"],
            "message": [None, None],
        }
    )
    check_frame(QUARANTINE, frame)  # identical rows are allowed: no natural key


def test_run_scoped_tables_need_a_run_id():
    frame = quality_frame()
    with pytest.raises(LoadError, match="run_id is required"):
        upsert(None, DATA_QUALITY_RESULT, frame)