import pandas as pd
import pytest

from pipeline.load.loader import LoadError, check_frame, to_rows
from pipeline.load.tables import AFFECTED_EVENT, AFFECTED_PACKAGE, AFFECTED_RELEASE


def test_entry_index_is_sent_as_a_plain_int():
    frame = pd.DataFrame([("V-1", 0, "app")], columns=AFFECTED_PACKAGE.column_names)
    row = to_rows(AFFECTED_PACKAGE, frame)[0]
    assert row[1] == 0 and type(row[1]) is int


def test_same_event_position_twice_is_rejected():
    row = ("V-1", 0, 0, 0, "introduced", "0")
    frame = pd.DataFrame([row, row], columns=AFFECTED_EVENT.column_names)
    with pytest.raises(LoadError, match="duplicate natural keys"):
        check_frame(AFFECTED_EVENT, frame)


def test_missing_in_range_becomes_none():
    frame = pd.DataFrame(
        [("app", "1.0", "V-1", 0, None, True)], columns=AFFECTED_RELEASE.column_names
    )
    row = to_rows(AFFECTED_RELEASE, frame)[0]
    assert row[AFFECTED_RELEASE.column_names.index("in_range")] is None
