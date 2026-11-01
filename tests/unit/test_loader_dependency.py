import pandas as pd
import pytest

from pipeline.load.loader import LoadError, check_frame, to_rows
from pipeline.load.tables import DEPENDENCY


def dependency_frame() -> pd.DataFrame:
    rows = [
        ("app", "1.0", "lib[x]>=2", True, "lib", ["x"], ">=2", None, False, False),
        ("app", "1.0", "!!bad", False, None, None, None, None, False, False),
    ]
    return pd.DataFrame(rows, columns=[name for name, _ in DEPENDENCY.columns])


def test_extras_lists_pass_through_and_missing_becomes_none():
    rows = to_rows(DEPENDENCY, dependency_frame())
    extras_index = DEPENDENCY.column_names.index("extras")
    assert rows[0][extras_index] == ["x"]
    assert rows[1][extras_index] is None


def test_same_requirement_twice_for_one_release_is_rejected():
    frame = pd.concat([dependency_frame().iloc[[0]]] * 2, ignore_index=True)
    with pytest.raises(LoadError, match="duplicate natural keys"):
        check_frame(DEPENDENCY, frame)