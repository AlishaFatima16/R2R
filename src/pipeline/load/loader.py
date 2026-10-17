"""Generic bulk upsert: DataFrame -> COPY into a staging table -> INSERT ... ON CONFLICT.

How it works for one table:
    1. Check the frame (exact columns, no duplicate natural keys).
    2. COPY the rows into a temporary staging table.
    3. Check that every foreign reference resolves (for example a release's package).
    4. INSERT ... SELECT from staging with ON CONFLICT DO UPDATE ... WHERE content_hash
       IS DISTINCT FROM. Unchanged rows are skipped, so running the same data twice
       changes nothing.

The loader treats content_hash as an opaque value computed by the transform stage.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

INTEGER_TYPES = {"SMALLINT", "INT", "INTEGER", "BIGINT"}


class LoadError(Exception):
    """The data cannot be loaded as given. Nothing from the failing load is committed."""


@dataclass(frozen=True)
class TableSpec:
    table: str
    columns: tuple[tuple[str, str], ...]  # (frame column, SQL type), in staging order
    key: tuple[str, ...]  # natural key, as frame columns
    upsert_sql: str  # INSERT ... SELECT FROM stg_<table> ... RETURNING (xmax = 0)
    unresolved_sql: str | None = None  # returns names that have no parent row

    @property
    def staging(self) -> str:
        return f"stg_{self.table}"

    @property
    def column_names(self) -> list[str]:
        return [name for name, _ in self.columns]


@dataclass(frozen=True)
class TableResult:
    table: str
    inserted: int
    updated: int
    unchanged: int


def check_frame(spec: TableSpec, frame: pd.DataFrame) -> None:
    expected = set(spec.column_names)
    actual = set(frame.columns)
    if actual != expected:
        raise LoadError(
            f"{spec.table}: frame columns do not match. "
            f"missing={sorted(expected - actual)} unexpected={sorted(actual - expected)}"
        )
    duplicated = frame.duplicated(subset=list(spec.key), keep=False)
    if duplicated.any():
        sample = frame.loc[duplicated, list(spec.key)].head(5).to_dict("records")
        raise LoadError(f"{spec.table}: duplicate natural keys in one batch, e.g. {sample}")


def to_rows(spec: TableSpec, frame: pd.DataFrame) -> list[tuple]:
    """Plain Python tuples for COPY: missing values become None, whole numbers become int."""
    ints = {name for name, sql_type in spec.columns if sql_type.upper() in INTEGER_TYPES}
    columns = []
    for name in spec.column_names:
        values = frame[name].astype(object).tolist()
        cleaned = []
        for value in values:
            if value is None or pd.isna(value):
                cleaned.append(None)
            elif name in ints:
                cleaned.append(int(value))
            elif isinstance(value, pd.Timestamp):
                cleaned.append(value.to_pydatetime())
            else:
                cleaned.append(value)
        columns.append(cleaned)
    return list(zip(*columns)) if columns else []


def upsert(conn, spec: TableSpec, frame: pd.DataFrame) -> TableResult:
    """Upsert one table. Call inside a transaction (conn.transaction())."""
    check_frame(spec, frame)
    rows = to_rows(spec, frame)
    if not rows:
        return TableResult(spec.table, 0, 0, 0)

    column_defs = ", ".join(f"{name} {sql_type}" for name, sql_type in spec.columns)
    column_list = ", ".join(spec.column_names)

    with conn.cursor() as cur:
        cur.execute(f"CREATE TEMP TABLE {spec.staging} ({column_defs}) ON COMMIT DROP")
        with cur.copy(f"COPY {spec.staging} ({column_list}) FROM STDIN") as copy:
            for row in rows:
                copy.write_row(row)

        if spec.unresolved_sql:
            cur.execute(spec.unresolved_sql)
            missing = [r[0] for r in cur.fetchall()]
            if missing:
                raise LoadError(f"{spec.table}: no parent row for {missing[:10]}")

        cur.execute(spec.upsert_sql)
        touched = [r[0] for r in cur.fetchall()]  # True = inserted, False = updated
        cur.execute(f"DROP TABLE {spec.staging}")

    inserted = sum(1 for was_inserted in touched if was_inserted)
    updated = len(touched) - inserted
    return TableResult(spec.table, inserted, updated, len(rows) - len(touched))