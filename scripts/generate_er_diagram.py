"""Generate the entity-relationship diagram from the live database schema.

The diagram is read from PostgreSQL's own catalog (tables, columns, primary keys, foreign
keys), so it cannot drift from the migrations. Output is a Mermaid ``erDiagram`` inside a
Markdown file, which GitHub renders directly.

Usage (PowerShell):
    $env:DATABASE_URL = "postgresql://postgres:<password>@localhost:5432/r2r"
    python scripts/generate_er_diagram.py            # writes docs/er_diagram.md
    python scripts/generate_er_diagram.py --out -    # prints to the screen
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

COLUMNS_SQL = """
SELECT c.relname, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY c.relname, a.attnum
"""

PRIMARY_KEYS_SQL = """
SELECT cl.relname, a.attname
FROM pg_constraint con
JOIN pg_class cl ON cl.oid = con.conrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = ANY (con.conkey)
WHERE con.contype = 'p' AND n.nspname = 'public'
ORDER BY cl.relname, a.attnum
"""

FOREIGN_KEYS_SQL = """
SELECT cl.relname, fl.relname,
       string_agg(a.attname, ',' ORDER BY k.ord)
FROM pg_constraint con
JOIN pg_class cl ON cl.oid = con.conrelid
JOIN pg_class fl ON fl.oid = con.confrelid
JOIN pg_namespace n ON n.oid = cl.relnamespace
CROSS JOIN LATERAL unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord)
JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum
WHERE con.contype = 'f' AND n.nspname = 'public'
GROUP BY con.oid, cl.relname, fl.relname
ORDER BY cl.relname, fl.relname, 3
"""

TYPE_NAMES = {
    "character varying": "varchar",
    "timestamp with time zone": "timestamptz",
    "timestamp without time zone": "timestamp",
    "double precision": "float8",
    "boolean": "bool",
    "integer": "int",
    "character": "char",
}

# Tables are listed in this order in the legend; anything else is listed under "Other".
GROUPS = (
    ("Operational (one row per run or response)",
     ("source", "pipeline_run", "raw_object", "quarantine", "data_quality_result")),
    ("Packages and releases", ("package", "release", "dependency", "resolved_node",
                              "release_external_advisory")),
    ("Advisories", ("vulnerability", "vulnerability_alias", "vulnerability_severity",
                    "affected_package", "affected_range", "affected_event", "affected_version",
                    "affected_release")),
)


def mermaid_type(sql_type: str) -> str:
    """A column type as one Mermaid-safe word (letters, digits, underscore)."""
    base = re.sub(r"\(.*?\)", "", sql_type).strip()
    array = base.endswith("[]")
    base = base.removesuffix("[]")
    word = TYPE_NAMES.get(base, base)
    word = re.sub(r"[^A-Za-z0-9_]+", "_", word).strip("_") or "unknown"
    return f"{word}_array" if array else word


def fetch_schema(conn) -> dict:
    """Read tables, columns, primary keys and foreign keys from the catalog."""
    columns: dict[str, list[tuple[str, str, bool]]] = defaultdict(list)
    for table, column, sql_type, not_null in conn.execute(COLUMNS_SQL).fetchall():
        columns[table].append((column, sql_type, bool(not_null)))
    primary: dict[str, set[str]] = defaultdict(set)
    for table, column in conn.execute(PRIMARY_KEYS_SQL).fetchall():
        primary[table].add(column)
    foreign = [
        (child, parent, tuple(cols.split(",")))
        for child, parent, cols in conn.execute(FOREIGN_KEYS_SQL).fetchall()
    ]
    return {"columns": dict(columns), "primary": dict(primary), "foreign": foreign}


def render_mermaid(schema: dict) -> str:
    """A Mermaid erDiagram: one block per table, one line per foreign key."""
    columns, primary, foreign = schema["columns"], schema["primary"], schema["foreign"]
    fk_columns: dict[str, set[str]] = defaultdict(set)
    for child, _parent, cols in foreign:
        fk_columns[child].update(cols)

    lines = ["erDiagram"]
    for child, parent, cols in sorted(foreign):
        nullable = any(not_null is False for name, _t, not_null in columns[child] if name in cols)
        left = "|o" if nullable else "||"
        label = ", ".join(cols)
        lines.append(f'    {parent} {left}--o{{ {child} : "{label}"')
    for table in sorted(columns):
        lines.append(f"    {table} {{")
        for name, sql_type, _not_null in columns[table]:
            marks = []
            if name in primary.get(table, set()):
                marks.append("PK")
            if name in fk_columns.get(table, set()):
                marks.append("FK")
            suffix = f" {', '.join(marks)}" if marks else ""
            lines.append(f"        {mermaid_type(sql_type)} {name}{suffix}")
        lines.append("    }")
    return "\n".join(lines)


def render_markdown(schema: dict) -> str:
    tables = set(schema["columns"])
    listed = {name for _title, names in GROUPS for name in names}
    legend = []
    for title, names in GROUPS:
        present = [name for name in names if name in tables]
        if present:
            legend.append(f"- **{title}:** " + ", ".join(f"`{name}`" for name in present))
    other = sorted(tables - listed)
    if other:
        legend.append("- **Other:** " + ", ".join(f"`{name}`" for name in other))
    return (
        "# Entity-relationship diagram\n\n"
        "Generated from the live database schema by `scripts/generate_er_diagram.py`, so it "
        "matches `migrations/` exactly. Do not edit by hand; re-run the script.\n\n"
        "Notation: `PK` primary key, `FK` foreign key. A relationship line reads "
        "*parent one-to-many child*; a `|o` on the parent side means the foreign key is "
        "optional (nullable).\n\n"
        "```mermaid\n" + render_mermaid(schema) + "\n```\n\n"
        "## Tables\n\n" + "\n".join(legend) + "\n\n"
        "Frames never carry surrogate ids: the loader resolves natural keys to the ids "
        "above (see `docs/interfaces.md`).\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--out", default="docs/er_diagram.md", help="file to write, or - for stdout"
    )
    args = parser.parse_args(argv)
    url = os.environ.get("DATABASE_URL")
    if not url:
        print("DATABASE_URL is not set", file=sys.stderr)
        return 2
    import psycopg

    with psycopg.connect(url) as conn:
        text = render_markdown(fetch_schema(conn))
    if args.out == "-":
        print(text)
    else:
        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
