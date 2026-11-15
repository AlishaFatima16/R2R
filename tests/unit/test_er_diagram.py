"""Unit tests for the ER diagram generator (no database needed)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

from generate_er_diagram import (
    fetch_schema,
    mermaid_type,
    render_markdown,
    render_mermaid,
)

SCHEMA = {
    "columns": {
        "package": [("package_id", "integer", True), ("canonical_name", "text", True)],
        "release": [
            ("release_id", "bigint", True),
            ("package_id", "integer", True),
            ("uploaded_at", "timestamp with time zone", False),
            ("extras", "text[]", False),
        ],
        "dependency": [
            ("dependency_id", "bigint", True),
            ("release_id", "bigint", True),
            ("target_package_id", "integer", False),
        ],
    },
    "primary": {"package": {"package_id"}, "release": {"release_id"},
                "dependency": {"dependency_id"}},
    "foreign": [
        ("release", "package", ("package_id",)),
        ("dependency", "release", ("release_id",)),
        ("dependency", "package", ("target_package_id",)),
    ],
}


def test_types_become_single_safe_words():
    assert mermaid_type("character varying(20)") == "varchar"
    assert mermaid_type("timestamp with time zone") == "timestamptz"
    assert mermaid_type("text[]") == "text_array"
    assert mermaid_type("numeric(10,2)") == "numeric"


def test_required_foreign_key_is_one_to_many_and_nullable_one_is_optional():
    text = render_mermaid(SCHEMA)
    assert 'package ||--o{ release : "package_id"' in text
    assert 'release ||--o{ dependency : "release_id"' in text
    assert 'package |o--o{ dependency : "target_package_id"' in text


def test_columns_are_marked_pk_and_fk():
    text = render_mermaid(SCHEMA)
    assert "bigint release_id PK" in text
    assert "int package_id FK" in text
    assert "int target_package_id FK" in text
    assert "text_array extras" in text


def test_markdown_wraps_a_mermaid_block_and_lists_tables():
    markdown = render_markdown(SCHEMA)
    assert markdown.count("```mermaid") == 1
    assert "`package`" in markdown and "`dependency`" in markdown


class FakeConn:
    def __init__(self, answers):
        self.answers = answers

    def execute(self, sql):
        key = "pg_attribute a\nJOIN pg_class c" if "format_type" in sql else None
        rows = self.answers["columns"] if key else (
            self.answers["foreign"] if "string_agg" in sql else self.answers["primary"]
        )

        class Result:
            def fetchall(self_inner):
                return rows

        return Result()


def test_fetch_schema_splits_foreign_key_column_lists():
    conn = FakeConn({
        "columns": [("release", "package_id", "integer", True)],
        "primary": [("release", "release_id")],
        "foreign": [("release", "package", "package_id,other_id")],
    })
    schema = fetch_schema(conn)
    assert schema["foreign"] == [("release", "package", ("package_id", "other_id"))]
    assert schema["primary"] == {"release": {"release_id"}}
