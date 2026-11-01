"""Turn validation failures into quarantine rows.

A quarantine row has the columns of the quarantine table (without run_id, which load()
adds): raw_object_id, stage, reason_code, field_path, message.

Reason codes:
    missing_field      a required field is absent
    type_error         a field has the wrong type (for example a string instead of a list)
    invalid_timestamp  a timestamp cannot be parsed
    invalid_value      the type is right but the value is not allowed
"""

from __future__ import annotations

from pydantic import ValidationError

QUARANTINE_COLUMNS = ("raw_object_id", "stage", "reason_code", "field_path", "message")
MAX_MESSAGE = 500


def reason_code(error_type: str) -> str:
    if error_type == "missing":
        return "missing_field"
    if error_type.startswith(("datetime", "date_", "time")):
        return "invalid_timestamp"
    if error_type.endswith(("_type", "_parsing")):
        return "type_error"
    return "invalid_value"


def format_path(prefix: str, location: tuple) -> str:
    path = prefix
    for part in location:
        path += f"[{part}]" if isinstance(part, int) else (f".{part}" if path else str(part))
    return path


def quarantine_row(raw_object_id, reason: str, field_path: str, message: str) -> dict:
    return {
        "raw_object_id": raw_object_id,
        "stage": "validate",
        "reason_code": reason,
        "field_path": field_path,
        "message": message[:MAX_MESSAGE],
    }


def rows_from_error(
    error: ValidationError, raw_object_id, prefix: str = "", context: str = ""
) -> list[dict]:
    """One quarantine row per problem. context (for example an advisory id) starts the message."""
    rows = []
    for item in error.errors(include_url=False):
        message = item["msg"]
        if context:
            message = f"{context}: {message}"
        rows.append(
            quarantine_row(
                raw_object_id,
                reason_code(item["type"]),
                format_path(prefix, item["loc"]),
                message,
            )
        )
    return rows
