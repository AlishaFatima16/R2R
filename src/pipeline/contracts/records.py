"""Shared validation records and quarantine helpers."""

from dataclasses import dataclass

REASON_CODES = frozenset(
    {
        "missing_field",
        "type_error",
        "invalid_timestamp",
        "malformed_identifier",
        "unexpected_structure",
        "empty_body",
        "duplicate_conflict",
    }
)


@dataclass(frozen=True)
class QuarantineRecord:
    raw_object_id: int | None
    stage: str
    reason_code: str
    field_path: str | None = None
    message: str | None = None

    def __post_init__(self) -> None:
        if self.reason_code not in REASON_CODES:
            raise ValueError(f"unknown quarantine reason code: {self.reason_code}")
        if self.stage not in {"validate", "transform", "load"}:
            raise ValueError(f"unknown quarantine stage: {self.stage}")


def quarantine_from_error(
    error: Exception, *, raw_object_id: int | None, stage: str = "validate"
) -> QuarantineRecord:
    """Convert a Pydantic-like validation error into the stable quarantine shape."""
    errors = getattr(error, "errors", list)()
    first = errors[0] if errors else {}
    error_type = str(first.get("type", "type_error"))
    reason = "missing_field" if error_type == "missing" else "type_error"
    location = first.get("loc")
    field_path = ".".join(str(item) for item in location) if location else None
    return QuarantineRecord(raw_object_id, stage, reason, field_path, str(error))
