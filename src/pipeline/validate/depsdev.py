"""Validation for deps.dev dependency graph responses."""

from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import ValidationError

from pipeline.contracts.depsdev import DepsDevGraph
from pipeline.validate.errors import quarantine_row, rows_from_error


@dataclass
class DepsDevResult:
    graph: DepsDevGraph | None = None
    quarantine: list[dict] = field(default_factory=list)


def validate_depsdev(body, raw_object_id=None) -> DepsDevResult:
    """Validate one deps.dev response, quarantining invalid responses."""
    if not isinstance(body, dict):
        return DepsDevResult(
            quarantine=[
                quarantine_row(
                    raw_object_id,
                    "type_error",
                    "",
                    "deps.dev response must be a JSON object",
                )
            ]
        )

    try:
        graph = DepsDevGraph.model_validate(body)
    except ValidationError as error:
        return DepsDevResult(
            quarantine=rows_from_error(error, raw_object_id)
        )

    return DepsDevResult(graph=graph)