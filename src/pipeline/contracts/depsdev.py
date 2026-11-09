"""Pydantic contract for deps.dev v3 GetDependencies responses."""
from __future__ import annotations

from pydantic import Field, field_validator

from pipeline.validate.common import Contract


class DepsDevVersionKey(Contract):
    system: str
    name: str
    version: str

    @field_validator("system", "name", "version")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value


class DepsDevNode(Contract):
    versionKey: DepsDevVersionKey
    relation: str
    bundled: bool = False
    errors: list[str] = Field(default_factory=list)

    @field_validator("relation")
    @classmethod
    def _valid_relation(cls, value: str) -> str:
        if value not in {"SELF", "DIRECT", "INDIRECT"}:
            raise ValueError("relation must be SELF, DIRECT, or INDIRECT")
        return value


class DepsDevEdge(Contract):
    fromNode: int
    toNode: int
    requirement: str | None = None


class DepsDevGraph(Contract):
    nodes: list[DepsDevNode]
    edges: list[DepsDevEdge] = Field(default_factory=list)
    error: str | None = None

    @field_validator("nodes")
    @classmethod
    def _root_required(cls, value):
        if not value:
            raise ValueError("nodes must contain the root node")
        if value[0].relation != "SELF":
            raise ValueError("the first deps.dev node must have relation SELF")
        return value

    @field_validator("edges")
    @classmethod
    def _edge_indices_non_negative(cls, value):
        if any(edge.fromNode < 0 or edge.toNode < 0 for edge in value):
            raise ValueError("edge node indexes cannot be negative")
        return value
