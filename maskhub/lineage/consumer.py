"""Downstream consumer of a dataset column.

Consumers describe *who reads which column and how they use it*. The usage
class is what turns a masked column into a blast-radius statement: masking a
``join_key`` breaks joins, masking a ``metric`` column collapses aggregates.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ColumnUsage(str, Enum):
    JOIN_KEY = "join_key"
    FILTER = "filter"
    METRIC = "metric"
    PASSTHROUGH = "passthrough"

    @property
    def order(self) -> int:
        return {
            ColumnUsage.JOIN_KEY: 0,
            ColumnUsage.FILTER: 1,
            ColumnUsage.METRIC: 2,
            ColumnUsage.PASSTHROUGH: 3,
        }[self]


@dataclass(frozen=True)
class ColumnUse:
    column: str
    usage: str

    def __post_init__(self) -> None:
        if not self.column.strip():
            raise ValueError("column use must name a column")
        try:
            ColumnUsage(self.usage)
        except ValueError as exc:
            raise ValueError(f"unknown column usage {self.usage!r}") from exc

    @property
    def usage_enum(self) -> ColumnUsage:
        return ColumnUsage(self.usage)

    def as_dict(self) -> dict[str, str]:
        return {"column": self.column, "usage": self.usage}

    @classmethod
    def from_dict(cls, payload: object) -> "ColumnUse | None":
        if not isinstance(payload, dict):
            return None
        column = payload.get("column")
        usage = payload.get("usage")
        if not isinstance(column, str) or not isinstance(usage, str):
            return None
        try:
            return cls(column=column, usage=usage)
        except ValueError:
            return None


@dataclass(frozen=True)
class Consumer:
    identifier: str
    kind: str
    owner: str
    reads: tuple[ColumnUse, ...]

    def __post_init__(self) -> None:
        if not self.identifier.strip():
            raise ValueError("consumer identifier is required")
        if not self.reads:
            raise ValueError("consumer must read at least one column")

    def columns(self) -> set[str]:
        return {item.column for item in self.reads}

    def uses(self, column: str) -> list[ColumnUse]:
        return [item for item in self.reads if item.column == column]

    def as_dict(self) -> dict[str, object]:
        return {
            "identifier": self.identifier,
            "kind": self.kind,
            "owner": self.owner,
            "reads": [item.as_dict() for item in self.reads],
        }

    @classmethod
    def from_dict(cls, payload: object) -> "Consumer | None":
        if not isinstance(payload, dict):
            return None
        identifier = payload.get("identifier")
        kind = payload.get("kind", "")
        owner = payload.get("owner", "")
        raw_reads = payload.get("reads")
        if not isinstance(identifier, str) or not isinstance(kind, str):
            return None
        if not isinstance(owner, str) or not isinstance(raw_reads, list):
            return None
        reads = tuple(
            item for item in (ColumnUse.from_dict(raw) for raw in raw_reads) if item is not None
        )
        if len(reads) != len(raw_reads):
            return None
        try:
            return cls(identifier=identifier, kind=kind, owner=owner, reads=reads)
        except ValueError:
            return None
