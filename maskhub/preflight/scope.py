"""Execution scope: a filter tree compiled to one parameterised predicate.

The same compiled object is consumed by the read-only preflight probe and by
the real executor, so the rows inspected are the rows that get changed. Raw
column names never reach the SQL text: they are validated against the
dataset's declared columns and quoted through the dialect.
"""

from __future__ import annotations

from dataclasses import dataclass

from maskhub.catalog.dataset import Dataset
from maskhub.errors import InvalidRequest

SUPPORTED_OPS = ("eq", "ne", "gt", "ge", "lt", "le", "in", "between")
SQL_OPERATORS = {"eq": "=", "ne": "!=", "gt": ">", "ge": ">=", "lt": "<", "le": "<="}
IDENTIFIER_ALPHABET = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


@dataclass(frozen=True)
class CompiledScope:
    where_sql: str
    parameters: tuple[object, ...]
    canonical: dict[str, object]

    @property
    def is_unscoped(self) -> bool:
        return not self.where_sql


def _quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _check_column(name: object, dataset: Dataset) -> str:
    if not isinstance(name, str) or not name:
        raise InvalidRequest("scope filter column must be a non-empty string")
    if any(char not in IDENTIFIER_ALPHABET for char in name):
        raise InvalidRequest(f"illegal scope column {name!r}")
    if dataset.field(name) is None:
        raise InvalidRequest(f"scope column {name!r} is not declared on {dataset.identifier}")
    return _quote_identifier(name)


def _check_scalar(value: object) -> object:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise InvalidRequest("scope values must be strings, numbers, or two-element bounds")
    return value


def _compile_filter(node: object, dataset: Dataset) -> tuple[str, list[object]]:
    if not isinstance(node, dict):
        raise InvalidRequest("each scope filter must be an object")
    op = node.get("op")
    column = _check_column(node.get("column"), dataset)
    if op in SQL_OPERATORS:
        return f"{column} {SQL_OPERATORS[str(op)]} ?", [_check_scalar(node.get("value"))]
    if op == "in":
        values = node.get("values")
        if not isinstance(values, list) or not values:
            raise InvalidRequest("'in' filter requires a non-empty values list")
        checked = [_check_scalar(item) for item in values]
        placeholders = ", ".join("?" for _ in checked)
        return f"{column} IN ({placeholders})", checked
    if op == "between":
        bounds = node.get("values")
        if not isinstance(bounds, list) or len(bounds) != 2:
            raise InvalidRequest("'between' filter requires exactly two bound values")
        low, high = (_check_scalar(item) for item in bounds)
        return f"{column} BETWEEN ? AND ?", [low, high]
    raise InvalidRequest(f"unsupported scope op {op!r}; expected one of {SUPPORTED_OPS}")


def compile_scope(raw_scope: object, dataset: Dataset) -> CompiledScope:
    """Parse a request ``scope`` payload against a dataset catalog entry."""

    if raw_scope in (None, {}):
        return CompiledScope("", (), {"filters": []})
    if not isinstance(raw_scope, dict):
        raise InvalidRequest("scope must be an object")
    raw_filters = raw_scope.get("filters")
    if raw_filters is None:
        return CompiledScope("", (), {"filters": []})
    if not isinstance(raw_filters, list) or not raw_filters:
        raise InvalidRequest("scope.filters must be a non-empty list")

    clauses: list[str] = []
    parameters: list[object] = []
    canonical_filters: list[dict[str, object]] = []
    for node in raw_filters:
        sql, params = _compile_filter(node, dataset)
        clauses.append(sql)
        parameters.extend(params)
        canonical_filters.append(
            {key: value for key, value in sorted(node.items()) if key in ("op", "column", "value", "values")}
        )
    where_sql = " AND ".join(clauses)
    return CompiledScope(
        where_sql=where_sql,
        parameters=tuple(parameters),
        canonical={"filters": canonical_filters},
    )
