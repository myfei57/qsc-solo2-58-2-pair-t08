"""Real-shape profiler.

Runs aggregate queries over the source: a cheap exact count pass (scope rows
and table rows) followed by one per-column distribution query built through
the masking UDFs. When the scope exceeds the scan budget the column pass
switches to a deterministic rowid-stride sample and its estimates are marked
``sampled``.

The query emits numbers and coarse length histograms only. There is no code
path on which a raw cell value leaves the database engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from maskhub.preflight.probe import ProbeResult, ScanBudgetExceeded, SqliteProbe
from maskhub.preflight.scope import CompiledScope
from maskhub.preflight.transform import ResolvedColumn, TransformBinder

PROFILER_VERSION = "preflight-profile/1"
LENGTH_BUCKETS = (0, 4, 8, 12, 18, 32, 64)


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


@dataclass
class ColumnProfile:
    column: str
    rule_id: str
    action: str
    non_null_in_scope: int
    changed_rows: int
    change_ratio: float
    distinct_before: int
    distinct_after: int
    distinct_ratio_after: float
    length_buckets: dict[str, int]

    def as_dict(self) -> dict[str, object]:
        return {
            "column": self.column,
            "rule_id": self.rule_id,
            "action": self.action,
            "non_null_in_scope": self.non_null_in_scope,
            "changed_rows": self.changed_rows,
            "change_ratio": round(self.change_ratio, 6),
            "distinct_before": self.distinct_before,
            "distinct_after": self.distinct_after,
            "distinct_ratio_after": round(self.distinct_ratio_after, 6),
            "length_buckets": self.length_buckets,
        }


@dataclass
class ProfileResult:
    scope_rows: int
    table_rows: int
    sampled: bool
    sample_scale: float
    incomplete: bool
    elapsed_ms: int
    columns: list[ColumnProfile] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "profiler_version": PROFILER_VERSION,
            "scope_rows": self.scope_rows,
            "table_rows": self.table_rows,
            "sampled": self.sampled,
            "sample_scale": round(self.sample_scale, 6),
            "incomplete": self.incomplete,
            "elapsed_ms": self.elapsed_ms,
            "columns": [column.as_dict() for column in self.columns],
        }


def _scope_clause(scope: CompiledScope) -> tuple[str, tuple[object, ...]]:
    if scope.is_unscoped:
        return "", ()
    return f" WHERE {scope.where_sql}", scope.parameters


def _length_bucket_sql(column: str) -> list[tuple[str, str]]:
    expr = f"LENGTH({_quote(column)})"
    checks = [
        (
            f"COALESCE(SUM(CASE WHEN {expr} IS NULL THEN 1 ELSE 0 END), 0)",
            f"{column}__len_null",
        )
    ]
    edges = (0,) + LENGTH_BUCKETS
    for low, high in zip(edges, edges[1:]):
        checks.append(
            (
                f"COALESCE(SUM(CASE WHEN {expr} >= {low} AND {expr} < {high} "
                f"THEN 1 ELSE 0 END), 0)",
                f"{column}__len_{low}_{high}",
            )
        )
    checks.append(
        (
            f"COALESCE(SUM(CASE WHEN {expr} >= {LENGTH_BUCKETS[-1]} THEN 1 ELSE 0 END), 0)",
            f"{column}__len_big",
        )
    )
    return checks


def _render(aggregates: list[tuple[str, str]]) -> str:
    return ", ".join(f'{expression} AS "{alias}"' for expression, alias in aggregates)


def _bound_expressions(
    binder: TransformBinder, resolved: list[ResolvedColumn], salt: str
) -> dict[str, str]:
    return {
        item.column: binder.bind(item.column, item.rule, salt)
        for item in resolved
    }


def count_scope(
    probe: SqliteProbe, table: str, scope: CompiledScope
) -> tuple[int, int, int]:
    """Exact, cheap: scope rows, table rows, current max rowid."""

    clause, params = _scope_clause(scope)
    result = probe.aggregate(
        f"SELECT COUNT(*), (SELECT COUNT(*) FROM {_quote(table)}) "
        f"FROM {_quote(table)}{clause}",
        params,
    )
    row = result.first() or (0, 0)
    return int(row[0]), int(row[1]), probe.max_rowid(table)


def _column_aggregates(
    resolved: list[ResolvedColumn],
    expressions: dict[str, str],
    include_buckets: bool,
) -> list[tuple[str, str]]:
    aggregates: list[tuple[str, str]] = []
    for item in resolved:
        quoted = _quote(item.column)
        masked = expressions[item.column]
        prefix = item.column
        aggregates.extend(
            [
                (
                    f"COALESCE(SUM(CASE WHEN {quoted} IS NOT NULL THEN 1 ELSE 0 END), 0)",
                    f"{prefix}__nn",
                ),
                (
                    f"COALESCE(SUM(CASE WHEN {quoted} IS NOT NULL "
                    f"AND COALESCE({quoted} <> {masked}, 1) THEN 1 ELSE 0 END), 0)",
                    f"{prefix}__ch",
                ),
                (f"COUNT(DISTINCT {quoted})", f"{prefix}__db"),
                (f"COUNT(DISTINCT {masked})", f"{prefix}__da"),
            ]
        )
        if include_buckets:
            aggregates.extend(_length_bucket_sql(item.column))
    return aggregates


def _exact_query(
    probe: SqliteProbe,
    table: str,
    scope: CompiledScope,
    resolved: list[ResolvedColumn],
    expressions: dict[str, str],
) -> ProbeResult:
    clause, params = _scope_clause(scope)
    aggregates = _column_aggregates(resolved, expressions, include_buckets=True)
    return probe.aggregate(
        f"SELECT {_render(aggregates)} FROM {_quote(table)}{clause}", params
    )


def _sampled_query(
    probe: SqliteProbe,
    table: str,
    scope: CompiledScope,
    resolved: list[ResolvedColumn],
    expressions: dict[str, str],
    stride: int,
) -> ProbeResult:
    clause, params = _scope_clause(scope)
    sample_filter = f"rowid % {int(stride)} = 0"
    full_clause = f" WHERE {sample_filter}" + (f" AND {scope.where_sql}" if clause else "")
    aggregates = _column_aggregates(resolved, expressions, include_buckets=False)
    return probe.aggregate(
        f"SELECT {_render(aggregates)} FROM {_quote(table)}{full_clause}", params
    )


def _bucket_labels() -> list[str]:
    return (
        ["null"]
        + [f"{lo}_{hi}" for lo, hi in zip((0,) + LENGTH_BUCKETS, LENGTH_BUCKETS)]
        + ["big"]
    )


def _parse_exact(
    values: tuple[object, ...], resolved: list[ResolvedColumn], scope_rows: int
) -> list[ColumnProfile]:
    profiles: list[ColumnProfile] = []
    cursor = 0
    labels = _bucket_labels()
    for item in resolved:
        non_null, changed, distinct_before, distinct_after = (
            int(values[cursor]),
            int(values[cursor + 1]),
            int(values[cursor + 2]),
            int(values[cursor + 3]),
        )
        cursor += 4
        buckets = {label: int(values[cursor + offset]) for offset, label in enumerate(labels)}
        cursor += len(labels)
        profiles.append(
            ColumnProfile(
                column=item.column,
                rule_id=item.rule_id,
                action=item.action,
                non_null_in_scope=non_null,
                changed_rows=changed,
                change_ratio=(changed / scope_rows) if scope_rows else 0.0,
                distinct_before=distinct_before,
                distinct_after=distinct_after,
                distinct_ratio_after=(distinct_after / distinct_before) if distinct_before else 1.0,
                length_buckets=buckets,
            )
        )
    return profiles


def _parse_sampled(
    values: tuple[object, ...], resolved: list[ResolvedColumn], scale: float
) -> list[ColumnProfile]:
    profiles: list[ColumnProfile] = []
    cursor = 0
    for item in resolved:
        non_null_raw, changed_raw, distinct_before, distinct_after = (
            int(values[cursor]),
            int(values[cursor + 1]),
            int(values[cursor + 2]),
            int(values[cursor + 3]),
        )
        cursor += 4
        non_null = int(round(non_null_raw * scale))
        changed = int(round(changed_raw * scale))
        profiles.append(
            ColumnProfile(
                column=item.column,
                rule_id=item.rule_id,
                action=item.action,
                non_null_in_scope=non_null,
                changed_rows=changed,
                change_ratio=(changed_raw / non_null_raw) if non_null_raw else 0.0,
                distinct_before=distinct_before,
                distinct_after=distinct_after,
                distinct_ratio_after=(distinct_after / distinct_before) if distinct_before else 1.0,
                length_buckets={},
            )
        )
    return profiles


def profile_source(
    probe: SqliteProbe,
    table: str,
    scope: CompiledScope,
    resolved: list[ResolvedColumn],
    salt: str,
    scan_budget_rows: int,
) -> ProfileResult:
    binder = TransformBinder(probe.connection)
    scope_rows, table_rows, max_rowid = count_scope(probe, table, scope)

    if not resolved or scope_rows == 0:
        return ProfileResult(
            scope_rows=scope_rows,
            table_rows=table_rows,
            sampled=False,
            sample_scale=1.0,
            incomplete=False,
            elapsed_ms=0,
            columns=[],
        )

    expressions = _bound_expressions(binder, resolved, salt)
    elapsed = 0

    if scope_rows <= scan_budget_rows:
        try:
            result = _exact_query(probe, table, scope, resolved, expressions)
        except ScanBudgetExceeded:
            # Headline counts are already exact; distribution metrics are absent.
            return ProfileResult(
                scope_rows=scope_rows,
                table_rows=table_rows,
                sampled=False,
                sample_scale=1.0,
                incomplete=True,
                elapsed_ms=elapsed,
                columns=[],
            )
        elapsed += result.elapsed_ms
        columns = _parse_exact((result.first() or ()), resolved, scope_rows)
        return ProfileResult(
            scope_rows=scope_rows,
            table_rows=table_rows,
            sampled=False,
            sample_scale=1.0,
            incomplete=False,
            elapsed_ms=elapsed,
            columns=columns,
        )

    # Wide scope: deterministic rowid-stride sample for distribution metrics.
    stride = max(1, (max_rowid + scan_budget_rows - 1) // max(1, scan_budget_rows))
    scale = float(stride)
    try:
        result = _sampled_query(probe, table, scope, resolved, expressions, stride)
    except ScanBudgetExceeded:
        return ProfileResult(
            scope_rows=scope_rows,
            table_rows=table_rows,
            sampled=True,
            sample_scale=scale,
            incomplete=True,
            elapsed_ms=elapsed,
            columns=[],
        )
    elapsed += result.elapsed_ms
    columns = _parse_sampled((result.first() or ()), resolved, scale)
    return ProfileResult(
        scope_rows=scope_rows,
        table_rows=table_rows,
        sampled=True,
        sample_scale=scale,
        incomplete=False,
        elapsed_ms=elapsed,
        columns=columns,
    )
