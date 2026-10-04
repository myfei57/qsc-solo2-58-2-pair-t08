"""Read-only adapters over physical data sources.

The probe is the *only* code path in preflight that talks to a source, and it
is deliberately narrow:

* the connection is opened read-only (``mode=ro``), so a buggy statement
  cannot mutate data even if every other guard failed;
* every statement must be a single SELECT/WITH without comments or multiple
  statements;
* a progress callback enforces a wall-clock deadline, aborting long scans;
* only scalar/aggregate rows are expected — callers never SELECT raw
  columns for display, the profiler aggregates inside the engine.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from typing import Any

from maskhub.errors import MaskHubError

PROGRESS_TICKS = 1000  # SQLite invokes the callback roughly every N VM ops


class SourceUnavailable(MaskHubError):
    """The source cannot be reached or rejects the read."""


class ScanBudgetExceeded(MaskHubError):
    """The deadline fired while scanning the source."""


class UnsafeProbeQuery(MaskHubError):
    """A query failed the single-statement read-only shape check."""


_FORBIDDEN_SQL_FRAGMENTS = (";", "--", "/*", "*/", "\x00")
_READ_PREFIXES = ("SELECT", "WITH")


def guard_aggregate_sql(sql: str) -> str:
    text = sql.strip()
    upper = text.upper()
    if not any(upper.startswith(prefix) for prefix in _READ_PREFIXES):
        raise UnsafeProbeQuery("probe only accepts SELECT/WITH queries")
    for fragment in _FORBIDDEN_SQL_FRAGMENTS:
        if fragment in text:
            raise UnsafeProbeQuery(f"probe query contains forbidden fragment {fragment!r}")
    if text.count("'") % 2:
        raise UnsafeProbeQuery("probe query contains an unbalanced quote")
    return text


@dataclass
class ProbeResult:
    rows: list[tuple[Any, ...]]
    elapsed_ms: int
    sampled: bool

    def first(self) -> tuple[Any, ...] | None:
        return self.rows[0] if self.rows else None


class SqliteProbe:
    """Aggregate-only, read-only view of one SQLite database file."""

    kind = "sqlite"

    def __init__(self, endpoint: str, deadline_ms: int) -> None:
        self._endpoint = endpoint
        self._deadline_ms = max(0, deadline_ms)
        try:
            self._connection = sqlite3.connect(
                f"file:{endpoint}?mode=ro", uri=True, timeout=2.0
            )
        except sqlite3.OperationalError as exc:
            raise SourceUnavailable(f"cannot open sqlite source {endpoint!r}: {exc}") from exc
        self._connection.row_factory = None

    @property
    def connection(self) -> sqlite3.Connection:
        return self._connection

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "SqliteProbe":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _install_deadline(self) -> int:
        start = time.monotonic()
        if self._deadline_ms == 0:
            return start

        def _on_progress() -> int:
            elapsed = (time.monotonic() - start) * 1000
            return 1 if elapsed > self._deadline_ms else 0

        self._connection.set_progress_handler(_on_progress, PROGRESS_TICKS)
        return start

    def aggregate(self, sql: str, parameters: tuple[object, ...] = ()) -> ProbeResult:
        statement = guard_aggregate_sql(sql)
        start = time.monotonic()
        self._install_deadline()
        try:
            cursor = self._connection.execute(statement, parameters)
            rows = cursor.fetchall()
        except sqlite3.OperationalError as exc:
            message = str(exc).lower()
            if "interrupted" in message:
                raise ScanBudgetExceeded(f"probe deadline of {self._deadline_ms}ms exceeded") from exc
            raise SourceUnavailable(f"source rejected query: {exc}") from exc
        finally:
            self._connection.set_progress_handler(None, PROGRESS_TICKS)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return ProbeResult(rows=rows, elapsed_ms=elapsed_ms, sampled=False)

    def max_rowid(self, table: str) -> int:
        safe_table = guard_aggregate_sql(f'SELECT MAX(rowid) FROM "{table}"')
        result = self.aggregate(safe_table)
        value = result.first()
        return int(value[0]) if value and value[0] is not None else 0


def open_probe(kind: str, endpoint: str, deadline_ms: int) -> SqliteProbe:
    if kind == SqliteProbe.kind:
        return SqliteProbe(endpoint, deadline_ms)
    raise SourceUnavailable(f"unsupported source kind {kind!r}")
