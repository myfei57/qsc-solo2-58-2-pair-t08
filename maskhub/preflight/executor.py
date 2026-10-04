"""Real masking executor.

Opens a read-write connection, binds the *same* transform UDFs the profiler
used, and applies one UPDATE inside a transaction. Before committing it
verifies the database-reported changed-row count against the ticket's exact
preflight count: any mismatch aborts the transaction and the run, which is
the last line of the "preflight equals execution" guarantee.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from maskhub.audit.journal import Journal
from maskhub.errors import InvalidRequest, MaskHubError
from maskhub.preflight.engine import PreparedPlan
from maskhub.preflight.probe import SourceUnavailable
from maskhub.preflight.ticket import PreflightTicket
from maskhub.preflight.transform import TransformBinder


class ExecutionMismatch(MaskHubError):
    """Reported changed rows differ from the preflight scope count."""


@dataclass(frozen=True)
class ExecutionResult:
    ticket_id: str
    updated_rows: int
    expected_rows: int
    columns: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "ticket_id": self.ticket_id,
            "updated_rows": self.updated_rows,
            "expected_rows": self.expected_rows,
            "columns": list(self.columns),
        }


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def execute_sqlite(
    ticket: PreflightTicket,
    plan: PreparedPlan,
    endpoint: str,
    journal: Journal,
) -> ExecutionResult:
    if ticket.profile.get("sampled"):
        # A sampled profile cannot certify an exact row count.
        raise InvalidRequest(
            "ticket was issued from a sampled profile; require an exact preflight before execution"
        )
    expected_rows = int(ticket.profile.get("scope_rows", -1))
    if expected_rows < 0:
        raise InvalidRequest("ticket is missing scope_rows")

    try:
        connection = sqlite3.connect(f"file:{endpoint}?mode=rwc", uri=True)
    except sqlite3.OperationalError as exc:
        raise SourceUnavailable(f"cannot open sqlite source {endpoint!r}: {exc}") from exc

    try:
        connection.execute("BEGIN IMMEDIATE")
        binder = TransformBinder(connection)
        assignments: list[str] = []
        for item in plan.resolved:
            expression = binder.bind(item.column, item.rule, plan.salt)
            assignments.append(f"{_quote(item.column)} = {expression}")
        sql = f'UPDATE {_quote(plan.dataset.identifier)} SET {", ".join(assignments)}'
        parameters: tuple[object, ...] = ()
        if not plan.scope.is_unscoped:
            sql += f" WHERE {plan.scope.where_sql}"
            parameters = plan.scope.parameters
        cursor = connection.execute(sql, parameters)
        updated_rows = cursor.rowcount
        if updated_rows != expected_rows:
            connection.rollback()
            raise ExecutionMismatch(
                f"preflight expected {expected_rows} in-scope rows but UPDATE matched "
                f"{updated_rows}; rolled back"
            )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

    result = ExecutionResult(
        ticket_id=ticket.ticket_id,
        updated_rows=updated_rows,
        expected_rows=expected_rows,
        columns=tuple(item.column for item in plan.resolved),
    )
    journal.append(
        "policy.execute",
        ticket.ticket_id,
        f"policy={ticket.policy} dataset={ticket.dataset} updated_rows={updated_rows}",
    )
    return result
