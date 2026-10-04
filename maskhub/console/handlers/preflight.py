"""Preflight and guarded-execution endpoints."""

from __future__ import annotations

from maskhub.console.http import Request, Response
from maskhub.console.validation import require_text
from maskhub.errors import InvalidRequest
from maskhub.preflight.engine import (
    DEFAULT_DEADLINE_MS,
    DEFAULT_SCAN_BUDGET_ROWS,
    PreflightRequest,
    prepare_plan,
    run_preflight,
)
from maskhub.preflight.executor import execute_sqlite
from maskhub.preflight.guard import GuardDecision, assert_guard_allows, guard_execution
from maskhub.preflight.ticket import DEFAULT_TTL_SECONDS
from maskhub.preflight.probe import SourceUnavailable


def _scope_payload(payload: dict[str, object]) -> dict[str, object]:
    scope = payload.get("scope", {})
    if scope in (None, {}):
        return {}
    if not isinstance(scope, dict):
        raise InvalidRequest("scope must be an object")
    return scope


def run(runtime, request: Request) -> Response:
    payload = request.json_object()
    preflight_request = PreflightRequest(
        policy_id=require_text(payload, "policy"),
        dataset_id=require_text(payload, "dataset"),
        scope=_scope_payload(payload),
        salt=str(payload.get("salt", "") or ""),
        scan_budget_rows=int(payload.get("scan_budget_rows", DEFAULT_SCAN_BUDGET_ROWS)),
        deadline_ms=int(payload.get("deadline_ms", DEFAULT_DEADLINE_MS)),
        ttl_seconds=int(payload.get("ttl_seconds", DEFAULT_TTL_SECONDS)),
    )
    ticket = run_preflight(
        preflight_request,
        policies=runtime.policies,
        datasets=runtime.datasets,
        rules=runtime.rules,
        consumers=runtime.consumers,
        sources=runtime.sources,
        tickets=runtime.tickets,
        journal=runtime.journal,
    )
    return Response.json(200, ticket.as_dict())


def get_ticket(runtime, request: Request) -> Response:
    identifier = request.query_one("ticket", "") or ""
    ticket = runtime.tickets.get(identifier)
    return Response.json(200, ticket.as_dict())


def list_tickets(runtime, request: Request) -> Response:
    tickets = [runtime.tickets.get(key).as_dict() for key in runtime.tickets.identifiers()]
    tickets.sort(key=lambda item: str(item["created_at"]), reverse=True)
    return Response.json(200, {"count": len(tickets), "tickets": tickets})


def execute(runtime, request: Request) -> Response:
    payload = request.json_object()
    ticket_id = require_text(payload, "ticket")
    ticket = runtime.tickets.get(ticket_id)

    raw_scope = payload.get("scope", ticket.scope)
    # The salt is a secret and is never stored in the ticket; the caller must
    # re-present exactly the value used at preflight time when transforms need one.
    salt_value = payload.get("salt", "")
    if not isinstance(salt_value, str):
        raise InvalidRequest("salt must be a string")
    salt = salt_value
    budget = int(payload.get("scan_budget_rows", ticket.params.get("scan_budget_rows", DEFAULT_SCAN_BUDGET_ROWS)))
    deadline = int(payload.get("deadline_ms", ticket.params.get("deadline_ms", DEFAULT_DEADLINE_MS)))
    raw_waivers = payload.get("waivers", [])
    if not isinstance(raw_waivers, list) or not all(isinstance(item, str) for item in raw_waivers):
        raise InvalidRequest("waivers must be a list of finding ids")

    plan = prepare_plan(
        policy_id=ticket.policy,
        dataset_id=ticket.dataset,
        raw_scope=raw_scope if isinstance(raw_scope, dict) else {},
        salt=salt,
        scan_budget_rows=budget,
        deadline_ms=deadline,
        policies=runtime.policies,
        datasets=runtime.datasets,
        rules=runtime.rules,
    )

    decision: GuardDecision = guard_execution(
        ticket=ticket,
        plan=plan,
        policies=runtime.policies,
        datasets=runtime.datasets,
        rules=runtime.rules,
        consumers=runtime.consumers,
        sources=runtime.sources,
        waivers=list(raw_waivers),
    )
    assert_guard_allows(decision)

    dataset = runtime.datasets.get(ticket.dataset)
    source = runtime.sources.get(dataset.source)
    if source.kind != "sqlite":
        raise SourceUnavailable(f"execution for source kind {source.kind!r} is not deployed")
    result = execute_sqlite(ticket, plan, source.endpoint, runtime.journal)
    return Response.json(200, result.as_dict())
