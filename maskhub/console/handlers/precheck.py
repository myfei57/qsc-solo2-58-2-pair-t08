"""Precheck endpoints: measure the blast radius before executing."""

from __future__ import annotations

from maskhub.console.http import Request, Response
from maskhub.console.validation import optional_int, optional_text, require_text
from maskhub.precheck import service
from maskhub.precheck.scope import Scope


def run_precheck(runtime, request: Request) -> Response:
    payload = request.json_object()
    report = service.run_precheck(
        runtime,
        policy_id=require_text(payload, "policy"),
        scope=Scope.parse(
            require_text(payload, "dataset"),
            optional_text(payload, "filter"),
        ),
        sample_size=optional_int(
            payload, "sample_size", service.DEFAULT_SAMPLE_SIZE, 1, service.MAX_SAMPLE_SIZE
        ),
        budget_ms=optional_int(
            payload, "budget_ms", service.DEFAULT_BUDGET_MS, 0, service.MAX_BUDGET_MS
        ),
        ttl_seconds=optional_int(
            payload, "ttl_seconds", service.DEFAULT_TTL_SECONDS, 0, service.MAX_TTL_SECONDS
        ),
    )
    return Response.json(200, report.as_dict())


def list_prechecks(runtime, request: Request) -> Response:
    summaries = [
        {
            "identifier": report.identifier,
            "policy": report.policy,
            "scope": dict(report.scope),
            "created_at": report.created_at,
            "expires_at": report.expires_at,
            "affected_rows": report.affected_rows,
            "risk": report.risk.get("level"),
        }
        for report in runtime.reports.all()
    ]
    return Response.json(200, {"count": len(summaries), "prechecks": summaries})


def get_precheck(runtime, request: Request) -> Response:
    identifier = request.query_one("precheck", "") or ""
    return Response.json(200, runtime.reports.get(identifier).as_dict())


def verify_precheck(runtime, request: Request) -> Response:
    payload = request.json_object()
    verdict = service.verify_precheck(
        runtime,
        report_id=require_text(payload, "report"),
        policy_id=require_text(payload, "policy"),
        scope=Scope.parse(
            require_text(payload, "dataset"),
            optional_text(payload, "filter"),
        ),
    )
    return Response.json(200, verdict)
