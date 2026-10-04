"""Precheck orchestration: measure the blast radius without touching data.

Running a precheck only reads from the source (through a read-only,
time-boxed probe) and only ever writes its own report — aggregates and
fingerprints, never raw values.  ``verify_precheck`` is the execution
gate: it recomputes the binding from the parameters the execution is
about to use and tells the caller whether the precheck still applies.
"""

from __future__ import annotations

from datetime import timedelta

from maskhub.errors import Conflict, InvalidRequest, NotFound
from maskhub.precheck.impact import (
    affected_columns,
    impacted_consumers,
    uncovered_sensitive_fields,
)
from maskhub.precheck.probe import Deadline, ScanTruncated
from maskhub.precheck.profile import ColumnProfiler, is_null
from maskhub.precheck.report import PrecheckReport, ScopeBinding, digest, utcnow
from maskhub.precheck.risk import assess_risk
from maskhub.precheck.scope import Scope
from maskhub.source.registry import SourceStatus

DEFAULT_SAMPLE_SIZE = 10_000
MAX_SAMPLE_SIZE = 100_000
DEFAULT_BUDGET_MS = 2_000
MAX_BUDGET_MS = 30_000
DEFAULT_TTL_SECONDS = 3_600
MAX_TTL_SECONDS = 86_400


def compute_binding(runtime, policy_id: str, scope: Scope) -> ScopeBinding:
    """Fingerprint the exact state an execution would depend on."""

    policy = runtime.policies.get(policy_id)
    dataset = runtime.datasets.get(scope.dataset)
    rules = [runtime.rules.get(rule_id).as_dict() for rule_id in sorted(policy.rules)]
    return ScopeBinding(
        policy=digest(policy.as_dict()),
        rules=digest(rules),
        dataset=digest(dataset.as_dict()),
        scope=digest(scope.canonical()),
    )


def run_precheck(
    runtime,
    *,
    policy_id: str,
    scope: Scope,
    sample_size: int = DEFAULT_SAMPLE_SIZE,
    budget_ms: int = DEFAULT_BUDGET_MS,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> PrecheckReport:
    policy = runtime.policies.get(policy_id)
    if not policy.covers(scope.dataset):
        raise NotFound(f"policy {policy_id} does not target dataset {scope.dataset}")
    dataset = runtime.datasets.get(scope.dataset)
    if scope.has_filter and dataset.field(scope.filter_field) is None:
        raise InvalidRequest(f"unknown filter field {scope.filter_field!r}")
    source = runtime.sources.get(dataset.source)
    if source.status != SourceStatus.ACTIVE.value:
        raise Conflict(
            f"source {source.identifier} is {source.status}; prechecks need an active source"
        )
    probe = runtime.probes.for_kind(source.kind)
    if probe is None:
        raise Conflict(f"no read-only probe registered for source kind {source.kind!r}")

    binding = compute_binding(runtime, policy_id, scope)
    columns = affected_columns(policy, dataset, runtime.rules)
    profilers = {column.name: ColumnProfiler(column.name) for column in columns}

    deadline = Deadline(budget_ms)
    rows_seen = 0
    affected = 0
    completed = True
    try:
        for row in probe.scan(source, dataset, scope, deadline):
            rows_seen += 1
            if rows_seen <= sample_size:
                row_hit = False
                for name, profiler in profilers.items():
                    value = row.get(name)
                    profiler.feed(value)
                    if not is_null(value):
                        row_hit = True
                if row_hit:
                    affected += 1
            # Beyond the sample we only count rows, never inspect values.
    except ScanTruncated:
        completed = False
    except OSError as exc:
        raise Conflict(f"source {source.identifier} is not readable: {exc}") from exc

    rows_profiled = min(rows_seen, sample_size)
    estimated = not completed or rows_seen > sample_size
    if estimated and rows_profiled:
        affected_rows = round(affected * rows_seen / rows_profiled)
    else:
        affected_rows = affected

    column_dicts = [
        profilers[column.name].as_dict(column.sensitivity, column.actions, column.rules)
        for column in columns
    ]
    consumers = impacted_consumers(runtime.consumers.for_dataset(scope.dataset), columns)
    uncovered = uncovered_sensitive_fields(dataset, columns)
    risk = assess_risk(
        affected_rows=affected_rows,
        estimated=estimated,
        columns=column_dicts,
        consumers=consumers,
        uncovered=uncovered,
    )

    created = utcnow()
    identifier = (
        f"{policy_id}-{scope.dataset}-{created:%Y%m%dT%H%M%SZ}-{binding.fingerprint[:8]}"
    )
    report = PrecheckReport(
        identifier=identifier,
        policy=policy_id,
        created_at=created.isoformat(),
        expires_at=(created + timedelta(seconds=ttl_seconds)).isoformat(),
        binding=binding,
        scope=scope.canonical(),
        scan={
            "sample_size": sample_size,
            "budget_ms": budget_ms,
            "rows_seen": rows_seen,
            "rows_profiled": rows_profiled,
            "completed": completed,
            "estimated": estimated,
        },
        affected_rows=affected_rows,
        affected_rows_estimated=estimated,
        columns=tuple(column_dicts),
        consumers=tuple(consumer.as_dict() for consumer in consumers),
        risk=risk.as_dict(),
    )
    runtime.reports.save(report)
    runtime.journal.append(
        "precheck.run",
        report.identifier,
        f"policy={policy_id} dataset={scope.dataset} affected={affected_rows} risk={risk.level}",
    )
    return report


def verify_precheck(
    runtime, *, report_id: str, policy_id: str, scope: Scope
) -> dict[str, object]:
    """Execution gate: does this report still cover these exact parameters?"""

    report = runtime.reports.get(report_id)
    current = compute_binding(runtime, policy_id, scope)
    drifted = report.binding.drifted(current)
    expired = report.expired(utcnow())
    verdict = "stale" if drifted else ("expired" if expired else "fresh")
    return {
        "report": report.identifier,
        "policy": policy_id,
        "scope": scope.canonical(),
        "verdict": verdict,
        "drifted": list(drifted),
        "expired": expired,
        "fingerprint": report.fingerprint,
        "current_fingerprint": current.fingerprint,
        "expires_at": report.expires_at,
        "checked_at": utcnow().isoformat(),
    }
