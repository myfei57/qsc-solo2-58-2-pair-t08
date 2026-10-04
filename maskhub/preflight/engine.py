"""Preflight orchestration.

Given a policy, a dataset and an execution scope, ``run_preflight`` resolves
the effective masking plan, opens a strictly read-only probe, profiles the
real data, walks the lineage graph, evaluates risk and persists a ticket.
Nothing here can mutate source data: the probe opens ``mode=ro`` and only
emits aggregate queries.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from maskhub.audit.journal import Journal
from maskhub.catalog.dataset import Dataset, DatasetRegistry
from maskhub.errors import InvalidRequest
from maskhub.lineage.registry import ConsumerRegistry
from maskhub.policy.registry import PolicyRegistry
from maskhub.preflight.fingerprint import Fingerprint, build_fingerprint
from maskhub.preflight.probe import SqliteProbe, open_probe
from maskhub.preflight.profiler import profile_source
from maskhub.preflight.risk import RiskReport, evaluate
from maskhub.preflight.scope import CompiledScope, compile_scope
from maskhub.preflight.ticket import (
    DEFAULT_TTL_SECONDS,
    PreflightTicket,
    TicketRegistry,
    issue_timestamp,
)
from maskhub.preflight.transform import ResolvedColumn, rule_needs_salt
from maskhub.rule.registry import RuleRegistry

DEFAULT_SCAN_BUDGET_ROWS = 50_000
DEFAULT_DEADLINE_MS = 3_000
MAX_DEADLINE_MS = 30_000


@dataclass(frozen=True)
class PreflightRequest:
    policy_id: str
    dataset_id: str
    scope: dict[str, object] = field(default_factory=dict)
    salt: str = ""
    scan_budget_rows: int = DEFAULT_SCAN_BUDGET_ROWS
    deadline_ms: int = DEFAULT_DEADLINE_MS
    ttl_seconds: int = DEFAULT_TTL_SECONDS


@dataclass(frozen=True)
class PreparedPlan:
    """Everything the profiler and the executor must agree on."""

    policy_id: str
    dataset: Dataset
    scope: CompiledScope
    resolved: tuple[ResolvedColumn, ...]
    uncovered_sensitive: tuple[str, ...]
    unresolved_rules: tuple[str, ...]
    salt: str
    scan_budget_rows: int
    deadline_ms: int


def _parse_options(payload: dict[str, object]) -> tuple[int, int, int, str]:
    budget = payload.get("scan_budget_rows", DEFAULT_SCAN_BUDGET_ROWS)
    deadline = payload.get("deadline_ms", DEFAULT_DEADLINE_MS)
    ttl = payload.get("ttl_seconds", DEFAULT_TTL_SECONDS)
    salt = payload.get("salt", "")
    if not isinstance(budget, int) or isinstance(budget, bool) or budget <= 0:
        raise InvalidRequest("scan_budget_rows must be a positive integer")
    if not isinstance(deadline, int) or isinstance(deadline, bool) or not 0 < deadline <= MAX_DEADLINE_MS:
        raise InvalidRequest(f"deadline_ms must be between 1 and {MAX_DEADLINE_MS}")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0:
        raise InvalidRequest("ttl_seconds must be a positive integer")
    if not isinstance(salt, str):
        raise InvalidRequest("salt must be a string")
    return budget, deadline, ttl, salt


def _resolve_columns(
    dataset: Dataset,
    rules_registry: RuleRegistry,
    rule_ids: list[str],
    binder: TransformBinder,
    salt: str,
) -> tuple[list[ResolvedColumn], list[str], list[str]]:
    unresolved: list[str] = []
    loaded = []
    for rule_id in rule_ids:
        rule = rules_registry.find(rule_id)
        if rule is None:
            unresolved.append(rule_id)
        else:
            loaded.append(rule)

    resolved: list[ResolvedColumn] = []
    for field_meta in dataset.masked_fields():
        match = next((rule for rule in loaded if rule.matches(field_meta.name)), None)
        if match is None:
            continue
        if rule_needs_salt(match) and not salt:
            raise InvalidRequest(
                f"rule {match.identifier} requires a salt for {match.action}; "
                "pass a non-empty 'salt' in the request"
            )
        expression = binder.bind(field_meta.name, match, salt)
        resolved.append(
            ResolvedColumn(
                column=field_meta.name,
                rule=match,
                action=match.action,
                expression_sql=expression,
            )
        )
    covered = {item.column for item in resolved}
    uncovered = [
        item.name for item in dataset.masked_fields() if item.name not in covered
    ]
    return resolved, uncovered, sorted(set(unresolved))


def prepare_plan(
    *,
    policy_id: str,
    dataset_id: str,
    raw_scope: dict[str, object],
    salt: str,
    scan_budget_rows: int,
    deadline_ms: int,
    policies: PolicyRegistry,
    datasets: DatasetRegistry,
    rules: RuleRegistry,
    binder: TransformBinder | None = None,
) -> PreparedPlan:
    policy = policies.get(policy_id)
    if not policy.covers(dataset_id):
        raise InvalidRequest(f"policy {policy_id} does not target dataset {dataset_id}")
    dataset = datasets.get(dataset_id)
    scope = compile_scope(raw_scope or {}, dataset)

    class _NullBinder:
        def bind(self, column: str, rule, salt: str) -> str:  # noqa: ANN001
            return f"<{rule.action}:{column}>"

    active_binder = binder or _NullBinder()
    resolved, uncovered, unresolved = _resolve_columns(
        dataset, rules, list(policy.rules), active_binder, salt
    )
    return PreparedPlan(
        policy_id=policy_id,
        dataset=dataset,
        scope=scope,
        resolved=tuple(resolved),
        uncovered_sensitive=tuple(uncovered),
        unresolved_rules=tuple(unresolved),
        salt=salt,
        scan_budget_rows=scan_budget_rows,
        deadline_ms=deadline_ms,
    )


def _watermark(probe: SqliteProbe, table: str, column: str) -> str:
    if not column:
        return ""
    quoted = '"' + column.replace('"', '""') + '"'
    result = probe.aggregate(f"SELECT MAX({quoted}) FROM \"{table}\"")
    row = result.first()
    return "" if row is None or row[0] is None else str(row[0])


def run_preflight(
    request: PreflightRequest,
    *,
    policies: PolicyRegistry,
    datasets: DatasetRegistry,
    rules: RuleRegistry,
    consumers: ConsumerRegistry,
    sources,
    tickets: TicketRegistry,
    journal: Journal,
) -> PreflightTicket:
    budget, deadline, ttl, salt = _parse_options(
        {
            "scan_budget_rows": request.scan_budget_rows,
            "deadline_ms": request.deadline_ms,
            "ttl_seconds": request.ttl_seconds,
            "salt": request.salt,
        }
    )

    # Source/dataset wiring is validated before any source connection opens.
    dataset = datasets.get(request.dataset_id)
    source = sources.get(dataset.source)
    table = dataset.identifier

    with open_probe(source.kind, source.endpoint, deadline) as probe:
        plan = prepare_plan(
            policy_id=request.policy_id,
            dataset_id=request.dataset_id,
            raw_scope=request.scope,
            salt=salt,
            scan_budget_rows=budget,
            deadline_ms=deadline,
            policies=policies,
            datasets=datasets,
            rules=rules,
        )
        watermark = _watermark(probe, table, dataset.watermark_column)
        profile = profile_source(
            probe=probe,
            table=table,
            scope=plan.scope,
            resolved=list(plan.resolved),
            salt=salt,
            scan_budget_rows=budget,
        )
    incomplete = profile.incomplete

    changed_columns = {item.column for item in profile.columns}
    downstream = consumers.downstream_of(dataset.identifier, changed_columns)

    report: RiskReport = evaluate(
        dataset_id=dataset.identifier,
        scope_rows=profile.scope_rows,
        table_rows=profile.table_rows,
        sampled=profile.sampled,
        incomplete=incomplete,
        columns=[item.as_dict() for item in profile.columns],
        downstream=downstream,
        uncovered_sensitive=list(plan.uncovered_sensitive),
        unresolved_rules=list(plan.unresolved_rules),
    )

    policy = policies.get(request.policy_id)
    fingerprint = build_fingerprint(
        policy=policy,
        rules=[item.rule for item in plan.resolved],
        dataset=dataset,
        scope=plan.scope,
        consumers=consumers.all(),
        scan_budget_rows=budget,
        deadline_ms=deadline,
        salt=salt,
    )

    created_at, expires_at = issue_timestamp(ttl)
    ticket_id = _ticket_id(fingerprint, request.dataset_id)
    ticket = PreflightTicket(
        ticket_id=ticket_id,
        policy=request.policy_id,
        dataset=request.dataset_id,
        created_at=created_at,
        expires_at=expires_at,
        fingerprint=fingerprint.as_dict(),
        watermark=watermark,
        profile=profile.as_dict(),
        columns=tuple(sorted(changed_columns)),
        downstream=tuple(downstream),
        risk=report.as_dict(),
        scope=plan.scope.canonical,
        params={
            "scan_budget_rows": budget,
            "deadline_ms": deadline,
            "salt_fingerprint": fingerprint.sections["salt"],
        },
    )
    tickets.save(ticket)
    journal.append(
        "preflight.run",
        ticket_id,
        f"policy={request.policy_id} dataset={request.dataset_id} verdict={report.verdict} "
        f"scope_rows={profile.scope_rows} columns={len(changed_columns)} "
        f"downstream={len(downstream)} sampled={profile.sampled}",
    )
    return ticket


def _ticket_id(fingerprint: Fingerprint, dataset_id: str) -> str:
    raw = fingerprint.digest + ":" + dataset_id
    return "pf_" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
