"""Execution guard: a live request must match its preflight ticket exactly.

The guard recomputes the fingerprint from the *current* registries and
request parameters rather than trusting anything in the ticket body, so an
operator cannot widen a scope, swap a salt or reuse a stale ticket after the
lineage graph changed.
"""

from __future__ import annotations

from dataclasses import dataclass

from maskhub.errors import Conflict, InvalidRequest
from maskhub.lineage.registry import ConsumerRegistry
from maskhub.catalog.dataset import DatasetRegistry
from maskhub.policy.registry import PolicyRegistry
from maskhub.preflight.engine import PreparedPlan
from maskhub.preflight.fingerprint import build_fingerprint
from maskhub.preflight.probe import open_probe
from maskhub.preflight.ticket import PreflightTicket
from maskhub.rule.registry import RuleRegistry


@dataclass(frozen=True)
class GuardDecision:
    allowed: bool
    reason: str
    drift: tuple[str, ...]


def _blocking_findings(ticket: PreflightTicket) -> list[dict[str, object]]:
    risk = ticket.risk if isinstance(ticket.risk, dict) else {}
    findings = risk.get("findings", [])
    return [
        item
        for item in findings
        if isinstance(item, dict) and item.get("severity") == "block"
    ]


def current_watermark(dataset, sources) -> str:
    if not dataset.watermark_column:
        return ""
    source = sources.get(dataset.source)
    with open_probe(source.kind, source.endpoint, 2_000) as probe:
        from maskhub.preflight.engine import _watermark

        return _watermark(probe, dataset.identifier, dataset.watermark_column)


def guard_execution(
    *,
    ticket: PreflightTicket,
    plan: PreparedPlan,
    policies: PolicyRegistry,
    datasets: DatasetRegistry,
    rules: RuleRegistry,
    consumers: ConsumerRegistry,
    sources,
    waivers: list[str],
) -> GuardDecision:
    if ticket.is_expired:
        return GuardDecision(False, f"ticket {ticket.ticket_id} has expired", ("expiry",))

    policy = policies.get(ticket.policy)
    dataset = datasets.get(ticket.dataset)
    live_fingerprint = build_fingerprint(
        policy=policy,
        rules=[item.rule for item in plan.resolved],
        dataset=dataset,
        scope=plan.scope,
        consumers=consumers.all(),
        scan_budget_rows=plan.scan_budget_rows,
        deadline_ms=plan.deadline_ms,
        salt=plan.salt,
    )

    drift: list[str] = []
    expected_sections = ticket.fingerprint.get("sections", {})
    for name, digest in live_fingerprint.sections.items():
        if expected_sections.get(name) != digest:
            drift.append(name)
    if drift:
        return GuardDecision(
            False,
            "execution inputs changed since preflight, re-run preflight: " + ", ".join(sorted(drift)),
            tuple(sorted(drift)),
        )

    live_watermark = current_watermark(dataset, sources)
    if live_watermark != ticket.watermark:
        return GuardDecision(
            False,
            f"source data changed (watermark {ticket.watermark!r} -> {live_watermark!r}); "
            "re-run preflight",
            ("watermark",),
        )

    blockers = _blocking_findings(ticket)
    if blockers:
        blocker_ids = {str(item.get("id")) for item in blockers}
        waived = set(waivers)
        missing = sorted(blocker_ids - waived)
        unknown = sorted(waived - blocker_ids)
        if unknown:
            raise InvalidRequest(f"waivers do not match blocking findings: {unknown}")
        if missing:
            return GuardDecision(
                False,
                "blocking findings require explicit waivers: " + ", ".join(missing),
                ("waivers",),
            )
    return GuardDecision(True, "ticket matches live inputs", ())


def assert_guard_allows(decision: GuardDecision) -> None:
    if not decision.allowed:
        raise Conflict(decision.reason)
