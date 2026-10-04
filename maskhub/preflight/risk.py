"""Risk evaluation over a completed profile and the lineage graph.

Findings are deterministic, machine-readable records (stable ids) so an
operator can waive a specific blocker and the executor can check the waiver
list precisely. Each finding carries its own remediation advice.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Ordered by severity; the worst finding decides the ticket verdict.
SEVERITIES = ("info", "low", "medium", "high", "block")

BLAST_RADIUS_HIGH = 0.50
BLAST_RADIUS_MEDIUM = 0.10
COLLAPSE_RATIO = 0.50
LOW_CHANGE_RATIO = 0.01


@dataclass
class Finding:
    code: str
    severity: str
    title: str
    detail: str
    recommendation: str
    subjects: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")

    @property
    def finding_id(self) -> str:
        suffix = ".".join(self.subjects) if self.subjects else "all"
        return f"{self.code}:{suffix}"

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.finding_id,
            "code": self.code,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "subjects": list(self.subjects),
        }


@dataclass
class RiskReport:
    verdict: str
    findings: list[Finding] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "verdict": self.verdict,
            "findings": [item.as_dict() for item in self.findings],
            "summary": self.summary,
            "recommendations": self.recommendations,
        }


def _usage_severity(usage: str, action: str) -> str:
    """How badly does transforming a column break this downstream usage?"""

    if usage == "join_key":
        # Hash/tokenize values are deterministic: joins survive only if every
        # joining side adopts the same salt+algorithm; redaction never survives.
        return "block" if action == "redact" else "high"
    if usage == "filter":
        return "high" if action in ("redact", "partial") else "medium"
    if usage == "metric":
        return "medium"
    return "low"


def _usage_advice(usage: str, action: str) -> str:
    if usage == "join_key":
        if action == "redact":
            return (
                "Redaction destroys join keys irreversibly. Drop this column from the "
                "scope, exclude the downstream consumer, or switch to a reversible/hash "
                "rule and migrate all joining sides together."
            )
        return (
            "Coordinate a same-salt, same-algorithm rollout on every joining side and "
            "cut them over in one window; stale joins will silently drop rows."
        )
    if usage == "filter":
        return (
            "Downstream WHERE/segmentation predicates are evaluated on this column. "
            "Notify the owner and migrate filters before the change, or keep a shadow "
            "column for one release."
        )
    if usage == "metric":
        return (
            "Aggregate reports read this column; confirm COUNT DISTINCT / grouping still "
            "meets their semantics and backfill or snapshot the affected dashboards."
        )
    return "Inform the consumer owner; raw-value exports/reports will visibly change."


def evaluate(
    *,
    dataset_id: str,
    scope_rows: int,
    table_rows: int,
    sampled: bool,
    incomplete: bool,
    columns: list[dict[str, object]],
    downstream: list[dict[str, object]],
    uncovered_sensitive: list[str],
    unresolved_rules: list[str],
) -> RiskReport:
    findings: list[Finding] = []

    if unresolved_rules:
        findings.append(
            Finding(
                code="RULE_UNRESOLVED",
                severity="block",
                title="Policy references unknown rules",
                detail=f"Rules not found in registry: {sorted(unresolved_rules)}",
                recommendation="Fix the policy definition before running a preflight.",
                subjects=tuple(sorted(unresolved_rules)),
            )
        )

    if uncovered_sensitive:
        findings.append(
            Finding(
                code="SENSITIVE_UNCOVERED",
                severity="high",
                title="Sensitive columns in scope are not covered by any rule",
                detail=(
                    f"Columns declared sensitive on {dataset_id} but matched by no policy "
                    f"rule: {uncovered_sensitive}"
                ),
                recommendation="Extend the policy rule patterns or explicitly exclude them.",
                subjects=tuple(uncovered_sensitive),
            )
        )

    if scope_rows == 0:
        findings.append(
            Finding(
                code="SCOPE_EMPTY",
                severity="info",
                title="Scope matches zero rows",
                detail="No row satisfies the given filters; nothing will change.",
                recommendation="Check the filter values; nothing will execute.",
            )
        )
    else:
        ratio = scope_rows / table_rows if table_rows else 0.0
        if ratio >= BLAST_RADIUS_HIGH:
            findings.append(
                Finding(
                    code="BLAST_HIGH",
                    severity="high",
                    title="Scope covers at least half of the table",
                    detail=f"{scope_rows} of {table_rows} rows ({ratio:.0%}) are in scope.",
                    recommendation=(
                        "Run during a maintenance window, snapshot the table first, and "
                        "stage the rollout with narrower partitions."
                    ),
                )
            )
        elif ratio >= BLAST_RADIUS_MEDIUM:
            findings.append(
                Finding(
                    code="BLAST_MEDIUM",
                    severity="medium",
                    title="Scope covers a significant share of the table",
                    detail=f"{scope_rows} of {table_rows} rows ({ratio:.0%}) are in scope.",
                    recommendation="Confirm the window and notify downstream owners.",
                )
            )

    changed_columns: set[str] = set()
    for column in columns:
        name = str(column["column"])
        changed_columns.add(name)
        change_ratio = float(column["change_ratio"])
        distinct_ratio = float(column["distinct_ratio_after"])
        non_null = int(column["non_null_in_scope"])

        if non_null and change_ratio < LOW_CHANGE_RATIO:
            findings.append(
                Finding(
                    code="CHANGE_LOW",
                    severity="info",
                    title="Column is effectively already masked in scope",
                    detail=(
                        f"{name}: only {change_ratio:.2%} of non-null values would change."
                    ),
                    recommendation="The rule is nearly a no-op on this scope; verify the pattern matches.",
                    subjects=(name,),
                )
            )
        if distinct_ratio < COLLAPSE_RATIO:
            findings.append(
                Finding(
                    code="CARDINALITY_COLLAPSE",
                    severity="high",
                    title="Masking collapses this column's cardinality",
                    detail=(
                        f"{name}: distinct values fall {int(column['distinct_before'])} -> "
                        f"{int(column['distinct_after'])} ({distinct_ratio:.0%}); groups, "
                        "deduplication and COUNT DISTINCT metrics will change."
                    ),
                    recommendation=(
                        "Prefer a distinct-preserving rule, or coordinate report/metric "
                        "changes with downstream owners."
                    ),
                    subjects=(name,),
                )
            )

    # Lineage: one finding per (severity, consumer) pair that reads a changed column.
    for consumer in downstream:
        consumer_id = str(consumer["consumer"])
        worst = "info"
        usages: list[str] = []
        actions: list[str] = []
        for use in consumer["uses"]:
            column_name = str(use["column"])
            usage = str(use["usage"])
            match = next(
                (item for item in columns if item["column"] == column_name), None
            )
            action = str(match["action"]) if match else "redact"
            severity = _usage_severity(usage, action)
            if SEVERITIES.index(severity) > SEVERITIES.index(worst):
                worst = severity
            usages.append(usage)
            actions.append(action)
        advice_usage = usages[0]
        advice_action = actions[0]
        findings.append(
            Finding(
                code="DOWNSTREAM_BREAK",
                severity=worst,
                title=f"Downstream consumer {consumer_id} reads changed columns",
                detail=(
                    f"{consumer_id} ({consumer['kind']}, owner {consumer['owner']}) uses "
                    f"the changed columns as: "
                    + ", ".join(f"{u['column']}={u['usage']}" for u in consumer["uses"])
                ),
                recommendation=_usage_advice(advice_usage, advice_action),
                subjects=(consumer_id,),
            )
        )

    if incomplete:
        findings.append(
            Finding(
                code="PROFILE_INCOMPLETE",
                severity="medium",
                title="Preflight profile is incomplete",
                detail="Some source statistics could not be collected within the budget.",
                recommendation="Re-run with a larger scan budget or a narrower scope.",
            )
        )
    elif sampled:
        findings.append(
            Finding(
                code="PROFILE_SAMPLED",
                severity="low",
                title="Column statistics are estimated from a sample",
                detail="Headline row counts are exact; distribution metrics carry sampling error.",
                recommendation="Require an exact preflight for sign-off, or accept the estimate.",
            )
        )

    return _build_report(findings)


def _build_report(findings: list[Finding]) -> RiskReport:
    findings.sort(
        key=lambda item: (-SEVERITIES.index(item.severity), item.finding_id)
    )
    summary = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        summary[finding.severity] += 1
    if summary["block"]:
        verdict = "BLOCK"
    elif summary["high"] or summary["medium"]:
        verdict = "WARN"
    else:
        verdict = "GO"
    recommendations: list[str] = []
    for finding in findings:
        if finding.severity in ("block", "high", "medium"):
            recommendations.append(f"[{finding.finding_id}] {finding.recommendation}")
    return RiskReport(
        verdict=verdict,
        findings=findings,
        summary=summary,
        recommendations=recommendations,
    )
