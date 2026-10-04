"""Deterministic risk verdict and remediation suggestions for a precheck."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from maskhub.precheck.impact import ImpactedConsumer

ROWS_MEDIUM = 100_000
ROWS_HIGH = 1_000_000

IRREVERSIBLE_ACTIONS = frozenset({"redact"})
JOIN_SAFE_ACTIONS = frozenset({"hash", "tokenize"})

_LEVEL_RANK = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class Finding:
    code: str
    level: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class Suggestion:
    code: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class RiskAssessment:
    level: str
    findings: tuple[Finding, ...]
    suggestions: tuple[Suggestion, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "level": self.level,
            "findings": [finding.as_dict() for finding in self.findings],
            "suggestions": [suggestion.as_dict() for suggestion in self.suggestions],
        }


def assess_risk(
    *,
    affected_rows: int,
    estimated: bool,
    columns: list[dict[str, object]],
    consumers: tuple[ImpactedConsumer, ...],
    uncovered: tuple[str, ...],
) -> RiskAssessment:
    findings: list[Finding] = []
    suggestions: list[Suggestion] = []

    if estimated:
        findings.append(
            Finding(
                "sampled_scan",
                "low",
                "row counts are extrapolated from a partial scan",
            )
        )
        suggestions.append(
            Suggestion(
                "rescan_wider",
                "raise sample_size or budget_ms, or narrow the filter, then re-run the precheck",
            )
        )

    if affected_rows >= ROWS_HIGH:
        findings.append(
            Finding("large_blast_radius", "high", f"about {affected_rows} rows will be rewritten")
        )
    elif affected_rows >= ROWS_MEDIUM:
        findings.append(
            Finding("large_blast_radius", "medium", f"about {affected_rows} rows will be rewritten")
        )
    if affected_rows >= ROWS_MEDIUM:
        suggestions.append(
            Suggestion("batch_execution", "execute in batches with a rollback point per batch")
        )

    irreversible = [
        str(column["name"])
        for column in columns
        if IRREVERSIBLE_ACTIONS & set(column["actions"])  # type: ignore[arg-type]
    ]
    if irreversible and consumers:
        findings.append(
            Finding(
                "irreversible_with_consumers",
                "high",
                f"irreversible actions on {irreversible} read by {len(consumers)} consumer(s)",
            )
        )
    elif irreversible:
        findings.append(
            Finding(
                "irreversible_action",
                "medium",
                f"irreversible actions on {irreversible} cannot be undone",
            )
        )
    if irreversible:
        suggestions.append(
            Suggestion(
                "consider_join_safe_action",
                "hash or tokenize keeps values joinable for downstreams; redact does not",
            )
        )

    special = [str(column["name"]) for column in columns if column["sensitivity"] == "special"]
    if special:
        level = "high" if set(special) & set(irreversible) else "medium"
        findings.append(
            Finding("special_sensitivity", level, f"special-category fields affected: {special}")
        )

    if consumers:
        findings.append(
            Finding(
                "downstream_impact",
                "medium",
                f"{len(consumers)} downstream consumer(s) read the affected columns",
            )
        )
        suggestions.append(
            Suggestion(
                "regression_check",
                "notify the impacted consumers and schedule a regression check before execution",
            )
        )
    else:
        findings.append(
            Finding("no_downstream", "low", "no registered consumer reads the affected columns")
        )

    if uncovered:
        findings.append(
            Finding(
                "coverage_gap",
                "medium",
                f"sensitive fields with no matching rule: {list(uncovered)}",
            )
        )
        suggestions.append(
            Suggestion(
                "extend_rules",
                "add rules for the uncovered fields or record an explicit exemption",
            )
        )

    level = "low"
    for finding in findings:
        if _LEVEL_RANK[finding.level] > _LEVEL_RANK[level]:
            level = finding.level
    return RiskAssessment(
        level=level,
        findings=tuple(findings),
        suggestions=tuple(suggestions),
    )
