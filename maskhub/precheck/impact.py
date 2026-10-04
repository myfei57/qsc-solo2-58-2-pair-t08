"""Blast-radius computation: which columns, and which downstream consumers."""

from __future__ import annotations

from dataclasses import dataclass

from maskhub.catalog.consumer import Consumer
from maskhub.catalog.dataset import Dataset
from maskhub.policy.policy import Policy
from maskhub.rule.registry import RuleRegistry


@dataclass(frozen=True)
class AffectedColumn:
    name: str
    sensitivity: str
    actions: tuple[str, ...]
    rules: tuple[str, ...]


def affected_columns(
    policy: Policy, dataset: Dataset, rules: RuleRegistry
) -> tuple[AffectedColumn, ...]:
    """Columns the policy would rewrite, with the actions each would get."""

    columns: list[AffectedColumn] = []
    for item in dataset.fields:
        hits: list[str] = []
        actions: list[str] = []
        for rule_id in policy.rules:
            rule = rules.get(rule_id)
            if rule.matches(item.name):
                hits.append(rule.identifier)
                if rule.action not in actions:
                    actions.append(rule.action)
        if hits:
            columns.append(
                AffectedColumn(
                    name=item.name,
                    sensitivity=item.sensitivity,
                    actions=tuple(actions),
                    rules=tuple(hits),
                )
            )
    return tuple(columns)


def uncovered_sensitive_fields(
    dataset: Dataset, columns: tuple[AffectedColumn, ...]
) -> tuple[str, ...]:
    covered = {column.name for column in columns}
    return tuple(item.name for item in dataset.masked_fields() if item.name not in covered)


@dataclass(frozen=True)
class ImpactedConsumer:
    identifier: str
    kind: str
    owner: str
    exposed_fields: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "identifier": self.identifier,
            "kind": self.kind,
            "owner": self.owner,
            "exposed_fields": list(self.exposed_fields),
        }


def impacted_consumers(
    consumers: list[Consumer], columns: tuple[AffectedColumn, ...]
) -> tuple[ImpactedConsumer, ...]:
    """Consumers whose read set intersects the columns being rewritten."""

    affected = {column.name for column in columns}
    impacted: list[ImpactedConsumer] = []
    for consumer in consumers:
        exposed = consumer.reads(affected)
        if exposed:
            impacted.append(
                ImpactedConsumer(
                    identifier=consumer.identifier,
                    kind=consumer.kind,
                    owner=consumer.owner,
                    exposed_fields=tuple(sorted(exposed)),
                )
            )
    return tuple(impacted)
