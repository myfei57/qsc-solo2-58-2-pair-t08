"""Composition root for the gateway."""

from __future__ import annotations

from dataclasses import dataclass

from maskhub.audit.journal import Journal
from maskhub.catalog.consumer import ConsumerRegistry
from maskhub.catalog.dataset import DatasetRegistry
from maskhub.policy.registry import PolicyRegistry
from maskhub.precheck.probe import CsvProbe, ProbeRegistry
from maskhub.precheck.report import ReportRegistry
from maskhub.rule.registry import RuleRegistry
from maskhub.source.registry import SourceRegistry
from maskhub.store.kvstore import RecordStore


@dataclass
class Runtime:
    store: RecordStore
    journal: Journal
    sources: SourceRegistry
    datasets: DatasetRegistry
    rules: RuleRegistry
    policies: PolicyRegistry
    consumers: ConsumerRegistry
    reports: ReportRegistry
    probes: ProbeRegistry


def build_runtime(store: RecordStore) -> Runtime:
    probes = ProbeRegistry()
    probes.register("csv", CsvProbe())
    return Runtime(
        store=store,
        journal=Journal(store),
        sources=SourceRegistry(store),
        datasets=DatasetRegistry(store),
        rules=RuleRegistry(store),
        policies=PolicyRegistry(store),
        consumers=ConsumerRegistry(store),
        reports=ReportRegistry(store),
        probes=probes,
    )
