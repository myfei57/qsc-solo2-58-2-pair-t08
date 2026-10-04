"""Stable fingerprints binding a preflight ticket to its exact execution scope.

Every input that could change *which rows*, *which values*, or *which blast
radius* a run will have is folded into the fingerprint. The executor
recomputes it from the live request and refuses to run on mismatch, so
"change a parameter but reuse the old preflight" is structurally impossible.

Sections are hashed separately so a rejected execution can report exactly
which input drifted (scope, policy, rules, parameters, catalog, lineage,
options, salt) instead of a single opaque hash mismatch.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from maskhub.lineage.consumer import Consumer
from maskhub.catalog.dataset import Dataset
from maskhub.policy.policy import Policy
from maskhub.preflight.scope import CompiledScope
from maskhub.preflight.transform import TRANSFORM_VERSION
from maskhub.rule.rule import Rule


def _digest_section(name: str, value: object) -> str:
    body = json.dumps(
        {"section": name, "value": value}, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Fingerprint:
    sections: dict[str, str]

    @property
    def digest(self) -> str:
        joined = "\n".join(f"{name}:{self.sections[name]}" for name in sorted(self.sections))
        return hashlib.sha256(joined.encode("utf-8")).hexdigest()

    def as_dict(self) -> dict[str, object]:
        return {"digest": self.digest, "sections": dict(sorted(self.sections.items()))}


def build_fingerprint(
    *,
    policy: Policy,
    rules: list[Rule],
    dataset: Dataset,
    scope: CompiledScope,
    consumers: list[Consumer],
    scan_budget_rows: int,
    deadline_ms: int,
    salt: str,
) -> Fingerprint:
    sections = {
        "policy": policy.as_dict(),
        "rules": [rule.as_dict() for rule in sorted(rules, key=lambda item: item.identifier)],
        "dataset": dataset.as_dict(),
        "scope": scope.canonical,
        "lineage": [consumer.as_dict() for consumer in sorted(consumers, key=lambda item: item.identifier)],
        "options": {
            "scan_budget_rows": scan_budget_rows,
            "deadline_ms": deadline_ms,
        },
        "salt": hashlib.sha256(salt.encode("utf-8")).hexdigest(),
        "engine": TRANSFORM_VERSION,
    }
    return Fingerprint(sections={name: _digest_section(name, value) for name, value in sections.items()})
