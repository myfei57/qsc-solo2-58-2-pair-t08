"""Precheck reports: the only artifact a precheck is allowed to persist."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from maskhub.errors import NotFound
from maskhub.store.kvstore import RecordStore

PREFIX = "precheck."


def _canonical(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(payload: object) -> str:
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


@dataclass(frozen=True)
class ScopeBinding:
    """Fingerprints of everything an execution depends on.

    If any component drifts — the policy, its rules, the dataset catalog
    or the data scope — the precheck conclusion no longer applies and a
    fresh precheck is required.
    """

    policy: str
    rules: str
    dataset: str
    scope: str

    @property
    def fingerprint(self) -> str:
        return digest(self.as_dict())

    def as_dict(self) -> dict[str, str]:
        return {
            "policy": self.policy,
            "rules": self.rules,
            "dataset": self.dataset,
            "scope": self.scope,
        }

    def drifted(self, other: "ScopeBinding") -> tuple[str, ...]:
        mine, theirs = self.as_dict(), other.as_dict()
        return tuple(name for name in sorted(mine) if mine[name] != theirs[name])

    @classmethod
    def from_dict(cls, payload: object) -> "ScopeBinding | None":
        if not isinstance(payload, dict):
            return None
        parts = [payload.get(name) for name in ("policy", "rules", "dataset", "scope")]
        if not all(isinstance(part, str) for part in parts):
            return None
        return cls(policy=parts[0], rules=parts[1], dataset=parts[2], scope=parts[3])


@dataclass(frozen=True)
class PrecheckReport:
    identifier: str
    policy: str
    created_at: str
    expires_at: str
    binding: ScopeBinding
    scope: dict[str, str]
    scan: dict[str, object]
    affected_rows: int
    affected_rows_estimated: bool
    columns: tuple[dict[str, object], ...]
    consumers: tuple[dict[str, object], ...]
    risk: dict[str, object]

    @property
    def fingerprint(self) -> str:
        return self.binding.fingerprint

    def expired(self, at: datetime) -> bool:
        return at >= datetime.fromisoformat(self.expires_at)

    def as_dict(self) -> dict[str, object]:
        return {
            "identifier": self.identifier,
            "policy": self.policy,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "fingerprint": self.fingerprint,
            "binding": self.binding.as_dict(),
            "scope": dict(self.scope),
            "scan": dict(self.scan),
            "affected_rows": self.affected_rows,
            "affected_rows_estimated": self.affected_rows_estimated,
            "columns": [dict(column) for column in self.columns],
            "consumers": [dict(consumer) for consumer in self.consumers],
            "risk": dict(self.risk),
        }

    @classmethod
    def from_dict(cls, payload: object) -> "PrecheckReport | None":
        if not isinstance(payload, dict):
            return None
        identifier = payload.get("identifier")
        policy = payload.get("policy")
        created_at = payload.get("created_at")
        expires_at = payload.get("expires_at")
        binding = ScopeBinding.from_dict(payload.get("binding"))
        scope = payload.get("scope")
        scan = payload.get("scan")
        affected_rows = payload.get("affected_rows")
        estimated = payload.get("affected_rows_estimated")
        columns = payload.get("columns")
        consumers = payload.get("consumers")
        risk = payload.get("risk")
        scalars = (identifier, policy, created_at, expires_at)
        if not all(isinstance(item, str) for item in scalars):
            return None
        if binding is None or not isinstance(scope, dict) or not isinstance(scan, dict):
            return None
        if not isinstance(affected_rows, int) or not isinstance(estimated, bool):
            return None
        if not isinstance(columns, list) or not isinstance(consumers, list):
            return None
        if not isinstance(risk, dict):
            return None
        return cls(
            identifier=identifier,
            policy=policy,
            created_at=created_at,
            expires_at=expires_at,
            binding=binding,
            scope=scope,
            scan=scan,
            affected_rows=affected_rows,
            affected_rows_estimated=estimated,
            columns=tuple(columns),
            consumers=tuple(consumers),
            risk=risk,
        )


def report_key(identifier: str) -> str:
    return PREFIX + identifier


class ReportRegistry:
    def __init__(self, store: RecordStore) -> None:
        self._store = store

    def save(self, report: PrecheckReport) -> PrecheckReport:
        self._store.put_json(report_key(report.identifier), report.as_dict())
        return report

    def find(self, identifier: str) -> PrecheckReport | None:
        return PrecheckReport.from_dict(self._store.get_json(report_key(identifier)))

    def get(self, identifier: str) -> PrecheckReport:
        report = self.find(identifier)
        if report is None:
            raise NotFound(f"unknown precheck report {identifier}")
        return report

    def identifiers(self) -> list[str]:
        from maskhub.store.query import keys_with_prefix

        return [key[len(PREFIX):] for key in keys_with_prefix(self._store, PREFIX)]

    def all(self) -> list[PrecheckReport]:
        return [self.get(identifier) for identifier in self.identifiers()]
