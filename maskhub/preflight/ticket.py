"""Preflight ticket: the signed artifact a real run must present.

A ticket holds aggregate numbers only — no raw cell value is ever written. It
is valid until ``expires_at`` or until any fingerprinted input changes, and a
BLOCK ticket additionally requires explicit per-finding waivers at execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from maskhub.errors import InvalidRequest
from maskhub.store.kvstore import RecordStore

PREFIX = "preflight."
DEFAULT_TTL_SECONDS = 24 * 3600


@dataclass(frozen=True)
class PreflightTicket:
    ticket_id: str
    policy: str
    dataset: str
    created_at: str
    expires_at: str
    fingerprint: dict[str, object]
    watermark: str
    profile: dict[str, object]
    columns: tuple[str, ...]
    downstream: tuple[dict[str, object], ...]
    risk: dict[str, object]
    scope: dict[str, object]
    params: dict[str, object]

    @property
    def is_expired(self) -> bool:
        now = datetime.now(timezone.utc)
        return now >= datetime.fromisoformat(self.expires_at)

    @property
    def verdict(self) -> str:
        return str(self.risk.get("verdict", ""))

    def as_dict(self) -> dict[str, object]:
        return {
            "ticket_id": self.ticket_id,
            "policy": self.policy,
            "dataset": self.dataset,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "fingerprint": self.fingerprint,
            "watermark": self.watermark,
            "profile": self.profile,
            "columns": list(self.columns),
            "downstream": [dict(item) for item in self.downstream],
            "risk": self.risk,
            "scope": self.scope,
            "params": self.params,
        }

    @classmethod
    def from_dict(cls, payload: object) -> "PreflightTicket | None":
        if not isinstance(payload, dict):
            return None
        try:
            downstream_raw = payload.get("downstream", [])
            if not isinstance(downstream_raw, list):
                return None
            columns_raw = payload.get("columns", [])
            if not isinstance(columns_raw, list):
                return None
            return cls(
                ticket_id=str(payload["ticket_id"]),
                policy=str(payload["policy"]),
                dataset=str(payload["dataset"]),
                created_at=str(payload["created_at"]),
                expires_at=str(payload["expires_at"]),
                fingerprint=dict(payload["fingerprint"]),
                watermark=str(payload.get("watermark", "")),
                profile=dict(payload["profile"]),
                columns=tuple(str(item) for item in columns_raw),
                downstream=tuple(dict(item) for item in downstream_raw),
                risk=dict(payload["risk"]),
                scope=dict(payload.get("scope", {})),
                params=dict(payload.get("params", {})),
            )
        except (KeyError, TypeError, ValueError):
            return None


def ticket_key(ticket_id: str) -> str:
    return PREFIX + ticket_id


class TicketRegistry:
    def __init__(self, store: RecordStore) -> None:
        self._store = store

    def save(self, ticket: PreflightTicket) -> PreflightTicket:
        self._store.put_json(ticket_key(ticket.ticket_id), ticket.as_dict())
        return ticket

    def get(self, ticket_id: str) -> PreflightTicket:
        ticket = self.find(ticket_id)
        if ticket is None:
            from maskhub.errors import NotFound

            raise NotFound(f"unknown preflight ticket {ticket_id}")
        return ticket

    def find(self, ticket_id: str) -> PreflightTicket | None:
        return PreflightTicket.from_dict(self._store.get_json(ticket_key(ticket_id)))

    def identifiers(self) -> list[str]:
        from maskhub.store.query import keys_with_prefix

        return [key[len(PREFIX):] for key in keys_with_prefix(self._store, PREFIX)]


def issue_timestamp(ttl_seconds: int) -> tuple[str, str]:
    if not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
        raise InvalidRequest("ttl_seconds must be a positive integer")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return now.isoformat(), (now + timedelta(seconds=ttl_seconds)).isoformat()
