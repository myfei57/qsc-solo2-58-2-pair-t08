"""Downstream consumers that read dataset fields."""

from __future__ import annotations

from dataclasses import dataclass

from maskhub.errors import Conflict, NotFound
from maskhub.store.kvstore import RecordStore

PREFIX = "consumer."


@dataclass(frozen=True)
class Consumer:
    """A downstream consumer reading a fixed set of dataset fields."""

    identifier: str
    kind: str
    dataset: str
    fields: tuple[str, ...]
    owner: str = ""

    def __post_init__(self) -> None:
        if not self.identifier.strip():
            raise ValueError("consumer identifier is required")
        if not self.kind.strip():
            raise ValueError("consumer kind is required")
        if not self.dataset.strip():
            raise ValueError("consumer dataset is required")
        if not self.fields:
            raise ValueError("consumer must read at least one field")

    def reads(self, field_names: set[str]) -> set[str]:
        return set(self.fields) & field_names

    def as_dict(self) -> dict[str, object]:
        return {
            "identifier": self.identifier,
            "kind": self.kind,
            "dataset": self.dataset,
            "fields": list(self.fields),
            "owner": self.owner,
        }

    @classmethod
    def from_dict(cls, payload: object) -> "Consumer | None":
        if not isinstance(payload, dict):
            return None
        identifier = payload.get("identifier")
        kind = payload.get("kind")
        dataset = payload.get("dataset")
        fields = payload.get("fields")
        owner = payload.get("owner", "")
        if not all(isinstance(item, str) for item in (identifier, kind, dataset, owner)):
            return None
        if not isinstance(fields, list) or not all(isinstance(item, str) for item in fields):
            return None
        try:
            return cls(
                identifier=identifier,
                kind=kind,
                dataset=dataset,
                fields=tuple(fields),
                owner=owner,
            )
        except ValueError:
            return None


def consumer_key(identifier: str) -> str:
    return PREFIX + identifier


class ConsumerRegistry:
    def __init__(self, store: RecordStore) -> None:
        self._store = store

    def register(self, consumer: Consumer) -> Consumer:
        if self._store.has(consumer_key(consumer.identifier)):
            raise Conflict(f"consumer {consumer.identifier} already registered")
        self._store.put_json(consumer_key(consumer.identifier), consumer.as_dict())
        return consumer

    def find(self, identifier: str) -> Consumer | None:
        return Consumer.from_dict(self._store.get_json(consumer_key(identifier)))

    def get(self, identifier: str) -> Consumer:
        consumer = self.find(identifier)
        if consumer is None:
            raise NotFound(f"unknown consumer {identifier}")
        return consumer

    def identifiers(self) -> list[str]:
        from maskhub.store.query import keys_with_prefix

        return [key[len(PREFIX):] for key in keys_with_prefix(self._store, PREFIX)]

    def all(self) -> list[Consumer]:
        return [self.get(identifier) for identifier in self.identifiers()]

    def for_dataset(self, dataset: str) -> list[Consumer]:
        return [consumer for consumer in self.all() if consumer.dataset == dataset]
