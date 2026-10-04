"""Lineage graph: which datasets each consumer reads.

Edges are stored on the consumer record. The registry index lets a preflight
walk "columns that will change -> consumers that read them" without touching
the source system.
"""

from __future__ import annotations

from maskhub.catalog.dataset import Dataset
from maskhub.errors import Conflict, NotFound
from maskhub.lineage.consumer import ColumnUsage, Consumer
from maskhub.store.kvstore import RecordStore

PREFIX = "consumer."


def consumer_key(identifier: str) -> str:
    return PREFIX + identifier


class ConsumerRegistry:
    def __init__(self, store: RecordStore) -> None:
        self._store = store

    def save(self, consumer: Consumer) -> Consumer:
        self._store.put_json(consumer_key(consumer.identifier), consumer.as_dict())
        return consumer

    def find(self, identifier: str) -> Consumer | None:
        return Consumer.from_dict(self._store.get_json(consumer_key(identifier)))

    def get(self, identifier: str) -> Consumer:
        consumer = self.find(identifier)
        if consumer is None:
            raise NotFound(f"unknown consumer {identifier}")
        return consumer

    def remove(self, identifier: str) -> None:
        if not self._store.has(consumer_key(identifier)):
            raise NotFound(f"unknown consumer {identifier}")
        self._store.delete(consumer_key(identifier))

    def identifiers(self) -> list[str]:
        from maskhub.store.query import keys_with_prefix

        return [key[len(PREFIX):] for key in keys_with_prefix(self._store, PREFIX)]

    def all(self) -> list[Consumer]:
        return [self.get(identifier) for identifier in self.identifiers()]

    def validate_for(self, dataset: Dataset) -> None:
        """Reject consumer edges pointing at undeclared columns."""

        known = {field.name for field in dataset.fields}
        for consumer in self.all():
            unknown = sorted(consumer.columns() - known)
            if unknown:
                raise Conflict(
                    f"consumer {consumer.identifier} reads undeclared columns "
                    f"{unknown} of {dataset.identifier}"
                )

    def downstream_of(self, dataset_id: str, columns: set[str]) -> list[dict[str, object]]:
        """Consumers that read any of ``columns`` on the dataset.

        Dataset scoping uses the ``<dataset>.<column>`` naming convention on
        consumer records; a bare column name matches every dataset and is
        treated as a stale edge.
        """

        hits: list[dict[str, object]] = []
        for consumer in self.all():
            touched: list[dict[str, str]] = []
            for use in consumer.reads:
                dataset_name, _, column = use.column.partition(".")
                if not column:
                    continue
                if dataset_name == dataset_id and column in columns:
                    touched.append({"column": column, "usage": use.usage})
            if touched:
                touched.sort(key=lambda item: ColumnUsage(item["usage"]).order)
                hits.append(
                    {
                        "consumer": consumer.identifier,
                        "kind": consumer.kind,
                        "owner": consumer.owner,
                        "uses": touched,
                    }
                )
        hits.sort(key=lambda item: str(item["consumer"]))
        return hits
