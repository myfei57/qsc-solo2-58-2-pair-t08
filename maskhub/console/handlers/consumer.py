"""Downstream consumer endpoints."""

from __future__ import annotations

from maskhub.catalog.consumer import Consumer
from maskhub.console.http import Request, Response
from maskhub.console.validation import optional_text, require_text, require_text_list
from maskhub.errors import InvalidRequest


def list_consumers(runtime, request: Request) -> Response:
    dataset = request.query_one("dataset")
    consumers = (
        runtime.consumers.for_dataset(dataset) if dataset else runtime.consumers.all()
    )
    payload = [consumer.as_dict() for consumer in consumers]
    return Response.json(200, {"count": len(payload), "consumers": payload})


def get_consumer(runtime, request: Request) -> Response:
    identifier = request.query_one("consumer", "") or ""
    return Response.json(200, runtime.consumers.get(identifier).as_dict())


def register_consumer(runtime, request: Request) -> Response:
    payload = request.json_object()
    dataset_id = require_text(payload, "dataset")
    dataset = runtime.datasets.get(dataset_id)
    fields = require_text_list(payload, "fields")
    unknown = [name for name in fields if dataset.field(name) is None]
    if unknown:
        raise InvalidRequest(f"unknown fields for dataset {dataset_id}: {unknown}")
    consumer = Consumer(
        identifier=require_text(payload, "identifier"),
        kind=require_text(payload, "kind"),
        dataset=dataset_id,
        fields=tuple(fields),
        owner=optional_text(payload, "owner"),
    )
    runtime.consumers.register(consumer)
    runtime.journal.append("consumer.register", consumer.identifier, consumer.dataset)
    return Response.json(200, consumer.as_dict())
