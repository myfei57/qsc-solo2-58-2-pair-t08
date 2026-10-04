"""Lineage (downstream consumer) endpoints."""

from __future__ import annotations

from maskhub.console.http import Request, Response
from maskhub.console.validation import require_text
from maskhub.errors import InvalidRequest
from maskhub.lineage.consumer import ColumnUse, Consumer


def _parse_reads(raw: object) -> tuple[ColumnUse, ...]:
    if not isinstance(raw, list) or not raw:
        raise InvalidRequest("reads must be a non-empty list")
    uses: list[ColumnUse] = []
    for item in raw:
        if not isinstance(item, dict):
            raise InvalidRequest("each read must be an object")
        column = require_text(item, "column")
        usage = require_text(item, "usage")
        try:
            uses.append(ColumnUse(column=column, usage=usage))
        except ValueError as exc:
            raise InvalidRequest(str(exc)) from exc
    return tuple(uses)


def list_consumers(runtime, request: Request) -> Response:
    consumers = [consumer.as_dict() for consumer in runtime.consumers.all()]
    return Response.json(200, {"count": len(consumers), "consumers": consumers})


def register_consumer(runtime, request: Request) -> Response:
    payload = request.json_object()
    consumer = Consumer(
        identifier=require_text(payload, "identifier"),
        kind=require_text(payload, "kind"),
        owner=require_text(payload, "owner"),
        reads=_parse_reads(payload.get("reads")),
    )
    runtime.consumers.save(consumer)
    runtime.journal.append("consumer.register", consumer.identifier, consumer.kind)
    return Response.json(200, consumer.as_dict())


def remove_consumer(runtime, request: Request) -> Response:
    payload = request.json_object()
    identifier = require_text(payload, "identifier")
    runtime.consumers.remove(identifier)
    runtime.journal.append("consumer.remove", identifier, "")
    return Response.json(200, {"removed": identifier})
