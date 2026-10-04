"""Read-only, time-boxed access to source data for prechecks."""

from __future__ import annotations

import csv
import time
from collections.abc import Iterator, Mapping
from typing import Protocol

from maskhub.catalog.dataset import Dataset
from maskhub.errors import MaskHubError
from maskhub.precheck.scope import Scope
from maskhub.source.registry import Source

CHECK_EVERY_ROWS = 256


class ScanTruncated(MaskHubError):
    """Raised inside a scan when the time budget runs out."""


class Deadline:
    """Monotonic countdown shared by probes so scans stay short."""

    def __init__(self, budget_ms: int) -> None:
        self._end = time.monotonic() + max(budget_ms, 0) / 1000.0

    @property
    def expired(self) -> bool:
        return time.monotonic() >= self._end

    @property
    def remaining_ms(self) -> int:
        return max(0, int((self._end - time.monotonic()) * 1000))


class SourceProbe(Protocol):
    """Read-only sampling interface every source adapter must implement.

    Probes may only read: there is deliberately no write, delete or
    schema method on this contract.  Implementations must honour the
    deadline so a precheck never holds a source for long.
    """

    def scan(
        self, source: Source, dataset: Dataset, scope: Scope, deadline: Deadline
    ) -> Iterator[Mapping[str, object]]:
        """Yield rows inside the scope, raising ScanTruncated at the deadline."""


class CsvProbe:
    """Probe for sources of kind ``csv`` whose endpoint is a local file."""

    def scan(
        self, source: Source, dataset: Dataset, scope: Scope, deadline: Deadline
    ) -> Iterator[Mapping[str, object]]:
        with open(source.endpoint, newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for index, row in enumerate(reader):
                if index % CHECK_EVERY_ROWS == 0 and deadline.expired:
                    raise ScanTruncated(f"scan budget exhausted after {index} rows")
                if scope.has_filter and row.get(scope.filter_field) != scope.filter_value:
                    continue
                yield row


class ProbeRegistry:
    """Maps source kinds to their read-only probe adapters."""

    def __init__(self) -> None:
        self._probes: dict[str, SourceProbe] = {}

    def register(self, kind: str, probe: SourceProbe) -> None:
        self._probes[kind.strip()] = probe

    def for_kind(self, kind: str) -> SourceProbe | None:
        return self._probes.get(kind.strip())
