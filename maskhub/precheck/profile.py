"""Streaming column profiles built from real values, keeping none of them.

Profilers see every sampled value so the report reflects the true data
shape, but only aggregates survive: counts, length statistics, shape
ratios and one-way digests.  Raw values are hashed and discarded in
memory and are never written to the store.
"""

from __future__ import annotations

import hashlib
import re

DISTINCT_CAP = 10_000

SHAPES: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
    "phone": re.compile(r"^\+?[0-9][0-9 \-]{6,18}$"),
    "digits": re.compile(r"^\d+$"),
    "iso_date": re.compile(r"^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?$"),
    "uuid": re.compile(r"^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$"),
}


def is_null(value: object) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


class ColumnProfiler:
    """Aggregates one column; raw values are hashed and discarded, never kept."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.rows = 0
        self.nulls = 0
        self.non_null = 0
        self.total_length = 0
        self.min_length: int | None = None
        self.max_length: int | None = None
        self.shapes: dict[str, int] = {shape: 0 for shape in SHAPES}
        self.distinct_capped = False
        self._distinct: set[str] = set()
        self._digest = hashlib.sha256()

    def feed(self, value: object) -> None:
        self.rows += 1
        if is_null(value):
            self.nulls += 1
            return
        text = str(value)
        self.non_null += 1
        length = len(text)
        self.total_length += length
        self.min_length = length if self.min_length is None else min(self.min_length, length)
        self.max_length = length if self.max_length is None else max(self.max_length, length)
        for shape, pattern in SHAPES.items():
            if pattern.match(text):
                self.shapes[shape] += 1
        if len(self._distinct) < DISTINCT_CAP:
            self._distinct.add(hashlib.sha256(text.encode("utf-8")).hexdigest())
        else:
            self.distinct_capped = True
        self._digest.update(f"{length}:".encode("utf-8"))
        self._digest.update(text.encode("utf-8"))
        self._digest.update(b"|")

    def as_dict(
        self, sensitivity: str, actions: tuple[str, ...], rules: tuple[str, ...]
    ) -> dict[str, object]:
        return {
            "name": self.name,
            "sensitivity": sensitivity,
            "actions": list(actions),
            "rules": list(rules),
            "rows": self.rows,
            "nulls": self.nulls,
            "non_null": self.non_null,
            "distinct": len(self._distinct),
            "distinct_capped": self.distinct_capped,
            "min_length": self.min_length or 0,
            "max_length": self.max_length or 0,
            "avg_length": round(self.total_length / self.non_null, 2) if self.non_null else 0.0,
            "shapes": dict(self.shapes),
            "stream_digest": self._digest.hexdigest(),
        }
