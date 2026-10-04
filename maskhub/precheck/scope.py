"""The data range an execution — and its precheck — operates on."""

from __future__ import annotations

from dataclasses import dataclass

from maskhub.errors import InvalidRequest


@dataclass(frozen=True)
class Scope:
    """Execution parameters that decide which rows a policy touches."""

    dataset: str
    filter_field: str = ""
    filter_value: str = ""

    def __post_init__(self) -> None:
        if not self.dataset.strip():
            raise ValueError("scope dataset is required")
        if bool(self.filter_field.strip()) != bool(self.filter_value.strip()):
            raise ValueError("scope filter needs both a field and a value")

    @property
    def has_filter(self) -> bool:
        return bool(self.filter_field.strip())

    def canonical(self) -> dict[str, str]:
        """Stable form used for fingerprinting; same scope, same dict."""

        return {
            "dataset": self.dataset,
            "filter": (
                f"{self.filter_field}={self.filter_value}" if self.has_filter else ""
            ),
        }

    @classmethod
    def parse(cls, dataset: str, raw_filter: str = "") -> "Scope":
        text = raw_filter.strip()
        if not text:
            return cls(dataset=dataset)
        field, sep, value = text.partition("=")
        if not sep or not field.strip() or not value.strip():
            raise InvalidRequest("filter must look like field=value")
        return cls(
            dataset=dataset,
            filter_field=field.strip(),
            filter_value=value.strip(),
        )
