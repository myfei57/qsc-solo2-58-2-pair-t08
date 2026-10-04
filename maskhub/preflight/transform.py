"""Rule actions bound as in-database masking expressions.

A transform is evaluated *inside* the source engine (never by pulling raw
values out). The same binding powers the preflight profiler (so cardinality
and collision estimates reflect the real transform) and the executor (so the
UPDATE writes exactly the value that was previewed).

Transform versioning: any change to an algorithm below must bump
``TRANSFORM_VERSION``; it participates in the preflight fingerprint and
invalidates earlier tickets.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from maskhub.errors import InvalidRequest
from maskhub.rule.rule import Rule

TRANSFORM_VERSION = "maskhub-transform/1"

REDACT_TOKEN = "***"


@dataclass(frozen=True)
class ResolvedColumn:
    column: str
    rule: Rule
    action: str
    expression_sql: str

    @property
    def rule_id(self) -> str:
        return self.rule.identifier


def _partial_mask(value: object, keep_prefix: int, keep_suffix: int) -> object:
    if value is None:
        return None
    text = str(value)
    if len(text) <= keep_prefix + keep_suffix:
        return "*" * len(text)
    middle = "*" * (len(text) - keep_prefix - keep_suffix)
    return text[:keep_prefix] + middle + text[len(text) - keep_suffix:]


def _digest(value: object, salt: str) -> str:
    return hashlib.sha256((salt + "\x00" + str(value)).encode("utf-8")).hexdigest()[:32]


class TransformBinder:
    """Registers deterministic masking UDFs on one DB-API connection."""

    def __init__(self, connection) -> None:
        self._connection = connection
        self._index = 0

    def _register(self, name: str, fn, arity: int) -> str:
        self._connection.create_function(name, arity, fn, deterministic=True)
        return name

    def bind(self, column: str, rule: Rule, salt: str) -> str:
        """Return the SQL expression that applies ``rule`` to ``column``."""

        quoted = '"' + column.replace('"', '""') + '"'
        self._index += 1
        suffix = self._index
        if rule.action == "redact":
            token = str(rule.parameters.get("token", REDACT_TOKEN))
            name = f"mh_redact_{suffix}"
            self._register(
                name,
                lambda value, token=token: None if value is None else token,
                1,
            )
            return f"{name}({quoted})"
        if rule.action == "hash":
            name = f"mh_hash_{suffix}"
            self._register(
                name,
                lambda value, bound_salt=salt: None if value is None else _digest(value, bound_salt),
                1,
            )
            return f"{name}({quoted})"
        if rule.action == "tokenize":
            name = f"mh_tokenize_{suffix}"
            self._register(
                name,
                lambda value, bound_salt=salt: None if value is None else "tok_" + _digest(value, bound_salt),
                1,
            )
            return f"{name}({quoted})"
        if rule.action == "partial":
            keep_prefix = int(rule.parameters.get("keep_prefix", 1))
            keep_suffix = int(rule.parameters.get("keep_suffix", 1))
            if keep_prefix < 0 or keep_suffix < 0:
                raise InvalidRequest("partial keep counts must be non-negative")
            name = f"mh_partial_{suffix}"
            self._register(
                name,
                lambda value, p=keep_prefix, s=keep_suffix: _partial_mask(value, p, s),
                1,
            )
            return f"{name}({quoted})"
        raise InvalidRequest(f"unsupported masking action {rule.action!r}")


def rule_needs_salt(rule: Rule) -> bool:
    return rule.action in ("hash", "tokenize")
