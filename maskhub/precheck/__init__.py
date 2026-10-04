"""Pre-execution checks for masking policies.

A precheck measures the blast radius of a policy against a concrete data
scope — affected rows, columns and downstream consumers — and freezes the
conclusion into a report bound to a fingerprint of the execution
parameters.  Prechecks are strictly read-only: they sample real values to
profile data shape, persist only aggregates, and stop at a time budget so
the source is never held for long.  Any change to the execution
parameters invalidates the report and forces a fresh precheck.
"""

from maskhub.precheck.scope import Scope

__all__ = ["Scope"]
