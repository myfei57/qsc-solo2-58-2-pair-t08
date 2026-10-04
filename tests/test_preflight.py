"""End-to-end preflight tests against a real (temporary) SQLite source."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from maskhub.catalog.dataset import Dataset
from maskhub.catalog.field import Field
from maskhub.console.errors import error_response
from maskhub.console.handlers import preflight as preflight_handler
from maskhub.console.http import Request
from maskhub.console.runtime import build_runtime
from maskhub.lineage.consumer import ColumnUse, Consumer
from maskhub.policy.policy import Policy
from maskhub.preflight.probe import SqliteProbe, UnsafeProbeQuery
from maskhub.rule.rule import Rule
from maskhub.source.registry import Source, SourceStatus
from maskhub.store.kvstore import RecordStore

DATASET_ID = "customer"


def _call(handler, runtime, request):
    try:
        return handler(runtime, request)
    except Exception as exc:
        return error_response(exc)


def _request(payload: dict[str, object] | None = None, query=None) -> Request:
    return Request(
        method="POST",
        path="/",
        query=query or {},
        headers={},
        body=json.dumps(payload).encode("utf-8") if payload is not None else b"",
    )


def _build_source_db(path: Path, rows: int = 120) -> None:
    connection = sqlite3.connect(path)
    connection.execute(
        f"""
        CREATE TABLE {DATASET_ID} (
            id INTEGER PRIMARY KEY,
            region TEXT NOT NULL,
            id_card TEXT,
            email TEXT,
            phone TEXT,
            updated_at TEXT NOT NULL
        )
        """
    )
    records = []
    for i in range(rows):
        region = "south" if i % 2 == 0 else "north"
        id_card = f"1101011990{ i % 10:02d}15{i:04d}X"
        email = f"user{i:04d}@example.test"
        # Groups of 10 share the last four digits -> 10-way collapse under partial mask.
        phone = f"139{ i % 10:02d}00{i // 10:04d}"
        updated_at = "2026-09-01" if region == "south" else "2026-10-01"
        records.append((i + 1, region, id_card, email, phone, updated_at))
    connection.executemany(
        f"INSERT INTO {DATASET_ID} VALUES (?, ?, ?, ?, ?, ?)", records
    )
    connection.commit()
    connection.close()


class PreflightFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.source_db = root / "source.db"
        _build_source_db(self.source_db)
        self.data_dir = root / "data"
        store = RecordStore(str(self.data_dir))
        store.load()
        self.runtime = build_runtime(store)

        self.runtime.sources.register(
            Source(
                identifier="crm-db",
                kind="sqlite",
                endpoint=str(self.source_db),
                status=SourceStatus.ACTIVE.value,
            )
        )
        self.runtime.datasets.save(
            Dataset(
                identifier=DATASET_ID,
                source="crm-db",
                owner="data-team",
                fields=(
                    Field("id", "public", "data-team"),
                    Field("region", "public", "data-team"),
                    Field("id_card", "special", "compliance"),
                    Field("email", "sensitive", "compliance"),
                    Field("phone", "personal", "compliance"),
                    Field("updated_at", "public", "data-team"),
                ),
                watermark_column="updated_at",
            )
        )
        self.runtime.rules.add(
            Rule("r-idcard", "id_card", "hash", {"algorithm": "sha256"})
        )
        self.runtime.rules.add(Rule("r-email", "email", "redact", {}))
        self.runtime.rules.add(
            Rule("r-phone", "phone", "partial", {"keep_prefix": 3, "keep_suffix": 4})
        )
        self.runtime.policies.save(
            Policy(
                identifier="p-pii",
                datasets=(DATASET_ID,),
                rules=("r-idcard", "r-email", "r-phone"),
            )
        )
        # Downstream consumers (lineage edges use dataset-qualified columns).
        self.runtime.consumers.save(
            Consumer(
                identifier="crm-export",
                kind="report",
                owner="ops",
                reads=(
                    ColumnUse(f"{DATASET_ID}.email", "passthrough"),
                    ColumnUse(f"{DATASET_ID}.phone", "passthrough"),
                ),
            )
        )
        self.runtime.consumers.save(
            Consumer(
                identifier="risk-join",
                kind="model",
                owner="risk",
                reads=(ColumnUse(f"{DATASET_ID}.id_card", "join_key"),),
            )
        )
        self.runtime.consumers.save(
            Consumer(
                identifier="daily-dashboard",
                kind="report",
                owner="bi",
                reads=(ColumnUse(f"{DATASET_ID}.email", "metric"),),
            )
        )
        # Reads an untouched column; must never appear in the blast radius.
        self.runtime.consumers.save(
            Consumer(
                identifier="region-segments",
                kind="report",
                owner="bi",
                reads=(ColumnUse(f"{DATASET_ID}.region", "filter"),),
            )
        )

        self.south_scope = {
            "filters": [{"op": "eq", "column": "region", "value": "south"}]
        }
        self.salt = "s3cret-salt"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run_preflight(self, scope=None, salt=None, **overrides) -> dict:
        payload = {
            "policy": "p-pii",
            "dataset": DATASET_ID,
            "scope": scope if scope is not None else self.south_scope,
            "salt": self.salt if salt is None else salt,
        }
        payload.update(overrides)
        response = _call(preflight_handler.run, self.runtime, _request(payload))
        self.assertEqual(response.status, 200, response.payload)
        return json.loads(response.payload)

    def _execute(self, ticket_id: str, salt: str, waivers=None) -> tuple[int, dict]:
        response = _call(
            preflight_handler.execute,
            self.runtime,
            _request(
                {
                    "ticket": ticket_id,
                    "scope": self.south_scope,
                    "salt": salt,
                    "waivers": waivers or [],
                }
            ),
        )
        return response.status, json.loads(response.payload)


class HappyPathTests(PreflightFixture):
    def test_preflight_reports_exact_blast_radius_and_downstream(self) -> None:
        ticket = self._run_preflight()

        profile = ticket["profile"]
        self.assertFalse(profile["sampled"])
        self.assertEqual(profile["scope_rows"], 60)
        self.assertEqual(profile["table_rows"], 120)

        columns = {item["column"]: item for item in profile["columns"]}
        self.assertEqual(set(columns), {"id_card", "email", "phone"})
        # Hashing keeps id_card cardinality; redaction collapses email fully.
        self.assertEqual(columns["id_card"]["distinct_after"], 60)
        self.assertEqual(columns["email"]["distinct_after"], 1)
        self.assertAlmostEqual(columns["email"]["distinct_ratio_after"], 1 / 60, places=6)
        self.assertLess(columns["phone"]["distinct_ratio_after"], 0.5)

        downstream = {item["consumer"]: item for item in ticket["downstream"]}
        self.assertIn("risk-join", downstream)
        self.assertIn("crm-export", downstream)
        self.assertIn("daily-dashboard", downstream)
        self.assertNotIn("region-segments", downstream)
        self.assertEqual(
            downstream["risk-join"]["uses"][0]["usage"], "join_key"
        )

        severity_by_code = {
            finding["code"]: finding["severity"]
            for finding in ticket["risk"]["findings"]
        }
        # id_card hashed while consumed as a join key -> high but not block.
        join_finding = next(
            f
            for f in ticket["risk"]["findings"]
            if f["code"] == "DOWNSTREAM_BREAK" and "risk-join" in f["id"]
        )
        self.assertEqual(join_finding["severity"], "high")
        self.assertEqual(ticket["risk"]["verdict"], "WARN")
        self.assertTrue(ticket["risk"]["recommendations"])

    def test_execute_requires_no_waiver_for_warn_ticket_and_matches_rowcount(self) -> None:
        ticket = self._run_preflight()
        self.assertEqual(ticket["risk"]["verdict"], "WARN")
        status, result = self._execute(ticket["ticket_id"], self.salt)
        self.assertEqual(status, 200, result)
        self.assertEqual(result["updated_rows"], 60)
        self.assertEqual(result["expected_rows"], 60)

        connection = sqlite3.connect(self.source_db)
        south = connection.execute(
            f"SELECT id_card, email, phone FROM {DATASET_ID} WHERE region = 'south' LIMIT 1"
        ).fetchone()
        north = connection.execute(
            f"SELECT id_card, email, phone FROM {DATASET_ID} WHERE region = 'north' LIMIT 1"
        ).fetchone()
        connection.close()
        # South masked, north untouched (scope equality).
        self.assertNotIn("110101", south[0])
        self.assertEqual(len(south[0]), 32)
        self.assertEqual(south[1], "***")
        self.assertTrue(south[2].startswith("139") and south[2][3:].count("*") >= 3)
        self.assertIn("110101", north[0])
        self.assertNotEqual(north[1], "***")

    def test_redaction_on_join_key_blocks_execution(self) -> None:
        self.runtime.rules.add(Rule("r-idcard-redact", "id_card", "redact", {}))
        self.runtime.policies.save(
            Policy(
                identifier="p-redact",
                datasets=(DATASET_ID,),
                rules=("r-idcard-redact", "r-email", "r-phone"),
            )
        )
        payload = {
            "policy": "p-redact",
            "dataset": DATASET_ID,
            "scope": self.south_scope,
            "salt": self.salt,
        }
        response = _call(
            preflight_handler.run,
            self.runtime,
            _request(payload),
        )
        ticket = json.loads(response.payload)
        self.assertEqual(response.status, 200, ticket)
        self.assertEqual(ticket["risk"]["verdict"], "BLOCK")
        blockers = [
            f["id"]
            for f in ticket["risk"]["findings"]
            if f["severity"] == "block"
        ]
        self.assertTrue(any("risk-join" in item for item in blockers))

        status, body = self._execute(ticket["ticket_id"], self.salt)
        self.assertEqual(status, 409)
        self.assertIn("waivers", body["error"])

        status, body = self._execute(ticket["ticket_id"], self.salt, waivers=blockers)
        self.assertEqual(status, 200, body)

    def test_ticket_never_contains_raw_values(self) -> None:
        ticket = self._run_preflight()
        on_disk = (self.data_dir / f"preflight.{ticket['ticket_id']}.json").read_text()
        self.assertNotIn("user0003", on_disk)
        self.assertNotIn("11010119", on_disk)
        # Aggregate shape is present instead.
        self.assertIn("length_buckets", on_disk)
        self.assertIn("scope_rows", on_disk)


class DriftTests(PreflightFixture):
    def test_scope_change_requires_repreflight(self) -> None:
        ticket = self._run_preflight()
        wider_scope = {"filters": [{"op": "ne", "column": "region", "value": "north"}]}
        response = _call(
            preflight_handler.execute,
            self.runtime,
            _request(
                {"ticket": ticket["ticket_id"], "scope": wider_scope, "salt": self.salt}
            ),
        )
        self.assertEqual(response.status, 409)
        body = json.loads(response.payload)
        self.assertIn("scope", body["error"])

    def test_wrong_salt_requires_repreflight(self) -> None:
        ticket = self._run_preflight()
        status, body = self._execute(ticket["ticket_id"], "different-salt")
        self.assertEqual(status, 409)
        self.assertIn("salt", body["error"])

    def test_policy_change_requires_repreflight(self) -> None:
        ticket = self._run_preflight()
        # Retire and re-create a draft with one fewer rule (identifier reused).
        self.runtime.policies.retire("p-pii")
        self.runtime.policies.save(
            Policy(
                identifier="p-pii",
                datasets=(DATASET_ID,),
                rules=("r-idcard", "r-email"),
            )
        )
        status, body = self._execute(ticket["ticket_id"], self.salt)
        self.assertEqual(status, 409)
        self.assertIn("policy", body["error"])

    def test_lineage_change_requires_repreflight(self) -> None:
        ticket = self._run_preflight()
        self.runtime.consumers.save(
            Consumer(
                identifier="new-exporter",
                kind="report",
                owner="newteam",
                reads=(ColumnUse(f"{DATASET_ID}.id_card", "passthrough"),),
            )
        )
        status, body = self._execute(ticket["ticket_id"], self.salt)
        self.assertEqual(status, 409)
        self.assertIn("lineage", body["error"])

    def test_source_data_change_invalidates_ticket(self) -> None:
        ticket = self._run_preflight()
        connection = sqlite3.connect(self.source_db)
        connection.execute(
            f"UPDATE {DATASET_ID} SET updated_at = '2026-10-02' WHERE region = 'south'"
        )
        connection.commit()
        connection.close()
        status, body = self._execute(ticket["ticket_id"], self.salt)
        self.assertEqual(status, 409)
        self.assertIn("watermark", body["error"])


class SafetyTests(PreflightFixture):
    def test_probe_is_read_only(self) -> None:
        with SqliteProbe(str(self.source_db), deadline_ms=2_000) as probe:
            with self.assertRaises(sqlite3.OperationalError):
                probe.connection.execute(
                    f"UPDATE {DATASET_ID} SET email = 'x' WHERE id = 1"
                )

    def test_probe_rejects_non_select_statements(self) -> None:
        with SqliteProbe(str(self.source_db), deadline_ms=2_000) as probe:
            for malicious in (
                f"UPDATE {DATASET_ID} SET email = 'x'",
                f"SELECT 1; DROP TABLE {DATASET_ID}",
                "SELECT * FROM customer -- ",
            ):
                with self.assertRaises(UnsafeProbeQuery):
                    probe.aggregate(malicious)

    def test_scope_column_must_be_declared(self) -> None:
        response = _call(
            preflight_handler.run,
            self.runtime,
            _request(
                {
                    "policy": "p-pii",
                    "dataset": DATASET_ID,
                    "scope": {"filters": [{"op": "eq", "column": "nope--", "value": "x"}]},
                    "salt": self.salt,
                }
            ),
        )
        self.assertEqual(response.status, 400)

    def test_sampled_ticket_cannot_execute(self) -> None:
        ticket = self._run_preflight(scan_budget_rows=10)
        self.assertTrue(ticket["profile"]["sampled"])
        status, body = self._execute(ticket["ticket_id"], self.salt)
        self.assertEqual(status, 400)
        self.assertIn("sampled", body["error"])

    def test_empty_scope_is_flagged(self) -> None:
        ticket = self._run_preflight(
            scope={"filters": [{"op": "eq", "column": "region", "value": "nowhere"}]}
        )
        self.assertEqual(ticket["profile"]["scope_rows"], 0)
        codes = {f["code"] for f in ticket["risk"]["findings"]}
        self.assertIn("SCOPE_EMPTY", codes)

    def test_preflight_does_not_modify_the_source(self) -> None:
        before = self.source_db.read_bytes()
        self._run_preflight()
        # A second preflight with a different scope, still no writes.
        self._run_preflight(
            scope={"filters": [{"op": "in", "column": "region", "values": ["south", "north"]}]},
            scan_budget_rows=5,
        )
        after = self.source_db.read_bytes()
        self.assertEqual(
            hashlib.sha256(before).hexdigest(), hashlib.sha256(after).hexdigest()
        )

    def test_sampled_profile_estimates_and_keeps_exact_counts(self) -> None:
        ticket = self._run_preflight(scan_budget_rows=10)
        profile = ticket["profile"]
        self.assertTrue(profile["sampled"])
        # Counts stay exact even though distribution metrics are estimated.
        self.assertEqual(profile["scope_rows"], 60)
        self.assertEqual(profile["table_rows"], 120)
        self.assertGreater(profile["sample_scale"], 1.0)
        codes = {f["code"] for f in ticket["risk"]["findings"]}
        self.assertIn("PROFILE_SAMPLED", codes)


if __name__ == "__main__":
    unittest.main()