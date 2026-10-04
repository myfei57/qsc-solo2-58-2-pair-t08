"""Precheck tests: impact, read-only guarantees and the consistency gate."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from maskhub.catalog.consumer import Consumer
from maskhub.catalog.dataset import Dataset
from maskhub.catalog.field import Field
from maskhub.console.http import Request
from maskhub.console.routes import build_router
from maskhub.console.runtime import build_runtime
from maskhub.errors import InvalidRequest, NotFound
from maskhub.policy.policy import Policy
from maskhub.precheck.scope import Scope
from maskhub.precheck.service import run_precheck, verify_precheck
from maskhub.rule.rule import Rule
from maskhub.source.registry import Source, SourceStatus
from maskhub.store.kvstore import RecordStore

SENTINEL_EMAIL = "alice.secret@example.com"
SENTINEL_PHONE = "138-0000-1111"

ROWS = [
    {"user_id": "u1", "email": SENTINEL_EMAIL, "phone": SENTINEL_PHONE, "region": "cn"},
    {"user_id": "u2", "email": "bob@example.com", "phone": "139-2222-3333", "region": "cn"},
    {"user_id": "u3", "email": "carol@example.com", "phone": "137-4444-5555", "region": "cn"},
    {"user_id": "u4", "email": "dan@example.com", "phone": "136-6666-7777", "region": "cn"},
    {"user_id": "u5", "email": "erin@example.com", "phone": "135-8888-9999", "region": "cn"},
    {"user_id": "u6", "email": "frank@example.com", "phone": "134-1111-2222", "region": "cn"},
    {"user_id": "u7", "email": "grace@example.com", "phone": "133-3333-4444", "region": "eu"},
    {"user_id": "u8", "email": "heidi@example.com", "phone": "132-5555-6666", "region": "eu"},
]


def _write_csv(path: Path) -> None:
    lines = ["user_id,email,phone,region"]
    lines.extend(
        f"{row['user_id']},{row['email']},{row['phone']},{row['region']}" for row in ROWS
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class PrecheckTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.csv_path = root / "users.csv"
        _write_csv(self.csv_path)

        self.store = RecordStore(root / "data")
        self.store.load()
        self.runtime = build_runtime(self.store)

        self.runtime.sources.register(Source("src-users", "csv", str(self.csv_path)))
        self.runtime.sources.set_status("src-users", SourceStatus.ACTIVE)
        self.runtime.datasets.save(
            Dataset(
                identifier="users",
                source="src-users",
                owner="data-team",
                fields=(
                    Field("user_id", "public", "data-team"),
                    Field("email", "personal", "data-team"),
                    Field("phone", "sensitive", "data-team"),
                    Field("region", "public", "data-team"),
                    Field("id_number", "special", "data-team"),
                ),
            )
        )
        self.runtime.rules.add(Rule("r-email", "email", "hash", {}))
        self.runtime.rules.add(Rule("r-phone", "phone", "redact", {}))
        self.runtime.policies.save(Policy("p-mask", ("users",), ("r-email", "r-phone")))
        self.runtime.consumers.register(
            Consumer("bi-dashboard", "report", "users", ("email", "region"), "bi-team")
        )
        self.runtime.consumers.register(
            Consumer("region-export", "export", "users", ("region",), "ops")
        )

    def _run(self, **overrides):
        options = {
            "policy_id": "p-mask",
            "scope": Scope("users"),
            "sample_size": 1000,
            "budget_ms": 5000,
            "ttl_seconds": 3600,
        }
        options.update(overrides)
        return run_precheck(self.runtime, **options)

    def test_impact_report(self) -> None:
        report = self._run()
        self.assertEqual(report.affected_rows, 8)
        self.assertFalse(report.affected_rows_estimated)
        self.assertTrue(report.scan["completed"])
        self.assertEqual(report.scan["rows_seen"], 8)

        by_name = {column["name"]: column for column in report.columns}
        self.assertEqual(set(by_name), {"email", "phone"})
        self.assertEqual(by_name["email"]["actions"], ["hash"])
        self.assertEqual(by_name["phone"]["actions"], ["redact"])
        self.assertEqual(by_name["email"]["non_null"], 8)
        self.assertEqual(by_name["email"]["shapes"]["email"], 8)
        self.assertEqual(by_name["phone"]["shapes"]["phone"], 8)

        self.assertEqual(len(report.consumers), 1)
        self.assertEqual(report.consumers[0]["identifier"], "bi-dashboard")
        self.assertEqual(report.consumers[0]["exposed_fields"], ["email"])

        self.assertEqual(report.risk["level"], "high")
        codes = {finding["code"] for finding in report.risk["findings"]}
        self.assertIn("irreversible_with_consumers", codes)
        self.assertIn("coverage_gap", codes)  # id_number has no matching rule
        self.assertTrue(report.risk["suggestions"])

    def test_no_raw_values_persisted(self) -> None:
        report = self._run()
        blob = json.dumps(report.as_dict(), ensure_ascii=False)
        self.assertNotIn(SENTINEL_EMAIL, blob)
        self.assertNotIn(SENTINEL_PHONE, blob)
        for path in Path(self._tmp.name).joinpath("data").glob("*.json"):
            content = path.read_text(encoding="utf-8")
            self.assertNotIn(SENTINEL_EMAIL, content)
            self.assertNotIn(SENTINEL_PHONE, content)
        email_column = next(c for c in report.columns if c["name"] == "email")
        self.assertEqual(email_column["distinct"], 8)
        self.assertEqual(len(email_column["stream_digest"]), 64)

    def test_source_file_untouched(self) -> None:
        before = self.csv_path.read_bytes()
        self._run()
        self.assertEqual(self.csv_path.read_bytes(), before)

    def test_verify_fresh_with_same_parameters(self) -> None:
        report = self._run()
        verdict = verify_precheck(
            self.runtime,
            report_id=report.identifier,
            policy_id="p-mask",
            scope=Scope("users"),
        )
        self.assertEqual(verdict["verdict"], "fresh")
        self.assertEqual(verdict["drifted"], [])

    def test_verify_stale_when_scope_changes(self) -> None:
        report = self._run()
        verdict = verify_precheck(
            self.runtime,
            report_id=report.identifier,
            policy_id="p-mask",
            scope=Scope.parse("users", "region=cn"),
        )
        self.assertEqual(verdict["verdict"], "stale")
        self.assertIn("scope", verdict["drifted"])

    def test_verify_stale_when_rule_changes(self) -> None:
        report = self._run()
        self.runtime.rules.remove("r-phone")
        self.runtime.rules.add(Rule("r-phone", "phone", "tokenize", {}))
        verdict = verify_precheck(
            self.runtime,
            report_id=report.identifier,
            policy_id="p-mask",
            scope=Scope("users"),
        )
        self.assertEqual(verdict["verdict"], "stale")
        self.assertIn("rules", verdict["drifted"])

    def test_verify_stale_when_dataset_changes(self) -> None:
        report = self._run()
        dataset = self.runtime.datasets.get("users")
        self.runtime.datasets.save(
            Dataset(
                identifier=dataset.identifier,
                source=dataset.source,
                owner=dataset.owner,
                fields=dataset.fields + (Field("nickname", "public", "data-team"),),
            )
        )
        verdict = verify_precheck(
            self.runtime,
            report_id=report.identifier,
            policy_id="p-mask",
            scope=Scope("users"),
        )
        self.assertEqual(verdict["verdict"], "stale")
        self.assertIn("dataset", verdict["drifted"])

    def test_verify_expired_when_ttl_elapses(self) -> None:
        report = self._run(ttl_seconds=0)
        verdict = verify_precheck(
            self.runtime,
            report_id=report.identifier,
            policy_id="p-mask",
            scope=Scope("users"),
        )
        self.assertEqual(verdict["verdict"], "expired")
        self.assertTrue(verdict["expired"])

    def test_zero_budget_truncates_scan(self) -> None:
        report = self._run(budget_ms=0)
        self.assertFalse(report.scan["completed"])
        self.assertEqual(report.scan["rows_profiled"], 0)
        self.assertTrue(report.affected_rows_estimated)
        codes = {finding["code"] for finding in report.risk["findings"]}
        self.assertIn("sampled_scan", codes)

    def test_filter_narrows_scope(self) -> None:
        report = self._run(scope=Scope.parse("users", "region=cn"))
        self.assertEqual(report.scan["rows_seen"], 6)
        self.assertEqual(report.affected_rows, 6)

    def test_unknown_filter_field_rejected(self) -> None:
        with self.assertRaises(InvalidRequest):
            self._run(scope=Scope.parse("users", "unknown=x"))

    def test_policy_must_target_dataset(self) -> None:
        self.runtime.datasets.save(
            Dataset(
                identifier="orders",
                source="src-users",
                owner="data-team",
                fields=(Field("order_id", "public", "data-team"),),
            )
        )
        with self.assertRaises(NotFound):
            self._run(scope=Scope("orders"))

    def test_http_round_trip(self) -> None:
        router = build_router(self.runtime)
        run_response = router.dispatch(
            Request(
                method="POST",
                path="/precheck",
                query={},
                headers={},
                body=json.dumps({"policy": "p-mask", "dataset": "users"}).encode("utf-8"),
            )
        )
        self.assertEqual(run_response.status, 200)
        report = json.loads(run_response.payload)
        self.assertEqual(report["affected_rows"], 8)
        self.assertEqual(report["risk"]["level"], "high")

        verify_response = router.dispatch(
            Request(
                method="POST",
                path="/precheck/verify",
                query={},
                headers={},
                body=json.dumps(
                    {
                        "report": report["identifier"],
                        "policy": "p-mask",
                        "dataset": "users",
                    }
                ).encode("utf-8"),
            )
        )
        self.assertEqual(verify_response.status, 200)
        self.assertEqual(json.loads(verify_response.payload)["verdict"], "fresh")

        list_response = router.dispatch(
            Request(method="GET", path="/prechecks", query={}, headers={})
        )
        self.assertEqual(json.loads(list_response.payload)["count"], 1)


if __name__ == "__main__":
    unittest.main()
