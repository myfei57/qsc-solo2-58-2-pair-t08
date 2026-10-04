"""HTTP-level integration: preflight -> blocked/allowed execute over the wire."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

from maskhub.bootstrap import create_server
from maskhub.config import Settings

from tests.test_preflight import DATASET_ID, _build_source_db


def _post(url: str, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _get(url: str) -> tuple[int, dict[str, object]]:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


class HttpFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.source_db = root / "source.db"
        _build_source_db(self.source_db)
        self.settings = Settings(
            data_dir=str(root / "data"), host="127.0.0.1", port=0
        )
        self.server = create_server(self.settings)
        self.server.start()
        self.base = self.server.url
        threading.Event().wait(0.05)

    def tearDown(self) -> None:
        self.server.stop()
        self.tmp.cleanup()

    def _seed(self) -> None:
        _post(f"{self.base}/sources", {"identifier": "crm-db", "kind": "sqlite",
                                        "endpoint": str(self.source_db)})
        _post(
            f"{self.base}/datasets",
            {
                "identifier": DATASET_ID,
                "source": "crm-db",
                "owner": "data-team",
                "watermark_column": "updated_at",
                "fields": [
                    {"name": "id", "sensitivity": "public"},
                    {"name": "region", "sensitivity": "public"},
                    {"name": "id_card", "sensitivity": "special"},
                    {"name": "email", "sensitivity": "sensitive"},
                    {"name": "phone", "sensitivity": "personal"},
                    {"name": "updated_at", "sensitivity": "public"},
                ],
            },
        )
        _post(f"{self.base}/rules", {"identifier": "r-idcard", "field_pattern": "id_card",
                                     "action": "hash", "parameters": {}})
        _post(f"{self.base}/rules", {"identifier": "r-email", "field_pattern": "email",
                                     "action": "redact", "parameters": {}})
        _post(
            f"{self.base}/policies",
            {"identifier": "p-pii", "datasets": [DATASET_ID],
             "rules": ["r-idcard", "r-email"]},
        )
        _post(
            f"{self.base}/consumers",
            {
                "identifier": "risk-join",
                "kind": "model",
                "owner": "risk",
                "reads": [{"column": f"{DATASET_ID}.id_card", "usage": "join_key"}],
            },
        )

    def test_preflight_then_execute_over_http(self) -> None:
        self._seed()
        scope = {"filters": [{"op": "eq", "column": "region", "value": "south"}]}
        status, ticket = _post(
            f"{self.base}/preflight/run",
            {"policy": "p-pii", "dataset": DATASET_ID, "scope": scope, "salt": "abc"},
        )
        self.assertEqual(status, 200, ticket)
        self.assertEqual(ticket["risk"]["verdict"], "WARN")

        status, fetched = _get(f"{self.base}/preflight/ticket?ticket={ticket['ticket_id']}")
        self.assertEqual(status, 200)
        self.assertEqual(fetched["ticket_id"], ticket["ticket_id"])

        # Salt omitted -> scope/options hash still matches but salt differs -> 409.
        status, body = _post(
            f"{self.base}/policy/execute",
            {"ticket": ticket["ticket_id"], "scope": scope},
        )
        self.assertEqual(status, 400)

        status, result = _post(
            f"{self.base}/policy/execute",
            {"ticket": ticket["ticket_id"], "scope": scope, "salt": "abc"},
        )
        self.assertEqual(status, 200, result)
        self.assertEqual(result["updated_rows"], 60)

        connection = sqlite3.connect(self.source_db)
        untouched = connection.execute(
            f"SELECT COUNT(*) FROM {DATASET_ID} WHERE email <> '***' AND region = 'south'"
        ).fetchone()[0]
        connection.close()
        self.assertEqual(untouched, 0)

        # The audit journal records both phases.
        status, audit = _get(f"{self.base}/audit")
        actions = {entry["action"] for entry in audit["entries"]}
        self.assertIn("preflight.run", actions)
        self.assertIn("policy.execute", actions)

    def test_unknown_source_kind_returns_503(self) -> None:
        self._seed()
        # Register a second dataset pointing at an unsupported source kind.
        _post(f"{self.base}/sources", {"identifier": "oracle-db", "kind": "oracle",
                                        "endpoint": "oracle://nowhere"})
        _post(
            f"{self.base}/datasets",
            {
                "identifier": "other",
                "source": "oracle-db",
                "owner": "data-team",
                "fields": [{"name": "id", "sensitivity": "public"}],
            },
        )
        _post(
            f"{self.base}/policies",
            {"identifier": "p-other", "datasets": ["other"], "rules": ["r-idcard"]},
        )
        status, body = _post(
            f"{self.base}/preflight/run",
            {"policy": "p-other", "dataset": "other", "salt": "x"},
        )
        self.assertEqual(status, 503, body)
        self.assertIn("unsupported source kind", body["error"])


if __name__ == "__main__":
    unittest.main()
