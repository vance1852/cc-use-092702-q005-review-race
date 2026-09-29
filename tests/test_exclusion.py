from __future__ import annotations

import json
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

from taxonomy_lab.clock import FrozenClock
from taxonomy_lab.errors import Conflict, ExclusionAlreadyDecided, Forbidden, InvalidState
from taxonomy_lab.jsonio import load_json
from taxonomy_lab.service import TaxonomyLabService
from taxonomy_lab.storage import connect

ROOT = Path(__file__).resolve().parents[1]


class ExclusionSingleTerminalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "lab.sqlite3"
        connection = connect(self.database)
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = TaxonomyLabService(connection, self.clock)
        for user_id, role in (
            ("operator", "operator"),
            ("stat", "statistician"),
            ("stat2", "statistician"),
            ("auditor", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)
        protocol = load_json(ROOT / "fixtures" / "demo_evidence_protocol.json")
        self.rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_evidence_items.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.service.register_device("operator", "scope-a", "A 型", "厂商")
        self.service.register_build("operator", "build-a", "scope-a", "1.0", "b" * 64)
        self.service.publish_evidence_protocol("stat", protocol)
        self.service.create_batch("operator", "batch-a", "demo-taxonomy-v1", 1, "build-a")
        self.service.start_batch("operator", "batch-a", 1)
        self.service.import_evidence_items("operator", "batch-a", "key-1", self.rows)
        self.item_id = connection.execute(
            "SELECT evidence_item_id FROM evidence_items ORDER BY evidence_item_id LIMIT 1"
        ).fetchone()[0]

    def tearDown(self) -> None:
        self.service.connection.close()
        self.temporary.cleanup()

    def _another_service(self) -> TaxonomyLabService:
        return TaxonomyLabService(connect(self.database), self.clock)

    def test_contradictory_concurrent_reviews_leave_one_terminal(self) -> None:
        requested = self.service.request_exclusion("operator", self.item_id, "现场记录失效")
        exclusion_id = requested["exclusion_id"]
        barrier = threading.Barrier(2)
        outcomes: dict[str, object] = {}

        def review(name: str, actor: str, approve: bool) -> None:
            service = self._another_service()
            try:
                barrier.wait(timeout=5)
                outcomes[name] = service.review_exclusion(actor, exclusion_id, approve, "同时给出的结论")
            except BaseException as exc:  # noqa: BLE001 - 记录竞争失败方的业务冲突
                outcomes[name] = exc
            finally:
                service.connection.close()

        thread_a = threading.Thread(target=review, args=("a", "stat", True))
        thread_b = threading.Thread(target=review, args=("b", "stat2", False))
        thread_a.start()
        thread_b.start()
        thread_a.join(timeout=10)
        thread_b.join(timeout=10)

        winner = outcomes["a"] if not isinstance(outcomes["a"], BaseException) else outcomes["b"]
        loser = outcomes["b"] if winner is outcomes["a"] else outcomes["a"]
        self.assertNotIsInstance(winner, BaseException)
        self.assertIsInstance(loser, ExclusionAlreadyDecided)

        row = self.service.connection.execute(
            "SELECT status,reviewed_by,review_request_sha256 FROM exclusion_requests WHERE exclusion_id=?",
            (exclusion_id,),
        ).fetchone()
        self.assertEqual(row["status"], winner["status"])
        self.assertEqual(row["reviewed_by"], winner["reviewed_by"])
        self.assertIn(row["status"], {"approved", "rejected"})

        # 只有胜出的决定留下终局审计，失败调用不得追加事件或第二条终局。
        terminal_events = self.service.connection.execute(
            "SELECT event_type FROM audit_events WHERE entity_type='exclusion' AND entity_id=?",
            (str(exclusion_id),),
        ).fetchall()
        self.assertEqual([row[0] for row in terminal_events], [f"exclusion.{winner['status']}"])
        self.assertEqual(
            self.service.connection.execute("SELECT count(*) FROM exclusion_requests").fetchone()[0], 1
        )

    def test_same_content_resubmit_returns_decision_without_second_terminal(self) -> None:
        requested = self.service.request_exclusion("operator", self.item_id, "现场记录失效")
        exclusion_id = requested["exclusion_id"]
        first = self.service.review_exclusion("stat", exclusion_id, True, "同意排除")
        self.assertFalse(first["replayed"])

        service_b = self._another_service()
        try:
            replay = service_b.review_exclusion("stat", exclusion_id, True, "同意排除")
        finally:
            service_b.connection.close()
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["status"], "approved")
        self.assertEqual(replay["exclusion_id"], first["exclusion_id"])
        self.assertEqual(
            self.service.connection.execute(
                "SELECT count(*) FROM audit_events WHERE entity_type='exclusion'"
            ).fetchone()[0],
            1,
        )

    def test_late_opposite_conclusion_is_identifiable_conflict(self) -> None:
        requested = self.service.request_exclusion("operator", self.item_id, "现场记录失效")
        exclusion_id = requested["exclusion_id"]
        self.service.review_exclusion("stat", exclusion_id, True, "批准")
        with self.assertRaises(ExclusionAlreadyDecided):
            self.service.review_exclusion("stat2", exclusion_id, False, "迟到的驳回")
        # 迟到请求使用的业务错误必须可识别，且不能改变既有终局。
        self.assertEqual(
            self.service.connection.execute(
                "SELECT status FROM exclusion_requests WHERE exclusion_id=?", (exclusion_id,)
            ).fetchone()[0],
            "approved",
        )

    def test_applicant_recusal_and_role_rules_remain(self) -> None:
        requested = self.service.request_exclusion("operator", self.item_id, "原因")
        with self.assertRaises(Forbidden):
            self.service.review_exclusion("operator", requested["exclusion_id"], True, "自己批准")
        with self.assertRaises(Forbidden):
            self.service.review_exclusion("operator", requested["exclusion_id"], False, "自己驳回")

        auditor_service = self._another_service()
        try:
            with self.assertRaises(Forbidden):
                auditor_service.review_exclusion("auditor", requested["exclusion_id"], True, "越权")
        finally:
            auditor_service.connection.close()

    def test_rejected_request_allows_reapplication_with_new_round(self) -> None:
        first = self.service.request_exclusion("operator", self.item_id, "初次理由")
        self.assertEqual(first["round_version"], 1)
        self.service.review_exclusion("stat", first["exclusion_id"], False, "证据不足")
        second = self.service.request_exclusion("operator", self.item_id, "补充理由")
        self.assertEqual(second["round_version"], 2)
        self.service.review_exclusion("stat2", second["exclusion_id"], True, "现在充分")

        view = self.service.get_exclusion("auditor", self.item_id)
        self.assertFalse(view["participates_in_analysis"])
        self.assertEqual(view["effective"]["exclusion_id"], second["exclusion_id"])
        self.assertEqual(view["effective"]["round_version"], 2)
        self.assertEqual(view["effective"]["reviewed_by"], "stat2")
        self.assertEqual([record["round_version"] for record in view["history"]], [1, 2])
        self.assertEqual([record["status"] for record in view["history"]], ["rejected", "approved"])

    def test_revoke_then_reapply_keeps_full_history_and_restores_participation(self) -> None:
        first = self.service.request_exclusion("operator", self.item_id, "现场记录失效")
        self.service.review_exclusion("stat", first["exclusion_id"], True, "同意")
        self.assertFalse(self.service.get_exclusion("auditor", self.item_id)["participates_in_analysis"])

        self.service.revoke_exclusion("operator", first["exclusion_id"], "记录找回")
        between = self.service.get_exclusion("auditor", self.item_id)
        self.assertTrue(between["participates_in_analysis"])
        self.assertIsNone(between["effective"])
        self.assertEqual(between["history"][-1]["status"], "revoked")

        second = self.service.request_exclusion("operator", self.item_id, "再次失效")
        self.service.review_exclusion("stat2", second["exclusion_id"], True, "同意")
        final = self.service.get_exclusion("auditor", self.item_id)
        self.assertEqual(final["effective"]["round_version"], 2)
        self.assertEqual([r["status"] for r in final["history"]], ["revoked", "approved"])

    def test_pending_means_still_participating_and_revoke_requires_approval(self) -> None:
        requested = self.service.request_exclusion("operator", self.item_id, "待复核")
        view = self.service.get_exclusion("auditor", self.item_id)
        self.assertTrue(view["participates_in_analysis"])
        self.assertEqual(view["effective"]["status"], "pending")
        with self.assertRaises(InvalidState):
            self.service.revoke_exclusion("operator", requested["exclusion_id"], "不能撤销待复核")

    def test_double_request_conflict_and_query_unknown_item(self) -> None:
        self.service.request_exclusion("operator", self.item_id, "第一次")
        with self.assertRaises(Conflict):
            self.service.request_exclusion("operator", self.item_id, "重复申请")
        from taxonomy_lab.errors import NotFound

        with self.assertRaises(NotFound):
            self.service.get_exclusion("auditor", 999_999)

    def test_report_separates_effective_decision_from_history_and_audit(self) -> None:
        first = self.service.request_exclusion("operator", self.item_id, "初次理由")
        self.service.review_exclusion("stat", first["exclusion_id"], False, "驳回")
        second = self.service.request_exclusion("operator", self.item_id, "补充理由")
        self.service.review_exclusion("stat2", second["exclusion_id"], True, "批准")

        report = self.service.report("auditor", "batch-a")
        self.assertEqual(len(report["exclusions"]), 2)
        self.assertEqual(len(report["effective_exclusions"]), 1)
        effective = report["effective_exclusions"][0]
        self.assertEqual(effective["exclusion_id"], second["exclusion_id"])
        self.assertEqual(effective["round_version"], 2)
        event_types = {event["event_type"] for event in report["events"]}
        self.assertIn("exclusion.approved", event_types)
        self.assertIn("exclusion.rejected", event_types)
        self.assertIn("exclusion.requested", event_types)

        review_events = [
            event for event in report["events"]
            if event["event_type"] in {"exclusion.approved", "exclusion.rejected"}
        ]
        self.assertEqual(len(review_events), 2)
        approved_event = next(event for event in review_events if event["event_type"] == "exclusion.approved")
        self.assertEqual(approved_event["actor_id"], "stat2")
        self.assertEqual(approved_event["payload"]["round_version"], 2)


if __name__ == "__main__":
    unittest.main()
