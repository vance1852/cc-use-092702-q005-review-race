from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

from taxonomy_lab.analysis import analyze
from taxonomy_lab.clock import FrozenClock
from taxonomy_lab.errors import Conflict, Forbidden, InvalidState, NotFound
from taxonomy_lab.jsonio import load_json
from taxonomy_lab.service import TaxonomyLabService
from taxonomy_lab.storage import connect


ROOT = Path(__file__).resolve().parents[1]


class ExclusionDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = TaxonomyLabService(self.connection, self.clock)
        for user_id, role in (
            ("operator", "operator"),
            ("stat-a", "statistician"),
            ("stat-b", "statistician"),
            ("approver", "approver"),
            ("auditor", "auditor"),
        ):
            self.service.create_user(user_id, user_id, role)
        self.evidence_protocol = load_json(ROOT / "fixtures" / "demo_evidence_protocol.json")
        self.rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_evidence_items.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.service.register_device("operator", "scope-a", "A 型", "厂商")
        self.service.register_build("operator", "build-a", "scope-a", "1.0", "b" * 64)
        self.service.publish_evidence_protocol("stat-a", self.evidence_protocol)
        self.service.create_batch("operator", "batch-a", "demo-taxonomy-v1", 1, "build-a")
        self.service.start_batch("operator", "batch-a", 1)
        self.service.import_evidence_items("operator", "batch-a", "key-1", self.rows)
        self.item_id = self.connection.execute(
            "SELECT evidence_item_id FROM evidence_items ORDER BY evidence_item_id LIMIT 1"
        ).fetchone()[0]

    def tearDown(self) -> None:
        self.connection.close()

    def _request(self) -> dict:
        return self.service.request_exclusion("operator", self.item_id, "现场记录失效")

    def _terminal_count(self, exclusion_id: int) -> int:
        return self.connection.execute(
            "SELECT count(*) FROM exclusion_decisions WHERE exclusion_id=?", (exclusion_id,)
        ).fetchone()[0]

    def _terminal_audit_count(self, exclusion_id: int) -> int:
        return self.connection.execute(
            "SELECT count(*) FROM audit_events "
            "WHERE entity_type='exclusion' AND entity_id=? AND event_type IN ('exclusion.approved','exclusion.rejected')",
            (str(exclusion_id),),
        ).fetchone()[0]

    # —— 单终局：数据库竞争下相反结论只有一个生效 ——

    def test_opposite_late_decision_conflicts_and_keeps_single_terminal(self) -> None:
        requested = self._request()
        exclusion_id = requested["exclusion_id"]
        approved = self.service.review_exclusion("stat-a", exclusion_id, True, "批准说明")
        self.assertEqual(approved["decision"], "approved")
        self.assertFalse(approved["replayed"])
        # 迟到的相反结论：可识别的业务冲突
        with self.assertRaises(Conflict):
            self.service.review_exclusion("stat-b", exclusion_id, False, "迟到的驳回")
        # 只有一条终局，终局仍是批准，申请状态也仍是 approved
        self.assertEqual(self._terminal_count(exclusion_id), 1)
        self.assertEqual(self._terminal_audit_count(exclusion_id), 1)
        status = self.connection.execute(
            "SELECT status FROM exclusion_requests WHERE exclusion_id=?", (exclusion_id,)
        ).fetchone()[0]
        self.assertEqual(status, "approved")

    def test_same_decision_replay_returns_existing_without_writing(self) -> None:
        requested = self._request()
        exclusion_id = requested["exclusion_id"]
        first = self.service.review_exclusion("stat-a", exclusion_id, True, "批准说明")
        second = self.service.review_exclusion("stat-b", exclusion_id, True, "相同结论再次提交")
        self.assertTrue(second["replayed"])
        self.assertEqual(second["decision_id"], first["decision_id"])
        self.assertEqual(second["reviewed_by"], first["reviewed_by"])
        self.assertEqual(second["note"], first["note"])
        self.assertEqual(self._terminal_count(exclusion_id), 1)
        self.assertEqual(self._terminal_audit_count(exclusion_id), 1)

    def test_concurrent_opposite_reviews_produce_single_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "race.sqlite3"
            seed = connect(database)
            try:
                seeder = TaxonomyLabService(seed, self.clock)
                for user_id, role in (
                    ("operator", "operator"),
                    ("stat-a", "statistician"),
                    ("stat-b", "statistician"),
                ):
                    seeder.create_user(user_id, user_id, role)
                seeder.register_device("operator", "scope-a", "A 型", "厂商")
                seeder.register_build("operator", "build-a", "scope-a", "1.0", "b" * 64)
                seeder.publish_evidence_protocol("stat-a", self.evidence_protocol)
                seeder.create_batch("operator", "batch-a", "demo-taxonomy-v1", 1, "build-a")
                seeder.start_batch("operator", "batch-a", 1)
                seeder.import_evidence_items("operator", "batch-a", "key-1", self.rows)
                item_id = seed.execute(
                    "SELECT evidence_item_id FROM evidence_items ORDER BY evidence_item_id LIMIT 1"
                ).fetchone()[0]
                exclusion_id = seeder.request_exclusion("operator", item_id, "竞争排除")["exclusion_id"]
            finally:
                seed.close()

            results: dict[str, object] = {}
            barrier = threading.Barrier(2)

            def worker(name: str, reviewer: str, approve: bool) -> None:
                connection = connect(database)
                try:
                    service = TaxonomyLabService(connection, self.clock)
                    barrier.wait()
                    results[name] = service.review_exclusion(reviewer, exclusion_id, approve, name)
                except Exception as exc:  # noqa: BLE001 - 记录竞争结果
                    results[name] = exc
                finally:
                    connection.close()

            t1 = threading.Thread(target=worker, args=("a", "stat-a", True))
            t2 = threading.Thread(target=worker, args=("b", "stat-b", False))
            t1.start()
            t2.start()
            t1.join()
            t2.join()

            values = list(results.values())
            successes = [v for v in values if not isinstance(v, Exception)]
            conflicts = [v for v in values if isinstance(v, Conflict)]
            self.assertEqual(len(successes), 1, f"应有且仅有一个决定生效: {results}")
            self.assertEqual(len(conflicts), 1)
            # 无论谁胜出，数据库中只有一条终局、一条终局审计，且二者结论一致
            checker = connect(database)
            try:
                terminal = checker.execute(
                    "SELECT d.decision AS decision,e.status AS status FROM exclusion_decisions d "
                    "JOIN exclusion_requests e ON e.exclusion_id=d.exclusion_id WHERE d.exclusion_id=?",
                    (exclusion_id,),
                ).fetchone()
                decision_count = checker.execute(
                    "SELECT count(*) FROM exclusion_decisions WHERE exclusion_id=?", (exclusion_id,)
                ).fetchone()[0]
                audit_count = checker.execute(
                    "SELECT count(*) FROM audit_events WHERE entity_type='exclusion' AND entity_id=? "
                    "AND event_type IN ('exclusion.approved','exclusion.rejected')",
                    (str(exclusion_id),),
                ).fetchone()[0]
            finally:
                checker.close()
            self.assertEqual(decision_count, 1)
            self.assertEqual(audit_count, 1)
            self.assertEqual(terminal["status"], terminal["decision"])
            self.assertEqual(successes[0]["decision"], terminal["decision"])

    # —— 既有规则：回避、角色授权 ——

    def test_applicant_cannot_review_own_request(self) -> None:
        exclusion_id = self._request()["exclusion_id"]
        with self.assertRaises(Forbidden):
            self.service.review_exclusion("operator", exclusion_id, True, "自批")

    def test_role_without_review_permission_is_forbidden(self) -> None:
        exclusion_id = self._request()["exclusion_id"]
        with self.assertRaises(Forbidden):
            self.service.review_exclusion("approver", exclusion_id, True, "越权")
        self.assertEqual(self._terminal_count(exclusion_id), 0)

    def test_review_unknown_request_is_not_found(self) -> None:
        with self.assertRaises(NotFound):
            self.service.review_exclusion("stat-a", 99999, True, "不存在")

    # —— 撤销后 / 驳回后重新申请仍按版本工作 ——

    def test_reapply_after_rejection_uses_new_version(self) -> None:
        first = self._request()
        self.service.review_exclusion("stat-a", first["exclusion_id"], False, "证据不足")
        second = self.service.request_exclusion("operator", self.item_id, "补充材料后再次申请")
        self.assertEqual(second["attempt_no"], first["attempt_no"] + 1)
        approved = self.service.review_exclusion("stat-a", second["exclusion_id"], True, "现在充分")
        self.assertEqual(approved["status"], "approved")
        report = self.service.report("auditor", "batch-a")
        history = [e for e in report["exclusions"] if e["evidence_item_id"] == self.item_id]
        self.assertEqual([e["attempt_no"] for e in history], [1, 2])
        self.assertEqual([e["status"] for e in history], ["rejected", "approved"])
        self.assertEqual(len(report["effective_exclusions"]), 1)
        self.assertEqual(report["effective_exclusions"][0]["attempt_no"], 2)

    def test_reapply_after_revoke_takes_effect_anew(self) -> None:
        first = self._request()
        self.service.review_exclusion("stat-a", first["exclusion_id"], True, "批准")
        self.service.revoke_exclusion("operator", first["exclusion_id"], "记录找回")
        # 撤销后样本不再被排除
        protocol, _ = self.service._evidence_protocol("demo-taxonomy-v1", 1)
        self.assertTrue(
            all(item.excluded_reason is None for item in self.service._analysis_evidence_items("batch-a", protocol))
        )
        second = self.service.request_exclusion("operator", self.item_id, "再次失效")
        self.assertEqual(second["attempt_no"], 2)
        self.service.review_exclusion("stat-b", second["exclusion_id"], True, "重新批准")
        items = self.service._analysis_evidence_items("batch-a", protocol)
        excluded = [item for item in items if item.excluded_reason is not None]
        self.assertEqual(len(excluded), 1)
        included = [item for item in items if item.excluded_reason is None]
        result = analyze(protocol, tuple(included))
        self.assertIsNotNone(result)

    def test_cannot_request_while_one_pending(self) -> None:
        self._request()
        with self.assertRaises(Conflict):
            self.service.request_exclusion("operator", self.item_id, "重复申请")

    def test_revoked_request_cannot_be_replayed_into_effect(self) -> None:
        exclusion_id = self._request()["exclusion_id"]
        self.service.review_exclusion("stat-a", exclusion_id, True, "批准")
        self.service.revoke_exclusion("operator", exclusion_id, "记录找回")
        # 即便提交与历史终局相同的批准，也不能让已撤销的这一轮重新生效
        with self.assertRaises(InvalidState):
            self.service.review_exclusion("stat-a", exclusion_id, True, "试图重放")
        with self.assertRaises(InvalidState):
            self.service.review_exclusion("stat-a", exclusion_id, False, "试图改判")
        self.assertEqual(self._terminal_count(exclusion_id), 1)

    def test_only_requester_may_revoke(self) -> None:
        exclusion_id = self._request()["exclusion_id"]
        self.service.review_exclusion("stat-a", exclusion_id, True, "批准")
        with self.assertRaises(Forbidden):
            self.service.revoke_exclusion("stat-a", exclusion_id, "非申请人撤销")

    # —— 审计事件与“是否参与分析”状态不得分歧 ——

    def test_audit_and_analysis_state_align_with_effective_decision(self) -> None:
        exclusion_id = self._request()["exclusion_id"]
        self.service.review_exclusion("stat-a", exclusion_id, True, "批准排除")
        protocol, _ = self.service._evidence_protocol("demo-taxonomy-v1", 1)
        items = self.service._analysis_evidence_items("batch-a", protocol)
        excluded = [item for item in items if item.excluded_reason is not None]
        self.assertEqual(len(excluded), 1)
        # 终局审计与生效状态一致
        self.assertEqual(self._terminal_audit_count(exclusion_id), 1)
        # 驳回不应排除样本：另取一个样本来验证驳回路径
        other_item = self.connection.execute(
            "SELECT evidence_item_id FROM evidence_items WHERE evidence_item_id!=? "
            "ORDER BY evidence_item_id LIMIT 1", (self.item_id,),
        ).fetchone()[0]
        other = self.service.request_exclusion("operator", other_item, "存疑")
        self.service.review_exclusion("stat-a", other["exclusion_id"], False, "驳回")
        items = self.service._analysis_evidence_items("batch-a", protocol)
        excluded_ids = {
            self.connection.execute(
                "SELECT evidence_item_id FROM evidence_items o WHERE o.evidence_group_key=? LIMIT 1",
                (item.evidence_group_key,),
            ).fetchone()[0]
            for item in items if item.excluded_reason is not None
        }
        self.assertNotIn(other_item, excluded_ids)
        self.assertIn(self.item_id, excluded_ids)

    def test_report_distinguishes_effective_version_history_and_operators(self) -> None:
        first = self._request()
        self.service.review_exclusion("stat-a", first["exclusion_id"], False, "首驳", )
        second = self.service.request_exclusion("operator", self.item_id, "第二轮")
        self.service.review_exclusion("stat-b", second["exclusion_id"], True, "二批准")
        report = self.service.report("auditor", "batch-a")
        history = [e for e in report["exclusions"] if e["evidence_item_id"] == self.item_id]
        self.assertEqual(len(history), 2)
        v1, v2 = history
        self.assertFalse(v1["effective"])
        self.assertEqual(v1["terminal_decision"]["decision"], "rejected")
        self.assertEqual(v1["terminal_decision"]["decided_by"], "stat-a")
        self.assertTrue(v2["effective"])
        self.assertEqual(v2["terminal_decision"]["decision"], "approved")
        self.assertEqual(v2["terminal_decision"]["decided_by"], "stat-b")
        self.assertEqual(v2["requested_by"], "operator")
        # 有效决定只指向第二版
        effective = report["effective_exclusions"]
        self.assertEqual(len(effective), 1)
        self.assertEqual(effective[0]["exclusion_id"], second["exclusion_id"])
        self.assertEqual(effective[0]["decision_id"], v2["terminal_decision"]["decision_id"])
        # 每版历史都带完整操作者审计轨迹（申请 + 终局）
        self.assertEqual([e["event_type"] for e in v1["events"]], ["exclusion.requested", "exclusion.rejected"])
        self.assertEqual([e["event_type"] for e in v2["events"]], ["exclusion.requested", "exclusion.approved"])

    def test_revoking_approved_after_seal_is_rejected(self) -> None:
        exclusion_id = self._request()["exclusion_id"]
        self.service.review_exclusion("stat-a", exclusion_id, True, "批准")
        self.service.seal_batch("stat-a", "batch-a", 2)
        with self.assertRaises(InvalidState):
            self.service.revoke_exclusion("operator", exclusion_id, "封存后撤销")


if __name__ == "__main__":
    unittest.main()
