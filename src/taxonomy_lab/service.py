"""分类实验观察采信服务的领域用例。"""

from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from decimal import Decimal
from typing import Any, Iterable, Mapping

from .analysis import ALGORITHM_VERSION, analyze
from .clock import SystemClock, isoformat
from .contracts import EvidenceItem, EvidenceProtocol, ValidationError
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .jsonio import canonical_json, content_digest
from .storage import initialize, transaction


ROLE_PERMISSIONS = {
    "operator": {
        "catalog.write", "batch.create", "batch.start", "evidence_item.import",
        "exclusion.request", "exclusion.revoke",
    },
    "statistician": {"evidence_protocol.publish", "batch.seal", "exclusion.review", "analysis.run"},
    "approver": {"decision.write"},
    "auditor": {"report.read", "audit.read"},
}


class TaxonomyLabService:
    """在单个 SQLite 连接上提供全部业务操作。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    def _now(self) -> str:
        return isoformat(self.clock.now())

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT user_id, display_name, role, active FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        user = self._user(user_id)
        if permission not in ROLE_PERMISSIONS[user["role"]]:
            raise Forbidden(f"角色 {user['role']} 无权执行 {permission}")
        return user

    def _audit(
        self, entity_type: str, entity_id: str, event_type: str, actor_id: str, payload: Mapping[str, Any]
    ) -> None:
        self.connection.execute(
            "INSERT INTO audit_events(entity_type,entity_id,event_type,actor_id,payload_json,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (entity_type, entity_id, event_type, actor_id, canonical_json(payload), self._now()),
        )

    def create_user(self, user_id: str, display_name: str, role: str) -> dict[str, Any]:
        if role not in ROLE_PERMISSIONS:
            raise ValidationFailed(f"未知角色: {role}")
        if not user_id.strip() or not display_name.strip():
            raise ValidationFailed("用户编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO users(user_id,display_name,role) VALUES(?,?,?)",
                    (user_id.strip(), display_name.strip(), role),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"用户已存在: {user_id}") from exc
        return {"user_id": user_id.strip(), "role": role}

    def register_device(
        self, actor_id: str, device_id: str, model_name: str, vendor: str
    ) -> dict[str, Any]:
        self._require(actor_id, "catalog.write")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO capture_devices(device_id,model_name,vendor,created_at) VALUES(?,?,?,?)",
                    (device_id, model_name, vendor, self._now()),
                )
                self._audit("device", device_id, "device.registered", actor_id, {"model_name": model_name})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"实验采集设备已存在: {device_id}") from exc
        return {"device_id": device_id, "model_name": model_name, "vendor": vendor}

    def register_build(
        self, actor_id: str, build_id: str, device_id: str, version: str, content_sha256: str
    ) -> dict[str, Any]:
        self._require(actor_id, "catalog.write")
        if len(content_sha256) != 64:
            raise ValidationFailed("构建摘要必须是 64 位 SHA-256")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO builds(build_id,device_id,version,content_sha256,created_at) VALUES(?,?,?,?,?)",
                    (build_id, device_id, version, content_sha256.lower(), self._now()),
                )
                self._audit("build", build_id, "build.registered", actor_id, {"device_id": device_id, "version": version})
        except sqlite3.IntegrityError as exc:
            raise Conflict("构建编号、版本或摘要冲突") from exc
        return {"build_id": build_id, "device_id": device_id, "version": version}

    def publish_evidence_protocol(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "evidence_protocol.publish")
        try:
            evidence_protocol = EvidenceProtocol.from_dict(raw)
        except ValidationError as exc:
            raise ValidationFailed(str(exc)) from exc
        text = canonical_json(raw)
        digest = content_digest([raw])
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO evidence_protocol_catalog(evidence_protocol_id,version,title,task_family,canonical_json,content_sha256,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        evidence_protocol.evidence_protocol_id,
                        evidence_protocol.version,
                        evidence_protocol.title,
                        evidence_protocol.task_family,
                        text,
                        digest,
                        self._now(),
                    ),
                )
                identity = f"{evidence_protocol.evidence_protocol_id}@{evidence_protocol.version}"
                self._audit("evidence_protocol", identity, "evidence_protocol.published", actor_id, {"sha256": digest})
        except sqlite3.IntegrityError as exc:
            raise Conflict("协议版本或内容摘要已经存在") from exc
        return {"evidence_protocol_id": evidence_protocol.evidence_protocol_id, "version": evidence_protocol.version, "sha256": digest}

    def _evidence_protocol(self, evidence_protocol_id: str, version: int) -> tuple[EvidenceProtocol, str]:
        row = self.connection.execute(
            "SELECT canonical_json,content_sha256 FROM evidence_protocol_catalog WHERE evidence_protocol_id=? AND version=?",
            (evidence_protocol_id, version),
        ).fetchone()
        if row is None:
            raise NotFound("协议版本不存在")
        return EvidenceProtocol.from_dict(json.loads(row["canonical_json"])), row["content_sha256"]

    def create_batch(
        self,
        actor_id: str,
        batch_id: str,
        evidence_protocol_id: str,
        evidence_protocol_version: int,
        build_id: str,
    ) -> dict[str, Any]:
        self._require(actor_id, "batch.create")
        self._evidence_protocol(evidence_protocol_id, evidence_protocol_version)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO batches(batch_id,evidence_protocol_id,evidence_protocol_version,build_id,state,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (batch_id, evidence_protocol_id, evidence_protocol_version, build_id, "draft", actor_id, self._now()),
                )
                self._audit("batch", batch_id, "batch.created", actor_id, {"build_id": build_id})
        except sqlite3.IntegrityError as exc:
            raise Conflict("批次编号冲突或构建不存在") from exc
        return self.get_batch(batch_id)

    def get_batch(self, batch_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM batches WHERE batch_id=?", (batch_id,)).fetchone()
        if row is None:
            raise NotFound("批次不存在")
        return dict(row)

    def start_batch(self, actor_id: str, batch_id: str, expected_revision: int) -> dict[str, Any]:
        self._require(actor_id, "batch.start")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE batches SET state='running',revision=revision+1,started_at=? "
                "WHERE batch_id=? AND state='draft' AND revision=?",
                (self._now(), batch_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise InvalidState("批次不是当前草稿版本")
            self._audit("batch", batch_id, "batch.started", actor_id, {"from_revision": expected_revision})
        return self.get_batch(batch_id)

    def _idempotent_response(self, scope: str, key: str, request_digest: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT request_sha256,response_json FROM idempotency_keys WHERE scope=? AND key=?",
            (scope, key),
        ).fetchone()
        if row is None:
            return None
        if row["request_sha256"] != request_digest:
            raise Conflict("同一幂等键对应了不同请求内容")
        return json.loads(row["response_json"])

    def import_evidence_items(
        self,
        actor_id: str,
        batch_id: str,
        idempotency_key: str,
        raw_rows: Iterable[Mapping[str, Any]],
    ) -> dict[str, Any]:
        self._require(actor_id, "evidence_item.import")
        rows = tuple(raw_rows)
        if not rows:
            raise ValidationFailed("观察记录数组不能为空")
        request_digest = content_digest(rows)
        scope = f"evidence_items:{batch_id}"
        existing = self._idempotent_response(scope, idempotency_key, request_digest)
        if existing is not None:
            return existing
        batch = self.get_batch(batch_id)
        if batch["state"] != "running":
            raise InvalidState("只有运行中的批次可以导入观察记录")
        evidence_protocol, _ = self._evidence_protocol(batch["evidence_protocol_id"], batch["evidence_protocol_version"])
        parsed: list[EvidenceItem] = []
        for raw in rows:
            try:
                item = EvidenceItem.from_dict(raw, evidence_protocol)
            except ValidationError as exc:
                raise ValidationFailed(str(exc)) from exc
            if item.device_id != self.connection.execute(
                "SELECT device_id FROM builds WHERE build_id=?", (batch["build_id"],)
            ).fetchone()["device_id"]:
                raise ValidationFailed("观察记录设备与批次登记不一致")
            parsed.append(item)
        response = {"batch_id": batch_id, "inserted": len(parsed), "request_sha256": request_digest}
        try:
            with transaction(self.connection, immediate=True):
                for item, raw in zip(parsed, rows):
                    self.connection.execute(
                        "INSERT INTO evidence_items(batch_id,source_batch,source_row,device_id,evidence_group_key,observed_at," 
                        "indicators_json,content_sha256,imported_by,imported_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (
                            batch_id,
                            item.source_batch,
                            item.source_row,
                            item.device_id,
                            item.evidence_group_key,
                            item.observed_at,
                            canonical_json({key: format(value, "f") for key, value in item.indicators.items()}),
                            content_digest([raw]),
                            actor_id,
                            self._now(),
                        ),
                    )
                self.connection.execute(
                    "INSERT INTO idempotency_keys(scope,key,request_sha256,response_json,created_at) VALUES(?,?,?,?,?)",
                    (scope, idempotency_key, request_digest, canonical_json(response), self._now()),
                )
                self._audit("batch", batch_id, "evidence_items.imported", actor_id, response)
        except sqlite3.IntegrityError as exc:
            raise Conflict("来源行重复或幂等键并发冲突") from exc
        return response

    def request_exclusion(self, actor_id: str, evidence_item_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "exclusion.request")
        evidence_item = self.connection.execute(
            "SELECT evidence_item_id FROM evidence_items WHERE evidence_item_id=?", (evidence_item_id,)
        ).fetchone()
        if evidence_item is None:
            raise NotFound("观察记录不存在")
        try:
            with transaction(self.connection, immediate=True):
                # 在写事务内取号：IMMEDIATE 锁让并发申请串行化，
                # 配合部分唯一索引，同一样本不会产生两个待处理/生效版本。
                next_attempt = self.connection.execute(
                    "SELECT COALESCE(MAX(attempt_no), 0) + 1 FROM exclusion_requests WHERE evidence_item_id=?",
                    (evidence_item_id,),
                ).fetchone()[0]
                cursor = self.connection.execute(
                    "INSERT INTO exclusion_requests("
                    "evidence_item_id,attempt_no,status,reason,requested_by,requested_at) "
                    "VALUES(?,?, 'pending',?,?,?)",
                    (evidence_item_id, next_attempt, reason, actor_id, self._now()),
                )
                exclusion_id = cursor.lastrowid
                self._audit(
                    "evidence_item",
                    str(evidence_item_id),
                    "exclusion.requested",
                    actor_id,
                    {"exclusion_id": exclusion_id, "attempt_no": next_attempt, "reason": reason},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("该观察记录已有待处理或生效排除") from exc
        return {
            "exclusion_id": exclusion_id,
            "evidence_item_id": evidence_item_id,
            "attempt_no": next_attempt,
            "status": "pending",
        }

    @staticmethod
    def _review_response(row: sqlite3.Row, *, replayed: bool) -> dict[str, Any]:
        """把终局决定行整理成对外响应；replayed 表示本次为相同内容的重放。"""

        return {
            "exclusion_id": row["exclusion_id"],
            "evidence_item_id": row["evidence_item_id"],
            "attempt_no": row["attempt_no"],
            "status": row["decision"],
            "decision_id": row["decision_id"],
            "decision": row["decision"],
            "reviewed_by": row["decided_by"],
            "reviewed_at": row["decided_at"],
            "note": row["note"],
            "replayed": replayed,
        }

    def review_exclusion(
        self, actor_id: str, exclusion_id: int, approve: bool, note: str
    ) -> dict[str, Any]:
        self._require(actor_id, "exclusion.review")
        requested_decision = "approved" if approve else "rejected"
        with transaction(self.connection, immediate=True):
            # 读、比较、写全部在同一个 IMMEDIATE 事务内：并发复核在此串行，
            # 后到者读到的一定是先提交者的终局，不可能再写入第二条终局。
            row = self.connection.execute(
                "SELECT e.exclusion_id,e.evidence_item_id,e.attempt_no,e.status,e.requested_by,"
                "d.decision_id,d.decision,d.decided_by,d.decided_at,d.note "
                "FROM exclusion_requests e "
                "LEFT JOIN exclusion_decisions d ON d.exclusion_id=e.exclusion_id "
                "WHERE e.exclusion_id=?",
                (exclusion_id,),
            ).fetchone()
            if row is None:
                raise NotFound("排除申请不存在")
            if row["requested_by"] == actor_id:
                raise Forbidden("申请人不能复核自己的排除申请")
            if row["status"] == "revoked":
                # 撤销关闭了本轮生命周期：历史终局仍可审计，但不能再“重放”为生效，
                # 必须由申请人重新发起（新版本）。
                raise InvalidState("排除已撤销，需重新发起排除申请")
            if row["decision"] is not None:
                # 已有终局：相同结论的再次提交按幂等重放返回原决定（零写入）；
                # 另一结论的迟到请求得到可识别的业务冲突，且不产生第二条终局。
                if row["decision"] == requested_decision:
                    return self._review_response(row, replayed=True)
                raise Conflict(
                    f"排除申请已有终局决定 {row['decision']}，"
                    f"迟到的 {requested_decision} 不发生效力"
                )
            if row["status"] != "pending":
                raise InvalidState("排除申请已经处理")
            try:
                cursor = self.connection.execute(
                    "INSERT INTO exclusion_decisions(exclusion_id,decision,note,decided_by,decided_at) "
                    "VALUES(?,?,?,?,?)",
                    (exclusion_id, requested_decision, note, actor_id, self._now()),
                )
            except sqlite3.IntegrityError:
                # 兜底：即便锁语义变化导致并发穿透，UNIQUE(exclusion_id) 也会挡住第二条终局。
                winner = self.connection.execute(
                    "SELECT e.exclusion_id,e.evidence_item_id,e.attempt_no,e.status,e.requested_by,"
                    "d.decision_id,d.decision,d.decided_by,d.decided_at,d.note "
                    "FROM exclusion_requests e JOIN exclusion_decisions d ON d.exclusion_id=e.exclusion_id "
                    "WHERE e.exclusion_id=?",
                    (exclusion_id,),
                ).fetchone()
                if winner is not None and winner["decision"] == requested_decision:
                    return self._review_response(winner, replayed=True)
                raise Conflict("排除申请在并发复核中已被另一结论终局，当前决定不发生效力") from None
            updated = self.connection.execute(
                "UPDATE exclusion_requests SET status=? WHERE exclusion_id=? AND status='pending'",
                (requested_decision, exclusion_id),
            )
            if updated.rowcount != 1:
                raise InvalidState("排除申请状态已变化")
            decision_id = cursor.lastrowid
            self._audit(
                "exclusion",
                str(exclusion_id),
                f"exclusion.{requested_decision}",
                actor_id,
                {
                    "decision_id": decision_id,
                    "evidence_item_id": row["evidence_item_id"],
                    "attempt_no": row["attempt_no"],
                    "note": note,
                },
            )
            stored = self.connection.execute(
                "SELECT e.exclusion_id,e.evidence_item_id,e.attempt_no,e.status,e.requested_by,"
                "d.decision_id,d.decision,d.decided_by,d.decided_at,d.note "
                "FROM exclusion_requests e JOIN exclusion_decisions d ON d.exclusion_id=e.exclusion_id "
                "WHERE e.exclusion_id=?",
                (exclusion_id,),
            ).fetchone()
            return self._review_response(stored, replayed=False)

    def revoke_exclusion(self, actor_id: str, exclusion_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "exclusion.revoke")
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT e.exclusion_id,e.evidence_item_id,e.attempt_no,e.status,e.requested_by,o.batch_id "
                "FROM exclusion_requests e "
                "JOIN evidence_items o ON o.evidence_item_id=e.evidence_item_id "
                "WHERE e.exclusion_id=?",
                (exclusion_id,),
            ).fetchone()
            if row is None:
                raise NotFound("排除记录不存在")
            if row["requested_by"] != actor_id:
                raise Forbidden("只有原申请人可以撤销排除")
            # 以终局表为唯一事实源：只有终局为 approved 的申请才能撤销。
            decision = self.connection.execute(
                "SELECT decision FROM exclusion_decisions WHERE exclusion_id=?", (exclusion_id,)
            ).fetchone()
            if decision is None or decision["decision"] != "approved":
                raise InvalidState("只有已批准的排除可以撤销")
            batch = self.get_batch(row["batch_id"])
            if batch["state"] != "running":
                raise InvalidState("批次封存后不能改变排除状态")
            cursor = self.connection.execute(
                "UPDATE exclusion_requests SET status='revoked',revoked_by=?,revoked_at=?,revoke_reason=? "
                "WHERE exclusion_id=? AND status='approved'",
                (actor_id, self._now(), reason, exclusion_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("排除状态已变化")
            self._audit(
                "evidence_item",
                str(row["evidence_item_id"]),
                "exclusion.revoked",
                actor_id,
                {
                    "exclusion_id": exclusion_id,
                    "attempt_no": row["attempt_no"],
                    "reason": reason,
                },
            )
        return {
            "exclusion_id": exclusion_id,
            "evidence_item_id": row["evidence_item_id"],
            "attempt_no": row["attempt_no"],
            "status": "revoked",
        }

    def seal_batch(self, actor_id: str, batch_id: str, expected_revision: int) -> dict[str, Any]:
        self._require(actor_id, "batch.seal")
        with transaction(self.connection, immediate=True):
            pending = self.connection.execute(
                "SELECT count(*) FROM exclusion_requests e JOIN evidence_items o ON o.evidence_item_id=e.evidence_item_id "
                "WHERE o.batch_id=? AND e.status='pending'", (batch_id,)
            ).fetchone()[0]
            if pending:
                raise InvalidState("仍有待复核的排除申请")
            cursor = self.connection.execute(
                "UPDATE batches SET state='sealed',revision=revision+1,sealed_at=? "
                "WHERE batch_id=? AND state='running' AND revision=?",
                (self._now(), batch_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise InvalidState("批次状态或版本已变化")
            new_revision = expected_revision + 1
            now = self._now()
            self.connection.execute(
                "INSERT INTO analysis_jobs(batch_id,batch_revision,state,available_at,created_at,updated_at) "
                "VALUES(?,?, 'queued', ?,?,?)",
                (batch_id, new_revision, now, now, now),
            )
            self._audit("batch", batch_id, "batch.sealed", actor_id, {"revision": new_revision})
        return self.get_batch(batch_id)

    def claim_job(self, worker_id: str, lease_seconds: int = 60) -> dict[str, Any] | None:
        if lease_seconds <= 0:
            raise ValidationFailed("租约时长必须大于零")
        now = self._now()
        expires = isoformat(self.clock.now() + timedelta(seconds=lease_seconds))
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT job_id FROM analysis_jobs WHERE "
                "(state='queued' AND available_at<=?) OR (state='leased' AND lease_expires_at<=?) "
                "ORDER BY available_at,job_id LIMIT 1",
                (now, now),
            ).fetchone()
            if row is None:
                return None
            self.connection.execute(
                "UPDATE analysis_jobs SET state='leased',attempts=attempts+1,lease_owner=?,lease_expires_at=?,updated_at=? "
                "WHERE job_id=?",
                (worker_id, expires, now, row["job_id"]),
            )
            claimed = self.connection.execute("SELECT * FROM analysis_jobs WHERE job_id=?", (row["job_id"],)).fetchone()
        return dict(claimed)

    def _analysis_evidence_items(self, batch_id: str, evidence_protocol: EvidenceProtocol) -> tuple[EvidenceItem, ...]:
        # 是否参与分析只承认“当前生效的批准”：申请 status='approved'
        # （未被撤销）且终局表存在 decision='approved'。二者在同一事务写入，
        # 配合每样本至多一个生效申请的部分唯一索引，结果天然唯一、无歧义。
        rows = self.connection.execute(
            "SELECT o.*,er.reason AS excluded_reason "
            "FROM evidence_items o "
            "LEFT JOIN exclusion_requests er "
            "    ON er.evidence_item_id=o.evidence_item_id AND er.status='approved' "
            "LEFT JOIN exclusion_decisions ed "
            "    ON ed.exclusion_id=er.exclusion_id AND ed.decision='approved' "
            "WHERE o.batch_id=? AND (er.exclusion_id IS NULL OR ed.exclusion_id IS NOT NULL) "
            "ORDER BY o.evidence_item_id",
            (batch_id,),
        ).fetchall()
        items: list[EvidenceItem] = []
        for row in rows:
            indicators = json.loads(row["indicators_json"])
            items.append(EvidenceItem(
                source_batch=row["source_batch"],
                source_row=row["source_row"],
                device_id=row["device_id"],
                evidence_protocol_id=evidence_protocol.evidence_protocol_id,
                evidence_protocol_version=evidence_protocol.version,
                evidence_group_key=row["evidence_group_key"],
                observed_at=row["observed_at"],
                indicators={key: Decimal(str(value)) for key, value in indicators.items()},
                excluded_reason=row["excluded_reason"],
            ))
        return tuple(items)

    def complete_job(self, worker_id: str, job_id: int, statistician_id: str) -> dict[str, Any]:
        self._require(statistician_id, "analysis.run")
        job = self.connection.execute("SELECT * FROM analysis_jobs WHERE job_id=?", (job_id,)).fetchone()
        if job is None:
            raise NotFound("分析任务不存在")
        if job["state"] != "leased" or job["lease_owner"] != worker_id:
            raise InvalidState("任务未由当前工作进程持有")
        if job["lease_expires_at"] <= self._now():
            raise InvalidState("任务租约已经过期")
        batch = self.get_batch(job["batch_id"])
        evidence_protocol, evidence_protocol_digest = self._evidence_protocol(batch["evidence_protocol_id"], batch["evidence_protocol_version"])
        evidence_items = self._analysis_evidence_items(batch["batch_id"], evidence_protocol)
        snapshot_rows = [
            {
                "source_batch": item.source_batch,
                "source_row": item.source_row,
                "evidence_group": item.evidence_group_key,
                "indicators": {key: format(value, "f") for key, value in item.indicators.items()},
                "excluded_reason": item.excluded_reason,
            }
            for item in evidence_items
        ]
        input_digest = content_digest(snapshot_rows)
        result = analyze(evidence_protocol, evidence_items)
        with transaction(self.connection, immediate=True):
            existing = self.connection.execute(
                "SELECT analysis_id,result_json FROM analyses WHERE batch_id=? AND batch_revision=? AND input_sha256=?",
                (batch["batch_id"], job["batch_revision"], input_digest),
            ).fetchone()
            if existing is None:
                cursor = self.connection.execute(
                    "INSERT INTO analyses(batch_id,batch_revision,evidence_protocol_sha256,input_sha256,algorithm_version,seed," 
                    "result_json,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        batch["batch_id"], job["batch_revision"], evidence_protocol_digest, input_digest,
                        ALGORITHM_VERSION, evidence_protocol.seed, canonical_json(result), statistician_id, self._now(),
                    ),
                )
                analysis_id = cursor.lastrowid
            else:
                analysis_id = existing["analysis_id"]
                result = json.loads(existing["result_json"])
            self.connection.execute(
                "UPDATE analysis_jobs SET state='succeeded',lease_owner=NULL,lease_expires_at=NULL,updated_at=? "
                "WHERE job_id=? AND state='leased' AND lease_owner=?",
                (self._now(), job_id, worker_id),
            )
            self.connection.execute(
                "UPDATE batches SET state='analyzed' WHERE batch_id=? AND state IN ('sealed','analyzing')",
                (batch["batch_id"],),
            )
            self._audit(
                "batch",
                batch["batch_id"],
                "analysis.completed",
                statistician_id,
                {"analysis_id": analysis_id, "input_sha256": input_digest},
            )
        return {"analysis_id": analysis_id, "input_sha256": input_digest, "result": result}

    def fail_job(self, worker_id: str, job_id: int, error: str, retry_seconds: int = 0) -> dict[str, Any]:
        available = isoformat(self.clock.now() + timedelta(seconds=retry_seconds))
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE analysis_jobs SET state='queued',available_at=?,lease_owner=NULL,lease_expires_at=NULL," 
                "last_error=?,updated_at=? WHERE job_id=? AND state='leased' AND lease_owner=?",
                (available, error[:1000], self._now(), job_id, worker_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("任务未由当前工作进程持有")
        return {"job_id": job_id, "state": "queued", "available_at": available}

    def decide(
        self, actor_id: str, batch_id: str, analysis_id: int, decision: str, reason: str
    ) -> dict[str, Any]:
        self._require(actor_id, "decision.write")
        if decision not in {"needs_more_data", "approved", "rejected"}:
            raise ValidationFailed("未知观察材料采信决定")
        analysis_row = self.connection.execute(
            "SELECT * FROM analyses WHERE analysis_id=? AND batch_id=?", (analysis_id, batch_id)
        ).fetchone()
        if analysis_row is None:
            raise NotFound("分析版本不存在")
        if analysis_row["created_by"] == actor_id:
            raise Forbidden("统计负责人不能批准自己的分析")
        batch = self.get_batch(batch_id)
        if batch["state"] != "analyzed" or batch["revision"] != analysis_row["batch_revision"]:
            raise InvalidState("分析不是批次当前可审批版本")
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO decisions(batch_id,analysis_id,decision,reason,decided_by,decided_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (batch_id, analysis_id, decision, reason, actor_id, self._now()),
                )
                self.connection.execute("UPDATE batches SET state='decided' WHERE batch_id=?", (batch_id,))
                self._audit(
                    "batch",
                    batch_id,
                    "decision.recorded",
                    actor_id,
                    {"decision_id": cursor.lastrowid, "analysis_id": analysis_id, "decision": decision},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("该分析版本已经形成决定") from exc
        return {"batch_id": batch_id, "analysis_id": analysis_id, "decision": decision}

    def report(self, actor_id: str, batch_id: str) -> dict[str, Any]:
        user = self._user(actor_id)
        if user["role"] not in {"statistician", "approver", "auditor"}:
            raise Forbidden("当前角色不能读取完整报告")
        batch = self.get_batch(batch_id)
        evidence_protocol, evidence_protocol_digest = self._evidence_protocol(batch["evidence_protocol_id"], batch["evidence_protocol_version"])
        analysis_row = self.connection.execute(
            "SELECT * FROM analyses WHERE batch_id=? ORDER BY analysis_id DESC LIMIT 1", (batch_id,)
        ).fetchone()
        decision_row = None
        if analysis_row is not None:
            decision_row = self.connection.execute(
                "SELECT * FROM decisions WHERE analysis_id=?", (analysis_row["analysis_id"],)
            ).fetchone()
        history_rows = self.connection.execute(
            "SELECT e.exclusion_id,e.evidence_item_id,e.attempt_no,e.status,e.reason,"
            "e.requested_by,e.requested_at,e.revoked_by,e.revoked_at,e.revoke_reason,"
            "d.decision_id,d.decision,d.decided_by,d.decided_at,d.note "
            "FROM exclusion_requests e "
            "JOIN evidence_items o ON o.evidence_item_id=e.evidence_item_id "
            "LEFT JOIN exclusion_decisions d ON d.exclusion_id=e.exclusion_id "
            "WHERE o.batch_id=? "
            "ORDER BY e.evidence_item_id,e.attempt_no,e.exclusion_id",
            (batch_id,),
        ).fetchall()
        exclusion_ids = [row["exclusion_id"] for row in history_rows]
        item_ids = sorted({row["evidence_item_id"] for row in history_rows})
        related_events: list[sqlite3.Row] = []
        if exclusion_ids or item_ids:
            placeholders_ex = ",".join("?" for _ in exclusion_ids)
            placeholders_it = ",".join("?" for _ in item_ids)
            clauses = []
            params: list[Any] = []
            if exclusion_ids:
                clauses.append(f"(entity_type='exclusion' AND entity_id IN ({placeholders_ex}))")
                params.extend(str(value) for value in exclusion_ids)
            if item_ids:
                clauses.append(f"(entity_type='evidence_item' AND entity_id IN ({placeholders_it}))")
                params.extend(str(value) for value in item_ids)
            related_events = self.connection.execute(
                "SELECT entity_type,entity_id,event_type,actor_id,payload_json,created_at FROM audit_events "
                f"WHERE {' OR '.join(clauses)} ORDER BY event_id",
                params,
            ).fetchall()
        events_by_exclusion: dict[int, list[dict[str, Any]]] = {ex_id: [] for ex_id in exclusion_ids}
        for audit in related_events:
            payload = json.loads(audit["payload_json"])
            target = payload.get("exclusion_id")
            if target is None and audit["entity_type"] == "exclusion":
                target = int(audit["entity_id"])
            if target in events_by_exclusion:
                events_by_exclusion[target].append({
                    "event_type": audit["event_type"],
                    "actor_id": audit["actor_id"],
                    "created_at": audit["created_at"],
                    "payload": payload,
                })
        exclusion_history: list[dict[str, Any]] = []
        effective_exclusions: list[dict[str, Any]] = []
        for row in history_rows:
            terminal = None if row["decision"] is None else {
                "decision_id": row["decision_id"],
                "decision": row["decision"],
                "note": row["note"],
                "decided_by": row["decided_by"],
                "decided_at": row["decided_at"],
            }
            # “有效”= 终局为批准且申请未被撤销；这与分析取数的判据严格同源。
            effective = row["status"] == "approved" and row["decision"] == "approved"
            entry = {
                "exclusion_id": row["exclusion_id"],
                "evidence_item_id": row["evidence_item_id"],
                "attempt_no": row["attempt_no"],
                "status": row["status"],
                "reason": row["reason"],
                "effective": effective,
                "requested_by": row["requested_by"],
                "requested_at": row["requested_at"],
                "terminal_decision": terminal,
                "revoked_by": row["revoked_by"],
                "revoked_at": row["revoked_at"],
                "revoke_reason": row["revoke_reason"],
                "events": events_by_exclusion.get(row["exclusion_id"], []),
            }
            exclusion_history.append(entry)
            if effective:
                effective_exclusions.append({
                    "evidence_item_id": row["evidence_item_id"],
                    "exclusion_id": row["exclusion_id"],
                    "attempt_no": row["attempt_no"],
                    "decision_id": row["decision_id"],
                    "decision": row["decision"],
                    "decided_by": row["decided_by"],
                    "decided_at": row["decided_at"],
                    "excluded_from_analysis": True,
                })
        events = self.connection.execute(
            "SELECT event_type,actor_id,payload_json,created_at FROM audit_events "
            "WHERE entity_type='batch' AND entity_id=? "
            "ORDER BY event_id", (batch_id,)
        ).fetchall()
        return {
            "batch": batch,
            "evidence_protocol": {
                "evidence_protocol_id": evidence_protocol.evidence_protocol_id,
                "version": evidence_protocol.version,
                "sha256": evidence_protocol_digest,
                "seed": evidence_protocol.seed,
                "bootstrap_samples": evidence_protocol.bootstrap_samples,
            },
            "analysis": None if analysis_row is None else {
                "analysis_id": analysis_row["analysis_id"],
                "input_sha256": analysis_row["input_sha256"],
                "algorithm_version": analysis_row["algorithm_version"],
                "created_by": analysis_row["created_by"],
                "result": json.loads(analysis_row["result_json"]),
            },
            "decision": None if decision_row is None else dict(decision_row),
            # 完整历史：每次申请一个版本（attempt_no），含其终局与操作者。
            "exclusions": exclusion_history,
            # 当前真正生效、样本据此不参与分析的终局；与有效决定一一对应。
            "effective_exclusions": effective_exclusions,
            "events": [dict(row) | {"payload": json.loads(row["payload_json"])} for row in events],
        }
