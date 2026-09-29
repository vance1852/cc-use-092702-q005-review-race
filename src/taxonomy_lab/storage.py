"""分类实验观察采信服务的 SQLite 模式与事务辅助。"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator
from pathlib import Path


SCHEMA_VERSION = 3

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_protocol_catalog (
    evidence_protocol_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    title TEXT NOT NULL,
    task_family TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_at TEXT NOT NULL,
    PRIMARY KEY (evidence_protocol_id, version),
    UNIQUE (content_sha256)
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('operator', 'statistician', 'approver', 'auditor')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
);

CREATE TABLE IF NOT EXISTS capture_devices (
    device_id TEXT PRIMARY KEY,
    model_name TEXT NOT NULL,
    vendor TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS builds (
    build_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES capture_devices(device_id),
    version TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_at TEXT NOT NULL,
    UNIQUE (device_id, version),
    UNIQUE (content_sha256)
);

CREATE TABLE IF NOT EXISTS batches (
    batch_id TEXT PRIMARY KEY,
    evidence_protocol_id TEXT NOT NULL,
    evidence_protocol_version INTEGER NOT NULL,
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    state TEXT NOT NULL CHECK (state IN ('draft', 'running', 'sealed', 'analyzing', 'analyzed', 'decided')),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    started_at TEXT,
    sealed_at TEXT,
    FOREIGN KEY (evidence_protocol_id, evidence_protocol_version) REFERENCES evidence_protocol_catalog(evidence_protocol_id, version)
);

CREATE TABLE IF NOT EXISTS evidence_items (
    evidence_item_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    source_batch TEXT NOT NULL,
    source_row TEXT NOT NULL,
    device_id TEXT NOT NULL REFERENCES capture_devices(device_id),
    evidence_group_key TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    indicators_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    imported_by TEXT NOT NULL REFERENCES users(user_id),
    imported_at TEXT NOT NULL,
    UNIQUE (batch_id, source_batch, source_row)
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (scope, key)
);

CREATE TABLE IF NOT EXISTS exclusion_requests (
    exclusion_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_item_id INTEGER NOT NULL REFERENCES evidence_items(evidence_item_id),
    attempt_no INTEGER NOT NULL CHECK (attempt_no > 0),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'revoked')),
    reason TEXT NOT NULL,
    requested_by TEXT NOT NULL REFERENCES users(user_id),
    requested_at TEXT NOT NULL,
    revoked_by TEXT REFERENCES users(user_id),
    revoked_at TEXT,
    revoke_reason TEXT,
    UNIQUE (evidence_item_id, attempt_no)
);

-- 同一观察记录至多存在一条“待复核”或“已生效”的排除申请；
-- 驳回或撤销之后才允许按递增的 attempt_no 重新申请。
CREATE UNIQUE INDEX IF NOT EXISTS one_open_exclusion_per_evidence_item
ON exclusion_requests(evidence_item_id)
WHERE status IN ('pending', 'approved');

-- 终局复核决定独立成表：UNIQUE(exclusion_id) 在数据库层保证每条申请
-- 至多有一个终局决定，从根上消除“批准/驳回双终局”。
CREATE TABLE IF NOT EXISTS exclusion_decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    exclusion_id INTEGER NOT NULL REFERENCES exclusion_requests(exclusion_id),
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
    note TEXT NOT NULL DEFAULT '',
    decided_by TEXT NOT NULL REFERENCES users(user_id),
    decided_at TEXT NOT NULL,
    UNIQUE (exclusion_id)
);

CREATE TABLE IF NOT EXISTS analysis_jobs (
    job_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    batch_revision INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('queued', 'leased', 'succeeded', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TEXT NOT NULL,
    lease_owner TEXT,
    lease_expires_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (batch_id, batch_revision)
);

CREATE TABLE IF NOT EXISTS analyses (
    analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    batch_revision INTEGER NOT NULL,
    evidence_protocol_sha256 TEXT NOT NULL CHECK (length(evidence_protocol_sha256) = 64),
    input_sha256 TEXT NOT NULL CHECK (length(input_sha256) = 64),
    algorithm_version TEXT NOT NULL,
    seed INTEGER NOT NULL,
    result_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (batch_id, batch_revision, input_sha256)
);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    analysis_id INTEGER NOT NULL REFERENCES analyses(analysis_id),
    decision TEXT NOT NULL CHECK (decision IN ('needs_more_data', 'approved', 'rejected')),
    reason TEXT NOT NULL,
    decided_by TEXT NOT NULL REFERENCES users(user_id),
    decided_at TEXT NOT NULL,
    UNIQUE (batch_id, analysis_id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

REQUIRED_TABLES = frozenset({
    "schema_meta", "evidence_protocol_catalog", "users", "capture_devices", "builds", "batches",
    "evidence_items", "idempotency_keys", "exclusion_requests", "exclusion_decisions",
    "analysis_jobs", "analyses", "decisions", "audit_events",
})


def connect(path: str | Path) -> sqlite3.Connection:
    """打开连接并启用严格的事务与外键设置。"""

    connection = sqlite3.connect(str(path), isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


@contextlib.contextmanager
def transaction(connection: sqlite3.Connection, *, immediate: bool = False) -> Iterator[None]:
    """显式事务；异常时保证回滚。"""

    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def _column_names(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}


def _migrate_legacy_exclusions(connection: sqlite3.Connection) -> None:
    """把 v2 的单表复核结构迁移到 v3 的申请/终局双表。"""

    exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='exclusion_requests'"
    ).fetchone()
    if exists is None or "attempt_no" in _column_names(connection, "exclusion_requests"):
        return  # 全新库或已是新结构
    with transaction(connection, immediate=True):
        connection.execute("ALTER TABLE exclusion_requests RENAME TO exclusion_requests_v2")
        # 旧的同名部分唯一索引仍挂在 v2 表上；删除后由 SCHEMA_SQL 在新表重建。
        connection.execute("DROP INDEX IF EXISTS one_open_exclusion_per_evidence_item")
        connection.execute(
            """
CREATE TABLE exclusion_requests (
    exclusion_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_item_id INTEGER NOT NULL REFERENCES evidence_items(evidence_item_id),
    attempt_no INTEGER NOT NULL CHECK (attempt_no > 0),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'revoked')),
    reason TEXT NOT NULL,
    requested_by TEXT NOT NULL REFERENCES users(user_id),
    requested_at TEXT NOT NULL,
    revoked_by TEXT REFERENCES users(user_id),
    revoked_at TEXT,
    revoke_reason TEXT,
    UNIQUE (evidence_item_id, attempt_no)
)
"""
        )
        connection.execute(
            """
INSERT INTO exclusion_requests(
    exclusion_id,evidence_item_id,attempt_no,status,reason,requested_by,requested_at,
    revoked_by,revoked_at,revoke_reason
)
SELECT exclusion_id,evidence_item_id,
       ROW_NUMBER() OVER (PARTITION BY evidence_item_id ORDER BY exclusion_id),
       status,reason,requested_by,requested_at,
       CASE WHEN status='revoked' THEN requested_by ELSE NULL END,
       CASE WHEN status='revoked' THEN reviewed_at ELSE NULL END,
       CASE WHEN status='revoked' THEN review_note ELSE NULL END
FROM exclusion_requests_v2
"""
        )
        connection.execute(
            """
CREATE TABLE exclusion_decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    exclusion_id INTEGER NOT NULL REFERENCES exclusion_requests(exclusion_id),
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
    note TEXT NOT NULL DEFAULT '',
    decided_by TEXT NOT NULL REFERENCES users(user_id),
    decided_at TEXT NOT NULL,
    UNIQUE (exclusion_id)
)
"""
        )
        # revoked 在旧结构中表示“曾批准、后撤销”：其历史终局为 approved，
        # 批准人仍是 reviewed_by（旧撤销流程不覆盖该列）；批准备注已被撤销原因
        # 覆盖而无法恢复，故留空，撤销原因已单独存入 revoke_reason。
        connection.execute(
            """
INSERT INTO exclusion_decisions(exclusion_id,decision,note,decided_by,decided_at)
SELECT exclusion_id,
       CASE WHEN status='rejected' THEN 'rejected' ELSE 'approved' END,
       CASE WHEN status='revoked' THEN '' ELSE COALESCE(review_note,'') END,
       reviewed_by,
       reviewed_at
FROM exclusion_requests_v2
WHERE status IN ('approved','rejected','revoked') AND reviewed_by IS NOT NULL
"""
        )
        connection.execute("DROP TABLE exclusion_requests_v2")


def initialize(connection: sqlite3.Connection) -> None:
    """初始化基础资料表，重复执行不改变已有数据。"""

    _migrate_legacy_exclusions(connection)
    connection.executescript(SCHEMA_SQL)
    with transaction(connection, immediate=True):
        connection.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )


def inspect_schema(connection: sqlite3.Connection) -> dict[str, object]:
    """返回适合机器检查的数据库结构摘要。"""

    table_rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    tables = tuple(row["name"] for row in table_rows)
    version_row = connection.execute(
        "SELECT value FROM schema_meta WHERE key='schema_version'"
    ).fetchone()
    missing = sorted(REQUIRED_TABLES - set(tables))
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
    return {
        "tables": tables,
        "missing_tables": missing,
        "schema_version": None if version_row is None else version_row["value"],
        "foreign_keys": bool(foreign_keys),
    }
