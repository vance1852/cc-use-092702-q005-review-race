from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from taxonomy_lab.storage import connect, initialize, inspect_schema, transaction


class StorageTests(unittest.TestCase):
    def test_initialize_is_repeatable(self) -> None:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            initialize(connection)
            initialize(connection)
            summary = inspect_schema(connection)
        finally:
            connection.close()
        self.assertEqual(summary["missing_tables"], [])
        self.assertEqual(summary["schema_version"], "3")

    def test_transaction_rolls_back_on_error(self) -> None:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.execute("CREATE TABLE items(value TEXT NOT NULL)")
        with self.assertRaises(RuntimeError):
            with transaction(connection):
                connection.execute("INSERT INTO items(value) VALUES('x')")
                raise RuntimeError("stop")
        count = connection.execute("SELECT count(*) FROM items").fetchone()[0]
        connection.close()
        self.assertEqual(count, 0)

    def test_connect_enables_foreign_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            connection = connect(Path(directory) / "test.sqlite3")
            try:
                self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            finally:
                connection.close()

    def test_migrates_v2_single_table_exclusions_to_decisions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "v2.sqlite3"
            legacy = sqlite3.connect(path)
            legacy.executescript(
                """
CREATE TABLE users(user_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE capture_devices(device_id TEXT PRIMARY KEY, model_name TEXT, vendor TEXT, created_at TEXT);
CREATE TABLE evidence_items(evidence_item_id INTEGER PRIMARY KEY AUTOINCREMENT, batch_id TEXT, source_batch TEXT,
    source_row TEXT, device_id TEXT, evidence_group_key TEXT, observed_at TEXT, indicators_json TEXT,
    content_sha256 TEXT, imported_by TEXT, imported_at TEXT);
CREATE TABLE exclusion_requests(exclusion_id INTEGER PRIMARY KEY AUTOINCREMENT, evidence_item_id INTEGER,
    status TEXT, reason TEXT, requested_by TEXT, requested_at TEXT, reviewed_by TEXT, reviewed_at TEXT, review_note TEXT);
CREATE UNIQUE INDEX one_open_exclusion_per_evidence_item ON exclusion_requests(evidence_item_id)
    WHERE status IN ('pending','approved');
CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO schema_meta VALUES('schema_version','2');
INSERT INTO users VALUES('op','操作员','operator',1);
INSERT INTO users VALUES('sa','统计','statistician',1);
INSERT INTO evidence_items(evidence_item_id,batch_id,source_batch,source_row,device_id,evidence_group_key,
    observed_at,indicators_json,content_sha256,imported_by,imported_at)
VALUES (1,'b','sb','1','scope-a','g','t','{}','placeholder_sha256_value_64_chars_long_xxxxxxxxxxxx','op','t');
INSERT INTO exclusion_requests(evidence_item_id,status,reason,requested_by,requested_at,reviewed_by,reviewed_at,review_note)
VALUES (1,'approved','理由','op','t','sa','t','批准备注');
INSERT INTO exclusion_requests(evidence_item_id,status,reason,requested_by,requested_at,reviewed_by,reviewed_at,review_note)
VALUES (1,'revoked','撤销原因','op','t','sa','t','撤销原因');
                """
            )
            legacy.commit()
            legacy.close()

            connection = connect(path)
            try:
                initialize(connection)
                summary = inspect_schema(connection)
                self.assertEqual(summary["schema_version"], "3")
                self.assertEqual(summary["missing_tables"], [])
                requests = connection.execute(
                    "SELECT attempt_no,status,revoked_by,revoke_reason FROM exclusion_requests ORDER BY exclusion_id"
                ).fetchall()
                self.assertEqual([tuple(r) for r in requests], [
                    (1, "approved", None, None),
                    (2, "revoked", "op", "撤销原因"),
                ])
                decisions = connection.execute(
                    "SELECT decision,note,decided_by FROM exclusion_decisions ORDER BY exclusion_id"
                ).fetchall()
                # revoked 在旧库表示“曾批准后撤销”，历史终局仍为 approved。
                self.assertEqual([tuple(r) for r in decisions], [
                    ("approved", "批准备注", "sa"),
                    ("approved", "", "sa"),
                ])
                # 部分唯一索引在新表上仍生效。
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "INSERT INTO exclusion_requests(evidence_item_id,attempt_no,status,reason,"
                        "requested_by,requested_at) VALUES(1,2,'pending','x','op','t')"
                    )
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
