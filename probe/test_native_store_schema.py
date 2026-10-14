from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from native_store_schema import NativeStoreSchemaError, survey_shortcuts_schema


PRIVATE_SENTINEL = "PRIVATE_SENTINEL_SHOULD_NEVER_APPEAR"


class NativeStoreSchemaTests(unittest.TestCase):
    def make_root(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name) / "owned-container"
        root.mkdir()
        return temporary, root

    def make_database(self, root: Path, name: str = "shortcuts.db") -> Path:
        database = root / name
        connection = sqlite3.connect(database)
        try:
            connection.execute(
                "CREATE TABLE message_condition (trigger_kind TEXT NOT NULL, enabled INTEGER, payload BLOB)"
            )
            connection.execute("INSERT INTO message_condition VALUES (?, ?, ?)",
                               ("synthetic", 1, PRIVATE_SENTINEL.encode("utf-8")))
            connection.execute("CREATE VIEW message_condition_view AS SELECT trigger_kind FROM message_condition")
            connection.commit()
        finally:
            connection.close()
        return database

    def test_reports_schema_names_and_types_without_private_row_data(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        database = self.make_database(root)
        before_hash = hashlib.sha256(database.read_bytes()).hexdigest()

        report = survey_shortcuts_schema(root)

        after_hash = hashlib.sha256(database.read_bytes()).hexdigest()
        rendered = repr(report)
        self.assertEqual(before_hash, after_hash)
        self.assertNotIn(PRIVATE_SENTINEL, rendered)
        self.assertEqual(1, report["candidate_count"])
        self.assertEqual("shortcuts.db", report["databases"][0]["path"])
        table = next(item for item in report["databases"][0]["objects"]
                     if item["name"] == "message_condition")
        self.assertEqual("table", table["kind"])
        self.assertEqual(
            [
                {"name": "trigger_kind", "type": "TEXT", "notnull": True, "pk": 0},
                {"name": "enabled", "type": "INTEGER", "notnull": False, "pk": 0},
                {"name": "payload", "type": "BLOB", "notnull": False, "pk": 0},
            ],
            table["columns"],
        )

    def test_only_metadata_sql_is_traced(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        self.make_database(root)
        statements: list[str] = []
        real_connect = sqlite3.connect

        def traced_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
            connection = real_connect(*args, **kwargs)
            connection.set_trace_callback(statements.append)
            return connection

        with mock.patch("native_store_schema.sqlite3.connect", new=traced_connect):
            survey_shortcuts_schema(root)

        select_statements = [statement.lower() for statement in statements if statement.lstrip().lower().startswith("select")]
        self.assertGreaterEqual(len(select_statements), 2)
        self.assertTrue(all("sqlite_master" in statement or "pragma_table_info" in statement
                            for statement in select_statements))
        self.assertFalse(any(PRIVATE_SENTINEL.lower() in statement for statement in select_statements))

    def test_skips_non_sqlite_extensions_without_reading_them_as_databases(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        (root / "notes.txt").write_bytes(PRIVATE_SENTINEL.encode("utf-8"))

        report = survey_shortcuts_schema(root)

        self.assertEqual({"schema_only": True, "candidate_count": 0, "databases": []}, report)

    def test_rejects_sqlite_file_over_size_limit(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        database = root / "large.sqlite"
        database.write_bytes(b"SQLite format 3\x00")
        with database.open("r+b") as output:
            output.truncate(64 * 1024 * 1024 + 1)

        with self.assertRaisesRegex(NativeStoreSchemaError, "SQLITE_FILE_SIZE_LIMIT"):
            survey_shortcuts_schema(root)

    def test_rejects_more_than_eight_sqlite_candidates(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        for index in range(9):
            database = root / f"candidate-{index}.db"
            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE schema_fixture (value TEXT)")
            connection.commit()
            connection.close()

        with self.assertRaisesRegex(NativeStoreSchemaError, "SQLITE_CANDIDATE_LIMIT"):
            survey_shortcuts_schema(root)

    def test_rejects_path_outside_container_through_symlink(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        outside = Path(temporary.name) / "outside"
        outside.mkdir()
        link = root / "escape"
        try:
            os.symlink(outside, link, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlink creation unavailable: {error}")

        with self.assertRaisesRegex(NativeStoreSchemaError, "CONTAINER_SYMLINK"):
            survey_shortcuts_schema(root)

    def test_rejects_more_than_node_limit(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        for index in range(10_000):
            (root / f"node-{index}").touch()

        # Keep the clock fixed: this falsifier proves the node bound wins even
        # on a slower host, rather than accidentally consuming the time budget.
        with mock.patch("native_store_schema.time.monotonic", return_value=0.0):
            with self.assertRaisesRegex(NativeStoreSchemaError, "CONTAINER_NODE_LIMIT"):
                survey_shortcuts_schema(root)

    def test_checks_total_deadline_before_scanning_nodes(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)

        with mock.patch("native_store_schema.time.monotonic", side_effect=(0.0, 5.0)):
            with self.assertRaisesRegex(NativeStoreSchemaError, "SQLITE_PROGRESS_LIMIT"):
                survey_shortcuts_schema(root)

    def test_checks_deadline_between_container_nodes(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        (root / "first.txt").touch()
        (root / "second.txt").touch()

        # Calls are: construct deadline, pre-walk check, loop check, first
        # entry check, then second entry check. The latter must stop traversal.
        clock = (0.0, 0.0, 0.0, 0.0, 5.0)
        with mock.patch("native_store_schema.time.monotonic", side_effect=clock):
            with self.assertRaisesRegex(NativeStoreSchemaError, "SQLITE_PROGRESS_LIMIT"):
                survey_shortcuts_schema(root)


if __name__ == "__main__":
    unittest.main()
