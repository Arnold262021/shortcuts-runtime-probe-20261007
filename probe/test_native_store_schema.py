from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from native_store_schema import (
    NativeStoreSchemaError,
    survey_observed_shortcuts_file,
    survey_shortcuts_schema,
)


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

    def make_observed_database(self, root: Path) -> Path:
        database = root / "Library" / "Shortcuts" / "Shortcuts.sqlite"
        database.parent.mkdir(parents=True)
        return self.make_database(database.parent, database.name)

    def test_surveys_only_the_exact_observed_shortcuts_file(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        database = self.make_observed_database(root)
        sibling = self.make_database(root, "sibling.db")
        before_hash = hashlib.sha256(database.read_bytes()).hexdigest()
        real_open = os.open
        real_connect = sqlite3.connect
        opened: list[str] = []
        connection_uris: list[str] = []

        def guarded_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
            resolved = os.path.normcase(os.path.realpath(os.fspath(path)))
            sibling_key = os.path.normcase(os.path.realpath(os.fspath(sibling)))
            if resolved == sibling_key:
                raise AssertionError("sibling database must never be opened")
            opened.append(resolved)
            return real_open(path, flags, *args, **kwargs)

        def guarded_connect(database_uri: str, *args: object, **kwargs: object) -> sqlite3.Connection:
            self.assertNotIn("sibling.db", database_uri)
            connection_uris.append(database_uri)
            return real_connect(database_uri, *args, **kwargs)

        with mock.patch("native_store_schema.os.open", new=guarded_open), \
                mock.patch("native_store_schema.sqlite3.connect", new=guarded_connect):
            report = survey_observed_shortcuts_file(
                root, ["Library/Shortcuts/Shortcuts.sqlite", "Library/Shortcuts/Shortcuts.sqlite-wal"]
            )

        self.assertEqual(before_hash, hashlib.sha256(database.read_bytes()).hexdigest())
        self.assertEqual("observed_shortcuts_file_schema_only", report["scope"])
        self.assertEqual(1, report["candidate_count"])
        self.assertEqual("Library/Shortcuts/Shortcuts.sqlite", report["databases"][0]["path"])
        self.assertTrue(opened)
        self.assertEqual(1, len(connection_uris))
        self.assertIn("?mode=ro", connection_uris[0])
        self.assertNotIn(PRIVATE_SENTINEL, repr(report))

    def test_rejects_missing_ambiguous_or_nonliteral_observation_before_opening(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        self.make_observed_database(root)

        with mock.patch("native_store_schema.os.open", side_effect=AssertionError("must not open")):
            for observed, code in (
                ([], "OBSERVED_SHORTCUTS_PATH_MISSING"),
                (["library/shortcuts/shortcuts.sqlite"], "OBSERVED_SHORTCUTS_PATH_MISSING"),
                (["Library/Shortcuts/Shortcuts.sqlite"] * 2, "OBSERVED_SHORTCUTS_PATH_AMBIGUOUS"),
                ("Library/Shortcuts/Shortcuts.sqlite", "OBSERVED_SHORTCUTS_PATH_MISMATCH"),
            ):
                with self.assertRaisesRegex(NativeStoreSchemaError, code):
                    survey_observed_shortcuts_file(root, observed)  # type: ignore[arg-type]

    def test_rejects_observed_file_boundaries_and_invalid_headers(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        database = self.make_observed_database(root)
        observed = ["Library/Shortcuts/Shortcuts.sqlite"]

        original_lstat = Path.lstat
        database_key = os.path.normcase(os.path.realpath(os.fspath(database)))

        def leaf_link(path: Path):
            if os.path.normcase(os.path.realpath(os.fspath(path))) == database_key:
                return SimpleNamespace(st_mode=stat.S_IFLNK)
            return original_lstat(path)

        with mock.patch.object(Path, "lstat", new=leaf_link), \
                mock.patch("native_store_schema.os.open", side_effect=AssertionError("must not open")):
            with self.assertRaisesRegex(NativeStoreSchemaError, "CONTAINER_SYMLINK"):
                survey_observed_shortcuts_file(root, observed)

        database.write_bytes(b"not sqlite")
        with self.assertRaisesRegex(NativeStoreSchemaError, "OBSERVED_SHORTCUTS_HEADER_INVALID"):
            survey_observed_shortcuts_file(root, observed)

    def test_observed_schema_metadata_sql_and_size_bound(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        database = self.make_observed_database(root)
        observed = ["Library/Shortcuts/Shortcuts.sqlite"]
        statements: list[str] = []
        real_connect = sqlite3.connect

        def traced_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
            connection = real_connect(*args, **kwargs)
            connection.set_trace_callback(statements.append)
            return connection

        with mock.patch("native_store_schema.sqlite3.connect", new=traced_connect):
            survey_observed_shortcuts_file(root, observed)

        selects = [statement.lower() for statement in statements if statement.lstrip().lower().startswith("select")]
        self.assertGreaterEqual(len(selects), 2)
        self.assertTrue(all("sqlite_master" in statement or "pragma_table_info" in statement for statement in selects))
        self.assertFalse(any(PRIVATE_SENTINEL.lower() in statement for statement in selects))

        status = database.lstat()
        oversized = type("Status", (), {
            "st_mode": stat.S_IFREG,
            "st_dev": status.st_dev,
            "st_ino": status.st_ino,
            "st_size": 64 * 1024 * 1024 + 1,
        })()
        with mock.patch("native_store_schema.os.fstat", return_value=oversized):
            with self.assertRaisesRegex(NativeStoreSchemaError, "SQLITE_FILE_SIZE_LIMIT"):
                survey_observed_shortcuts_file(root, observed)

    def test_normalizes_sqlite_setup_error_without_leaking_diagnostics(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        self.make_observed_database(root)

        class SetupFailure:
            def execute(self, _statement: str) -> None:
                raise sqlite3.OperationalError(PRIVATE_SENTINEL)

            def close(self) -> None:
                raise sqlite3.OperationalError("close must not replace setup")

        with mock.patch("native_store_schema.sqlite3.connect", return_value=SetupFailure()):
            with self.assertRaises(NativeStoreSchemaError) as raised:
                survey_observed_shortcuts_file(root, ["Library/Shortcuts/Shortcuts.sqlite"])

        self.assertEqual("SQLITE_SETUP_FAILED", raised.exception.code)
        self.assertNotIn(PRIVATE_SENTINEL, str(raised.exception))

    def test_normalizes_only_sqlite_close_error_without_leaking_diagnostics(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        self.make_observed_database(root)
        real_connect = sqlite3.connect

        class CloseFailure:
            def __init__(self, connection: sqlite3.Connection):
                self.connection = connection

            def __getattr__(self, name: str) -> object:
                return getattr(self.connection, name)

            def close(self) -> None:
                self.connection.close()
                raise sqlite3.OperationalError(PRIVATE_SENTINEL)

        def close_failing_connect(*args: object, **kwargs: object) -> CloseFailure:
            return CloseFailure(real_connect(*args, **kwargs))

        with mock.patch("native_store_schema.sqlite3.connect", new=close_failing_connect):
            with self.assertRaises(NativeStoreSchemaError) as raised:
                survey_observed_shortcuts_file(root, ["Library/Shortcuts/Shortcuts.sqlite"])

        self.assertEqual("SQLITE_CLOSE_FAILED", raised.exception.code)
        self.assertNotIn(PRIVATE_SENTINEL, str(raised.exception))

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
        notes = root / "notes.txt"
        notes.write_bytes(PRIVATE_SENTINEL.encode("utf-8"))
        original_open = Path.open

        def reject_non_sqlite_open(path: Path, *args: object, **kwargs: object):
            if path == notes:
                raise AssertionError("inventory must not open non-SQLite files")
            return original_open(path, *args, **kwargs)

        with mock.patch.object(Path, "open", new=reject_non_sqlite_open):
            report = survey_shortcuts_schema(root, include_inventory=True)

        self.assertEqual(True, report["schema_only"])
        self.assertEqual(0, report["candidate_count"])
        self.assertEqual([], report["databases"])
        self.assertEqual(
            [{"path": "notes.txt", "size": len(PRIVATE_SENTINEL), "suffix": ".txt"}],
            report["file_inventory"],
        )
        self.assertNotIn(PRIVATE_SENTINEL, repr(report))

    def test_rejects_inventory_larger_than_bounded_metadata_limit(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        for index in range(257):
            (root / f"metadata-{index}.cache").touch()

        with self.assertRaisesRegex(NativeStoreSchemaError, "FILE_INVENTORY_LIMIT"):
            survey_shortcuts_schema(root, include_inventory=True)

    def test_default_survey_omits_inventory_and_ignores_inventory_limit(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        (root / "excluded.cache").write_bytes(PRIVATE_SENTINEL.encode())

        with mock.patch("native_store_schema.MAX_FILE_INVENTORY_ENTRIES", 0):
            report = survey_shortcuts_schema(root)

        self.assertNotIn("file_inventory", report)
        self.assertNotIn(PRIVATE_SENTINEL, repr(report))

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
        with mock.patch("native_store_schema.MAX_FILE_INVENTORY_ENTRIES", 10_001), \
                mock.patch("native_store_schema.time.monotonic", return_value=0.0):
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
