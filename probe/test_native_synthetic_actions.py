from __future__ import annotations

import hashlib
from pathlib import Path
import plistlib
import sqlite3
import tempfile
import traceback
import unittest
from unittest import mock

from native_synthetic_actions import NativeSyntheticActionsError, inspect_observed_synthetic_actions


PRIVATE_SENTINEL = "PRIVATE_SENTINEL_NEVER_RETURNED"
OBSERVED = ["Library/Shortcuts/Shortcuts.sqlite"]


class NativeSyntheticActionsTests(unittest.TestCase):
    def make_database(self, *, action_count: int = 1, marker_count: int = 1, framing: str = "binary", primary_key: bool = True) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name) / "own"
        database = root / "Library" / "Shortcuts" / "Shortcuts.sqlite"
        database.parent.mkdir(parents=True)
        connection = sqlite3.connect(database)
        pk = " PRIMARY KEY" if primary_key else ""
        connection.execute(f"CREATE TABLE ZSHORTCUT (Z_PK INTEGER{pk}, ZACTIONS INTEGER, SECRET TEXT)")
        connection.execute(f"CREATE TABLE ZSHORTCUTACTIONS (Z_PK INTEGER{pk}, ZSHORTCUT INTEGER, ZDATA BLOB, SECRET TEXT)")
        connection.execute("INSERT INTO ZSHORTCUT VALUES (1, 10, ?)", (PRIVATE_SENTINEL,))
        payload: dict[str, object] = {"WFWorkflowActionIdentifier": "is.workflow.actions.filter.messages"}
        if marker_count:
            payload["marker"] = "AUTOMATION_TEST_ONLY"
        if marker_count > 1:
            payload["second"] = "AUTOMATION_TEST_ONLY"
        blob = plistlib.dumps(payload, fmt=plistlib.FMT_BINARY if framing == "binary" else plistlib.FMT_XML)
        for index in range(action_count):
            connection.execute("INSERT INTO ZSHORTCUTACTIONS VALUES (?, 1, ?, ?)", (10 + index, blob, PRIVATE_SENTINEL))
        connection.commit()
        connection.close()
        return temporary, root

    def test_reads_one_action_redacted_and_unchanged(self) -> None:
        temporary, root = self.make_database()
        self.addCleanup(temporary.cleanup)
        database = root / "Library" / "Shortcuts" / "Shortcuts.sqlite"
        before = hashlib.sha256(database.read_bytes()).hexdigest()

        report = inspect_observed_synthetic_actions(root, OBSERVED)

        self.assertEqual(before, hashlib.sha256(database.read_bytes()).hexdigest())
        self.assertEqual("SYNTHETIC_ACTION_MARKER_OBSERVED", report["status"])
        self.assertTrue(report["contents_read"])
        self.assertTrue(report["marker_count_exactly_one"])
        self.assertTrue(report["action_identifier_syntax_valid"])
        self.assertEqual("binary_plist", report["blob"]["framing"])
        self.assertNotIn(PRIVATE_SENTINEL, repr(report))
        self.assertNotIn("is.workflow.actions.filter.messages", repr(report))

    def test_rejects_missing_similar_or_multiple_actions(self) -> None:
        temporary, root = self.make_database(action_count=2)
        self.addCleanup(temporary.cleanup)
        for paths in ([], ["Library/Shortcuts/Shortcuts.sqlite-wal"]):
            with self.assertRaises(NativeSyntheticActionsError):
                inspect_observed_synthetic_actions(root, paths)
        with self.assertRaisesRegex(NativeSyntheticActionsError, "SYNTHETIC_ACTIONS_ROW_CARDINALITY"):
            inspect_observed_synthetic_actions(root, OBSERVED)

    def test_rejects_marker_absent_duplicate_and_unknown_framing(self) -> None:
        for markers, framing, code in (
            (0, "binary", "SYNTHETIC_ACTIONS_MARKER_UNCONFIRMED"),
            (2, "binary", "SYNTHETIC_ACTIONS_MARKER_UNCONFIRMED"),
        ):
            temporary, root = self.make_database(marker_count=markers, framing=framing)
            self.addCleanup(temporary.cleanup)
            with self.assertRaisesRegex(NativeSyntheticActionsError, code) as raised:
                inspect_observed_synthetic_actions(root, OBSERVED)
            self.assertEqual("binary_plist", raised.exception.diagnostic()["framing"])
            self.assertNotIn(PRIVATE_SENTINEL, repr(raised.exception.diagnostic()))
        temporary, root = self.make_database()
        self.addCleanup(temporary.cleanup)
        database = root / "Library" / "Shortcuts" / "Shortcuts.sqlite"
        connection = sqlite3.connect(database)
        connection.execute("UPDATE ZSHORTCUTACTIONS SET ZDATA = ?", (b"compressed" + PRIVATE_SENTINEL.encode(),))
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(NativeSyntheticActionsError, "SYNTHETIC_ACTIONS_BLOB_FORMAT_UNCONFIRMED") as raised:
            inspect_observed_synthetic_actions(root, OBSERVED)
        self.assertEqual("unknown", raised.exception.diagnostic()["framing"])
        self.assertNotIn(PRIVATE_SENTINEL, repr(raised.exception.diagnostic()))

        temporary, root = self.make_database()
        self.addCleanup(temporary.cleanup)
        database = root / "Library" / "Shortcuts" / "Shortcuts.sqlite"
        connection = sqlite3.connect(database)
        connection.execute(
            "UPDATE ZSHORTCUTACTIONS SET ZDATA = ?",
            (plistlib.dumps({"bad/key": "AUTOMATION_TEST_ONLY"}, fmt=plistlib.FMT_BINARY),),
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(NativeSyntheticActionsError, "SYNTHETIC_ACTIONS_TREE_KEY_INVALID"):
            inspect_observed_synthetic_actions(root, OBSERVED)

    def test_rejects_zero_shortcuts_and_reciprocal_mismatch(self) -> None:
        temporary, root = self.make_database()
        self.addCleanup(temporary.cleanup)
        database = root / "Library" / "Shortcuts" / "Shortcuts.sqlite"
        connection = sqlite3.connect(database)
        connection.execute("DELETE FROM ZSHORTCUT")
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(NativeSyntheticActionsError, "SYNTHETIC_ACTIONS_ROW_CARDINALITY"):
            inspect_observed_synthetic_actions(root, OBSERVED)

    def test_rejects_schema_without_measured_primary_keys(self) -> None:
        temporary, root = self.make_database(primary_key=False)
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(NativeSyntheticActionsError, "REQUIRED_SCHEMA_MISSING"):
            inspect_observed_synthetic_actions(root, OBSERVED)

    def test_normalizes_decoder_recursion_without_leaking_payload(self) -> None:
        temporary, root = self.make_database()
        self.addCleanup(temporary.cleanup)
        with mock.patch(
            "native_synthetic_actions.plistlib.loads",
            side_effect=RecursionError(PRIVATE_SENTINEL),
        ):
            with self.assertRaisesRegex(NativeSyntheticActionsError, "SYNTHETIC_ACTIONS_BLOB_FORMAT_UNCONFIRMED") as raised:
                inspect_observed_synthetic_actions(root, OBSERVED)
        self.assertNotIn(PRIVATE_SENTINEL, str(raised.exception))
        self.assertNotIn(PRIVATE_SENTINEL, repr(raised.exception.diagnostic()))
        rendered_traceback = "".join(traceback.format_exception(raised.exception))
        self.assertNotIn(PRIVATE_SENTINEL, rendered_traceback)

    def test_rejects_invalid_error_diagnostics_without_echoing_them(self) -> None:
        base = {"length": 1, "sha256": "0" * 64, "framing": "binary_plist"}
        invalid = [
            {"length": 1, "sha256": "0" * 64},
            {**base, "length": True},
            {**base, "framing": []},
            {**base, "private": PRIVATE_SENTINEL},
        ]
        for diagnostic in invalid:
            with self.assertRaises(ValueError) as raised:
                NativeSyntheticActionsError("SYNTHETIC_ACTIONS_BLOB_INVALID", diagnostic)
            self.assertNotIn(PRIVATE_SENTINEL, str(raised.exception))

    def test_rejects_tree_limit_bad_xml_and_unsafe_keys(self) -> None:
        temporary, root = self.make_database()
        self.addCleanup(temporary.cleanup)
        database = root / "Library" / "Shortcuts" / "Shortcuts.sqlite"
        oversized_tree = {"first": "AUTOMATION_TEST_ONLY", "WFWorkflowActionIdentifier": "com.apple.action"}
        oversized_tree.update({f"key{index}": index for index in range(520)})
        oversized_tree["last"] = "AUTOMATION_TEST_ONLY"
        connection = sqlite3.connect(database)
        connection.execute("UPDATE ZSHORTCUTACTIONS SET ZDATA = ?", (plistlib.dumps(oversized_tree, fmt=plistlib.FMT_BINARY),))
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(NativeSyntheticActionsError, "SYNTHETIC_ACTIONS_TREE_LIMIT"):
            inspect_observed_synthetic_actions(root, OBSERVED)

        temporary, root = self.make_database()
        self.addCleanup(temporary.cleanup)
        database = root / "Library" / "Shortcuts" / "Shortcuts.sqlite"
        connection = sqlite3.connect(database)
        connection.execute("UPDATE ZSHORTCUTACTIONS SET ZDATA = ?", (b"<?xml broken",))
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(NativeSyntheticActionsError, "SYNTHETIC_ACTIONS_BLOB_FORMAT_UNCONFIRMED") as raised:
            inspect_observed_synthetic_actions(root, OBSERVED)
        self.assertEqual("xml_plist", raised.exception.diagnostic()["framing"])
        self.assertNotIn(PRIVATE_SENTINEL, repr(raised.exception.diagnostic()))

        temporary, root = self.make_database()
        self.addCleanup(temporary.cleanup)
        database = root / "Library" / "Shortcuts" / "Shortcuts.sqlite"
        connection = sqlite3.connect(database)
        connection.execute("UPDATE ZSHORTCUTACTIONS SET Z_PK = 11")
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(NativeSyntheticActionsError, "SYNTHETIC_ACTIONS_RELATIONSHIP_MISMATCH"):
            inspect_observed_synthetic_actions(root, OBSERVED)


if __name__ == "__main__":
    unittest.main()
