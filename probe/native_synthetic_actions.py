"""Read one measured synthetic Shortcuts action without retaining its payload."""

from __future__ import annotations

import hashlib
from pathlib import Path
import plistlib
import re
import sqlite3
import sys
import time
from xml.parsers.expat import ExpatError

import native_store_schema as store


MAX_ACTION_BLOB_BYTES = 256 * 1024
MAX_TREE_DEPTH = 16
MAX_TREE_NODES = 512
_MARKER = "AUTOMATION_TEST_ONLY"
_ACTION_IDENTIFIER_KEY = "WFWorkflowActionIdentifier"
_PUBLIC_ACTION_IDENTIFIER = re.compile(r"(?:is\.workflow\.actions\.|com\.apple\.)[A-Za-z0-9._-]{1,96}\Z")
_DIAGNOSTIC_FRAMINGS = frozenset({"binary_plist", "xml_plist", "unknown"})

_ERROR_CODES = frozenset(
    {
        "OBSERVED_SCHEMA_UNCONFIRMED",
        "REQUIRED_SCHEMA_MISSING",
        "SYNTHETIC_ACTIONS_OPEN_FAILED",
        "SYNTHETIC_ACTIONS_SETUP_FAILED",
        "SYNTHETIC_ACTIONS_QUERY_FAILED",
        "SYNTHETIC_ACTIONS_ROW_CARDINALITY",
        "SYNTHETIC_ACTIONS_IDENTIFIER_INVALID",
        "SYNTHETIC_ACTIONS_RELATIONSHIP_MISMATCH",
        "SYNTHETIC_ACTIONS_BLOB_INVALID",
        "SYNTHETIC_ACTIONS_BLOB_TOO_LARGE",
        "SYNTHETIC_ACTIONS_BLOB_FORMAT_UNCONFIRMED",
        "SYNTHETIC_ACTIONS_MARKER_UNCONFIRMED",
        "SYNTHETIC_ACTIONS_TREE_KEY_INVALID",
        "SYNTHETIC_ACTIONS_TREE_LIMIT",
        "SYNTHETIC_ACTIONS_PROGRESS_LIMIT",
        "SYNTHETIC_ACTIONS_CLOSE_FAILED",
    }
)


class NativeSyntheticActionsError(RuntimeError):
    """Stable, redacted failure from the one-synthetic-action reader."""

    def __init__(self, code: str, diagnostic: dict[str, object] | None = None):
        if code not in _ERROR_CODES:
            raise ValueError("unknown synthetic actions error code")
        if diagnostic is not None:
            expected = {"length", "sha256", "framing"}
            keys = set(diagnostic)
            if keys not in {frozenset(expected), frozenset(expected | {"marker_count"})}:
                raise ValueError("unknown synthetic actions diagnostic field")
            if not isinstance(diagnostic["length"], int) or isinstance(diagnostic["length"], bool) or not 0 < diagnostic["length"] <= MAX_ACTION_BLOB_BYTES:
                raise ValueError("invalid synthetic actions diagnostic length")
            if not isinstance(diagnostic["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", diagnostic["sha256"]):
                raise ValueError("invalid synthetic actions diagnostic hash")
            if not isinstance(diagnostic["framing"], str) or diagnostic["framing"] not in _DIAGNOSTIC_FRAMINGS:
                raise ValueError("invalid synthetic actions diagnostic framing")
            if "marker_count" in diagnostic and (not isinstance(diagnostic["marker_count"], int) or isinstance(diagnostic["marker_count"], bool) or diagnostic["marker_count"] < 0):
                raise ValueError("invalid synthetic actions diagnostic marker count")
            self._diagnostic = dict(diagnostic)
        else:
            self._diagnostic = None
        super().__init__(code)
        self.code = code

    def diagnostic(self) -> dict[str, object] | None:
        """Return only the validated post-blob diagnostic, if available."""
        return None if self._diagnostic is None else dict(self._diagnostic)


def _blob_diagnostic(blob: bytes, framing: str, marker_count: int | None = None) -> dict[str, object]:
    diagnostic: dict[str, object] = {
        "length": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "framing": framing,
    }
    if marker_count is not None:
        diagnostic["marker_count"] = marker_count
    return diagnostic


def _required_schema(report: dict[str, object]) -> None:
    try:
        database = report["databases"][0]
        objects = database["objects"]
    except (KeyError, IndexError, TypeError):
        raise NativeSyntheticActionsError("REQUIRED_SCHEMA_MISSING") from None
    expected = {
        "ZSHORTCUT": {"Z_PK": ("INTEGER", 1), "ZACTIONS": ("INTEGER", 0)},
        "ZSHORTCUTACTIONS": {"Z_PK": ("INTEGER", 1), "ZSHORTCUT": ("INTEGER", 0), "ZDATA": ("BLOB", 0)},
    }
    actual: dict[str, dict[str, tuple[str, int]]] = {}
    try:
        for item in objects:
            actual[item["name"]] = {
                column["name"]: (column["type"], column["pk"]) for column in item["columns"]
            }
    except (KeyError, TypeError):
        raise NativeSyntheticActionsError("REQUIRED_SCHEMA_MISSING") from None
    if any(actual.get(table, {}).get(column) != kind for table, columns in expected.items() for column, kind in columns.items()):
        raise NativeSyntheticActionsError("REQUIRED_SCHEMA_MISSING")


def _positive_integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise NativeSyntheticActionsError("SYNTHETIC_ACTIONS_IDENTIFIER_INVALID")
    return value


def _actions_authorizer(action: int, first: str | None, second: str | None, *_unused: object) -> int:
    allowed_reads = {
        ("ZSHORTCUT", "Z_PK"), ("ZSHORTCUT", "ZACTIONS"),
        ("ZSHORTCUTACTIONS", "Z_PK"), ("ZSHORTCUTACTIONS", "ZSHORTCUT"),
        ("ZSHORTCUTACTIONS", "ZDATA"),
    }
    if action == sqlite3.SQLITE_READ:
        return sqlite3.SQLITE_OK if (first, second) in allowed_reads else sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_PRAGMA:
        return sqlite3.SQLITE_OK if first == "query_only" else sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION:
        return sqlite3.SQLITE_OK if second in {"typeof", "length"} else sqlite3.SQLITE_DENY
    if action in {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_TRANSACTION}:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _safe_key(key: object) -> str:
    if not isinstance(key, str) or not key.isascii() or not re.fullmatch(r"[$A-Za-z_][$A-Za-z0-9_.-]{0,127}", key):
        raise NativeSyntheticActionsError("SYNTHETIC_ACTIONS_TREE_KEY_INVALID")
    return key


def _redacted_tree(value: object, state: dict[str, object], depth: int = 0) -> dict[str, object]:
    if depth > MAX_TREE_DEPTH or state["nodes"] >= MAX_TREE_NODES:
        state["truncated"] = True
        return {"type": "truncated"}
    state["nodes"] += 1
    if isinstance(value, dict):
        entries = []
        for key, child in value.items():
            key = _safe_key(key)
            entries.append({"key": key, "value": _redacted_tree(child, state, depth + 1)})
            if state["truncated"]:
                break
        return {"type": "dict", "count": len(value), "entries": entries}
    if isinstance(value, list):
        items = []
        for child in value:
            items.append(_redacted_tree(child, state, depth + 1))
            if state["truncated"]:
                break
        return {"type": "list", "count": len(value), "items": items}
    if isinstance(value, str):
        if value == _MARKER:
            state["marker_count"] += 1
        return {"type": "string"}
    if isinstance(value, plistlib.UID):
        return {"type": "uid"}
    if isinstance(value, bytes):
        return {"type": "bytes"}
    if isinstance(value, bool):
        return {"type": "bool"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "real"}
    if value is None:
        return {"type": "null"}
    return {"type": "unknown"}


def _action_identifier_syntax(value: object) -> bool:
    candidates: list[object] = []
    pending = [(value, 0)]
    inspected = 0
    while pending and inspected < MAX_TREE_NODES:
        node, depth = pending.pop()
        inspected += 1
        if depth >= MAX_TREE_DEPTH:
            continue
        if isinstance(node, dict):
            for key, child in node.items():
                if key == _ACTION_IDENTIFIER_KEY:
                    candidates.append(child)
                pending.append((child, depth + 1))
        elif isinstance(node, list):
            pending.extend((child, depth + 1) for child in node)
    return len(candidates) == 1 and isinstance(candidates[0], str) and candidates[0].isascii() and bool(
        _PUBLIC_ACTION_IDENTIFIER.fullmatch(candidates[0])
    )


def inspect_observed_synthetic_actions(own_data: Path, observed_paths: list[str]) -> dict[str, object]:
    """Return redacted action-blob metadata for exactly one observed shortcut."""
    try:
        schema = store.survey_observed_shortcuts_file(own_data, observed_paths)
    except store.NativeStoreSchemaError as error:
        raise NativeSyntheticActionsError("OBSERVED_SCHEMA_UNCONFIRMED") from error
    _required_schema(schema)

    deadline = time.monotonic() + store.SCHEMA_DEADLINE_SECONDS
    try:
        root = store._resolve_root(own_data)
        database, identity = store._observed_shortcuts_file(root)
        store._validate_observed_sqlite_header(database, identity)
        store._ensure_deadline(deadline)
    except store.NativeStoreSchemaError as error:
        raise NativeSyntheticActionsError("OBSERVED_SCHEMA_UNCONFIRMED") from error
    try:
        connection = sqlite3.connect(store._database_uri(database), uri=True, timeout=1.0)
    except sqlite3.Error as error:
        raise NativeSyntheticActionsError("SYNTHETIC_ACTIONS_OPEN_FAILED") from error

    def progress() -> int:
        return int(time.monotonic() >= deadline)

    try:
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.set_authorizer(_actions_authorizer)
            connection.set_progress_handler(progress, 1_000)
            connection.execute("BEGIN")
        except sqlite3.Error as error:
            raise NativeSyntheticActionsError("SYNTHETIC_ACTIONS_SETUP_FAILED") from error
        try:
            shortcuts = connection.execute("SELECT Z_PK, ZACTIONS FROM ZSHORTCUT LIMIT 2").fetchall()
            if len(shortcuts) != 1:
                raise NativeSyntheticActionsError("SYNTHETIC_ACTIONS_ROW_CARDINALITY")
            shortcut_id, action_id = map(_positive_integer, shortcuts[0])
            actions = connection.execute(
                "SELECT Z_PK, ZSHORTCUT, typeof(ZDATA), length(ZDATA) FROM ZSHORTCUTACTIONS "
                "WHERE ZSHORTCUT = ? LIMIT 2", (shortcut_id,)
            ).fetchall()
            if len(actions) != 1:
                raise NativeSyntheticActionsError("SYNTHETIC_ACTIONS_ROW_CARDINALITY")
            row_action_id, row_shortcut_id, blob_type, blob_length = actions[0]
            if _positive_integer(row_action_id) != action_id or _positive_integer(row_shortcut_id) != shortcut_id:
                raise NativeSyntheticActionsError("SYNTHETIC_ACTIONS_RELATIONSHIP_MISMATCH")
            if blob_type != "blob" or not isinstance(blob_length, int) or isinstance(blob_length, bool) or blob_length < 1:
                raise NativeSyntheticActionsError("SYNTHETIC_ACTIONS_BLOB_INVALID")
            if blob_length > MAX_ACTION_BLOB_BYTES:
                raise NativeSyntheticActionsError("SYNTHETIC_ACTIONS_BLOB_TOO_LARGE")
            blobs = connection.execute(
                "SELECT ZDATA FROM ZSHORTCUTACTIONS WHERE Z_PK = ? AND ZSHORTCUT = ? LIMIT 2",
                (action_id, shortcut_id),
            ).fetchall()
            if len(blobs) != 1 or not isinstance(blobs[0][0], bytes) or len(blobs[0][0]) != blob_length:
                raise NativeSyntheticActionsError("SYNTHETIC_ACTIONS_BLOB_INVALID")
            blob = blobs[0][0]
        except NativeSyntheticActionsError:
            raise
        except sqlite3.Error as error:
            code = "SYNTHETIC_ACTIONS_PROGRESS_LIMIT" if time.monotonic() >= deadline else "SYNTHETIC_ACTIONS_QUERY_FAILED"
            raise NativeSyntheticActionsError(code) from error
    finally:
        prior_failure = sys.exc_info()[0] is not None
        try:
            connection.close()
        except sqlite3.Error as error:
            if not prior_failure:
                raise NativeSyntheticActionsError("SYNTHETIC_ACTIONS_CLOSE_FAILED") from error

    if blob.startswith(b"bplist00"):
        framing = "binary_plist"
    elif blob.lstrip().startswith((b"<?xml", b"<plist")):
        framing = "xml_plist"
    else:
        raise NativeSyntheticActionsError(
            "SYNTHETIC_ACTIONS_BLOB_FORMAT_UNCONFIRMED", _blob_diagnostic(blob, "unknown")
        )
    try:
        decoded = plistlib.loads(blob)
    except (plistlib.InvalidFileException, ValueError, TypeError, ExpatError, RecursionError) as error:
        raise NativeSyntheticActionsError(
            "SYNTHETIC_ACTIONS_BLOB_FORMAT_UNCONFIRMED", _blob_diagnostic(blob, framing)
        ) from None
    state: dict[str, object] = {"nodes": 0, "truncated": False, "marker_count": 0}
    try:
        tree = _redacted_tree(decoded, state)
    except NativeSyntheticActionsError as error:
        raise NativeSyntheticActionsError(error.code, _blob_diagnostic(blob, framing)) from None
    if state["truncated"]:
        raise NativeSyntheticActionsError("SYNTHETIC_ACTIONS_TREE_LIMIT", _blob_diagnostic(blob, framing))
    if state["marker_count"] != 1:
        raise NativeSyntheticActionsError(
            "SYNTHETIC_ACTIONS_MARKER_UNCONFIRMED", _blob_diagnostic(blob, framing, state["marker_count"])
        )
    return {
        "status": "SYNTHETIC_ACTION_MARKER_OBSERVED",
        "scope": "one_observed_synthetic_shortcut_action_redacted",
        "schema_check": True,
        "contents_read": True,
        "blob": {"length": len(blob), "sha256": hashlib.sha256(blob).hexdigest(), "framing": framing},
        "tree": tree,
        "tree_truncated": bool(state["truncated"]),
        "marker_count_exactly_one": True,
        "action_identifier_syntax_valid": _action_identifier_syntax(decoded),
    }
