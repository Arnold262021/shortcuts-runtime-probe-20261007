"""Bounded, schema-only inspection of SQLite files in an owned simulator container.

The caller establishes that the container belongs to a simulator created for
the current run.  This module verifies its local traversal boundary again, but
does not discover simulators, copy databases, or inspect stored rows.
"""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import stat
import time
from typing import Iterator
from urllib.parse import quote


MAX_CONTAINER_NODES = 10_000
MAX_SQLITE_CANDIDATES = 8
MAX_SQLITE_BYTES = 64 * 1024 * 1024
MAX_SCHEMA_OBJECTS = 200
MAX_COLUMNS_PER_OBJECT = 200
MAX_IDENTIFIER_BYTES = 128
SCHEMA_DEADLINE_SECONDS = 5.0
SQLITE_MAGIC = b"SQLite format 3\x00"
SQLITE_SUFFIXES = {".sqlite", ".sqlite3", ".db"}

_ERROR_CODES = frozenset(
    {
        "CONTAINER_ROOT_MISSING",
        "CONTAINER_ROOT_SYMLINK",
        "CONTAINER_ROOT_NOT_DIRECTORY",
        "CONTAINER_NODE_LIMIT",
        "CONTAINER_SYMLINK",
        "CONTAINER_ESCAPE",
        "CONTAINER_UNREADABLE",
        "SQLITE_CANDIDATE_LIMIT",
        "SQLITE_FILE_SIZE_LIMIT",
        "SQLITE_OPEN_FAILED",
        "SQLITE_SCHEMA_QUERY_FAILED",
        "SQLITE_TABLE_INFO_FAILED",
        "SQLITE_PROGRESS_LIMIT",
        "SCHEMA_OBJECT_LIMIT",
        "SCHEMA_COLUMN_LIMIT",
        "SCHEMA_IDENTIFIER_LIMIT",
    }
)


class NativeStoreSchemaError(RuntimeError):
    """A stable, sanitized reason why the bounded survey could not finish."""

    def __init__(self, code: str):
        if code not in _ERROR_CODES:
            raise ValueError("unknown native store schema error code")
        super().__init__(code)
        self.code = code


def _within(child: Path, root: Path) -> bool:
    try:
        child.relative_to(root)
    except ValueError:
        return False
    return True


def _ensure_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise NativeStoreSchemaError("SQLITE_PROGRESS_LIMIT")


def _resolve_root(container_root: Path) -> Path:
    try:
        root_status = container_root.lstat()
    except FileNotFoundError as error:
        raise NativeStoreSchemaError("CONTAINER_ROOT_MISSING") from error
    if stat.S_ISLNK(root_status.st_mode):
        raise NativeStoreSchemaError("CONTAINER_ROOT_SYMLINK")
    if not stat.S_ISDIR(root_status.st_mode):
        raise NativeStoreSchemaError("CONTAINER_ROOT_NOT_DIRECTORY")
    try:
        return container_root.resolve(strict=True)
    except OSError as error:
        raise NativeStoreSchemaError("CONTAINER_UNREADABLE") from error


def _walk_regular_files(root: Path, deadline: float) -> Iterator[Path]:
    pending = [root]
    node_count = 1
    while pending:
        _ensure_deadline(deadline)
        current = pending.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    _ensure_deadline(deadline)
                    node_count += 1
                    if node_count > MAX_CONTAINER_NODES:
                        raise NativeStoreSchemaError("CONTAINER_NODE_LIMIT")
                    path = Path(entry.path)
                    try:
                        entry_status = path.lstat()
                    except OSError as error:
                        raise NativeStoreSchemaError("CONTAINER_UNREADABLE") from error
                    if stat.S_ISLNK(entry_status.st_mode):
                        raise NativeStoreSchemaError("CONTAINER_SYMLINK")
                    try:
                        resolved = path.resolve(strict=True)
                    except OSError as error:
                        raise NativeStoreSchemaError("CONTAINER_UNREADABLE") from error
                    if not _within(resolved, root):
                        raise NativeStoreSchemaError("CONTAINER_ESCAPE")
                    if stat.S_ISDIR(entry_status.st_mode):
                        pending.append(resolved)
                    elif stat.S_ISREG(entry_status.st_mode):
                        yield resolved
        except OSError as error:
            raise NativeStoreSchemaError("CONTAINER_UNREADABLE") from error


def _sqlite_candidates(root: Path, deadline: float) -> list[Path]:
    candidates: list[Path] = []
    for path in _walk_regular_files(root, deadline):
        _ensure_deadline(deadline)
        if path.suffix.lower() not in SQLITE_SUFFIXES:
            continue
        try:
            file_size = path.stat().st_size
        except OSError as error:
            raise NativeStoreSchemaError("CONTAINER_UNREADABLE") from error
        if file_size > MAX_SQLITE_BYTES:
            raise NativeStoreSchemaError("SQLITE_FILE_SIZE_LIMIT")
        try:
            with path.open("rb") as database_file:
                if database_file.read(len(SQLITE_MAGIC)) != SQLITE_MAGIC:
                    continue
        except OSError as error:
            raise NativeStoreSchemaError("CONTAINER_UNREADABLE") from error
        candidates.append(path)
        if len(candidates) > MAX_SQLITE_CANDIDATES:
            raise NativeStoreSchemaError("SQLITE_CANDIDATE_LIMIT")
    return candidates


def _require_identifier(value: object) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_IDENTIFIER_BYTES:
        raise NativeStoreSchemaError("SCHEMA_IDENTIFIER_LIMIT")
    return value


def _schema_authorizer(
    action: int,
    first: str | None,
    _second: str | None,
    _database: str | None,
    _source: str | None,
) -> int:
    if action == sqlite3.SQLITE_READ:
        return (
            sqlite3.SQLITE_OK
            if first in {"sqlite_master", "sqlite_schema", "pragma_table_info"}
            else sqlite3.SQLITE_DENY
        )
    if action == sqlite3.SQLITE_PRAGMA:
        return sqlite3.SQLITE_OK if first in {"query_only", "table_info"} else sqlite3.SQLITE_DENY
    if action in {
        sqlite3.SQLITE_INSERT,
        sqlite3.SQLITE_UPDATE,
        sqlite3.SQLITE_DELETE,
        sqlite3.SQLITE_ATTACH,
        sqlite3.SQLITE_DETACH,
        sqlite3.SQLITE_ALTER_TABLE,
        sqlite3.SQLITE_DROP_TABLE,
        sqlite3.SQLITE_DROP_INDEX,
        sqlite3.SQLITE_DROP_TRIGGER,
        sqlite3.SQLITE_DROP_VIEW,
        sqlite3.SQLITE_CREATE_INDEX,
        sqlite3.SQLITE_CREATE_TABLE,
        sqlite3.SQLITE_CREATE_TRIGGER,
        sqlite3.SQLITE_CREATE_VIEW,
    }:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def _database_uri(path: Path) -> str:
    return "file:" + quote(str(path), safe="/") + "?mode=ro"


def _survey_database(path: Path, root: Path, deadline: float) -> dict[str, object]:
    _ensure_deadline(deadline)
    try:
        connection = sqlite3.connect(_database_uri(path), uri=True, timeout=1.0)
    except sqlite3.Error as error:
        raise NativeStoreSchemaError("SQLITE_OPEN_FAILED") from error

    def stop_after_deadline() -> int:
        return int(time.monotonic() >= deadline)

    try:
        connection.execute("PRAGMA query_only=ON")
        connection.set_authorizer(_schema_authorizer)
        connection.set_progress_handler(stop_after_deadline, 1_000)
        try:
            objects = connection.execute(
                "SELECT name, type FROM sqlite_master "
                "WHERE type IN (?, ?) ORDER BY name LIMIT ?",
                ("table", "view", MAX_SCHEMA_OBJECTS + 1),
            ).fetchall()
        except sqlite3.Error as error:
            code = "SQLITE_PROGRESS_LIMIT" if time.monotonic() >= deadline else "SQLITE_SCHEMA_QUERY_FAILED"
            raise NativeStoreSchemaError(code) from error
        if len(objects) > MAX_SCHEMA_OBJECTS:
            raise NativeStoreSchemaError("SCHEMA_OBJECT_LIMIT")

        report_objects: list[dict[str, object]] = []
        for object_name, object_type in objects:
            _ensure_deadline(deadline)
            name = _require_identifier(object_name)
            kind = _require_identifier(object_type)
            try:
                columns = connection.execute(
                    "SELECT name, type, \"notnull\", pk FROM pragma_table_info(?) LIMIT ?",
                    (name, MAX_COLUMNS_PER_OBJECT + 1),
                ).fetchall()
            except sqlite3.Error as error:
                code = "SQLITE_PROGRESS_LIMIT" if time.monotonic() >= deadline else "SQLITE_TABLE_INFO_FAILED"
                raise NativeStoreSchemaError(code) from error
            if len(columns) > MAX_COLUMNS_PER_OBJECT:
                raise NativeStoreSchemaError("SCHEMA_COLUMN_LIMIT")
            report_columns: list[dict[str, object]] = []
            for column_name, declared_type, is_not_null, primary_key_position in columns:
                report_columns.append(
                    {
                        "name": _require_identifier(column_name),
                        "type": _require_identifier(declared_type),
                        "notnull": bool(is_not_null),
                        "pk": int(primary_key_position),
                    }
                )
            report_objects.append({"name": name, "kind": kind, "columns": report_columns})
    finally:
        connection.close()

    try:
        relative_path = path.relative_to(root).as_posix()
    except ValueError as error:
        raise NativeStoreSchemaError("CONTAINER_ESCAPE") from error
    return {"path": relative_path, "objects": report_objects}


def survey_shortcuts_schema(container_root: Path) -> dict[str, object]:
    """Return bounded SQLite schema metadata from a caller-validated container.

    The result exposes database-relative paths, tables/views, and column
    metadata only. It does not read application table rows, serialized blobs,
    raw DDL, property lists, or shortcut semantics.
    """
    deadline = time.monotonic() + SCHEMA_DEADLINE_SECONDS
    root = _resolve_root(container_root)
    _ensure_deadline(deadline)
    databases = _sqlite_candidates(root, deadline)
    reports = [_survey_database(path, root, deadline) for path in databases]
    return {
        "schema_only": True,
        "candidate_count": len(reports),
        "databases": reports,
    }
