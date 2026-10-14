"""Decode bounded simulator app-group metadata without reading workflow stores."""

from __future__ import annotations

import json
import os
from pathlib import Path
import plistlib
import shlex
import stat
from typing import Any
from xml.parsers.expat import ExpatError


MAX_METADATA_BYTES = 64 * 1024
MAX_GROUPS = 8
MAX_IDENTIFIER_BYTES = 128
MCM_METADATA_NAME = ".com.apple.mobile_container_manager.metadata.plist"

_ERROR_CODES = frozenset(
    {
        "GROUP_METADATA_EMPTY",
        "GROUP_METADATA_TOO_LARGE",
        "GROUP_METADATA_FORMAT_UNCONFIRMED",
        "GROUP_METADATA_SHAPE_UNCONFIRMED",
        "GROUP_METADATA_COUNT_LIMIT",
        "GROUP_METADATA_IDENTIFIER_UNCONFIRMED",
        "GROUP_METADATA_PATH_UNCONFIRMED",
        "GROUP_METADATA_PATH_MISSING",
        "GROUP_METADATA_PATH_SYMLINK",
        "GROUP_METADATA_PATH_ESCAPE",
        "GROUP_METADATA_PATH_DUPLICATE",
        "GROUP_METADATA_OWN_DATA_UNCONFIRMED",
        "GROUP_METADATA_MCM_MISSING",
        "GROUP_METADATA_MCM_SYMLINK",
        "GROUP_METADATA_MCM_TOO_LARGE",
        "GROUP_METADATA_MCM_UNCONFIRMED",
        "GROUP_METADATA_MCM_IDENTIFIER_MISMATCH",
    }
)


class NativeGroupMetadataError(RuntimeError):
    """Stable, sanitized decoding failure for optional native group metadata."""

    def __init__(self, code: str):
        if code not in _ERROR_CODES:
            raise ValueError("unknown native group metadata error code")
        super().__init__(code)
        self.code = code


def _resolved_directory(path: Path) -> Path:
    try:
        status = path.lstat()
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
            raise NativeGroupMetadataError("GROUP_METADATA_OWN_DATA_UNCONFIRMED")
        return path.resolve(strict=True)
    except NativeGroupMetadataError:
        raise
    except OSError as error:
        raise NativeGroupMetadataError("GROUP_METADATA_OWN_DATA_UNCONFIRMED") from error


def _app_group_directory(own_root: Path) -> Path:
    current = own_root
    try:
        for segment in ("Containers", "Shared", "AppGroup"):
            current = current / segment
            status = current.lstat()
            if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
                raise NativeGroupMetadataError("GROUP_METADATA_OWN_DATA_UNCONFIRMED")
        resolved = current.resolve(strict=True)
        resolved.relative_to(own_root)
        return resolved
    except NativeGroupMetadataError:
        raise
    except (OSError, ValueError) as error:
        raise NativeGroupMetadataError("GROUP_METADATA_OWN_DATA_UNCONFIRMED") from error


def _parse_payload(raw_metadata: bytes) -> tuple[dict[object, object] | list[object] | str, str]:
    if not isinstance(raw_metadata, bytes):
        raise NativeGroupMetadataError("GROUP_METADATA_FORMAT_UNCONFIRMED")
    if not raw_metadata:
        raise NativeGroupMetadataError("GROUP_METADATA_EMPTY")
    if len(raw_metadata) > MAX_METADATA_BYTES:
        raise NativeGroupMetadataError("GROUP_METADATA_TOO_LARGE")

    try:
        text = raw_metadata.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    decoded: Any = None
    decoded_json = False
    if text is not None:
        try:
            decoded = json.loads(text)
            decoded_json = True
        except json.JSONDecodeError:
            pass
    if not decoded_json:
        try:
            decoded = plistlib.loads(raw_metadata)
        except (plistlib.InvalidFileException, ValueError, TypeError, ExpatError) as error:
            lines = text.splitlines() if text is not None else []
            if lines:
                decoded = text
                return decoded, "lines"
            else:
                raise NativeGroupMetadataError("GROUP_METADATA_FORMAT_UNCONFIRMED") from error

    if isinstance(decoded, (dict, list, str)):
        return decoded, "structured"
    raise NativeGroupMetadataError("GROUP_METADATA_SHAPE_UNCONFIRMED")


def _is_group_identifier(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("group.")
        and len(value) > len("group.")
        and value.isascii()
        and len(value.encode("ascii")) <= MAX_IDENTIFIER_BYTES
        and all(character.isalnum() or character in "._-" for character in value)
    )


def _declared_groups(
    decoded: dict[object, object] | list[object] | str, source: str
) -> list[tuple[str | None, str | None, bool]]:
    if isinstance(decoded, dict):
        # A dictionary's key/value meaning is not documented by simctl. Do not
        # turn a convenient JSON shape into a group-container contract.
        raise NativeGroupMetadataError("GROUP_METADATA_SHAPE_UNCONFIRMED")
    if isinstance(decoded, str):
        if source == "lines":
            lines = decoded.splitlines()
            # Keep the previously supported raw forms literal. In particular,
            # shlex would consume Windows backslashes before paths reach the
            # strict boundary validator.
            if lines and all(Path(line).is_absolute() for line in lines):
                if len(lines) > MAX_GROUPS:
                    raise NativeGroupMetadataError("GROUP_METADATA_COUNT_LIMIT")
                return [(None, line, False) for line in lines]
            if lines and all(_is_group_identifier(line) for line in lines):
                if len(lines) > MAX_GROUPS:
                    raise NativeGroupMetadataError("GROUP_METADATA_COUNT_LIMIT")
                return [(line, None, False) for line in lines]
            try:
                token_lines = [shlex.split(line) for line in lines]
            except ValueError as error:
                raise NativeGroupMetadataError("GROUP_METADATA_FORMAT_UNCONFIRMED") from error
            if not token_lines or any(not tokens for tokens in token_lines):
                raise NativeGroupMetadataError("GROUP_METADATA_FORMAT_UNCONFIRMED")
            if all(len(tokens) == 2 for tokens in token_lines):
                if not all(_is_group_identifier(tokens[0]) and Path(tokens[1]).is_absolute()
                           for tokens in token_lines):
                    raise NativeGroupMetadataError("GROUP_METADATA_FORMAT_UNCONFIRMED")
                if len(token_lines) > MAX_GROUPS:
                    raise NativeGroupMetadataError("GROUP_METADATA_COUNT_LIMIT")
                return [(tokens[0], tokens[1], True) for tokens in token_lines]
            if not all(len(tokens) == 1 for tokens in token_lines):
                raise NativeGroupMetadataError("GROUP_METADATA_FORMAT_UNCONFIRMED")
            declared: list[object] = [tokens[0] for tokens in token_lines]
            if not all(_is_group_identifier(item) or (isinstance(item, str) and Path(item).is_absolute())
                       for item in declared):
                raise NativeGroupMetadataError("GROUP_METADATA_FORMAT_UNCONFIRMED")
        else:
            declared = [decoded]
    else:
        declared = decoded

    if not declared:
        raise NativeGroupMetadataError("GROUP_METADATA_EMPTY")
    if len(declared) > MAX_GROUPS:
        raise NativeGroupMetadataError("GROUP_METADATA_COUNT_LIMIT")

    if all(_is_group_identifier(item) for item in declared):
        return [(item, None, False) for item in declared]

    normalized: list[tuple[str | None, str | None, bool]] = []
    for path_text in declared:
        if not isinstance(path_text, str) or not path_text or not Path(path_text).is_absolute():
            raise NativeGroupMetadataError("GROUP_METADATA_PATH_UNCONFIRMED")
        normalized.append((None, path_text, False))
    return normalized


def _safe_group_path(path_text: str, app_group_root: Path) -> Path:
    candidate = Path(path_text)
    if not candidate.is_absolute():
        raise NativeGroupMetadataError("GROUP_METADATA_PATH_UNCONFIRMED")

    # Resolve only the declared parent. It may be the Darwin /var alias for a
    # canonical /private/var AppGroup root, but the leaf must remain a direct
    # child and is inspected through the canonical root below.
    lexical = Path(os.path.abspath(os.path.normpath(str(candidate))))
    try:
        if lexical.parent.resolve(strict=True) != app_group_root:
            raise NativeGroupMetadataError("GROUP_METADATA_PATH_ESCAPE")
        canonical_candidate = app_group_root / lexical.name
        status = canonical_candidate.lstat()
        if stat.S_ISLNK(status.st_mode):
            raise NativeGroupMetadataError("GROUP_METADATA_PATH_SYMLINK")
        if not stat.S_ISDIR(status.st_mode):
            raise NativeGroupMetadataError("GROUP_METADATA_PATH_UNCONFIRMED")
        resolved = canonical_candidate.resolve(strict=True)
    except NativeGroupMetadataError:
        raise
    except FileNotFoundError as error:
        raise NativeGroupMetadataError("GROUP_METADATA_PATH_MISSING") from error
    except (OSError, ValueError) as error:
        raise NativeGroupMetadataError("GROUP_METADATA_PATH_UNCONFIRMED") from error

    try:
        resolved.relative_to(app_group_root)
    except ValueError as error:
        raise NativeGroupMetadataError("GROUP_METADATA_PATH_ESCAPE") from error
    return resolved


def _verify_mcm_identifier(group_path: Path, identifier: str) -> None:
    metadata = group_path / MCM_METADATA_NAME
    try:
        before = metadata.lstat()
        if stat.S_ISLNK(before.st_mode):
            raise NativeGroupMetadataError("GROUP_METADATA_MCM_SYMLINK")
        if not stat.S_ISREG(before.st_mode):
            raise NativeGroupMetadataError("GROUP_METADATA_MCM_MISSING")
        if before.st_size > MAX_METADATA_BYTES:
            raise NativeGroupMetadataError("GROUP_METADATA_MCM_TOO_LARGE")
        descriptor = os.open(str(metadata), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise NativeGroupMetadataError("GROUP_METADATA_MCM_UNCONFIRMED")
            raw = os.read(descriptor, MAX_METADATA_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(raw) > MAX_METADATA_BYTES:
            raise NativeGroupMetadataError("GROUP_METADATA_MCM_TOO_LARGE")
        content = plistlib.loads(raw)
        if not isinstance(content, dict):
            raise NativeGroupMetadataError("GROUP_METADATA_MCM_UNCONFIRMED")
        if content.get("MCMMetadataIdentifier") != identifier:
            raise NativeGroupMetadataError("GROUP_METADATA_MCM_IDENTIFIER_MISMATCH")
    except NativeGroupMetadataError:
        raise
    except FileNotFoundError as error:
        raise NativeGroupMetadataError("GROUP_METADATA_MCM_MISSING") from error
    except (OSError, ValueError, TypeError, plistlib.InvalidFileException, ExpatError) as error:
        raise NativeGroupMetadataError("GROUP_METADATA_MCM_UNCONFIRMED") from error


def decode_group_metadata(raw_metadata: bytes, own_data: Path) -> list[dict[str, object]]:
    """Decode declared app-group paths with a narrowly bounded MCM check.

    ``own_data`` must be the already-authorized data root for the fresh owned
    simulator. Returned ``Path`` instances are canonical and remain in memory;
    this function neither creates files nor queries SQLite, workflow-store
    rows, or shortcut semantics. For raw ``ID path`` pairs only, it reads the
    single known MCM metadata plist (at most 64 KiB) to verify that exact ID;
    it does not return that plist's contents.
    """
    own_root = _resolved_directory(own_data)
    decoded, source = _parse_payload(raw_metadata)
    declared = _declared_groups(decoded, source)

    groups: list[dict[str, object]] = []
    seen_paths: set[Path] = set()
    seen_identifiers: set[str] = set()
    app_group_root: Path | None = None
    for identifier, path_text, requires_mcm_match in declared:
        if identifier is not None:
            if identifier in seen_identifiers:
                raise NativeGroupMetadataError("GROUP_METADATA_PATH_DUPLICATE")
            seen_identifiers.add(identifier)
            if path_text is None:
                groups.append({"identifier": identifier, "path": None})
                continue
        if app_group_root is None:
            app_group_root = _app_group_directory(own_root)
        assert path_text is not None
        path = _safe_group_path(path_text, app_group_root)
        if requires_mcm_match:
            assert identifier is not None
            _verify_mcm_identifier(path, identifier)
        if path in seen_paths:
            raise NativeGroupMetadataError("GROUP_METADATA_PATH_DUPLICATE")
        seen_paths.add(path)
        group: dict[str, object] = {"path": path}
        if identifier is not None:
            group["identifier"] = identifier
        groups.append(group)
    return groups
