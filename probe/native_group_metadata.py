"""Decode bounded simulator app-group metadata without accessing group stores."""

from __future__ import annotations

import json
import os
from pathlib import Path
import plistlib
import stat
from typing import Any
from xml.parsers.expat import ExpatError


MAX_METADATA_BYTES = 64 * 1024
MAX_GROUPS = 8
MAX_IDENTIFIER_BYTES = 128

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
            if lines and all(line and Path(line).is_absolute() for line in lines):
                decoded = text
                return decoded, "lines"
            if text is not None and _is_group_identifier(text):
                return text, "structured"
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
) -> list[tuple[str | None, str | None]]:
    if isinstance(decoded, dict):
        # A dictionary's key/value meaning is not documented by simctl. Do not
        # turn a convenient JSON shape into a group-container contract.
        raise NativeGroupMetadataError("GROUP_METADATA_SHAPE_UNCONFIRMED")
    if isinstance(decoded, str):
        if source == "lines":
            declared: list[object] = decoded.splitlines()
        else:
            declared = [decoded]
    else:
        declared = decoded

    if not declared:
        raise NativeGroupMetadataError("GROUP_METADATA_EMPTY")
    if len(declared) > MAX_GROUPS:
        raise NativeGroupMetadataError("GROUP_METADATA_COUNT_LIMIT")

    if all(_is_group_identifier(item) for item in declared):
        return [(item, None) for item in declared]

    normalized: list[tuple[str | None, str | None]] = []
    for path_text in declared:
        if not isinstance(path_text, str) or not path_text or not Path(path_text).is_absolute():
            raise NativeGroupMetadataError("GROUP_METADATA_PATH_UNCONFIRMED")
        normalized.append((None, path_text))
    return normalized


def _safe_group_path(path_text: str, app_group_root: Path) -> Path:
    candidate = Path(path_text)
    if not candidate.is_absolute():
        raise NativeGroupMetadataError("GROUP_METADATA_PATH_UNCONFIRMED")

    # Normalize lexical aliases before looking for symlinks. This avoids a
    # mocked/home alias affecting the containment comparison while keeping any
    # symlink component visible to lstat below.
    lexical = Path(os.path.abspath(os.path.normpath(str(candidate))))
    try:
        relative = lexical.relative_to(app_group_root)
    except ValueError as error:
        raise NativeGroupMetadataError("GROUP_METADATA_PATH_ESCAPE") from error
    if not relative.parts:
        raise NativeGroupMetadataError("GROUP_METADATA_PATH_UNCONFIRMED")

    current = app_group_root
    try:
        for segment in relative.parts:
            current = current / segment
            status = current.lstat()
            if stat.S_ISLNK(status.st_mode):
                raise NativeGroupMetadataError("GROUP_METADATA_PATH_SYMLINK")
        if not stat.S_ISDIR(status.st_mode):
            raise NativeGroupMetadataError("GROUP_METADATA_PATH_UNCONFIRMED")
        resolved = lexical.resolve(strict=True)
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


def decode_group_metadata(raw_metadata: bytes, own_data: Path) -> list[dict[str, object]]:
    """Decode declared app-group paths without reading any group container.

    ``own_data`` must be the already-authorized data root for the fresh owned
    simulator. Returned ``Path`` instances are canonical and remain in memory;
    this function neither creates files nor queries SQLite, plist stores, or
    group-container contents.
    """
    own_root = _resolved_directory(own_data)
    decoded, source = _parse_payload(raw_metadata)
    declared = _declared_groups(decoded, source)

    groups: list[dict[str, object]] = []
    seen_paths: set[Path] = set()
    seen_identifiers: set[str] = set()
    app_group_root: Path | None = None
    for identifier, path_text in declared:
        if identifier is not None:
            if identifier in seen_identifiers:
                raise NativeGroupMetadataError("GROUP_METADATA_PATH_DUPLICATE")
            seen_identifiers.add(identifier)
            groups.append({"identifier": identifier, "path": None})
            continue
        if app_group_root is None:
            app_group_root = _app_group_directory(own_root)
        assert path_text is not None
        path = _safe_group_path(path_text, app_group_root)
        if path in seen_paths:
            raise NativeGroupMetadataError("GROUP_METADATA_PATH_DUPLICATE")
        seen_paths.add(path)
        group: dict[str, object] = {"path": path}
        if identifier is not None:
            group["identifier"] = identifier
        groups.append(group)
    return groups
