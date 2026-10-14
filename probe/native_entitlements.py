"""Bounded parsing of codesign entitlements and declared SystemGroup headers."""

from __future__ import annotations

import os
from pathlib import Path
import plistlib
import stat
import time
from typing import Any
from xml.parsers.expat import ExpatError


MAX_CODESIGN_OUTPUT_BYTES = 256 * 1024
MAX_ENTITLEMENT_KEYS = 128
MAX_IDENTIFIER_BYTES = 128
MAX_GROUP_IDS = 8
MAX_SYSTEM_GROUP_DIRS = 256
MAX_MCM_METADATA_BYTES = 64 * 1024
SYSTEM_GROUP_DEADLINE_SECONDS = 5.0
MCM_METADATA_NAME = ".com.apple.mobile_container_manager.metadata.plist"
APPLICATION_GROUPS_KEY = "com.apple.security.application-groups"
SYSTEM_GROUPS_KEY = "com.apple.security.system-groups"

_ERROR_CODES = frozenset(
    {
        "ENTITLEMENTS_EMPTY",
        "ENTITLEMENTS_TOO_LARGE",
        "ENTITLEMENTS_FORMAT_UNCONFIRMED",
        "ENTITLEMENTS_SHAPE_UNCONFIRMED",
        "ENTITLEMENTS_KEY_LIMIT",
        "ENTITLEMENTS_KEY_UNCONFIRMED",
        "ENTITLEMENTS_GROUPS_UNCONFIRMED",
        "ENTITLEMENTS_GROUP_LIMIT",
        "SYSTEM_GROUP_ROOT_MISSING",
        "SYSTEM_GROUP_ROOT_SYMLINK",
        "SYSTEM_GROUP_ROOT_UNCONFIRMED",
        "SYSTEM_GROUP_DEADLINE",
        "SYSTEM_GROUP_DIR_LIMIT",
        "SYSTEM_GROUP_SYMLINK",
        "SYSTEM_GROUP_METADATA_SYMLINK",
        "SYSTEM_GROUP_METADATA_TOO_LARGE",
        "SYSTEM_GROUP_METADATA_UNCONFIRMED",
        "SYSTEM_GROUP_DECLARED_MISSING",
        "SYSTEM_GROUP_DECLARED_AMBIGUOUS",
    }
)


class NativeEntitlementsError(RuntimeError):
    """Stable, sanitized error for optional entitlement metadata."""

    def __init__(self, code: str):
        if code not in _ERROR_CODES:
            raise ValueError("unknown native entitlements error code")
        super().__init__(code)
        self.code = code


def _type_name(value: object) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, str):
        return "string"
    if isinstance(value, bytes):
        return "data"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "dict"
    if isinstance(value, (int, float)):
        return "number"
    return "other"


def _safe_identifier(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or len(value.encode("ascii")) > MAX_IDENTIFIER_BYTES
        or not all(character.isalnum() or character in "._-" for character in value)
    ):
        raise NativeEntitlementsError("ENTITLEMENTS_GROUPS_UNCONFIRMED")
    return value


def _parse_plist_stream(raw_output: bytes) -> dict[object, object] | None:
    if not isinstance(raw_output, bytes):
        raise NativeEntitlementsError("ENTITLEMENTS_FORMAT_UNCONFIRMED")
    if not raw_output:
        return None
    if len(raw_output) > MAX_CODESIGN_OUTPUT_BYTES:
        raise NativeEntitlementsError("ENTITLEMENTS_TOO_LARGE")
    try:
        content: Any = plistlib.loads(raw_output)
    except (plistlib.InvalidFileException, ValueError, TypeError, ExpatError) as error:
        raise NativeEntitlementsError("ENTITLEMENTS_FORMAT_UNCONFIRMED") from error
    if not isinstance(content, dict):
        raise NativeEntitlementsError("ENTITLEMENTS_SHAPE_UNCONFIRMED")
    return content


def _declared_groups(content: dict[object, object], key: str) -> list[str] | None:
    if key not in content:
        return None
    values = content[key]
    if not isinstance(values, list):
        raise NativeEntitlementsError("ENTITLEMENTS_GROUPS_UNCONFIRMED")
    if len(values) > MAX_GROUP_IDS:
        raise NativeEntitlementsError("ENTITLEMENTS_GROUP_LIMIT")
    declared = [_safe_identifier(value) for value in values]
    if len(set(declared)) != len(declared):
        raise NativeEntitlementsError("ENTITLEMENTS_GROUPS_UNCONFIRMED")
    return declared


def parse_codesign_entitlements(stdout: bytes, stderr: bytes = b"") -> dict[str, object]:
    """Return metadata from the complete stdout plist, never raw streams."""
    if not isinstance(stderr, bytes):
        raise NativeEntitlementsError("ENTITLEMENTS_FORMAT_UNCONFIRMED")
    if len(stderr) > MAX_CODESIGN_OUTPUT_BYTES:
        raise NativeEntitlementsError("ENTITLEMENTS_TOO_LARGE")
    if not stdout:
        if stderr:
            raise NativeEntitlementsError("ENTITLEMENTS_FORMAT_UNCONFIRMED")
        raise NativeEntitlementsError("ENTITLEMENTS_EMPTY")
    # codesign commonly writes diagnostics to stderr. It is not an entitlement
    # contract and is neither parsed nor retained.
    content = _parse_plist_stream(stdout)
    assert content is not None
    if len(content) > MAX_ENTITLEMENT_KEYS:
        raise NativeEntitlementsError("ENTITLEMENTS_KEY_LIMIT")
    key_types: dict[str, str] = {}
    for key, value in content.items():
        if not isinstance(key, str) or not key or len(key.encode("utf-8")) > MAX_IDENTIFIER_BYTES:
            raise NativeEntitlementsError("ENTITLEMENTS_KEY_UNCONFIRMED")
        key_types[key] = _type_name(value)
    application_groups = _declared_groups(content, APPLICATION_GROUPS_KEY)
    system_groups = _declared_groups(content, SYSTEM_GROUPS_KEY)
    return {
        "entitlement_types": key_types,
        "application_groups": application_groups or [],
        "system_groups": system_groups or [],
        "system_groups_declared": system_groups is not None,
        "system_groups_status": (
            "SYSTEM_GROUP_ENTITLEMENT_DECLARED"
            if system_groups is not None
            else "SYSTEM_GROUP_ENTITLEMENT_NOT_DECLARED"
        ),
    }


def _ensure_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise NativeEntitlementsError("SYSTEM_GROUP_DEADLINE")


def _resolve_system_group_root(own_data: Path) -> Path:
    try:
        own_status = own_data.lstat()
        if stat.S_ISLNK(own_status.st_mode) or not stat.S_ISDIR(own_status.st_mode):
            raise NativeEntitlementsError("SYSTEM_GROUP_ROOT_UNCONFIRMED")
        own_root = own_data.resolve(strict=True)
        current = own_root
        for segment in ("Containers", "Shared", "SystemGroup"):
            current = current / segment
            status = current.lstat()
            if stat.S_ISLNK(status.st_mode):
                raise NativeEntitlementsError("SYSTEM_GROUP_ROOT_SYMLINK")
            if not stat.S_ISDIR(status.st_mode):
                raise NativeEntitlementsError("SYSTEM_GROUP_ROOT_UNCONFIRMED")
        resolved = current.resolve(strict=True)
        resolved.relative_to(own_root)
        return resolved
    except NativeEntitlementsError:
        raise
    except FileNotFoundError as error:
        raise NativeEntitlementsError("SYSTEM_GROUP_ROOT_MISSING") from error
    except (OSError, ValueError) as error:
        raise NativeEntitlementsError("SYSTEM_GROUP_ROOT_UNCONFIRMED") from error


def _read_mcm_identifier(directory: Path) -> str | None:
    metadata = directory / MCM_METADATA_NAME
    try:
        before = metadata.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise NativeEntitlementsError("SYSTEM_GROUP_METADATA_UNCONFIRMED") from error
    if stat.S_ISLNK(before.st_mode):
        raise NativeEntitlementsError("SYSTEM_GROUP_METADATA_SYMLINK")
    if not stat.S_ISREG(before.st_mode):
        return None
    if before.st_size > MAX_MCM_METADATA_BYTES:
        raise NativeEntitlementsError("SYSTEM_GROUP_METADATA_TOO_LARGE")
    try:
        descriptor = os.open(str(metadata), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise NativeEntitlementsError("SYSTEM_GROUP_METADATA_UNCONFIRMED")
            raw = os.read(descriptor, MAX_MCM_METADATA_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(raw) > MAX_MCM_METADATA_BYTES:
            raise NativeEntitlementsError("SYSTEM_GROUP_METADATA_TOO_LARGE")
        content = plistlib.loads(raw)
        if not isinstance(content, dict):
            raise NativeEntitlementsError("SYSTEM_GROUP_METADATA_UNCONFIRMED")
        identifier = content.get("MCMMetadataIdentifier")
        return _safe_identifier(identifier)
    except NativeEntitlementsError:
        raise
    except (OSError, ValueError, TypeError, plistlib.InvalidFileException, ExpatError) as error:
        raise NativeEntitlementsError("SYSTEM_GROUP_METADATA_UNCONFIRMED") from error


def locate_declared_system_groups(own_data: Path, system_group_ids: list[str]) -> list[dict[str, object]]:
    """Locate only declared SystemGroups through their bounded MCM headers."""
    if not isinstance(system_group_ids, list):
        raise NativeEntitlementsError("ENTITLEMENTS_GROUPS_UNCONFIRMED")
    if len(system_group_ids) > MAX_GROUP_IDS:
        raise NativeEntitlementsError("ENTITLEMENTS_GROUP_LIMIT")
    declared = [_safe_identifier(identifier) for identifier in system_group_ids]
    if len(set(declared)) != len(declared):
        raise NativeEntitlementsError("ENTITLEMENTS_GROUPS_UNCONFIRMED")
    if not declared:
        raise NativeEntitlementsError("SYSTEM_GROUP_DECLARED_MISSING")

    deadline = time.monotonic() + SYSTEM_GROUP_DEADLINE_SECONDS
    root = _resolve_system_group_root(own_data)
    matches: dict[str, Path] = {}
    directory_count = 0
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                _ensure_deadline(deadline)
                path = Path(entry.path)
                status = path.lstat()
                if stat.S_ISLNK(status.st_mode):
                    raise NativeEntitlementsError("SYSTEM_GROUP_SYMLINK")
                if not stat.S_ISDIR(status.st_mode):
                    continue
                directory_count += 1
                if directory_count > MAX_SYSTEM_GROUP_DIRS:
                    raise NativeEntitlementsError("SYSTEM_GROUP_DIR_LIMIT")
                resolved = path.resolve(strict=True)
                try:
                    resolved.relative_to(root)
                except ValueError as error:
                    raise NativeEntitlementsError("SYSTEM_GROUP_ROOT_UNCONFIRMED") from error
                identifier = _read_mcm_identifier(resolved)
                if identifier not in declared:
                    continue
                if identifier in matches:
                    raise NativeEntitlementsError("SYSTEM_GROUP_DECLARED_AMBIGUOUS")
                matches[identifier] = resolved
    except NativeEntitlementsError:
        raise
    except OSError as error:
        raise NativeEntitlementsError("SYSTEM_GROUP_ROOT_UNCONFIRMED") from error
    _ensure_deadline(deadline)
    if set(matches) != set(declared):
        raise NativeEntitlementsError("SYSTEM_GROUP_DECLARED_MISSING")
    return [{"identifier": identifier, "path": matches[identifier]} for identifier in declared]
