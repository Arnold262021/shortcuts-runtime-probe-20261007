"""Bounded metadata parsers for an observed Shortcuts process and its open paths."""

from __future__ import annotations

import os
from pathlib import Path
import re
import stat
from typing import Final


MAX_STDOUT_BYTES: Final = 64 * 1024
MAX_LSOF_LINES: Final = 512
MAX_OPEN_PATHS: Final = 512
MAX_PID: Final = 2**31 - 1
SHORTCUTS_COMMAND: Final = "Shortcuts"
_LSOF_FIELD_CLASSES: Final = ("p", "c", "n", "f", "blank", "unknown")

_ERROR_CODES = frozenset(
    {
        "LAUNCH_EMPTY",
        "LAUNCH_TOO_LARGE",
        "LAUNCH_FORMAT_UNCONFIRMED",
        "LSOF_EMPTY",
        "LSOF_TOO_LARGE",
        "LSOF_LINE_LIMIT",
        "LSOF_FORMAT_UNCONFIRMED",
        "LSOF_PID_UNCONFIRMED",
        "LSOF_COMMAND_UNCONFIRMED",
        "OWN_DATA_MISSING",
        "OWN_DATA_SYMLINK",
        "OWN_DATA_UNCONFIRMED",
        "OPEN_FILE_SYMLINK",
        "OPEN_FILE_UNCONFIRMED",
        "NO_ASSOCIATED_OPEN_HANDLE_OBSERVED",
    }
)


class NativeOpenFilesError(RuntimeError):
    """Stable, sanitized reason why open-file metadata is unusable."""

    def __init__(self, code: str):
        if code not in _ERROR_CODES:
            raise ValueError("unknown native open-file error code")
        super().__init__(code)
        self.code = code


def _bounded_bytes(value: bytes, *, empty_code: str, too_large_code: str) -> bytes:
    if not isinstance(value, bytes):
        raise NativeOpenFilesError("LSOF_FORMAT_UNCONFIRMED")
    if not value:
        raise NativeOpenFilesError(empty_code)
    if len(value) > MAX_STDOUT_BYTES:
        raise NativeOpenFilesError(too_large_code)
    return value


def lsof_output_shape(stdout: bytes) -> dict[str, object]:
    """Describe bounded `lsof -F` framing without retaining field values.

    This diagnostic intentionally does not validate a process association and
    never returns PIDs, commands, paths, or other field contents.
    """
    if not isinstance(stdout, bytes):
        raise NativeOpenFilesError("LSOF_FORMAT_UNCONFIRMED")
    if len(stdout) > MAX_STDOUT_BYTES:
        raise NativeOpenFilesError("LSOF_TOO_LARGE")

    records = [] if not stdout else stdout.split(b"\n")
    if records and stdout.endswith(b"\n"):
        records.pop()
    if len(records) > MAX_LSOF_LINES:
        raise NativeOpenFilesError("LSOF_LINE_LIMIT")

    classes: list[str] = []
    counts = {field_class: 0 for field_class in _LSOF_FIELD_CLASSES}
    absolute_n_path_count = 0
    for record in records:
        if not record:
            field_class = "blank"
        elif record[:1] in (b"p", b"c", b"n", b"f"):
            field_class = record[:1].decode("ascii")
        else:
            field_class = "unknown"
        classes.append(field_class)
        counts[field_class] += 1
        if field_class == "n" and record[1:].startswith(b"/"):
            absolute_n_path_count += 1

    return {
        "byte_count": len(stdout),
        "newline_count": stdout.count(b"\n"),
        "nul_count": stdout.count(b"\x00"),
        "ends_newline": stdout.endswith(b"\n"),
        "record_count": len(records),
        "field_classes": classes,
        "field_class_counts": counts,
        "absolute_n_path_count": absolute_n_path_count,
    }


def parse_simctl_launch(stdout: bytes) -> int:
    """Parse exactly one observed `com.apple.shortcuts: PID` launch line."""
    raw = _bounded_bytes(stdout, empty_code="LAUNCH_EMPTY", too_large_code="LAUNCH_TOO_LARGE")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise NativeOpenFilesError("LAUNCH_FORMAT_UNCONFIRMED") from error
    if not text.endswith("\n") or text.count("\n") != 1 or "\r" in text:
        raise NativeOpenFilesError("LAUNCH_FORMAT_UNCONFIRMED")
    match = re.fullmatch(r"com\.apple\.shortcuts: ([1-9][0-9]*)\n", text)
    if match is None:
        raise NativeOpenFilesError("LAUNCH_FORMAT_UNCONFIRMED")
    pid = int(match.group(1))
    if pid > MAX_PID:
        raise NativeOpenFilesError("LAUNCH_FORMAT_UNCONFIRMED")
    return pid


def _resolve_own_root(own_data: Path) -> tuple[Path, tuple[int, int]]:
    try:
        initial = own_data.lstat()
    except FileNotFoundError as error:
        raise NativeOpenFilesError("OWN_DATA_MISSING") from error
    except OSError as error:
        raise NativeOpenFilesError("OWN_DATA_UNCONFIRMED") from error
    if stat.S_ISLNK(initial.st_mode):
        raise NativeOpenFilesError("OWN_DATA_SYMLINK")
    if not stat.S_ISDIR(initial.st_mode):
        raise NativeOpenFilesError("OWN_DATA_UNCONFIRMED")
    try:
        root = own_data.resolve(strict=True)
        canonical = root.lstat()
    except OSError as error:
        raise NativeOpenFilesError("OWN_DATA_UNCONFIRMED") from error
    if stat.S_ISLNK(canonical.st_mode) or not stat.S_ISDIR(canonical.st_mode):
        raise NativeOpenFilesError("OWN_DATA_UNCONFIRMED")
    return root, (canonical.st_dev, canonical.st_ino)


def _relative_open_path(path_text: str, root: Path, root_identity: tuple[int, int]) -> str | None:
    try:
        candidate = Path(path_text)
        if not candidate.is_absolute():
            # `lsof -Fn` also represents comments and network addresses. They
            # are not filesystem associations and are never retained.
            return None
        lexical = Path(os.path.abspath(os.path.normpath(str(candidate))))
        # Resolve only the observed parent to accept Darwin's /var alias, then
        # reconstruct the leaf below that canonical parent before touching it.
        parent = lexical.parent.resolve(strict=True)
        try:
            parent.relative_to(root)
        except ValueError:
            return None
        canonical_candidate = parent / lexical.name
        if canonical_candidate == root:
            return None
        status = canonical_candidate.lstat()
        if stat.S_ISLNK(status.st_mode):
            raise NativeOpenFilesError("OPEN_FILE_SYMLINK")
        if not (stat.S_ISREG(status.st_mode) or stat.S_ISDIR(status.st_mode)):
            return None
        resolved = canonical_candidate.resolve(strict=True)
        try:
            relative = resolved.relative_to(root)
        except ValueError:
            return None
        if not relative.parts:
            return None
        after = root.lstat()
        if (after.st_dev, after.st_ino) != root_identity:
            raise NativeOpenFilesError("OWN_DATA_UNCONFIRMED")
        return relative.as_posix()
    except NativeOpenFilesError:
        raise
    except FileNotFoundError:
        # An observed descriptor may close between lsof and local validation;
        # it is not a confirmed association.
        return None
    except (OSError, ValueError) as error:
        raise NativeOpenFilesError("OPEN_FILE_UNCONFIRMED") from error


def parse_lsof_metadata(stdout: bytes, expected_pid: int, own_data: Path) -> dict[str, object]:
    """Return relative open-path metadata for the exact observed process only.

    This reads path metadata only (lstat/resolve); it never opens candidate
    files, headers, databases, rows, or payloads.
    """
    raw = _bounded_bytes(stdout, empty_code="LSOF_EMPTY", too_large_code="LSOF_TOO_LARGE")
    if not isinstance(expected_pid, int) or isinstance(expected_pid, bool) or not 0 < expected_pid <= MAX_PID:
        raise NativeOpenFilesError("LSOF_PID_UNCONFIRMED")
    if b"\x00" in raw:
        raise NativeOpenFilesError("LSOF_FORMAT_UNCONFIRMED")
    if not raw.endswith(b"\n"):
        raise NativeOpenFilesError("LSOF_FORMAT_UNCONFIRMED")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise NativeOpenFilesError("LSOF_FORMAT_UNCONFIRMED") from error
    if not lines or len(lines) > MAX_LSOF_LINES:
        raise NativeOpenFilesError("LSOF_LINE_LIMIT")

    root, root_identity = _resolve_own_root(own_data)
    observed_pid: int | None = None
    observed_command: str | None = None
    paths: list[str] = []
    seen_paths: set[str] = set()
    for line in lines:
        if len(line) < 2:
            raise NativeOpenFilesError("LSOF_FORMAT_UNCONFIRMED")
        field, value = line[0], line[1:]
        if field == "p":
            if observed_pid is not None or not value.isascii() or not value.isdecimal():
                raise NativeOpenFilesError("LSOF_PID_UNCONFIRMED")
            parsed = int(value)
            if parsed != expected_pid:
                raise NativeOpenFilesError("LSOF_PID_UNCONFIRMED")
            observed_pid = parsed
        elif field == "c":
            if observed_pid is None or observed_command is not None or value != SHORTCUTS_COMMAND:
                raise NativeOpenFilesError("LSOF_COMMAND_UNCONFIRMED")
            observed_command = value
        elif field == "f":
            if observed_pid is None or observed_command is None:
                raise NativeOpenFilesError("LSOF_FORMAT_UNCONFIRMED")
            # `lsof -Ff` describes an FD token. It is validated only so the
            # observed record framing stays strict; it is not retained.
            if not 0 < len(value) <= 32 or not value.isascii() or any(
                ord(character) < 32 or ord(character) > 126 for character in value
            ):
                raise NativeOpenFilesError("LSOF_FORMAT_UNCONFIRMED")
        elif field == "n":
            if observed_pid is None or observed_command is None:
                raise NativeOpenFilesError("LSOF_FORMAT_UNCONFIRMED")
            relative = _relative_open_path(value, root, root_identity)
            if relative is not None and relative not in seen_paths:
                seen_paths.add(relative)
                paths.append(relative)
                if len(paths) > MAX_OPEN_PATHS:
                    raise NativeOpenFilesError("LSOF_LINE_LIMIT")
        else:
            raise NativeOpenFilesError("LSOF_FORMAT_UNCONFIRMED")
    if observed_pid is None:
        raise NativeOpenFilesError("LSOF_PID_UNCONFIRMED")
    if observed_command is None:
        raise NativeOpenFilesError("LSOF_COMMAND_UNCONFIRMED")
    if not paths:
        raise NativeOpenFilesError("NO_ASSOCIATED_OPEN_HANDLE_OBSERVED")
    return {"pid": observed_pid, "command": observed_command, "open_paths": paths}
