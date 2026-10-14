"""Collect a bounded, local Shortcuts export from a caller-resolved container.

This module intentionally validates only the file boundary.  A recognized
container signature does not prove a shortcut's semantics, signature, or SMS
behavior.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Iterator


MAX_SHORTCUT_BYTES = 10 * 1024 * 1024
MAX_CONTAINER_NODES = 10_000
SHORTCUT_FILENAME = "synthetic.shortcut"
RECEIPT_FILENAME = "synthetic.shortcut.receipt.json"


class ShortcutArtifactError(ValueError):
    """The selected container does not meet the constrained export contract."""


@dataclass(frozen=True)
class ShortcutArtifactReceipt:
    bytes: int
    sha256: str
    magic: str

    def as_dict(self) -> dict[str, int | str]:
        return asdict(self)


@dataclass(frozen=True)
class CollectedShortcutArtifact:
    artifact_path: Path
    receipt_path: Path
    receipt: ShortcutArtifactReceipt


def _is_within(child: Path, root: Path) -> bool:
    try:
        child.relative_to(root)
    except ValueError:
        return False
    return True


def _resolve_regular_root(container_root: Path) -> Path:
    try:
        root_status = container_root.lstat()
    except FileNotFoundError as error:
        raise ShortcutArtifactError("container root does not exist") from error
    if stat.S_ISLNK(root_status.st_mode):
        raise ShortcutArtifactError("container root must not be a symlink")
    if not stat.S_ISDIR(root_status.st_mode):
        raise ShortcutArtifactError("container root must be a directory")
    return container_root.resolve(strict=True)


def _walk_container(root: Path, max_nodes: int) -> Iterator[Path]:
    """Yield regular files while rejecting every symlink and path escape."""
    if max_nodes < 1:
        raise ValueError("max_nodes must be positive")

    pending = [root]
    visited_nodes = 1  # Count the root as part of the traversal budget.
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    visited_nodes += 1
                    if visited_nodes > max_nodes:
                        raise ShortcutArtifactError("container node limit exceeded")

                    entry_path = Path(entry.path)
                    try:
                        entry_status = entry_path.lstat()
                    except OSError as error:
                        raise ShortcutArtifactError("container entry changed during inspection") from error
                    if stat.S_ISLNK(entry_status.st_mode):
                        raise ShortcutArtifactError("symlinks are not permitted in container")

                    try:
                        resolved_entry = entry_path.resolve(strict=True)
                    except OSError as error:
                        raise ShortcutArtifactError("cannot resolve container entry") from error
                    if not _is_within(resolved_entry, root):
                        raise ShortcutArtifactError("container entry escapes supplied root")

                    if stat.S_ISDIR(entry_status.st_mode):
                        pending.append(resolved_entry)
                    elif stat.S_ISREG(entry_status.st_mode):
                        yield resolved_entry
        except OSError as error:
            raise ShortcutArtifactError("cannot inspect container") from error


def _detect_magic(prefix: bytes) -> str:
    if prefix.startswith(b"AEA1"):
        return "AEA1"
    if prefix.startswith(b"bplist00"):
        return "bplist00"

    xml_candidate = prefix.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if xml_candidate.startswith(b"<plist"):
        return "xml-plist"
    if xml_candidate.startswith(b"<?xml") and b"<plist" in xml_candidate[:4096]:
        return "xml-plist"
    raise ShortcutArtifactError("shortcut export has an unrecognized container magic")


def _read_validated_bytes(source: Path) -> tuple[bytes, ShortcutArtifactReceipt]:
    """Read once, bounded at the file contract, before retaining any bytes."""
    try:
        with source.open("rb") as export_file:
            payload = export_file.read(MAX_SHORTCUT_BYTES + 1)
    except OSError as error:
        raise ShortcutArtifactError("cannot read shortcut export") from error
    if not 0 < len(payload) <= MAX_SHORTCUT_BYTES:
        raise ShortcutArtifactError("shortcut export size is outside permitted bounds")
    return payload, ShortcutArtifactReceipt(
        bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        magic=_detect_magic(payload[:4096]),
    )


def collect_shortcut_artifact(
    container_root: Path,
    artifacts_dir: Path,
    *,
    max_nodes: int = MAX_CONTAINER_NODES,
) -> CollectedShortcutArtifact:
    """Copy the sole valid ``.shortcut`` file and write its boundary receipt.

    ``container_root`` must already have been resolved by the caller from
    evidence about the simulator.  This function neither discovers simulator
    containers nor interprets the shortcut payload.
    """
    root = _resolve_regular_root(container_root)
    candidates = [
        path
        for path in _walk_container(root, max_nodes)
        if path.suffix == ".shortcut"
    ]
    if not candidates:
        raise ShortcutArtifactError("no .shortcut file found in container")
    if len(candidates) != 1:
        raise ShortcutArtifactError("container has an ambiguous number of .shortcut files")

    artifacts_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifacts_dir / SHORTCUT_FILENAME
    receipt_path = artifacts_dir / RECEIPT_FILENAME
    temporary_artifact_path = artifacts_dir / f".{SHORTCUT_FILENAME}.tmp"
    temporary_receipt_path = artifacts_dir / f".{RECEIPT_FILENAME}.tmp"
    try:
        payload, receipt = _read_validated_bytes(candidates[0])
        temporary_artifact_path.write_bytes(payload)
        os.replace(temporary_artifact_path, artifact_path)
        temporary_receipt_path.write_text(
            json.dumps(receipt.as_dict(), sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary_receipt_path, receipt_path)
    except OSError as error:
        raise ShortcutArtifactError("cannot write collected shortcut artifact") from error
    except ShortcutArtifactError:
        temporary_artifact_path.unlink(missing_ok=True)
        temporary_receipt_path.unlink(missing_ok=True)
        raise
    return CollectedShortcutArtifact(artifact_path, receipt_path, receipt)
