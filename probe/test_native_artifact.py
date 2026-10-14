from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

from native_artifact import (
    MAX_SHORTCUT_BYTES,
    ShortcutArtifactError,
    collect_shortcut_artifact,
)


class ShortcutArtifactCollectionTests(unittest.TestCase):
    def make_root(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        base = Path(temporary.name)
        root = base / "resolved-container"
        root.mkdir()
        return temporary, root, base / "artifacts"

    @staticmethod
    def lexical_alias(root: Path) -> Path:
        alias_parent = root.parent / "lexical-alias"
        alias_parent.mkdir()
        return alias_parent / ".." / root.name

    @staticmethod
    def canonical_key(path: Path) -> str:
        # Keep this comparison independent from the patched Path.stat below.
        return os.path.normcase(os.path.realpath(os.fspath(path)))

    def test_collects_single_valid_export_with_identical_bytes_and_hash(self) -> None:
        temporary, root, artifacts = self.make_root()
        self.addCleanup(temporary.cleanup)
        original = b"AEA1\x00synthetic-shortcut-payload"
        (root / "sample.shortcut").write_bytes(original)

        result = collect_shortcut_artifact(root, artifacts)

        self.assertEqual(original, result.artifact_path.read_bytes())
        self.assertEqual(hashlib.sha256(original).hexdigest(), result.receipt.sha256)
        self.assertEqual(len(original), result.receipt.bytes)
        self.assertEqual("AEA1", result.receipt.magic)
        self.assertEqual(result.receipt.as_dict(), json.loads(result.receipt_path.read_text()))

    def test_buffers_source_once_before_writing_artifact_and_receipt(self) -> None:
        temporary, root, artifacts = self.make_root()
        self.addCleanup(temporary.cleanup)
        source = root / ".." / root.name / "changing.shortcut"
        first_payload = b"AEA1first-observation"
        source.write_bytes(first_payload)
        original_open = Path.open
        source_reads = 0

        def mutate_on_second_source_read(path: Path, *args: object, **kwargs: object):
            nonlocal source_reads
            mode = args[0] if args else kwargs.get("mode", "r")
            if path.resolve() == source.resolve() and mode == "rb":
                source_reads += 1
                if source_reads == 2:
                    source.write_bytes(b"AEA1later-content")
            return original_open(path, *args, **kwargs)

        with mock.patch.object(Path, "open", new=mutate_on_second_source_read):
            result = collect_shortcut_artifact(root, artifacts)

        self.assertEqual(1, source_reads)
        self.assertEqual(first_payload, result.artifact_path.read_bytes())
        self.assertEqual(hashlib.sha256(first_payload).hexdigest(), result.receipt.sha256)

    def test_rejects_preexisting_export_when_birthtime_precedes_boundary(self) -> None:
        temporary, root, artifacts = self.make_root()
        self.addCleanup(temporary.cleanup)
        source = self.lexical_alias(root) / "old.shortcut"
        source.write_bytes(b"AEA1old")
        source_key = self.canonical_key(source)
        actual_stat = source.stat()
        original_stat = Path.stat

        def stat_with_old_birthtime(path: Path, *args: object, **kwargs: object):
            if self.canonical_key(path) == source_key:
                return SimpleNamespace(
                    st_size=actual_stat.st_size,
                    st_mode=actual_stat.st_mode,
                    st_birthtime_ns=1_000,
                )
            return original_stat(path, *args, **kwargs)

        with mock.patch.object(Path, "stat", new=stat_with_old_birthtime):
            with self.assertRaisesRegex(ShortcutArtifactError, "predates"):
                collect_shortcut_artifact(root, artifacts, not_before_ns=1_001)

    def test_accepts_recent_export_and_records_birthtime(self) -> None:
        temporary, root, artifacts = self.make_root()
        self.addCleanup(temporary.cleanup)
        source = self.lexical_alias(root) / "new.shortcut"
        source.write_bytes(b"AEA1new")
        source_key = self.canonical_key(source)
        actual_stat = source.stat()
        original_stat = Path.stat

        def stat_with_recent_birthtime(path: Path, *args: object, **kwargs: object):
            if self.canonical_key(path) == source_key:
                return SimpleNamespace(
                    st_size=actual_stat.st_size,
                    st_mode=actual_stat.st_mode,
                    st_birthtime_ns=2_000,
                )
            return original_stat(path, *args, **kwargs)

        with mock.patch.object(Path, "stat", new=stat_with_recent_birthtime):
            result = collect_shortcut_artifact(root, artifacts, not_before_ns=2_000)

        self.assertEqual(2_000, result.receipt.birthtime_ns)

    def test_rejects_missing_birthtime_when_boundary_is_required(self) -> None:
        temporary, root, artifacts = self.make_root()
        self.addCleanup(temporary.cleanup)
        source = self.lexical_alias(root) / "unknown-birthtime.shortcut"
        source.write_bytes(b"AEA1unknown")
        source_key = self.canonical_key(source)
        actual_stat = source.stat()
        original_stat = Path.stat

        def stat_without_birthtime(path: Path, *args: object, **kwargs: object):
            if self.canonical_key(path) == source_key:
                return SimpleNamespace(
                    st_size=actual_stat.st_size,
                    st_mode=actual_stat.st_mode,
                )
            return original_stat(path, *args, **kwargs)

        with mock.patch.object(Path, "stat", new=stat_without_birthtime):
            with self.assertRaisesRegex(ShortcutArtifactError, "no usable birth"):
                collect_shortcut_artifact(root, artifacts, not_before_ns=1)

    def test_rejects_zero_candidates(self) -> None:
        temporary, root, artifacts = self.make_root()
        self.addCleanup(temporary.cleanup)
        (root / "ordinary.txt").write_text("nothing")

        with self.assertRaisesRegex(ShortcutArtifactError, "no .shortcut"):
            collect_shortcut_artifact(root, artifacts)

    def test_rejects_multiple_candidates(self) -> None:
        temporary, root, artifacts = self.make_root()
        self.addCleanup(temporary.cleanup)
        (root / "one.shortcut").write_bytes(b"AEA1one")
        (root / "two.shortcut").write_bytes(b"AEA1two")

        with self.assertRaisesRegex(ShortcutArtifactError, "ambiguous"):
            collect_shortcut_artifact(root, artifacts)

    def test_rejects_symlink_that_escapes_container(self) -> None:
        temporary, root, artifacts = self.make_root()
        self.addCleanup(temporary.cleanup)
        outside = Path(temporary.name) / "outside.shortcut"
        outside.write_bytes(b"AEA1outside")
        link = root / "escape.shortcut"
        try:
            os.symlink(outside, link)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlink creation unavailable: {error}")

        with self.assertRaisesRegex(ShortcutArtifactError, "symlinks"):
            collect_shortcut_artifact(root, artifacts)

    def test_rejects_file_larger_than_ten_mebibytes(self) -> None:
        temporary, root, artifacts = self.make_root()
        self.addCleanup(temporary.cleanup)
        export = root / "oversized.shortcut"
        with export.open("wb") as output:
            output.write(b"AEA1")
            output.truncate(MAX_SHORTCUT_BYTES + 1)

        with self.assertRaisesRegex(ShortcutArtifactError, "size"):
            collect_shortcut_artifact(root, artifacts)

    def test_rejects_unrecognized_file_magic(self) -> None:
        temporary, root, artifacts = self.make_root()
        self.addCleanup(temporary.cleanup)
        (root / "invalid.shortcut").write_bytes(b"not-a-shortcut")

        with self.assertRaisesRegex(ShortcutArtifactError, "unrecognized"):
            collect_shortcut_artifact(root, artifacts)

    def test_enforces_bounded_container_walk(self) -> None:
        temporary, root, artifacts = self.make_root()
        self.addCleanup(temporary.cleanup)
        (root / "one.txt").write_text("one")
        (root / "two.shortcut").write_bytes(b"AEA1two")

        with self.assertRaisesRegex(ShortcutArtifactError, "node limit"):
            collect_shortcut_artifact(root, artifacts, max_nodes=2)

    def test_accepts_xml_plist_signature_without_interpreting_contents(self) -> None:
        temporary, root, artifacts = self.make_root()
        self.addCleanup(temporary.cleanup)
        (root / "xml.shortcut").write_bytes(b"<?xml version='1.0'?><plist><dict/></plist>")

        result = collect_shortcut_artifact(root, artifacts)

        self.assertEqual("xml-plist", result.receipt.magic)


if __name__ == "__main__":
    unittest.main()
