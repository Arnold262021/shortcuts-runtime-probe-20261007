from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import native_open_files as open_files
from native_open_files import (
    NativeOpenFilesError,
    lsof_output_shape,
    parse_lsof_metadata,
    parse_simctl_launch,
)


class NativeOpenFilesTests(unittest.TestCase):
    def make_root(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name) / "device" / "data"
        root.mkdir(parents=True)
        return temporary, root

    def test_parses_exact_launch_contract(self) -> None:
        self.assertEqual(4321, parse_simctl_launch(b"com.apple.shortcuts: 4321\n"))
        for invalid in (
            b"",
            b"com.apple.shortcuts: 4321",
            b"com.apple.shortcuts: 0\n",
            b"com.apple.shortcuts: 4\nextra\n",
            b"other: 4\n",
        ):
            with self.assertRaises(NativeOpenFilesError):
                parse_simctl_launch(invalid)

    def test_describes_lsof_shape_without_retaining_values(self) -> None:
        raw = (
            b"p4242\n"
            b"cShortcuts\n"
            b"fPRIVATE_FD\n"
            b"n/private/PRIVATE_SENTINEL\n"
            b"nTCP->203.0.113.9:443\n"
            b"\n"
            b"xPRIVATE_UNKNOWN\n"
        )

        shape = lsof_output_shape(raw)

        self.assertEqual(
            {
                "byte_count": len(raw),
                "newline_count": 7,
                "nul_count": 0,
                "ends_newline": True,
                "record_count": 7,
                "field_classes": ["p", "c", "f", "n", "n", "blank", "unknown"],
                "field_class_counts": {"p": 1, "c": 1, "n": 2, "f": 1, "blank": 1, "unknown": 1},
                "absolute_n_path_count": 1,
            },
            shape,
        )
        self.assertNotIn("PRIVATE", repr(shape))
        self.assertNotIn("203.0.113.9", repr(shape))

    def test_diagnoses_truncation_and_nul_without_accepting_lsof(self) -> None:
        self.assertEqual(0, lsof_output_shape(b"")["record_count"])
        shape = lsof_output_shape(b"p42\nnPRIVATE\x00VALUE")

        self.assertFalse(shape["ends_newline"])
        self.assertEqual(1, shape["nul_count"])
        self.assertEqual(["p", "n"], shape["field_classes"])
        self.assertEqual(0, shape["absolute_n_path_count"])
        with self.assertRaisesRegex(NativeOpenFilesError, "LSOF_TOO_LARGE"):
            lsof_output_shape(b"x" * (64 * 1024 + 1))
        with self.assertRaisesRegex(NativeOpenFilesError, "LSOF_LINE_LIMIT"):
            lsof_output_shape(b"\n" * 513)

    def test_parses_golden_lsof_and_deduplicates_relative_paths(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        path = root / "Library" / "state file"
        path.parent.mkdir()
        path.write_bytes(b"PRIVATE_SENTINEL")
        raw = f"p42\ncShortcuts\nn{path}\nn{path}\n".encode()

        report = parse_lsof_metadata(raw, 42, root)

        self.assertEqual({"pid": 42, "command": "Shortcuts", "open_paths": ["Library/state file"]}, report)
        self.assertNotIn("PRIVATE_SENTINEL", repr(report))

    def test_accepts_valid_fd_metadata_after_process_and_command(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        path = root / "Library" / "state"
        path.parent.mkdir()
        path.write_text("fixture")

        report = parse_lsof_metadata(f"p42\ncShortcuts\nf3u\nn{path}\n".encode(), 42, root)

        self.assertEqual(["Library/state"], report["open_paths"])
        self.assertNotIn("3u", repr(report))

    def test_ignores_outside_paths_without_claiming_association(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        outside = Path(temporary.name) / "outside-PRIVATE_SENTINEL"
        outside.write_text("not opened")
        raw = f"p42\ncShortcuts\nn{outside}\n".encode()

        with self.assertRaisesRegex(NativeOpenFilesError, "NO_ASSOCIATED_OPEN_HANDLE_OBSERVED"):
            parse_lsof_metadata(raw, 42, root)

    def test_ignores_lsof_comments_network_names_and_special_files(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        special = root / "pipe"
        special.write_text("metadata fixture")
        special_key = os.path.normcase(os.path.realpath(str(special.resolve(strict=True))))
        original_lstat = Path.lstat

        def special_lstat(path: Path):
            if os.path.normcase(os.path.realpath(str(path))) == special_key:
                return SimpleNamespace(st_mode=stat.S_IFIFO)
            return original_lstat(path)

        raw = f"p42\ncShortcuts\nnTCP->203.0.113.9:443\nn(socket comment)\nn{special}\n".encode()
        with mock.patch.object(Path, "lstat", new=special_lstat):
            with self.assertRaisesRegex(NativeOpenFilesError, "NO_ASSOCIATED_OPEN_HANDLE_OBSERVED"):
                parse_lsof_metadata(raw, 42, root)

    def test_rejects_wrong_pid_command_malformed_nul_and_bounds(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        good = root / "good"
        good.write_text("fixture")
        for raw in (
            f"p43\ncShortcuts\nn{good}\n".encode(),
            f"p42\ncOther\nn{good}\n".encode(),
            f"cShortcuts\np42\nn{good}\n".encode(),
            f"f3u\np42\ncShortcuts\nn{good}\n".encode(),
            f"n{good}\np42\ncShortcuts\n".encode(),
            f"p42\ncShortcuts\nf\nn{good}\n".encode(),
            f"p42\ncShortcuts\nf\x01\nn{good}\n".encode(),
            f"p42\ncShortcuts\nf{'a' * 33}\nn{good}\n".encode(),
            f"p42\ncShortcuts\nn{good}".encode(),
            b"p42\ncShortcuts\nn/a\x00b\n",
            b"xunknown\n",
        ):
            with self.assertRaises(NativeOpenFilesError):
                parse_lsof_metadata(raw, 42, root)
        with self.assertRaisesRegex(NativeOpenFilesError, "LSOF_TOO_LARGE"):
            parse_lsof_metadata(b"x" * (64 * 1024 + 1), 42, root)
        with self.assertRaisesRegex(NativeOpenFilesError, "LSOF_LINE_LIMIT"):
            parse_lsof_metadata((f"p42\ncShortcuts\n" + "n/a\n" * 511).encode(), 42, root)

    def test_rejects_canonical_symlink_leaf_before_leaf_resolution(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        candidate = root / "leaf"
        candidate.write_text("fixture")
        canonical_candidate = candidate.resolve(strict=True)
        canonical_key = os.path.normcase(os.path.realpath(str(canonical_candidate)))
        original_lstat = Path.lstat
        original_resolve = Path.resolve

        def symlink_leaf(path: Path):
            if os.path.normcase(os.path.realpath(str(path))) == canonical_key:
                return SimpleNamespace(st_mode=stat.S_IFLNK)
            return original_lstat(path)

        def fail_leaf_resolve(path: Path, strict: bool = False) -> Path:
            if os.path.normcase(os.path.realpath(str(path))) == canonical_key:
                raise AssertionError("must not resolve symlink leaf")
            return original_resolve(path, strict=strict)

        with mock.patch.object(Path, "lstat", new=symlink_leaf), \
                mock.patch.object(Path, "resolve", new=fail_leaf_resolve):
            with self.assertRaisesRegex(NativeOpenFilesError, "OPEN_FILE_SYMLINK"):
                parse_lsof_metadata(f"p42\ncShortcuts\nn{candidate}\n".encode(), 42, root)

    def test_accepts_alias_parent_via_canonical_reconstruction(self) -> None:
        temporary, root = self.make_root()
        self.addCleanup(temporary.cleanup)
        canonical_parent = root / "Library"
        canonical_leaf = canonical_parent / "state"
        canonical_parent.mkdir()
        canonical_leaf.write_text("fixture")
        canonical_root = root.resolve(strict=True)
        lexical_parent = Path(temporary.name) / "alias" / "data" / "Library"
        lexical_candidate = lexical_parent / "state"
        original_resolve = Path.resolve

        def map_parent(path: Path, strict: bool = False) -> Path:
            if path == lexical_parent:
                return canonical_parent.resolve(strict=True)
            return original_resolve(path, strict=strict)

        with mock.patch.object(Path, "resolve", new=map_parent):
            report = parse_lsof_metadata(f"p42\ncShortcuts\nn{lexical_candidate}\n".encode(), 42, canonical_root)

        self.assertEqual(["Library/state"], report["open_paths"])


if __name__ == "__main__":
    unittest.main()
