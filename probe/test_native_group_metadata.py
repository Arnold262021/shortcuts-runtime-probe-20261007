from __future__ import annotations

import json
import os
from pathlib import Path
import plistlib
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import native_group_metadata as group_metadata
from native_group_metadata import NativeGroupMetadataError, decode_group_metadata


class NativeGroupMetadataTests(unittest.TestCase):
    def make_layout(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name) / "simulator" / "data"
        app_groups = root / "Containers" / "Shared" / "AppGroup"
        app_groups.mkdir(parents=True)
        return temporary, root, app_groups

    def test_decodes_json_list_to_canonical_in_memory_paths(self) -> None:
        temporary, own_data, app_groups = self.make_layout()
        self.addCleanup(temporary.cleanup)
        group = app_groups / "group.synthetic"
        group.mkdir()

        result = decode_group_metadata(
            json.dumps([str(group)]).encode("utf-8"), own_data
        )

        self.assertEqual([{"path": group.resolve()}], result)

    def test_decodes_structured_group_identifiers_without_resolving_them(self) -> None:
        temporary, own_data, _ = self.make_layout()
        self.addCleanup(temporary.cleanup)

        json_result = decode_group_metadata(json.dumps("group.workflow.synthetic").encode(), own_data)
        plist_result = decode_group_metadata(
            plistlib.dumps(["group.workflow.first", "group.workflow.second"]), own_data
        )
        text_result = decode_group_metadata(b"group.workflow.text", own_data)

        self.assertEqual([{"identifier": "group.workflow.synthetic", "path": None}], json_result)
        self.assertEqual(
            [
                {"identifier": "group.workflow.first", "path": None},
                {"identifier": "group.workflow.second", "path": None},
            ],
            plist_result,
        )
        self.assertEqual([{"identifier": "group.workflow.text", "path": None}], text_result)

    def test_decodes_plist_list_and_line_paths(self) -> None:
        temporary, own_data, app_groups = self.make_layout()
        self.addCleanup(temporary.cleanup)
        first = app_groups / "first"
        second = app_groups / "second"
        first.mkdir()
        second.mkdir()

        plist_result = decode_group_metadata(plistlib.dumps([str(first)]), own_data)
        line_result = decode_group_metadata((str(first) + "\n" + str(second)).encode(), own_data)

        self.assertEqual([{"path": first.resolve()}], plist_result)
        self.assertEqual([{"path": first.resolve()}, {"path": second.resolve()}], line_result)

    def test_canonicalizes_lexical_own_data_alias(self) -> None:
        temporary, own_data, app_groups = self.make_layout()
        self.addCleanup(temporary.cleanup)
        group = app_groups / "canonical"
        group.mkdir()
        alias = own_data.parent / "." / "data"

        result = decode_group_metadata(json.dumps([str(group)]).encode(), alias)

        self.assertEqual(group.resolve(), result[0]["path"])

    def test_rejects_unknown_or_empty_payload_without_echoing_contents(self) -> None:
        temporary, own_data, _ = self.make_layout()
        self.addCleanup(temporary.cleanup)
        private = b"PRIVATE_SENTINEL_NOT_A_PATH"

        with self.assertRaisesRegex(NativeGroupMetadataError, "GROUP_METADATA_FORMAT_UNCONFIRMED") as error:
            decode_group_metadata(private, own_data)

        self.assertNotIn("PRIVATE_SENTINEL", str(error.exception))
        with self.assertRaisesRegex(NativeGroupMetadataError, "GROUP_METADATA_EMPTY"):
            decode_group_metadata(b"", own_data)

    def test_rejects_undocumented_dictionary_contract(self) -> None:
        temporary, own_data, app_groups = self.make_layout()
        self.addCleanup(temporary.cleanup)
        path = app_groups / "declared"
        path.mkdir()

        with self.assertRaisesRegex(NativeGroupMetadataError, "GROUP_METADATA_SHAPE_UNCONFIRMED"):
            decode_group_metadata(json.dumps({"group.synthetic": str(path)}).encode(), own_data)

    def test_rejects_app_group_root_and_regular_file(self) -> None:
        temporary, own_data, app_groups = self.make_layout()
        self.addCleanup(temporary.cleanup)
        regular_file = app_groups / "not-a-container"
        regular_file.write_text("metadata only")

        with self.assertRaisesRegex(NativeGroupMetadataError, "GROUP_METADATA_PATH_ESCAPE"):
            decode_group_metadata(json.dumps([str(app_groups)]).encode(), own_data)
        with self.assertRaisesRegex(NativeGroupMetadataError, "GROUP_METADATA_PATH_UNCONFIRMED"):
            decode_group_metadata(json.dumps([str(regular_file)]).encode(), own_data)

    def test_normalizes_truncated_plist_and_nul_path_to_sanitized_codes(self) -> None:
        temporary, own_data, app_groups = self.make_layout()
        self.addCleanup(temporary.cleanup)

        with self.assertRaisesRegex(NativeGroupMetadataError, "GROUP_METADATA_FORMAT_UNCONFIRMED"):
            decode_group_metadata(b'<?xml version="1.0"?><plist><array><string>', own_data)
        nul_path = str(app_groups / "bad\x00path")
        with self.assertRaisesRegex(NativeGroupMetadataError, "GROUP_METADATA_PATH_UNCONFIRMED"):
            decode_group_metadata(json.dumps([nul_path]).encode(), own_data)

    def test_accepts_lexical_parent_alias_only_after_canonical_parent_match(self) -> None:
        temporary, _, _ = self.make_layout()
        self.addCleanup(temporary.cleanup)
        canonical_root_lexical = Path(temporary.name) / "canonical" / "AppGroup"
        (canonical_root_lexical / "group").mkdir(parents=True)
        canonical_root = canonical_root_lexical.resolve(strict=True)
        canonical_group = canonical_root / "group"
        lexical_parent = Path(temporary.name) / "lexical-alias" / "AppGroup"
        lexical_candidate = lexical_parent / "group"
        original_resolve = Path.resolve

        def map_parent(path: Path, strict: bool = False) -> Path:
            if path == lexical_parent:
                return canonical_root
            return original_resolve(path, strict=strict)

        with mock.patch.object(Path, "resolve", new=map_parent):
            result = group_metadata._safe_group_path(str(lexical_candidate), canonical_root)

        self.assertEqual(canonical_group, result)

    def test_rejects_alias_parent_that_resolves_outside_app_group(self) -> None:
        temporary, _, _ = self.make_layout()
        self.addCleanup(temporary.cleanup)
        canonical_root_lexical = Path(temporary.name) / "canonical" / "AppGroup"
        canonical_root_lexical.mkdir(parents=True)
        canonical_root = canonical_root_lexical.resolve(strict=True)
        outside = Path(temporary.name) / "outside"
        outside.mkdir()
        lexical_candidate = Path(temporary.name) / "lexical-alias" / "AppGroup" / "group"
        original_resolve = Path.resolve

        def map_parent(path: Path, strict: bool = False) -> Path:
            if path == lexical_candidate.parent:
                return outside
            return original_resolve(path, strict=strict)

        with mock.patch.object(Path, "resolve", new=map_parent):
            with self.assertRaisesRegex(NativeGroupMetadataError, "GROUP_METADATA_PATH_ESCAPE"):
                group_metadata._safe_group_path(str(lexical_candidate), canonical_root)

    def test_rejects_symlink_leaf_before_any_leaf_resolution(self) -> None:
        temporary, _, _ = self.make_layout()
        self.addCleanup(temporary.cleanup)
        canonical_root_lexical = Path(temporary.name) / "canonical" / "AppGroup"
        (canonical_root_lexical / "group").mkdir(parents=True)
        canonical_root = canonical_root_lexical.resolve(strict=True)
        candidate = canonical_root / "group"
        original_lstat = Path.lstat
        original_resolve = Path.resolve

        def symlink_leaf(path: Path):
            if path == candidate:
                return SimpleNamespace(st_mode=stat.S_IFLNK)
            return original_lstat(path)

        def fail_if_leaf_resolved(path: Path, strict: bool = False) -> Path:
            if path == candidate:
                raise AssertionError("the symlink leaf must not be resolved")
            return original_resolve(path, strict=strict)

        with mock.patch.object(Path, "lstat", new=symlink_leaf), \
                mock.patch.object(Path, "resolve", new=fail_if_leaf_resolved):
            with self.assertRaisesRegex(NativeGroupMetadataError, "GROUP_METADATA_PATH_SYMLINK"):
                group_metadata._safe_group_path(str(candidate), canonical_root)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin /var alias only")
    def test_darwin_var_alias_matches_private_var_canonical_parent(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        lexical_root = Path(temporary.name) / "AppGroup"
        lexical_group = lexical_root / "group"
        lexical_group.mkdir(parents=True)
        canonical_root = lexical_root.resolve(strict=True)
        if not str(lexical_root).startswith("/var/") or not str(canonical_root).startswith("/private/var/"):
            self.skipTest("temporary directory is not exposed through the Darwin /var alias")

        result = group_metadata._safe_group_path(str(lexical_group), canonical_root)

        self.assertEqual(canonical_root / "group", result)

    def test_rejects_outside_and_symlink_paths(self) -> None:
        temporary, own_data, app_groups = self.make_layout()
        self.addCleanup(temporary.cleanup)
        outside = Path(temporary.name) / "outside"
        outside.mkdir()
        with self.assertRaisesRegex(NativeGroupMetadataError, "GROUP_METADATA_PATH_ESCAPE"):
            decode_group_metadata(json.dumps([str(outside)]).encode(), own_data)

        link = app_groups / "escape"
        try:
            os.symlink(outside, link, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        with self.assertRaisesRegex(NativeGroupMetadataError, "GROUP_METADATA_PATH_SYMLINK"):
            decode_group_metadata(json.dumps([str(link)]).encode(), own_data)

    def test_rejects_count_duplicate_and_size_limits(self) -> None:
        temporary, own_data, app_groups = self.make_layout()
        self.addCleanup(temporary.cleanup)
        groups = []
        for index in range(9):
            path = app_groups / f"group-{index}"
            path.mkdir()
            groups.append(str(path))

        with self.assertRaisesRegex(NativeGroupMetadataError, "GROUP_METADATA_COUNT_LIMIT"):
            decode_group_metadata(json.dumps(groups).encode(), own_data)
        with self.assertRaisesRegex(NativeGroupMetadataError, "GROUP_METADATA_PATH_DUPLICATE"):
            decode_group_metadata(json.dumps([groups[0], groups[0]]).encode(), own_data)
        with self.assertRaisesRegex(NativeGroupMetadataError, "GROUP_METADATA_TOO_LARGE"):
            decode_group_metadata(b"x" * (64 * 1024 + 1), own_data)


if __name__ == "__main__":
    unittest.main()
