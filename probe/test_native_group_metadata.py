from __future__ import annotations

import json
import os
from pathlib import Path
import plistlib
import tempfile
import unittest

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

        for candidate in (app_groups, regular_file):
            with self.assertRaisesRegex(NativeGroupMetadataError, "GROUP_METADATA_PATH_UNCONFIRMED"):
                decode_group_metadata(json.dumps([str(candidate)]).encode(), own_data)

    def test_normalizes_truncated_plist_and_nul_path_to_sanitized_codes(self) -> None:
        temporary, own_data, app_groups = self.make_layout()
        self.addCleanup(temporary.cleanup)

        with self.assertRaisesRegex(NativeGroupMetadataError, "GROUP_METADATA_FORMAT_UNCONFIRMED"):
            decode_group_metadata(b'<?xml version="1.0"?><plist><array><string>', own_data)
        nul_path = str(app_groups / "bad\x00path")
        with self.assertRaisesRegex(NativeGroupMetadataError, "GROUP_METADATA_PATH_UNCONFIRMED"):
            decode_group_metadata(json.dumps([nul_path]).encode(), own_data)

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
