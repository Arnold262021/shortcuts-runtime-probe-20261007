from __future__ import annotations

import os
from pathlib import Path
import plistlib
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import native_entitlements as entitlements
from native_entitlements import (
    MCM_METADATA_NAME,
    NativeEntitlementsError,
    locate_declared_system_groups,
    parse_codesign_entitlements,
)


class NativeEntitlementsTests(unittest.TestCase):
    def make_layout(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        own_data = Path(temporary.name) / "device" / "data"
        root = own_data / "Containers" / "Shared" / "SystemGroup"
        root.mkdir(parents=True)
        return temporary, own_data, root

    def write_mcm(self, directory: Path, identifier: str) -> None:
        (directory / MCM_METADATA_NAME).write_bytes(plistlib.dumps({"MCMMetadataIdentifier": identifier}))

    def test_parses_xml_keys_types_and_safe_declared_groups_without_other_values(self) -> None:
        raw = plistlib.dumps(
            {
                "com.example.secret": "PRIVATE_SENTINEL",
                "com.apple.security.application-groups": ["group.app"],
                "com.apple.security.system-groups": ["group.system"],
                "flag": True,
            },
            fmt=plistlib.FMT_XML,
        )
        report = parse_codesign_entitlements(raw, b"Executable=/private/var/example\n")

        self.assertEqual("string", report["entitlement_types"]["com.example.secret"])
        self.assertEqual(["group.app"], report["application_groups"])
        self.assertEqual(["group.system"], report["system_groups"])
        self.assertTrue(report["system_groups_declared"])
        self.assertEqual("SYSTEM_GROUP_ENTITLEMENT_DECLARED", report["system_groups_status"])
        self.assertNotIn("PRIVATE_SENTINEL", repr(report))

    def test_parses_binary_plist_and_reports_system_groups_not_declared(self) -> None:
        report = parse_codesign_entitlements(plistlib.dumps({"flag": False}, fmt=plistlib.FMT_BINARY))
        self.assertFalse(report["system_groups_declared"])
        self.assertEqual([], report["system_groups"])
        self.assertEqual("SYSTEM_GROUP_ENTITLEMENT_NOT_DECLARED", report["system_groups_status"])

    def test_ignores_stderr_diagnostic_but_rejects_missing_stdout_contract(self) -> None:
        plist_one = plistlib.dumps({"flag": True})
        report = parse_codesign_entitlements(plist_one, b"Executable=/private/var/example\n")
        self.assertEqual("bool", report["entitlement_types"]["flag"])
        with self.assertRaisesRegex(NativeEntitlementsError, "ENTITLEMENTS_FORMAT_UNCONFIRMED"):
            parse_codesign_entitlements(b"warning text", plist_one)
        with self.assertRaisesRegex(NativeEntitlementsError, "ENTITLEMENTS_FORMAT_UNCONFIRMED"):
            parse_codesign_entitlements(b"", plist_one)

    def test_rejects_entitlement_shape_and_size_limits(self) -> None:
        with self.assertRaisesRegex(NativeEntitlementsError, "ENTITLEMENTS_SHAPE_UNCONFIRMED"):
            parse_codesign_entitlements(plistlib.dumps(["not", "a", "dict"]))
        with self.assertRaisesRegex(NativeEntitlementsError, "ENTITLEMENTS_TOO_LARGE"):
            parse_codesign_entitlements(b"x" * (256 * 1024 + 1))
        with self.assertRaisesRegex(NativeEntitlementsError, "ENTITLEMENTS_GROUPS_UNCONFIRMED"):
            parse_codesign_entitlements(plistlib.dumps({"com.apple.security.system-groups": ["bad value"]}))

    def test_locator_rejects_absent_declared_identifier_list(self) -> None:
        temporary, own_data, _ = self.make_layout()
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(NativeEntitlementsError, "SYSTEM_GROUP_DECLARED_MISSING"):
            locate_declared_system_groups(own_data, [])

    def test_locates_only_declared_groups_from_matching_mcm_metadata(self) -> None:
        temporary, own_data, root = self.make_layout()
        self.addCleanup(temporary.cleanup)
        declared = root / "opaque-one"
        unknown = root / "opaque-two"
        declared.mkdir()
        unknown.mkdir()
        self.write_mcm(declared, "group.system")
        self.write_mcm(unknown, "group.other")

        result = locate_declared_system_groups(own_data, ["group.system"])

        self.assertEqual([{"identifier": "group.system", "path": declared.resolve()}], result)

    def test_locator_canonicalizes_lexical_own_data_alias(self) -> None:
        temporary, own_data, root = self.make_layout()
        self.addCleanup(temporary.cleanup)
        directory = root / "opaque"
        directory.mkdir()
        self.write_mcm(directory, "group.system")
        alias = own_data.parent / "." / "data"

        result = locate_declared_system_groups(alias, ["group.system"])

        self.assertEqual(directory.resolve(), result[0]["path"])

    def test_rejects_system_group_directory_limit(self) -> None:
        temporary, own_data, root = self.make_layout()
        self.addCleanup(temporary.cleanup)
        for index in range(257):
            (root / f"opaque-{index}").mkdir()

        with self.assertRaisesRegex(NativeEntitlementsError, "SYSTEM_GROUP_DIR_LIMIT"):
            locate_declared_system_groups(own_data, ["group.system"])

    def test_rejects_system_group_symlink_before_metadata_open(self) -> None:
        temporary, own_data, root = self.make_layout()
        self.addCleanup(temporary.cleanup)
        directory = root / "opaque"
        directory.mkdir()
        canonical_directory = directory.resolve(strict=True)
        original_lstat = Path.lstat
        canonical_key = os.path.normcase(os.path.realpath(str(canonical_directory)))

        def symlink_directory(path: Path):
            if os.path.normcase(os.path.realpath(str(path))) == canonical_key:
                return SimpleNamespace(st_mode=stat.S_IFLNK)
            return original_lstat(path)

        with mock.patch.object(Path, "lstat", new=symlink_directory):
            with self.assertRaisesRegex(NativeEntitlementsError, "SYSTEM_GROUP_SYMLINK"):
                locate_declared_system_groups(own_data, ["group.system"])

    def test_rejects_missing_duplicate_and_oversize_metadata(self) -> None:
        temporary, own_data, root = self.make_layout()
        self.addCleanup(temporary.cleanup)
        directory = root / "opaque"
        directory.mkdir()
        with self.assertRaisesRegex(NativeEntitlementsError, "SYSTEM_GROUP_DECLARED_MISSING"):
            locate_declared_system_groups(own_data, ["group.system"])
        self.write_mcm(directory, "group.system")
        second = root / "second"
        second.mkdir()
        self.write_mcm(second, "group.system")
        with self.assertRaisesRegex(NativeEntitlementsError, "SYSTEM_GROUP_DECLARED_AMBIGUOUS"):
            locate_declared_system_groups(own_data, ["group.system"])
        (second / MCM_METADATA_NAME).unlink()
        second.rmdir()
        metadata = directory / MCM_METADATA_NAME
        metadata.write_bytes(b"x" * (64 * 1024 + 1))
        with self.assertRaisesRegex(NativeEntitlementsError, "SYSTEM_GROUP_METADATA_TOO_LARGE"):
            locate_declared_system_groups(own_data, ["group.system"])

    def test_does_not_open_non_metadata_store_files(self) -> None:
        temporary, own_data, root = self.make_layout()
        self.addCleanup(temporary.cleanup)
        directory = root / "opaque"
        directory.mkdir()
        self.write_mcm(directory, "group.system")
        store = directory / "store.db"
        store.write_bytes(b"PRIVATE_SENTINEL")
        original_open = os.open

        def reject_store(path: str, flags: int, *args: object) -> int:
            if Path(path) == store.resolve():
                raise AssertionError("must not open group stores")
            return original_open(path, flags, *args)

        with mock.patch("native_entitlements.os.open", new=reject_store):
            locate_declared_system_groups(own_data, ["group.system"])


if __name__ == "__main__":
    unittest.main()
