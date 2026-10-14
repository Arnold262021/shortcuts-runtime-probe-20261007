import unittest
import tempfile
import json
import plistlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import inspect_simulator as probe

NATIVE_TIMEOUT_PROBE = probe.native_timeout_probe


class OpenHandleBoundaryTests(unittest.TestCase):
    def exercise(self, last_pid=123, lsof_exit=0, bundle_valid=True, internal_path=True,
                 inspect_schema=False, observed_name="observed.db", stale_artifact=False,
                 inspect_actions=False):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            data = home / "Library/Developer/CoreSimulator/Devices/owned/data"
            data.mkdir(parents=True)
            inside = data / observed_name
            inside.parent.mkdir(parents=True, exist_ok=True)
            inside.touch()
            outside = home / "SENTINEL_PRIVATE_DO_NOT_RETAIN.db"
            outside.touch()
            lsof = f"p123\ncShortcuts\nf3u\nn{outside}\n"
            if internal_path:
                lsof += f"f4u\nn{inside}\n"
            if stale_artifact:
                (home / "native-open-file-paths.json").write_text(json.dumps({
                    "paths": ["Library/Shortcuts/Shortcuts.sqlite"]}))
            results = [probe.subprocess.CompletedProcess([], 0, b"not retained bundle path", b""),
                       probe.subprocess.CompletedProcess([], 0, b"com.apple.shortcuts: 123\n", b""),
                       probe.subprocess.CompletedProcess([], lsof_exit, lsof.encode(), b"PRIVATE_STDERR_SENTINEL"),
                       probe.subprocess.CompletedProcess([], 0, f"com.apple.shortcuts: {last_pid}\n".encode(), b"")]
            with patch.object(Path, "home", return_value=home), \
                    patch.object(probe, "ARTIFACTS", home), \
                    patch.object(probe, "verify_native_shortcuts_bundle",
                                 side_effect=None if bundle_valid else RuntimeError("BUNDLE_ID_UNCONFIRMED")), \
                    patch.object(probe, "command", side_effect=results) as command:
                result = probe.collect_native_open_files("owned", inspect_schema=inspect_schema,
                                                        inspect_actions=inspect_actions)
            artifact = home / "native-open-file-paths.json"
            metadata = artifact.read_text() if artifact.exists() else None
            schema_file = home / "native-shortcuts-library-schema.json"
            self.assertEqual(schema_file.exists(), result["status"] == "SHORTCUTS_LIBRARY_SCHEMA_ONLY")
            if schema_file.exists():
                self.assertNotIn("SENTINEL", schema_file.read_text())
            actions_file = home / "native-synthetic-action-shape.json"
            self.assertEqual(actions_file.exists(), result["status"] == "SYNTHETIC_ACTION_MARKER_OBSERVED")
            if actions_file.exists():
                self.assertNotIn("SENTINEL", actions_file.read_text())
            failure_file = home / "native-synthetic-action-failure.json"
            self.assertEqual(failure_file.exists(), "blob_diagnostic" in result)
            if failure_file.exists():
                saved_failure = json.loads(failure_file.read_text())
                self.assertEqual(saved_failure["blob"], result["blob_diagnostic"])
                self.assertNotIn("SENTINEL", failure_file.read_text())
            shape_file = home / "native-shortcuts-lsof-shape.json"
            if shape_file.exists():
                shape = shape_file.read_text()
                self.assertNotIn("SENTINEL", shape)
                self.assertNotIn("observed.db", shape)
                self.assertFalse(json.loads(shape)["shortcuts_association_proven"])
            if last_pid != 123:
                self.assertFalse(shape_file.exists())
            return result, metadata, command.call_args_list

    def test_only_own_relative_paths_survive_stable_native_process(self):
        result, metadata, calls = self.exercise()
        self.assertEqual(result["status"], "OPEN_HANDLE_PATH_METADATA_OBSERVED")
        self.assertEqual(result["observed_paths"], 1)
        self.assertTrue(result["process_identity_stable"])
        self.assertFalse(result["open_handle_contents_read"])
        self.assertEqual(json.loads(metadata)["paths"], ["observed.db"])
        self.assertNotIn("SENTINEL", metadata)
        self.assertEqual(calls[2].args[0], ["lsof", "-nP", "-a", "-p", "123", "-Fpcn"])
        self.assertEqual(calls[2].kwargs["timeout"], 10)

    def test_changed_pid_discards_valid_paths_and_every_raw_diagnostic(self):
        result, metadata, _ = self.exercise(last_pid=456)
        self.assertEqual(result["status"], "OPEN_HANDLE_PID_UNSTABLE")
        self.assertIsNone(metadata)
        self.assertNotIn("SENTINEL", str(result))
        self.assertNotIn("paths", result)

    def test_own_device_or_data_symlink_prevents_every_command(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            device = home / "Library/Developer/CoreSimulator/Devices/owned"
            data = device / "data"
            data.mkdir(parents=True)
            for linked in (device, data):
                with self.subTest(linked=linked.name), \
                        patch.object(Path, "home", return_value=home), \
                        patch.object(Path, "is_symlink", autospec=True,
                                     side_effect=lambda path: path == linked), \
                        patch.object(probe, "command") as command:
                    result = probe.collect_native_open_files("owned")
                self.assertEqual(result["status"], "OPEN_HANDLE_OWN_DATA_UNCONFIRMED")
                command.assert_not_called()

    def test_zero_owned_handles_is_not_store_absence(self):
        result, metadata, _ = self.exercise(internal_path=False)
        self.assertEqual(result["status"], "NO_ASSOCIATED_OPEN_HANDLE_OBSERVED")
        self.assertEqual(json.loads(metadata)["paths"], [])
        self.assertTrue(result["process_identity_stable"])
        self.assertFalse(result["condition_payload_proven"])

    def test_bundle_failure_prevents_launch_and_nonzero_lsof_is_unconfirmed(self):
        result, metadata, calls = self.exercise(bundle_valid=False)
        self.assertEqual(len(calls), 1)
        self.assertIsNone(metadata)
        self.assertEqual(result["status"], "OPEN_HANDLE_NATIVE_METADATA_UNCONFIRMED")
        result, metadata, calls = self.exercise(lsof_exit=1)
        self.assertEqual(result["status"], "OPEN_HANDLE_COMMAND_UNCONFIRMED")
        self.assertEqual(len(calls), 3)
        self.assertIsNone(metadata)
        self.assertNotIn("SENTINEL", str(result))

    def test_schema_mode_binds_only_current_owned_observation(self):
        target = "Library/Shortcuts/Shortcuts.sqlite"
        survey = {"schema_only": True, "candidate_count": 1,
                  "databases": [{"path": target, "objects": []}]}
        with patch("native_store_schema.survey_observed_shortcuts_file", return_value=survey) as read:
            result, metadata, calls = self.exercise(inspect_schema=True, observed_name=target)
        self.assertEqual(result["status"], "SHORTCUTS_LIBRARY_SCHEMA_ONLY")
        self.assertTrue(result["open_handle_contents_read"])
        self.assertTrue(result["schema_attempted"])
        self.assertFalse(result["row_values_read"])
        self.assertFalse(result["condition_payload_proven"])
        self.assertEqual(result["schema_databases"], 1)
        self.assertEqual(read.call_count, 1)
        self.assertEqual(read.call_args.args[1], [target])
        self.assertEqual(read.call_args.args[0].name, "data")
        self.assertEqual(len(calls), 4)
        self.assertFalse(json.loads(metadata)["open_handle_contents_read"])

    def test_schema_mode_cannot_reuse_old_artifact_or_other_current_db(self):
        for internal in (False, True):
            with self.subTest(internal=internal), patch("native_store_schema.sqlite3.connect") as connect:
                result, metadata, _ = self.exercise(inspect_schema=True, internal_path=internal,
                                                    stale_artifact=True)
            connect.assert_not_called()
            self.assertEqual(result["status"], "SHORTCUTS_LIBRARY_SCHEMA_UNCONFIRMED")
            self.assertEqual(result["schema_error"], "OBSERVED_SHORTCUTS_PATH_MISSING")
            self.assertNotIn("Library/Shortcuts/Shortcuts.sqlite", json.loads(metadata)["paths"])

    def test_partial_schema_failure_does_not_claim_contents_unread(self):
        from native_store_schema import NativeStoreSchemaError
        with patch("native_store_schema.survey_observed_shortcuts_file", side_effect=
                   NativeStoreSchemaError("SQLITE_SCHEMA_QUERY_FAILED")):
            result, _, _ = self.exercise(inspect_schema=True)
        self.assertEqual(result["status"], "SHORTCUTS_LIBRARY_SCHEMA_UNCONFIRMED")
        self.assertEqual(result["open_handle_contents_read"], "unconfirmed")
        self.assertFalse(result["row_values_read"])

    def test_schema_never_runs_when_pid_changed_or_in_metadata_mode(self):
        with patch("native_store_schema.survey_observed_shortcuts_file") as read:
            result, _, _ = self.exercise(inspect_schema=True, last_pid=456)
            self.assertEqual(result["status"], "OPEN_HANDLE_PID_UNSTABLE")
            self.exercise()
        read.assert_not_called()

    def test_schema_artifact_write_failure_never_claims_contents_unread(self):
        real_write = Path.write_text

        def fail_schema_write(path, *args, **kwargs):
            if path.name == "native-shortcuts-library-schema.json":
                raise OSError("PRIVATE_SENTINEL")
            return real_write(path, *args, **kwargs)

        with patch("native_store_schema.survey_observed_shortcuts_file", return_value={
                "schema_only": True, "databases": []}), \
                patch.object(Path, "write_text", autospec=True, side_effect=fail_schema_write):
            result, _, _ = self.exercise(inspect_schema=True)
        self.assertEqual(result["status"], "OPEN_HANDLE_NATIVE_METADATA_UNCONFIRMED")
        self.assertEqual(result["open_handle_contents_read"], "unconfirmed")
        self.assertNotIn("SENTINEL", str(result))

    def test_actions_analysis_uses_current_owned_paths_without_payload_claim(self):
        target = "Library/Shortcuts/Shortcuts.sqlite"
        with patch("native_synthetic_actions.inspect_observed_synthetic_actions", return_value={
                "status": "SYNTHETIC_ACTION_MARKER_OBSERVED", "marker_count_exactly_one": True}) as read:
            result, _, _ = self.exercise(inspect_actions=True, observed_name=target)
        self.assertEqual(read.call_args.args[1], [target])
        self.assertEqual(read.call_count, 1)
        self.assertTrue(result["row_values_read"])
        self.assertTrue(result["selected_action_blob_only"])
        self.assertFalse(result["condition_payload_proven"])
        self.assertFalse(result["database_copy"])

    def test_conflicting_modes_and_changed_pid_never_read_actions(self):
        with patch("native_synthetic_actions.inspect_observed_synthetic_actions") as read:
            result, _, calls = self.exercise(inspect_schema=True, inspect_actions=True)
            self.assertEqual(result["status"], "NATIVE_INSPECTION_MODES_CONFLICT")
            self.assertEqual(calls, [])
            self.exercise(inspect_actions=True, last_pid=456)
            self.exercise()
        read.assert_not_called()

    def test_actions_partial_failure_and_old_artifact_do_not_authorize(self):
        from native_synthetic_actions import NativeSyntheticActionsError
        with patch("native_synthetic_actions.inspect_observed_synthetic_actions", side_effect=
                   NativeSyntheticActionsError("SYNTHETIC_ACTIONS_QUERY_FAILED")):
            result, _, _ = self.exercise(inspect_actions=True)
        self.assertEqual(result["status"], "SYNTHETIC_ACTION_BLOB_UNCONFIRMED")
        self.assertEqual(result["open_handle_contents_read"], "unconfirmed")
        self.assertEqual(result["row_values_read"], "unconfirmed")
        with patch("native_synthetic_actions.sqlite3.connect") as connect:
            result, _, _ = self.exercise(inspect_actions=True, stale_artifact=True)
        connect.assert_not_called()
        self.assertEqual(result["status"], "SYNTHETIC_ACTION_BLOB_UNCONFIRMED")

    def test_actions_artifact_failure_preserves_unknown_read_state(self):
        real_write = Path.write_text

        def fail_actions_write(path, *args, **kwargs):
            if path.name == "native-synthetic-action-shape.json":
                raise OSError("PRIVATE_SENTINEL")
            return real_write(path, *args, **kwargs)

        with patch("native_synthetic_actions.inspect_observed_synthetic_actions", return_value={
                "status": "SYNTHETIC_ACTION_MARKER_OBSERVED"}), \
                patch.object(Path, "write_text", autospec=True, side_effect=fail_actions_write):
            result, _, _ = self.exercise(inspect_actions=True)
        self.assertEqual(result["status"], "OPEN_HANDLE_NATIVE_METADATA_UNCONFIRMED")
        self.assertEqual(result["row_values_read"], "unconfirmed")
        self.assertEqual(result["open_handle_contents_read"], "unconfirmed")
        self.assertNotIn("SENTINEL", str(result))

    def test_actions_failure_retains_only_allowlisted_post_blob_diagnostic(self):
        from native_synthetic_actions import NativeSyntheticActionsError
        diagnostic = {"length": 20, "sha256": "a" * 64, "framing": "unknown"}
        error = NativeSyntheticActionsError("SYNTHETIC_ACTIONS_BLOB_FORMAT_UNCONFIRMED", diagnostic)
        with patch("native_synthetic_actions.inspect_observed_synthetic_actions", side_effect=error):
            result, _, _ = self.exercise(inspect_actions=True)
        self.assertEqual(result["status"], "SYNTHETIC_ACTION_BLOB_UNCONFIRMED")
        self.assertEqual(result["blob_diagnostic"], diagnostic)
        self.assertFalse(result["condition_payload_proven"])


class HostLsofPreflightTests(unittest.TestCase):
    def test_wda_build_actual_destination_error_reaches_receipt(self):
        from appium_host_preflight import _build_failure
        error = _build_failure(probe.subprocess.CompletedProcess(
            [], 70, b"", b"xcodebuild: error: Unable to find a destination matching the provided destination specifier"))
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(probe, "ARTIFACTS", Path(directory) / "artifacts"), \
                patch.object(probe.sys, "platform", "darwin"), \
                patch.dict(probe.os.environ, {"GITHUB_ACTIONS": "true",
                           "SHORTCUTS_PROBE_EXECUTION_MODE": "appium-wda-build-preflight"}), \
                patch("appium_host_preflight.run_appium_wda_build_preflight", create=True, side_effect=error), \
                patch("builtins.print"):
            self.assertEqual(probe.main(), 1)
            receipt = json.loads((probe.ARTIFACTS / "receipt.json").read_text())
            self.assertEqual(receipt["appium_wda_build_failure"]["build_failure_category"], "destination_not_supported")
            self.assertEqual(receipt["appium_wda_build_failure"]["build_exit"], 70)

    def test_wda_build_failure_retains_only_typed_allowlist(self):
        from appium_host_preflight import AppiumHostPreflightError
        for malformed in (False, True):
            error = AppiumHostPreflightError("HOST_WDA_BUILD", cleanup_exited=True)
            error.build_exit = False if malformed else 70
            error.build_stdout_bytes = -1 if malformed else 123
            error.build_stderr_bytes = "PRIVATE" if malformed else 456
            error.build_failure_category = ["PRIVATE"] if malformed else "destination_not_supported"
            error.build_stdout_sha256 = "PRIVATE" if malformed else "a" * 64
            error.build_stderr_sha256 = "PRIVATE" if malformed else "b" * 64
            with self.subTest(malformed=malformed), tempfile.TemporaryDirectory() as directory, \
                    patch.object(probe, "ARTIFACTS", Path(directory) / "artifacts"), \
                    patch.object(probe.sys, "platform", "darwin"), \
                    patch.dict(probe.os.environ, {"GITHUB_ACTIONS": "true",
                               "SHORTCUTS_PROBE_EXECUTION_MODE": "appium-wda-build-preflight"}), \
                    patch("appium_host_preflight.run_appium_wda_build_preflight", create=True, side_effect=error), \
                    patch("builtins.print"):
                self.assertEqual(probe.main(), 1)
                text = (probe.ARTIFACTS / "receipt.json").read_text()
                self.assertNotIn("PRIVATE", text)
                receipt = json.loads(text)
                self.assertEqual(receipt["failure"], "HOST_WDA_BUILD")
                if malformed:
                    self.assertNotIn("appium_wda_build_failure", receipt)
                else:
                    self.assertEqual(receipt["appium_wda_build_failure"], {
                        "build_exit": 70, "build_stdout_bytes": 123, "build_stderr_bytes": 456,
                        "build_failure_category": "destination_not_supported",
                        "build_stdout_sha256": "a" * 64, "build_stderr_sha256": "b" * 64})

    def test_wda_build_mode_never_requests_session_or_simulator_boot(self):
        from appium_host_preflight import AppiumHostPreflightError
        good = {"status": "HOST_WDA_COMPILED_ONLY", "build_exit": 0,
                "runner_bundle_verified": True, "xctestrun_verified": True,
                "simulator_state_unchanged": True, "cleanup_exited": True}
        cases = [(good, None, 0)]
        for key in ("runner_bundle_verified", "xctestrun_verified", "simulator_state_unchanged", "cleanup_exited"):
            cases.append((dict(good, **{key: False}), None, 1))
        cases.append((dict(good, build_exit=False), None, 1))
        cases.append(({}, AppiumHostPreflightError("HOST_PREFLIGHT_CLEANUP_UNCONFIRMED", cleanup_exited=False,
                      temporary_retained=True, primary_code="HOST_PREFLIGHT_CALLBACK_UNCONFIRMED"), 1))
        for observed, error, expected in cases:
            with self.subTest(observed=observed, error=error), tempfile.TemporaryDirectory() as directory, \
                    patch.object(probe, "ARTIFACTS", Path(directory) / "artifacts"), \
                    patch.object(probe.sys, "platform", "darwin"), \
                    patch.dict(probe.os.environ, {"GITHUB_ACTIONS": "true",
                               "SHORTCUTS_PROBE_EXECUTION_MODE": "appium-wda-build-preflight"}), \
                    patch("appium_host_preflight.run_appium_wda_build_preflight", create=True,
                          return_value=observed, side_effect=error) as build, \
                    patch.object(probe, "command") as command, \
                    patch.object(probe, "sim_json") as sim_json, \
                    patch.object(probe, "native_timeout_probe") as timeout, \
                    patch.object(probe, "appium_session_preflight") as session, patch("builtins.print"):
                self.assertEqual(probe.main(), expected)
                build.assert_called_once_with(command, probe.SAFE_ENV)
                command.assert_not_called()
                sim_json.assert_not_called()
                timeout.assert_not_called()
                session.assert_not_called()
                receipt = json.loads((probe.ARTIFACTS / "receipt.json").read_text())
                self.assertFalse(receipt["simulator_boot_requested"])
                self.assertFalse(receipt["webdriver_session_created"])
                self.assertFalse(receipt["ui_gestures_run"])
                self.assertFalse(receipt["xcode_test_suite_run"])
                self.assertFalse(receipt["store_read"])
                self.assertFalse(receipt["otp_proven"])
                if error is not None:
                    self.assertEqual(receipt["appium_primary_failure"], error.primary_code)

    def test_appium_host_preflight_never_starts_simulator_or_ui(self):
        from appium_host_preflight import AppiumHostPreflightError
        for failed in (False, True):
            error = AppiumHostPreflightError("HOST_PREFLIGHT_CLEANUP_UNCONFIRMED", cleanup_exited=False,
                                            temporary_retained=True,
                                            primary_code="HOST_PREFLIGHT_STATUS_UNCONFIRMED")
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as directory, \
                    patch.object(probe, "ARTIFACTS", Path(directory) / "artifacts"), \
                    patch.object(probe.sys, "platform", "darwin"), \
                    patch.dict(probe.os.environ, {"GITHUB_ACTIONS": "true",
                               "SHORTCUTS_PROBE_EXECUTION_MODE": "appium-host-preflight"}), \
                    patch("appium_host_preflight.run_appium_host_preflight",
                          return_value={"status_ready": True}, side_effect=error if failed else None) as host, \
                    patch.object(probe, "command") as command, \
                    patch.object(probe, "native_timeout_probe") as timeout, \
                    patch.object(probe, "sim_json") as sim_json, patch("builtins.print"):
                self.assertEqual(probe.main(), int(failed))
                command.assert_not_called()
                sim_json.assert_not_called()
                timeout.assert_not_called()
                host.assert_called_once_with(command, probe.SAFE_ENV)
                receipt = json.loads((probe.ARTIFACTS / "receipt.json").read_text())
                self.assertFalse(receipt["simulator_started"])
                self.assertFalse(receipt["ui_run"])
                self.assertFalse(receipt["webdriver_session_created"])
                self.assertFalse(receipt["otp_proven"])
                if failed:
                    self.assertFalse(receipt["appium_cleanup_exited"])
                    self.assertTrue(receipt["appium_temporary_retained"])
                    self.assertEqual(receipt["appium_primary_failure"], "HOST_PREFLIGHT_STATUS_UNCONFIRMED")

    def test_host_mode_never_starts_simulator_or_ui(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(probe, "ARTIFACTS", Path(directory) / "artifacts"), \
                patch.object(probe.sys, "platform", "darwin"), \
                patch.dict(probe.os.environ, {"GITHUB_ACTIONS": "true",
                           "SHORTCUTS_PROBE_EXECUTION_MODE": "lsof-preflight"}), \
                patch.object(probe, "host_lsof_field_preflight", return_value={
                    "status": "HOST_LSOF_FIELD_SHAPE_OBSERVED", "fixture_handle_observed": True}), \
                patch.object(probe, "command") as command, \
                patch.object(probe, "sim_json") as sim_json, patch("builtins.print"):
            self.assertEqual(probe.main(), 0)
            command.assert_not_called()
            sim_json.assert_not_called()
            receipt = json.loads((probe.ARTIFACTS / "receipt.json").read_text())
            self.assertFalse(receipt["simulator_started"])
            self.assertFalse(receipt["ui_run"])
            self.assertFalse(receipt["shortcuts_association_proven"])
            self.assertEqual(receipt["scope"], "host_cli_field_shape_only")

    def test_preflight_keeps_fixture_open_and_never_retains_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture_dir = root / "fixture"
            fixture_dir.mkdir()
            real_open = Path.open
            opened_streams = []

            def track_open(path, *args, **kwargs):
                stream = real_open(path, *args, **kwargs)
                opened_streams.append(stream)
                return stream

            def fake_command(args, **kwargs):
                fixture = fixture_dir / "synthetic-open-file.txt"
                self.assertTrue(fixture.exists())
                self.assertEqual(len(opened_streams), 1)
                self.assertFalse(opened_streams[0].closed)
                raw = f"p{probe.os.getpid()}\ncSENTINEL_PRIVATE_COMMAND\nf4\nn{fixture}\n\n".encode()
                return probe.subprocess.CompletedProcess(args, 0, raw, b"PRIVATE_STDERR")

            with patch.object(probe, "ARTIFACTS", root), \
                    patch.object(probe.tempfile, "TemporaryDirectory") as temporary, \
                    patch.object(Path, "open", autospec=True, side_effect=track_open), \
                    patch.object(probe, "command", side_effect=fake_command) as command:
                temporary.return_value.__enter__.return_value = str(fixture_dir)
                result = probe.host_lsof_field_preflight()
            self.assertEqual(result["status"], "HOST_LSOF_FIELD_SHAPE_OBSERVED")
            self.assertTrue(opened_streams[0].closed)
            self.assertFalse(result["shortcuts_association_proven"])
            saved = (root / "native-host-lsof-shape.json").read_text()
            self.assertNotIn("SENTINEL", saved)
            self.assertNotIn("synthetic-open-file", saved)
            self.assertNotIn(str(probe.os.getpid()), saved)
            self.assertEqual(json.loads(saved)["field_class_counts"]["f"], 1)
            self.assertEqual(command.call_args.kwargs["timeout"], 10)

    def test_nonzero_or_missing_fixture_is_red(self):
        for exit_code in (0, 1):
            with self.subTest(exit_code=exit_code), tempfile.TemporaryDirectory() as directory, \
                    patch.object(probe, "ARTIFACTS", Path(directory)), \
                    patch.object(probe, "command", return_value=probe.subprocess.CompletedProcess(
                        [], exit_code, f"p{probe.os.getpid()}\ncPython\nn/not-the-fixture\n".encode(), b"")):
                with self.assertRaisesRegex(RuntimeError, "LSOF_PREFLIGHT_UNCONFIRMED"):
                    probe.host_lsof_field_preflight()


class ExportBoundaryTests(unittest.TestCase):
    def test_entitlements_do_not_scan_system_groups_when_key_is_missing(self):
        import native_entitlements
        with tempfile.TemporaryDirectory() as directory:
            artifacts = Path(directory)
            results = [probe.subprocess.CompletedProcess([], 0, b"not retained bundle path", b""),
                       probe.subprocess.CompletedProcess([], 0, plistlib.dumps({"public.permission": True}),
                                                        b"Executable=/private/SENTINEL")]
            with patch.object(probe, "ARTIFACTS", artifacts), \
                    patch.object(probe, "verify_native_shortcuts_bundle", return_value=Path("bundle/Shortcuts.app")), \
                    patch.object(probe, "command", side_effect=results), \
                    patch.object(native_entitlements, "locate_declared_system_groups") as locate:
                result = probe.collect_native_entitlement_metadata("owned")
            locate.assert_not_called()
            self.assertEqual(result["status"], "SYSTEM_GROUP_ENTITLEMENT_NOT_DECLARED")
            self.assertFalse(result["system_store_read"])
            self.assertNotIn("SENTINEL", (artifacts / "native-entitlement-types.json").read_text())

    def test_bundle_info_identity_is_exact_before_codesign(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "Shortcuts.app"
            bundle.mkdir()
            info = bundle / "Info.plist"
            info.write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.apple.shortcuts"}))
            self.assertEqual(probe.verify_native_shortcuts_bundle(str(bundle).encode()), bundle.resolve())
            info.write_bytes(plistlib.dumps({"CFBundleIdentifier": "different.app"}))
            with self.assertRaisesRegex(RuntimeError, "BUNDLE_ID_UNCONFIRMED"):
                probe.verify_native_shortcuts_bundle(str(bundle).encode())
            with patch.object(probe, "command", return_value=probe.subprocess.CompletedProcess([], 0, str(bundle).encode(), b"")) as command:
                result = probe.collect_native_entitlement_metadata("owned")
            self.assertEqual(command.call_count, 1)
            self.assertFalse(result["system_store_read"])

    def test_declared_system_schema_requires_positive_exact_metadata_association(self):
        import native_entitlements
        import native_store_schema
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            own_data = home / "Library/Developer/CoreSimulator/Devices/owned/data"
            group = own_data / "Containers/Shared/SystemGroup/declared"
            group.mkdir(parents=True)
            outputs = [probe.subprocess.CompletedProcess([], 0, b"bundle path not retained", b""),
                       probe.subprocess.CompletedProcess([], 0, plistlib.dumps({
                           "com.apple.security.system-groups": ["systemgroup.synthetic"]}), b"")]
            with patch.object(Path, "home", return_value=home), \
                    patch.object(probe, "ARTIFACTS", home), \
                    patch.object(probe, "verify_native_shortcuts_bundle", return_value=Path("bundle/Shortcuts.app")), \
                    patch.object(probe, "command", side_effect=outputs), \
                    patch.object(native_entitlements, "locate_declared_system_groups",
                                 return_value=[{"identifier": "systemgroup.synthetic", "path": group.resolve()}]) as locate, \
                    patch.object(native_store_schema, "survey_shortcuts_schema", return_value={"databases": []}) as survey:
                result = probe.collect_native_entitlement_metadata("owned")
            locate.assert_called_once_with(own_data.resolve(), ["systemgroup.synthetic"])
            survey.assert_called_once_with(group.resolve(), include_inventory=False)
            self.assertEqual(result["status"], "SYSTEM_GROUP_SCHEMA_ONLY")
            self.assertFalse(result["system_rows_read"])
            retained = (home / "native-system-group-schema.json").read_text()
            self.assertNotIn(str(home), retained)

    def test_system_association_missing_or_outside_never_reaches_schema(self):
        import native_entitlements
        import native_store_schema
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            own_data = home / "Library/Developer/CoreSimulator/Devices/owned/data"
            own_data.mkdir(parents=True)
            outside = home / "outside"
            outside.mkdir()
            for groups in ([], [{"identifier": "systemgroup.synthetic", "path": outside.resolve()}]):
                outputs = [probe.subprocess.CompletedProcess([], 0, b"bundle", b""),
                           probe.subprocess.CompletedProcess([], 0, plistlib.dumps({
                               "com.apple.security.system-groups": ["systemgroup.synthetic"]}), b"")]
                with patch.object(Path, "home", return_value=home), \
                        patch.object(probe, "ARTIFACTS", home), \
                        patch.object(probe, "verify_native_shortcuts_bundle", return_value=Path("bundle/Shortcuts.app")), \
                        patch.object(probe, "command", side_effect=outputs), \
                        patch.object(native_entitlements, "locate_declared_system_groups", return_value=groups), \
                        patch.object(native_store_schema, "survey_shortcuts_schema") as survey:
                    result = probe.collect_native_entitlement_metadata("owned")
                survey.assert_not_called()
                self.assertFalse(result["system_store_read"])

    def test_fixture_metadata_finds_only_exact_shortcuts_identity_without_rpc(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            base = home / "Library/Developer/CoreSimulator/Devices/owned/data/Containers/Data/Application"
            target = base / "shortcuts"
            target.mkdir(parents=True)
            other = base / "unrelated"
            other.mkdir()
            name = ".com.apple.mobile_container_manager.metadata.plist"
            (target / name).write_bytes(plistlib.dumps({"MCMMetadataIdentifier": "com.apple.shortcuts"}))
            (other / name).write_bytes(plistlib.dumps({"MCMMetadataIdentifier": "com.example.other"}))
            (other / "private-row-data.db").write_bytes(b"PRIVATE_SENTINEL_DO_NOT_READ")
            original_open = probe.os.open
            opened = []

            def metadata_only_open(path, *args, **kwargs):
                self.assertEqual(Path(path).name, name)
                opened.append(Path(path).name)
                return original_open(path, *args, **kwargs)

            with patch.object(Path, "home", return_value=home), \
                    patch.object(probe.os, "open", new=metadata_only_open), \
                    patch.object(probe, "command") as command:
                found = probe.find_owned_shortcuts_data_container("owned")
            self.assertEqual(found, target.resolve())
            self.assertEqual(len(opened), 2)
            command.assert_not_called()

    def test_fixture_metadata_rejects_ambiguous_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            base = home / "Library/Developer/CoreSimulator/Devices/owned/data/Containers/Data/Application"
            for name in ("one", "two"):
                folder = base / name
                folder.mkdir(parents=True)
                (folder / ".com.apple.mobile_container_manager.metadata.plist").write_bytes(
                    plistlib.dumps({"MCMMetadataIdentifier": "com.apple.shortcuts"}))
            with patch.object(Path, "home", return_value=home):
                with self.assertRaisesRegex(RuntimeError, "METADATA_NOT_UNIQUE"):
                    probe.find_owned_shortcuts_data_container("owned")

    def test_fixture_metadata_rejects_missing_and_corrupt_descriptors(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            base = home / "Library/Developer/CoreSimulator/Devices/owned/data/Containers/Data/Application"
            target = base / "shortcuts"
            target.mkdir(parents=True)
            with patch.object(Path, "home", return_value=home):
                with self.assertRaisesRegex(RuntimeError, "METADATA_NOT_UNIQUE"):
                    probe.find_owned_shortcuts_data_container("owned")
                (target / ".com.apple.mobile_container_manager.metadata.plist").write_bytes(
                    b"<?xml version='1.0'?><plist>broken-private-structure")
                with self.assertRaisesRegex(RuntimeError, "METADATA_UNCONFIRMED"):
                    probe.find_owned_shortcuts_data_container("owned")

    def test_fixture_metadata_has_entry_and_time_budgets(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            base = home / "Library/Developer/CoreSimulator/Devices/owned/data/Containers/Data/Application"
            (base / "one").mkdir(parents=True)
            with patch.object(Path, "home", return_value=home), \
                    patch.object(probe.time, "monotonic", side_effect=[0, 6]):
                with self.assertRaisesRegex(RuntimeError, "METADATA_BUDGET"):
                    probe.find_owned_shortcuts_data_container("owned")
            for index in range(256):
                (base / f"extra-{index}").mkdir()
            with patch.object(Path, "home", return_value=home), \
                    patch.object(probe.time, "monotonic", return_value=0):
                with self.assertRaisesRegex(RuntimeError, "METADATA_LIMIT"):
                    probe.find_owned_shortcuts_data_container("owned")

    def test_fixture_metadata_refuses_symlink_to_external_container(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            base = home / "Library/Developer/CoreSimulator/Devices/owned/data/Containers/Data/Application"
            base.mkdir(parents=True)
            outside = home / "outside"
            outside.mkdir()
            (outside / ".com.apple.mobile_container_manager.metadata.plist").write_bytes(
                plistlib.dumps({"MCMMetadataIdentifier": "com.apple.shortcuts"}))
            try:
                probe.os.symlink(outside, base / "alias", target_is_directory=True)
            except OSError as error:
                self.skipTest("symlink permission unavailable: " + type(error).__name__)
            with patch.object(Path, "home", return_value=home):
                with self.assertRaisesRegex(RuntimeError, "METADATA_SYMLINK"):
                    probe.find_owned_shortcuts_data_container("owned")

    def test_fixture_metadata_refuses_oversized_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            target = home / "Library/Developer/CoreSimulator/Devices/owned/data/Containers/Data/Application/shortcuts"
            target.mkdir(parents=True)
            (target / ".com.apple.mobile_container_manager.metadata.plist").write_bytes(b"x" * 65537)
            with patch.object(Path, "home", return_value=home):
                with self.assertRaisesRegex(RuntimeError, "METADATA_TOO_LARGE"):
                    probe.find_owned_shortcuts_data_container("owned")

    @unittest.skipUnless(hasattr(probe.os, "O_NOFOLLOW"), "O_NOFOLLOW is required on native Mac runner")
    def test_fixture_metadata_replacement_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            target = home / "Library/Developer/CoreSimulator/Devices/owned/data/Containers/Data/Application/shortcuts"
            target.mkdir(parents=True)
            metadata = target / ".com.apple.mobile_container_manager.metadata.plist"
            metadata.write_bytes(plistlib.dumps({"MCMMetadataIdentifier": "com.apple.shortcuts"}))
            outside = home / "external-private-file"
            outside.write_bytes(b"PRIVATE_SENTINEL_MUST_NOT_BE_READ")
            original_open = probe.os.open

            def replace_before_open(path, *args, **kwargs):
                metadata.unlink()
                probe.os.symlink(outside, metadata)
                return original_open(path, *args, **kwargs)

            with patch.object(Path, "home", return_value=home), \
                    patch.object(probe.os, "open", new=replace_before_open):
                with self.assertRaisesRegex(RuntimeError, "METADATA_UNCONFIRMED"):
                    probe.find_owned_shortcuts_data_container("owned")

    def test_optional_group_rpc_timeout_preserves_schema_result(self):
        with patch.object(probe, "command", side_effect=probe.subprocess.TimeoutExpired([], 10)):
            result = probe.collect_shortcuts_group_metadata("owned")
        self.assertEqual(result["status"], "GROUP_METADATA_NATIVE_COMMAND_UNCONFIRMED")
        self.assertFalse(result["group_store_read"])

    def test_group_metadata_requires_help_and_never_retains_external_paths(self):
        absent_help = probe.subprocess.CompletedProcess([], 0, b"app data", b"")
        with patch.object(probe, "command", return_value=absent_help) as command:
            self.assertEqual(probe.collect_shortcuts_group_metadata("owned")["status"],
                             "GROUPS_NOT_IN_NATIVE_HELP")
            self.assertEqual(command.call_count, 1)
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / "Library/Developer/CoreSimulator/Devices/owned/data").mkdir(parents=True)
            outside = home / "outside"
            (home / "Library/Developer/CoreSimulator/Devices/owned/data/Containers/Shared/AppGroup").mkdir(parents=True)
            outside.mkdir()
            help_result = probe.subprocess.CompletedProcess([], 0, b"app data groups", b"")
            paths = probe.subprocess.CompletedProcess([], 0,
                json.dumps([str(outside)]).encode(), b"")
            with patch.object(Path, "home", return_value=home), \
                    patch.object(probe, "ARTIFACTS", home), \
                    patch.object(probe, "command", side_effect=[help_result, paths]):
                result = probe.collect_shortcuts_group_metadata("owned")
            self.assertEqual(result, {"status": "GROUP_METADATA_PATH_ESCAPE", "group_store_read": False})
            self.assertNotIn(str(outside), json.dumps(result))

    def test_owned_group_metadata_is_relative_and_reads_only_schema(self):
        import native_store_schema
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            container = home / "Library/Developer/CoreSimulator/Devices/owned/data/Containers/Shared/AppGroup/synthetic"
            container.mkdir(parents=True)
            help_result = probe.subprocess.CompletedProcess([], 0, b"app data groups", b"")
            paths = probe.subprocess.CompletedProcess([], 0,
                json.dumps([str(container)]).encode(), b"")
            with patch.object(Path, "home", return_value=home), \
                    patch.object(probe, "ARTIFACTS", home), \
                    patch.object(native_store_schema, "survey_shortcuts_schema",
                                 return_value={"databases": [], "schema_only": True}) as survey, \
                    patch.object(probe, "command", side_effect=[help_result, paths]):
                result = probe.collect_shortcuts_group_metadata("owned")
            self.assertEqual(result["groups"], 1)
            self.assertFalse(result["group_rows_read"])
            self.assertFalse(result["database_copy"])
            survey.assert_called_once_with(container.resolve(), include_inventory=False)
            retained = (home / "native-group-store-schema.json").read_text(encoding="utf-8")
            self.assertIn("Containers/Shared/AppGroup/synthetic", retained)
            self.assertNotIn(str(home), retained)
            self.assertNotIn(str(home), (home / "native-groups-shape.json").read_text(encoding="utf-8"))

    def test_declared_group_identifier_is_resolved_only_by_native_api(self):
        import native_store_schema
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            container = home / "Library/Developer/CoreSimulator/Devices/owned/data/Containers/Shared/AppGroup/synthetic"
            container.mkdir(parents=True)
            responses = [probe.subprocess.CompletedProcess([], 0, b"app data groups", b""),
                         probe.subprocess.CompletedProcess([], 0, b"group.com.apple.shortcuts", b""),
                         probe.subprocess.CompletedProcess([], 0, str(container).encode(), b"")]
            with patch.object(Path, "home", return_value=home), \
                    patch.object(probe, "ARTIFACTS", home), \
                    patch.object(native_store_schema, "survey_shortcuts_schema",
                                 return_value={"databases": [], "schema_only": True}) as survey, \
                    patch.object(probe, "command", side_effect=responses) as command:
                result = probe.collect_shortcuts_group_metadata("owned")
            self.assertEqual(result["status"], "GROUP_STORE_SCHEMA_ONLY")
            self.assertEqual(command.call_args_list[-1].args[0][-1], "group.com.apple.shortcuts")
            survey.assert_called_once_with(container.resolve(), include_inventory=True)

    def test_tips_group_is_not_surveyed_and_workflow_inventory_is_opt_in(self):
        import native_store_schema
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            group_root = home / "Library/Developer/CoreSimulator/Devices/owned/data/Containers/Shared/AppGroup"
            workflow, tips = group_root / "workflow", group_root / "tips"
            workflow.mkdir(parents=True)
            tips.mkdir()
            responses = [probe.subprocess.CompletedProcess([], 0, b"app data groups", b""),
                         probe.subprocess.CompletedProcess([], 0, b'["group.com.apple.shortcuts", "group.com.apple.tipsnext"]', b""),
                         probe.subprocess.CompletedProcess([], 0, str(workflow).encode(), b""),
                         probe.subprocess.CompletedProcess([], 0, str(tips).encode(), b"")]
            with patch.object(Path, "home", return_value=home), \
                    patch.object(probe, "ARTIFACTS", home), \
                    patch.object(native_store_schema, "survey_shortcuts_schema",
                                 return_value={"databases": [], "schema_only": True, "file_inventory": []}) as survey, \
                    patch.object(probe, "command", side_effect=responses):
                result = probe.collect_shortcuts_group_metadata("owned")
            survey.assert_called_once_with(workflow.resolve(), include_inventory=True)
            self.assertEqual(result["excluded_group_roles"], 1)
            self.assertEqual(result["associated_groups"], 2)
            self.assertEqual(result["groups"], 1)
            retained = (home / "native-group-store-schema.json").read_text(encoding="utf-8")
            self.assertNotIn("tips", retained)

    def test_unknown_group_format_is_retained_sanitized_without_store_access(self):
        import native_store_schema
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / "Library/Developer/CoreSimulator/Devices/owned/data").mkdir(parents=True)
            unknown = json.dumps({"unknown": str(home / "private")}).encode()
            responses = [probe.subprocess.CompletedProcess([], 0, b"app data groups", b""),
                         probe.subprocess.CompletedProcess([], 0, unknown, b"")]
            with patch.object(Path, "home", return_value=home), \
                    patch.object(probe, "ARTIFACTS", home), \
                    patch.object(native_store_schema, "survey_shortcuts_schema") as survey, \
                    patch.object(probe, "command", side_effect=responses):
                result = probe.collect_shortcuts_group_metadata("owned")
            self.assertEqual(result["status"], "GROUP_METADATA_SHAPE_UNCONFIRMED")
            survey.assert_not_called()
            retained = (home / "native-groups-shape.json").read_text(encoding="utf-8")
            self.assertNotIn(str(home), retained)
            self.assertNotIn("unknown", retained)
            self.assertIn("absolute_path", retained)

    def test_group_shape_never_retains_unknown_text_or_paths(self):
        for raw in (b"PRIVATE_SENTINEL_NOT_A_PATH", b"group.synthetic: /private/SENTINEL", 
                    b'{"PRIVATE_SENTINEL": "PRIVATE_VALUE"}'):
            retained = json.dumps(probe.native_group_output_shape(raw))
            self.assertNotIn("PRIVATE", retained)
            self.assertNotIn("SENTINEL", retained)
            self.assertNotIn("synthetic", retained)

    def test_group_schema_failure_is_not_reported_as_observed(self):
        import native_store_schema
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            container = home / "Library/Developer/CoreSimulator/Devices/owned/data/Containers/Shared/AppGroup/synthetic"
            container.mkdir(parents=True)
            responses = [probe.subprocess.CompletedProcess([], 0, b"app data groups", b""),
                         probe.subprocess.CompletedProcess([], 0, json.dumps([str(container)]).encode(), b"")]
            with patch.object(Path, "home", return_value=home), \
                    patch.object(probe, "ARTIFACTS", home), \
                    patch.object(native_store_schema, "survey_shortcuts_schema",
                                 side_effect=native_store_schema.NativeStoreSchemaError("CONTAINER_UNREADABLE")), \
                    patch.object(probe, "command", side_effect=responses):
                result = probe.collect_shortcuts_group_metadata("owned")
            self.assertEqual(result["status"], "GROUP_STORE_SCHEMA_PARTIAL_UNCONFIRMED")
            self.assertEqual(result["surveyed_ok"], 0)
            self.assertEqual(result["failed"], 1)
            self.assertFalse(result["group_schema_read"])

    def test_mixed_group_surveys_are_partial_not_all_observed(self):
        import native_store_schema
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            group_root = home / "Library/Developer/CoreSimulator/Devices/owned/data/Containers/Shared/AppGroup"
            containers = [group_root / "one", group_root / "two"]
            for container in containers:
                container.mkdir(parents=True)
            responses = [probe.subprocess.CompletedProcess([], 0, b"app data groups", b""),
                         probe.subprocess.CompletedProcess([], 0, json.dumps([str(path) for path in containers]).encode(), b"")]
            with patch.object(Path, "home", return_value=home), \
                    patch.object(probe, "ARTIFACTS", home), \
                    patch.object(native_store_schema, "survey_shortcuts_schema", side_effect=[
                        {"databases": [], "schema_only": True},
                        native_store_schema.NativeStoreSchemaError("CONTAINER_UNREADABLE")]), \
                    patch.object(probe, "command", side_effect=responses):
                result = probe.collect_shortcuts_group_metadata("owned")
            self.assertEqual(result["status"], "GROUP_STORE_SCHEMA_PARTIAL_UNCONFIRMED")
            self.assertEqual((result["surveyed_ok"], result["failed"]), (1, 1))
            self.assertFalse(result["group_schema_read"])

    def test_schema_reader_rejects_container_outside_fresh_device(self):
        with patch.object(probe, "find_owned_shortcuts_data_container",
                          side_effect=RuntimeError("OWN_CONTAINER_METADATA_ESCAPE")), \
                patch.object(probe, "command") as command:
            with self.assertRaisesRegex(RuntimeError, "OWN_CONTAINER_METADATA_ESCAPE"):
                probe.survey_native_schema("owned")
            command.assert_not_called()

    def test_every_collector_failure_has_a_sanitized_code(self):
        import ast
        import native_artifact
        tree = ast.parse(Path(native_artifact.__file__).read_text(encoding="utf-8"))
        errors = [node.args[0].value for node in ast.walk(tree)
                  if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                  and node.func.id == "ShortcutArtifactError"
                  and node.args and isinstance(node.args[0], ast.Constant)]
        self.assertTrue(errors)
        for message in errors:
            with self.subTest(message=message):
                error = ("private detail\nnative_artifact.ShortcutArtifactError: " + message).encode()
                self.assertNotEqual(probe.native_artifact_failure_code(error),
                                    "COLLECTOR_FAILED_UNKNOWN")

    def test_collection_passes_run_boundary_to_subprocess(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            container = home / "Library/Developer/CoreSimulator/Devices/owned/data/Container"
            container.mkdir(parents=True)
            artifacts = home / "artifacts"
            artifacts.mkdir()
            (artifacts / "synthetic.shortcut.receipt.json").write_text("{}", encoding="utf-8")
            resolved = probe.subprocess.CompletedProcess([], 0, str(container).encode(), b"")
            collected = probe.subprocess.CompletedProcess([], 0, b"", b"")
            with patch.object(Path, "home", return_value=home), \
                    patch.object(probe, "ARTIFACTS", artifacts), \
                    patch.object(probe, "command", side_effect=[resolved, collected]) as command:
                self.assertEqual(probe.collect_native_export("owned", 123456789), {})
            invocation = command.call_args.args[0]
            self.assertEqual(invocation[-1], "123456789")
            self.assertIn("not_before_ns=int(sys.argv[3])", invocation[2])

    def test_collector_failure_retains_only_allowlisted_code(self):
        self.assertEqual(probe.native_artifact_failure_code(
            b"private diagnostic\nnative_artifact.ShortcutArtifactError: no .shortcut file found in container"),
            "NO_NATIVE_FILE")
        self.assertEqual(probe.native_artifact_failure_code(
            b"private diagnostic\nnative_artifact.ShortcutArtifactError: symlinks are not permitted in container"),
            "CONTAINER_HAS_SYMLINK")
        self.assertEqual(probe.native_artifact_failure_code(b"unexpected private diagnostic"),
                         "COLLECTOR_FAILED_UNKNOWN")

    def test_external_container_never_reaches_collector(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            own = home / "Library/Developer/CoreSimulator/Devices/owned/data"
            own.mkdir(parents=True)
            outside = home / "outside"
            outside.mkdir()
            result = probe.subprocess.CompletedProcess([], 0, str(outside).encode(), b"")
            with patch.object(Path, "home", return_value=home), \
                    patch.object(probe, "command", return_value=result) as command:
                with self.assertRaisesRegex(RuntimeError, "OUTSIDE_OWN_SIMULATOR"):
                    probe.collect_native_export("owned", 1)
                self.assertEqual(command.call_count, 1)

    def test_missing_container_is_sanitized(self):
        result = probe.subprocess.CompletedProcess([], 0, b"/missing-synthetic-container", b"")
        with patch.object(probe, "command", return_value=result) as command:
            with self.assertRaisesRegex(RuntimeError, "NATIVE_EXPORT_CONTAINER_UNCONFIRMED"):
                probe.collect_native_export("owned", 1)
            self.assertEqual(command.call_count, 1)


class SelectionTests(unittest.TestCase):
    def setUp(self):
        mode = patch.dict(probe.os.environ, {"SHORTCUTS_PROBE_EXECUTION_MODE": "open-handles"})
        mode.start()
        self.addCleanup(mode.stop)
        timeout_probe = patch.object(probe, "native_timeout_probe", return_value={
            "wrapper_return_bounded_with_descendant_present": True,
            "descendant_marker_seen": True, "seconds": 1.0})
        timeout_probe.start()
        self.addCleanup(timeout_probe.stop)
        schema_probe = patch.object(probe, "survey_native_schema", return_value={
            "scope": "schema_only_no_rows_no_database_copy", "sqlite_files": 0,
            "condition_payload_proven": False})
        self.schema_probe = schema_probe.start()
        self.addCleanup(schema_probe.stop)
        groups_probe = patch.object(probe, "collect_shortcuts_group_metadata", return_value={
            "status": "GROUP_PATH_METADATA_ONLY", "groups": {}, "group_store_read": False})
        self.groups_probe = groups_probe.start()
        self.addCleanup(groups_probe.stop)
        entitlements_probe = patch.object(probe, "collect_native_entitlement_metadata", return_value={
            "status": "SYSTEM_GROUP_ENTITLEMENT_NOT_DECLARED", "system_store_read": False})
        self.entitlements_probe = entitlements_probe.start()
        self.addCleanup(entitlements_probe.stop)
        open_probe = patch.object(probe, "collect_native_open_files", return_value={
            "status": "OPEN_HANDLE_PATH_METADATA_OBSERVED", "observed_paths": 1,
            "open_handle_contents_read": False, "condition_payload_proven": False})
        self.open_probe = open_probe.start()
        self.addCleanup(open_probe.stop)
        self.runtimes = {"runtimes": [{"isAvailable": True, "version": "27.0",
                         "identifier": "com.apple.CoreSimulator.SimRuntime.iOS-27-0"}]}
        self.types = {"devicetypes": [{"name": "iPhone Test", "identifier": "test.iphone",
                                      "productFamily": "iPhone"}]}
        self.devices = {"devices": {"com.apple.CoreSimulator.SimRuntime.iOS-27-0": [
            {"name": "iPhone Test", "isAvailable": True}]}}

    def test_selects_only_existing_compatible_template(self):
        self.assertEqual(probe.choose_device(self.runtimes, self.devices, self.types),
                         ("com.apple.CoreSimulator.SimRuntime.iOS-27-0", "test.iphone"))

    def test_prebuilt_session_mode_still_never_uses_native_ui_or_store(self):
        identifier = "ABCDEF01-2345-6789-ABCD-EF0123456789"
        for status, expected in (("APPIUM_PREBUILT_SESSION_READY_ONLY", 0), ("APPIUM_SESSION_READY_ONLY", 1)):
            seen = []

            def fake_command(args, **kwargs):
                seen.append(args)
                return probe.subprocess.CompletedProcess(args, 0,
                    identifier.encode() if args[1:3] == ["simctl", "create"] else b"", b"")

            def fake_session(device_id, *, prepare_device, prebuild_wda):
                self.assertTrue(prebuild_wda)
                seen.append(["BUILD_AND_HOST_READY"])
                self.assertEqual(prepare_device(), identifier)
                return {"status": status}

            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory, \
                    patch.object(probe, "ARTIFACTS", Path(directory) / "artifacts"), \
                    patch.object(probe.sys, "platform", "darwin"), \
                    patch.dict(probe.os.environ, {"GITHUB_ACTIONS": "true",
                               "SHORTCUTS_PROBE_EXECUTION_MODE": "appium-prebuilt-session-preflight"}), \
                    patch.object(probe, "sim_json", side_effect=[self.runtimes, self.devices, self.types]), \
                    patch.object(probe, "command", side_effect=fake_command), \
                    patch.object(probe, "appium_session_preflight", side_effect=fake_session), \
                    patch.object(probe, "native_timeout_probe") as timeout_probe, patch("builtins.print"):
                self.assertEqual(probe.main(), expected)
                self.open_probe.assert_not_called()
                self.schema_probe.assert_not_called()
                timeout_probe.assert_not_called()
                self.assertLess(seen.index(["BUILD_AND_HOST_READY"]), next(
                    i for i, args in enumerate(seen) if args[1:3] == ["simctl", "create"]))
                self.assertEqual(seen.count(["xcrun", "simctl", "shutdown", identifier]), 1)
                self.assertEqual(seen.count(["xcrun", "simctl", "delete", identifier]), 1)
                receipt = json.loads((probe.ARTIFACTS / "receipt.json").read_text())
                self.assertTrue(receipt["prebuilt_wda_mode"])
                self.assertFalse(receipt["native_probe_xcode_test_suite_run"])
                self.assertFalse(receipt["ui_gestures_run"])
                self.assertFalse(receipt["page_source_read"])
                self.assertFalse(receipt["store_read"])
                self.assertFalse(receipt["otp_proven"])

    def test_prebuilt_requires_both_host_build_and_effective_caps_without_private_paths(self):
        good_build = {"build_exit": 0, "runner_bundle_verified": True,
                      "xctestrun_verified": True, "simulator_state_unchanged": True}
        good_session = {"stage": "session_only_completed", "session_initialized": True, "idle0": True,
                        "cleanup_unconfirmed": False, "failure_code": None,
                        "prebuilt_wda_requested": True, "prebuilt_wda_verified": True}
        cases = [(dict(good_build), dict(good_session), True, 0)]
        for key in ("runner_bundle_verified", "xctestrun_verified", "simulator_state_unchanged"):
            cases.append((dict(good_build, **{key: False}), dict(good_session), True, 1))
        cases.append((dict(good_build, build_exit=False), dict(good_session), True, 1))
        cases.append((dict(good_build), dict(good_session), False, 1))
        for key in ("prebuilt_wda_requested", "prebuilt_wda_verified"):
            cases.append((dict(good_build), dict(good_session, **{key: False}), True, 1))
        options = {"derived_data_path": "/private/SENTINEL_PRIVATE_DERIVED"}
        for build, session, cleanup, failed in cases:
            events = []

            def host(command, env, callback):
                events.append("compiled_host_ready")
                callback("http://127.0.0.1:1234", options)
                events.append("host_cleanup")
                return {"wda_build": build, "cleanup_exited": cleanup}

            def prepare():
                events.append("boot")
                return "own"

            with self.subTest(build=build, session=session, cleanup=cleanup), \
                    patch("appium_host_preflight.run_appium_with_prebuilt_owned_server", create=True, side_effect=host), \
                    patch("appium_host_preflight.run_appium_with_owned_server") as old_host, \
                    patch("appium_synthetic_ui.run_synthetic_appium_fixture", return_value=session) as client, \
                    patch.object(probe, "DEADLINE", None):
                result = probe.appium_session_preflight(None, prepare_device=prepare, prebuild_wda=True)
                old_host.assert_not_called()
                client.assert_called_once_with("http://127.0.0.1:1234", "own", mode="session-only", prebuilt_wda=options)
                self.assertEqual(events, ["compiled_host_ready", "boot", "host_cleanup"])
                self.assertNotIn("SENTINEL", json.dumps(result))
                self.assertTrue(result["host_prebuilt_before_device_preparation"])
                self.assertEqual(result["status"], "APPIUM_SESSION_UNCONFIRMED" if failed else "APPIUM_PREBUILT_SESSION_READY_ONLY")

    def test_prebuilt_build_failure_never_prepares_device_or_creates_session(self):
        from appium_host_preflight import AppiumHostPreflightError
        error = AppiumHostPreflightError("HOST_WDA_BUILD", cleanup_exited=True, build_exit=70,
                                        build_failure_category="destination_not_supported")
        with patch("appium_host_preflight.run_appium_with_prebuilt_owned_server", create=True, side_effect=error), \
                patch("appium_synthetic_ui.run_synthetic_appium_fixture") as client, patch.object(probe, "DEADLINE", None):
            prepare = MagicMock()
            result = probe.appium_session_preflight(None, prepare_device=prepare, prebuild_wda=True)
            prepare.assert_not_called()
            client.assert_not_called()
            self.assertEqual(result["status"], "HOST_WDA_BUILD")
            self.assertEqual(result["wda_build_failure"], {"build_exit": 70, "build_failure_category": "destination_not_supported"})

    def test_prebuilt_missing_private_options_never_boots_or_posts(self):
        for options in (None, {}, {"derived_data_path": None}, {"derived_data_path": ""},
                        {"derived_data_path": "/private/own", "udid": "other"}):
            def host(command, env, callback):
                callback("http://127.0.0.1:1234", options)
                return {"cleanup_exited": True}

            with self.subTest(options=options), \
                    patch("appium_host_preflight.run_appium_with_prebuilt_owned_server", create=True, side_effect=host), \
                    patch("appium_synthetic_ui.run_synthetic_appium_fixture") as client, patch.object(probe, "DEADLINE", None):
                prepare = MagicMock()
                result = probe.appium_session_preflight(None, prepare_device=prepare, prebuild_wda=True)
                prepare.assert_not_called()
                client.assert_not_called()
                self.assertEqual(result["session"]["failure_code"], "prebuilt_wda_input_unconfirmed")
                self.assertEqual(result["status"], "APPIUM_SESSION_UNCONFIRMED")

    def test_appium_session_mode_never_uses_native_ui_or_store_reader(self):
        identifier = "ABCDEF01-2345-6789-ABCD-EF0123456789"
        for status, failure_action, cleanup_failure, expected in (
                ("APPIUM_SESSION_READY_ONLY", None, None, 0),
                ("APPIUM_SESSION_UNCONFIRMED", None, None, 1),
                ("APPIUM_SESSION_READY_ONLY", "shutdown", "timeout", 1),
                ("APPIUM_SESSION_READY_ONLY", "shutdown", "nonzero", 1),
                ("APPIUM_SESSION_READY_ONLY", "delete", "nonzero", 1),
                ("APPIUM_SESSION_UNCONFIRMED", "delete", "nonzero", 1)):
            seen = []

            def fake_command(args, **kwargs):
                seen.append(args)
                if failure_action is not None and args[1:3] == ["simctl", failure_action]:
                    if cleanup_failure == "timeout":
                        raise probe.subprocess.TimeoutExpired("owned-cleanup", 30)
                    return probe.subprocess.CompletedProcess(args, 1, b"", b"")
                stdout = identifier.encode() if args[1:3] == ["simctl", "create"] else b""
                return probe.subprocess.CompletedProcess(args, 0, stdout, b"")

            def fake_session(device_id, *, prepare_device):
                self.assertIsNone(device_id)
                seen.append(["HOST_READY_BEFORE_BOOT"])
                self.assertEqual(prepare_device(), identifier)
                return {"status": status}

            with self.subTest(status=status, action=failure_action, failure=cleanup_failure), tempfile.TemporaryDirectory() as directory, \
                    patch.object(probe, "ARTIFACTS", Path(directory) / "artifacts"), \
                    patch.object(probe.sys, "platform", "darwin"), \
                    patch.dict(probe.os.environ, {"GITHUB_ACTIONS": "true",
                               "SHORTCUTS_PROBE_EXECUTION_MODE": "appium-session-preflight"}), \
                    patch.object(probe, "sim_json", side_effect=[self.runtimes, self.devices, self.types]), \
                    patch.object(probe, "command", side_effect=fake_command), \
                    patch.object(probe, "appium_session_preflight", side_effect=fake_session) as session, \
                    patch.object(probe, "native_timeout_probe") as timeout_probe, patch("builtins.print"):
                self.open_probe.reset_mock()
                self.assertEqual(probe.main(), expected)
                session.assert_called_once()
                self.assertIsNone(session.call_args.args[0])
                self.assertTrue(callable(session.call_args.kwargs["prepare_device"]))
                self.open_probe.assert_not_called()
                timeout_probe.assert_not_called()
                self.schema_probe.assert_not_called()
                self.assertTrue(all(args[0] != "xcodebuild" for args in seen))
                self.assertLess(seen.index(["HOST_READY_BEFORE_BOOT"]), next(
                    i for i, args in enumerate(seen) if args[1:3] == ["simctl", "create"]))
                self.assertEqual(seen.count(["xcrun", "simctl", "shutdown", identifier]), 1)
                self.assertEqual(seen.count(["xcrun", "simctl", "delete", identifier]), 1)
                receipt = json.loads((probe.ARTIFACTS / "receipt.json").read_text())
                self.assertEqual(receipt["scope"], "fresh_account_free_session_only")
                self.assertFalse(receipt["ui_gestures_run"])
                self.assertFalse(receipt["xcode_test_suite_run"])
                self.assertFalse(receipt["page_source_read"])
                self.assertFalse(receipt["store_read"])
                self.assertFalse(receipt["message_access"])
                self.assertFalse(receipt["otp_proven"])
                if failure_action is not None:
                    self.assertEqual(receipt["failure"], "SIMULATOR_CLEANUP_UNCONFIRMED")
                    self.assertEqual(receipt["status_before_simulator_cleanup"], status)
                    self.assertEqual(receipt["appium_preflight"]["status"], status)
                    self.assertTrue(receipt["cleanup_errors"])

    def test_appium_host_failure_never_creates_or_boots_a_simulator(self):
        from appium_host_preflight import AppiumHostPreflightError
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(probe, "ARTIFACTS", Path(directory) / "artifacts"), \
                patch.object(probe.sys, "platform", "darwin"), \
                patch.dict(probe.os.environ, {"GITHUB_ACTIONS": "true",
                           "SHORTCUTS_PROBE_EXECUTION_MODE": "appium-session-preflight"}), \
                patch.object(probe, "sim_json", side_effect=[self.runtimes, self.devices, self.types]), \
                patch("appium_host_preflight.run_appium_with_owned_server", side_effect=AppiumHostPreflightError("HOST_PREFLIGHT_NPM_COMMAND")), \
                patch("appium_synthetic_ui.run_synthetic_appium_fixture") as client, \
                patch.object(probe, "command") as command, patch("builtins.print"):
            self.assertEqual(probe.main(), 1)
            command.assert_not_called()
            client.assert_not_called()
            receipt = json.loads((probe.ARTIFACTS / "receipt.json").read_text())
            self.assertFalse(receipt["simulator_started"])
            self.assertEqual(receipt["cleanup_errors"], [])
            self.assertEqual(receipt["failure"], "HOST_PREFLIGHT_NPM_COMMAND")

    def test_session_preflight_prepares_device_only_inside_ready_server_callback(self):
        events = []

        def prepare():
            events.append("own_create_boot")
            return "own-uuid"

        def owned(command, env, callback):
            events.append("host_ready")
            callback("http://127.0.0.1:1234")
            events.append("host_cleanup")
            return {"cleanup_exited": True}

        def session(url, identifier, *, mode):
            self.assertEqual(identifier, "own-uuid")
            self.assertEqual(mode, "session-only")
            events.append("session")
            return {"stage": "session_only_completed", "failure_code": None,
                    "session_initialized": True, "idle0": True, "cleanup_unconfirmed": False}

        with patch("appium_host_preflight.run_appium_with_owned_server", side_effect=owned), \
                patch("appium_synthetic_ui.run_synthetic_appium_fixture", side_effect=session), \
                patch.object(probe, "DEADLINE", None):
            result = probe.appium_session_preflight(None, prepare_device=prepare)
        self.assertEqual(events, ["host_ready", "own_create_boot", "session", "host_cleanup"])
        self.assertTrue(result["host_ready_before_device_preparation"])
        self.assertTrue(result["device_preparation_completed"])
        self.assertEqual(result["status"], "APPIUM_SESSION_READY_ONLY")

    def test_device_preparation_failure_never_creates_session_but_stops_server(self):
        cleaned = []

        def owned(command, env, callback):
            callback("http://127.0.0.1:1234")
            cleaned.append(True)
            return {"cleanup_exited": True}

        with patch("appium_host_preflight.run_appium_with_owned_server", side_effect=owned), \
                patch("appium_synthetic_ui.run_synthetic_appium_fixture") as client, \
                patch.object(probe, "DEADLINE", None):
            result = probe.appium_session_preflight(None, prepare_device=MagicMock(
                side_effect=probe.subprocess.TimeoutExpired("own-boot", 300)))
        client.assert_not_called()
        self.assertEqual(cleaned, [True])
        self.assertEqual(result["session"]["failure_code"], "simulator_preparation_unconfirmed")
        self.assertEqual(result["status"], "APPIUM_SESSION_UNCONFIRMED")

    def test_session_preflight_requires_effective_gates_and_independent_cleanup(self):
        clean = {"stage": "session_only_completed", "session_initialized": True, "idle0": True,
                 "cleanup_unconfirmed": False, "failure_code": None}

        def owned(command, env, callback):
            callback("http://127.0.0.1:1234")
            return {"cleanup_exited": True}

        for changes, expected in (({}, "APPIUM_SESSION_READY_ONLY"),
                                  ({"stage": "completed"}, "APPIUM_SESSION_UNCONFIRMED"),
                                  ({"session_initialized": False}, "APPIUM_SESSION_UNCONFIRMED"),
                                  ({"idle0": False}, "APPIUM_SESSION_UNCONFIRMED"),
                                  ({"cleanup_unconfirmed": True}, "APPIUM_SESSION_UNCONFIRMED"),
                                  ({"failure_code": "session_creation_ambiguous"}, "APPIUM_SESSION_UNCONFIRMED")):
            with self.subTest(changes=changes), \
                    patch("appium_host_preflight.run_appium_with_owned_server", side_effect=owned), \
                    patch("appium_synthetic_ui.run_synthetic_appium_fixture", return_value=dict(clean, **changes)) as client, \
                    patch.object(probe, "DEADLINE", None):
                result = probe.appium_session_preflight("owned")
                self.assertEqual(result["status"], expected)
                client.assert_called_once_with("http://127.0.0.1:1234", "owned", mode="session-only")
                self.assertFalse(result["library_read"])
                self.assertFalse(result["ui_gestures_run"])

    def test_session_preflight_retains_session_when_host_cleanup_fails(self):
        from appium_host_preflight import AppiumHostPreflightError

        def owned(command, env, callback):
            callback("http://127.0.0.1:1234")
            raise AppiumHostPreflightError("HOST_PREFLIGHT_CLEANUP_UNCONFIRMED", cleanup_exited=False,
                                          temporary_retained=True, primary_code="HOST_PREFLIGHT_CALLBACK_UNCONFIRMED")

        with patch("appium_host_preflight.run_appium_with_owned_server", side_effect=owned), \
                patch("appium_synthetic_ui.run_synthetic_appium_fixture", return_value={"failure_code": "session_creation_ambiguous"}), \
                patch.object(probe, "DEADLINE", None):
            result = probe.appium_session_preflight("owned")
        self.assertEqual(result["session"]["failure_code"], "session_creation_ambiguous")
        self.assertFalse(result["cleanup_exited"])
        self.assertTrue(result["temporary_retained"])
        self.assertEqual(result["status"], "HOST_PREFLIGHT_CLEANUP_UNCONFIRMED")

    def test_session_preflight_will_not_post_when_global_budget_insufficient(self):
        def owned(command, env, callback):
            callback("http://127.0.0.1:1234")
            return {"cleanup_exited": True}

        with patch("appium_host_preflight.run_appium_with_owned_server", side_effect=owned), \
                patch("appium_synthetic_ui.run_synthetic_appium_fixture") as client, \
                patch.object(probe, "DEADLINE", 300), patch.object(probe.time, "monotonic", return_value=100):
            result = probe.appium_session_preflight("owned")
        client.assert_not_called()
        self.assertEqual(result["session"]["failure_code"], "session_budget_exhausted")
        self.assertEqual(result["status"], "APPIUM_SESSION_UNCONFIRMED")

    def test_unavailable_runtime_rejected(self):
        self.runtimes["runtimes"][0]["isAvailable"] = False
        with self.assertRaisesRegex(RuntimeError, "TEMPLATE_ABSENT"):
            probe.choose_device(self.runtimes, self.devices, self.types)

    def test_older_runtime_not_substituted(self):
        self.runtimes["runtimes"][0]["version"] = "26.0"
        with self.assertRaisesRegex(RuntimeError, "TEMPLATE_ABSENT"):
            probe.choose_device(self.runtimes, self.devices, self.types)

    def test_unknown_device_not_guessed(self):
        self.types["devicetypes"][0]["name"] = "Different iPhone"
        with self.assertRaisesRegex(RuntimeError, "TEMPLATE_ABSENT"):
            probe.choose_device(self.runtimes, self.devices, self.types)

    def test_refuses_non_runner_without_subprocess(self):
        with patch.dict(probe.os.environ, {"GITHUB_ACTIONS": "false"}), \
                patch.object(probe, "command") as command:
            with self.assertRaisesRegex(RuntimeError, "RUNNER_REQUIRED"):
                probe.main()
            command.assert_not_called()

    def test_cleanup_timeout_does_not_discard_result(self):
        with patch.object(probe, "command", side_effect=[
                probe.subprocess.TimeoutExpired("shutdown", 30),
                probe.subprocess.CompletedProcess([], 0)]) as command:
            self.assertEqual(probe.cleanup_device("synthetic-id"),
                             ["shutdown:cleanup_unconfirmed"])
            self.assertEqual(command.call_count, 2)

    def test_project_and_scheme_invoked_exist(self):
        self.assertTrue((probe.ROOT / "AppleSimulatorProbe.xcodeproj").is_dir())
        self.assertTrue((probe.ROOT / "AppleSimulatorProbe.xcodeproj" / "xcshareddata" /
                         "xcschemes" / "AppleSimulatorProbe.xcscheme").is_file())

    def test_schema_requires_synthetic_fixture_marker_before_reading_store(self):
        identifier = "ABCDEF01-2345-6789-ABCD-EF0123456789"

        def fake_command(args, **kwargs):
            stdout = identifier.encode() if args[1:3] == ["simctl", "create"] else b""
            return probe.subprocess.CompletedProcess(args, 0, stdout, b"")

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(probe, "ROOT", Path(directory) / "probe"), \
                patch.object(probe, "ARTIFACTS", Path(directory) / "artifacts"), \
                patch.object(probe.sys, "platform", "darwin"), \
                patch.dict(probe.os.environ, {"GITHUB_ACTIONS": "true"}), \
                patch.object(probe, "sim_json", side_effect=[self.runtimes, self.devices, self.types]), \
                patch.object(probe, "command", side_effect=fake_command), patch("builtins.print"):
            self.assertEqual(probe.main(), 1)
            self.schema_probe.assert_not_called()
            receipt = json.loads((probe.ARTIFACTS / "receipt.json").read_text())
            self.assertEqual(receipt["failure"], "SYNTHETIC_FILTER_STATE_UNCONFIRMED")
            self.assertFalse(receipt["otp_proven"])

    def test_device_id_preserves_case(self):
        original = "ABCDEF01-2345-6789-ABCD-EF0123456789"
        for identifier in (original, original.lower()):
            self.assertEqual(probe.validated_device_id((identifier + "\n").encode()), identifier)

    def test_schema_requires_relaunched_library_witness_not_just_ui_green(self):
        identifier = "ABCDEF01-2345-6789-ABCD-EF0123456789"

        def fake_command(args, **kwargs):
            stdout = identifier.encode() if args[1:3] == ["simctl", "create"] else b""
            if args[:2] == ["xcodebuild", "test"]:
                stdout = b"PROBE_SYNTHETIC_FILTER_READY=true\n"
            return probe.subprocess.CompletedProcess(args, 0, stdout, b"")

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(probe, "ROOT", Path(directory) / "probe"), \
                patch.object(probe, "ARTIFACTS", Path(directory) / "artifacts"), \
                patch.object(probe.sys, "platform", "darwin"), \
                patch.dict(probe.os.environ, {"GITHUB_ACTIONS": "true"}), \
                patch.object(probe, "sim_json", side_effect=[self.runtimes, self.devices, self.types]), \
                patch.object(probe, "command", side_effect=fake_command), patch("builtins.print"):
            self.assertEqual(probe.main(), 1)
            self.schema_probe.assert_not_called()
            receipt = json.loads((probe.ARTIFACTS / "receipt.json").read_text())
            self.assertEqual(receipt["failure"], "SYNTHETIC_LIBRARY_PERSISTENCE_UNCONFIRMED")
            self.assertFalse(receipt["synthetic_library_nonempty_after_relaunch_observed"])
            self.assertFalse(receipt["otp_proven"])

    def test_schema_trial_requires_schema_success_not_metadata_success(self):
        identifier = "ABCDEF01-2345-6789-ABCD-EF0123456789"

        def fake_command(args, **kwargs):
            stdout = identifier.encode() if args[1:3] == ["simctl", "create"] else b""
            if args[:2] == ["xcodebuild", "test"]:
                stdout = b"PROBE_SYNTHETIC_FILTER_READY=true\nPROBE_SYNTHETIC_LIBRARY_NONEMPTY_AFTER_RELAUNCH=true\n"
            return probe.subprocess.CompletedProcess(args, 0, stdout, b"")

        for status, expected in (("SHORTCUTS_LIBRARY_SCHEMA_ONLY", 0),
                                 ("SHORTCUTS_LIBRARY_SCHEMA_UNCONFIRMED", 1),
                                 ("OPEN_HANDLE_PATH_METADATA_OBSERVED", 1),
                                 ("NO_ASSOCIATED_OPEN_HANDLE_OBSERVED", 1)):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory, \
                    patch.object(probe, "ROOT", Path(directory) / "probe"), \
                    patch.object(probe, "ARTIFACTS", Path(directory) / "artifacts"), \
                    patch.object(probe.sys, "platform", "darwin"), \
                    patch.dict(probe.os.environ, {"GITHUB_ACTIONS": "true",
                               "SHORTCUTS_PROBE_EXECUTION_MODE": "observed-shortcuts-schema"}), \
                    patch.object(probe, "sim_json", side_effect=[self.runtimes, self.devices, self.types]), \
                    patch.object(probe, "command", side_effect=fake_command), patch("builtins.print"):
                self.open_probe.reset_mock()
                self.open_probe.return_value = {"status": status}
                self.assertEqual(probe.main(), expected)
                self.open_probe.assert_called_once_with(identifier, inspect_schema=True)
                receipt = json.loads((probe.ARTIFACTS / "receipt.json").read_text())
                self.assertFalse(receipt["otp_proven"])
                if expected:
                    self.assertEqual(receipt["failure"], status)

    def test_actions_trial_requires_empty_fixture_and_only_actions_success(self):
        identifier = "ABCDEF01-2345-6789-ABCD-EF0123456789"
        for empty, status, expected in ((False, "SYNTHETIC_ACTION_MARKER_OBSERVED", 1),
                                        (True, "SYNTHETIC_ACTION_MARKER_OBSERVED", 0),
                                        (True, "SHORTCUTS_LIBRARY_SCHEMA_ONLY", 1),
                                        (True, "SYNTHETIC_ACTION_BLOB_UNCONFIRMED", 1)):
            def fake_command(args, **kwargs):
                stdout = identifier.encode() if args[1:3] == ["simctl", "create"] else b""
                if args[:2] == ["xcodebuild", "test"]:
                    stdout = b"PROBE_SYNTHETIC_FILTER_READY=true\nPROBE_SYNTHETIC_LIBRARY_NONEMPTY_AFTER_RELAUNCH=true\n"
                    if empty:
                        stdout += b"PROBE_FRESH_LIBRARY_EMPTY=true\n"
                return probe.subprocess.CompletedProcess(args, 0, stdout, b"")

            with self.subTest(empty=empty, status=status), tempfile.TemporaryDirectory() as directory, \
                    patch.object(probe, "ROOT", Path(directory) / "probe"), \
                    patch.object(probe, "ARTIFACTS", Path(directory) / "artifacts"), \
                    patch.object(probe.sys, "platform", "darwin"), \
                    patch.dict(probe.os.environ, {"GITHUB_ACTIONS": "true",
                               "SHORTCUTS_PROBE_EXECUTION_MODE": "synthetic-action-shape"}), \
                    patch.object(probe, "sim_json", side_effect=[self.runtimes, self.devices, self.types]), \
                    patch.object(probe, "command", side_effect=fake_command), patch("builtins.print"):
                self.open_probe.reset_mock()
                self.open_probe.return_value = {"status": status}
                self.assertEqual(probe.main(), expected)
                if empty:
                    self.open_probe.assert_called_once_with(identifier, inspect_actions=True)
                else:
                    self.open_probe.assert_not_called()
                receipt = json.loads((probe.ARTIFACTS / "receipt.json").read_text())
                self.assertFalse(receipt["otp_proven"])
                if not empty:
                    self.assertEqual(receipt["failure"], "FRESH_SYNTHETIC_LIBRARY_EMPTY_UNCONFIRMED")

    def test_device_id_rejects_malformed_and_noncanonical(self):
        for identifier in (b"", b"not-a-uuid", b"ABCDEF0123456789ABCDEF0123456789",
                           b"{ABCDEF01-2345-6789-ABCD-EF0123456789}"):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                probe.validated_device_id(identifier)

    def test_xcode_destination_gets_original_created_identifier(self):
        identifier = "ABCDEF01-2345-6789-ABCD-EF0123456789"

        def fake_command(args, **kwargs):
            stdout = (identifier + "\n").encode() if args[1:3] == ["simctl", "create"] else b""
            if args[:2] == ["xcodebuild", "test"]:
                stdout = b"PROBE_SYNTHETIC_FILTER_READY=true\nPROBE_SYNTHETIC_LIBRARY_NONEMPTY_AFTER_RELAUNCH=true\n"
            if "-showdestinations" in args:
                return probe.subprocess.CompletedProcess(args, 70, b"Available destinations:\n", b"Synthetic error\n")
            return probe.subprocess.CompletedProcess(args, 0, stdout, b"")

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(probe, "ROOT", Path(directory) / "probe"), \
                patch.object(probe, "ARTIFACTS", Path(directory) / "artifacts"), \
                patch.object(probe.sys, "platform", "darwin"), \
                patch.dict(probe.os.environ, {"GITHUB_ACTIONS": "true"}), \
                patch.object(probe, "sim_json", side_effect=[
                    self.runtimes, self.devices, self.types]) as sim_json, \
                patch.object(probe, "command", side_effect=fake_command) as command, \
                patch("builtins.print"):
            self.assertEqual(probe.main(), 0)
            build_args = next(call.args[0] for call in command.call_args_list
                              if call.args[0][:2] == ["xcodebuild", "test"])
            self.assertEqual(build_args[build_args.index("-destination") + 1],
                             "platform=iOS Simulator,id=" + identifier)
            calls = [call.args[0] for call in command.call_args_list]
            destinations = ["xcodebuild", *probe.PROJECT_ARGS, "-showdestinations"]
            create = next(args for args in calls if args[1:3] == ["simctl", "create"])
            boot = next(args for args in calls if args[1:3] == ["simctl", "boot"])
            self.assertLess(calls.index(["xcodebuild", "-showsdks"]), calls.index(create))
            self.assertLess(calls.index(create), calls.index(destinations))
            self.assertLess(calls.index(destinations), calls.index(boot))
            self.assertLess(calls.index(boot), calls.index(build_args))
            self.assertEqual(sim_json.call_count, 3)
            self.assertIn("Available destinations:",
                          (probe.ARTIFACTS / "destinations_preboot.txt").read_text(encoding="utf-8"))
            receipt = json.loads((probe.ARTIFACTS / "receipt.json").read_text())
            self.assertEqual(receipt["destinations_preboot_diagnostic_exit"], 70)
            self.assertEqual(receipt["bootstatus_exit"], 0)
            self.assertFalse(receipt["message_access"])
            self.assertFalse(receipt["otp_proven"])
            self.assertEqual(receipt["status"], "OPEN_HANDLE_PATH_METADATA_OBSERVED")
            self.open_probe.assert_called_once_with(identifier, inspect_schema=False)
            self.schema_probe.assert_not_called()
            self.groups_probe.assert_not_called()
            self.entitlements_probe.assert_not_called()
            build_call = next(call for call in command.call_args_list
                              if call.args[0][:2] == ["xcodebuild", "test"])
            self.assertEqual(build_call.kwargs["env"]["TEST_RUNNER_SHORTCUTS_PROBE_MODE"], "schema-only")
            self.assertEqual(build_args[build_args.index("-default-test-execution-time-allowance") + 1], "180")
            self.assertEqual(build_args[build_args.index("-maximum-test-execution-time-allowance") + 1], "180")
            self.assertEqual(build_call.kwargs["timeout"], 480)
            self.assertIsNone(probe.DEADLINE)

    def test_nonzero_ui_exit_blocks_stores_even_with_all_witness_markers(self):
        identifier = "ABCDEF01-2345-6789-ABCD-EF0123456789"

        def fake_command(args, **kwargs):
            stdout = identifier.encode() if args[1:3] == ["simctl", "create"] else b""
            if args[:2] == ["xcodebuild", "test"]:
                return probe.subprocess.CompletedProcess(args, 65,
                    b"PROBE_SYNTHETIC_FILTER_READY=true\nPROBE_SYNTHETIC_LIBRARY_NONEMPTY_AFTER_RELAUNCH=true\n", b"")
            return probe.subprocess.CompletedProcess(args, 0, stdout, b"")

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(probe, "ROOT", Path(directory) / "probe"), \
                patch.object(probe, "ARTIFACTS", Path(directory) / "artifacts"), \
                patch.object(probe.sys, "platform", "darwin"), \
                patch.dict(probe.os.environ, {"GITHUB_ACTIONS": "true"}), \
                patch.object(probe, "sim_json", side_effect=[self.runtimes, self.devices, self.types]), \
                patch.object(probe, "command", side_effect=fake_command), patch("builtins.print"):
            self.assertEqual(probe.main(), 1)
            self.schema_probe.assert_not_called()
            self.entitlements_probe.assert_not_called()
            self.groups_probe.assert_not_called()
            self.open_probe.assert_not_called()
            receipt = json.loads((probe.ARTIFACTS / "receipt.json").read_text())
            self.assertEqual(receipt["failure"], "UI_TEST_FAILED")
            self.assertNotIn("native_entitlement_metadata", receipt)
            self.assertFalse(receipt["otp_proven"])

    def test_command_timeout_obeys_remaining_budget(self):
        with patch.object(probe, "DEADLINE", 102), \
                patch.object(probe.time, "monotonic", return_value=100), \
                patch.object(probe, "run_with_timeout", return_value=
                             probe.subprocess.CompletedProcess([], 0)) as run, \
                patch("builtins.print"):
            probe.command(["synthetic", "diagnostic"], timeout=60)
            self.assertEqual(run.call_args.kwargs["timeout"], 2)

    def test_command_label_never_retains_temporary_executable_path(self):
        with patch.object(probe, "DEADLINE", None), \
                patch.object(probe, "run_with_timeout", return_value=
                             probe.subprocess.CompletedProcess([], 0)), patch("builtins.print") as output:
            probe.command(["/private/SENTINEL/appium", "driver", "--help"], check=False)
        self.assertEqual(probe.TIMINGS[-1]["command"], "appium driver --help")
        self.assertNotIn("SENTINEL", str(output.call_args_list))

    def test_bounded_process_uses_files_and_its_own_session(self):
        process = MagicMock(pid=4321, returncode=0)

        def launch(args, **kwargs):
            kwargs["stdout"].write(b"synthetic stdout")
            kwargs["stderr"].write(b"synthetic stderr")
            return process

        with patch.object(probe.subprocess, "Popen", side_effect=launch) as popen:
            result = probe.run_with_timeout(["synthetic"], 2, {"SAFE": "1"})
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"synthetic stdout")
        self.assertEqual(result.stderr, b"synthetic stderr")
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertNotEqual(popen.call_args.kwargs["stdout"], probe.subprocess.PIPE)
        process.wait.assert_called_once_with(timeout=2)

    def test_process_timeout_kills_only_owned_group_and_second_wait_is_bounded(self):
        process = MagicMock(pid=4321, returncode=None)
        process.wait.side_effect = [probe.subprocess.TimeoutExpired("synthetic", 2),
                                    probe.subprocess.TimeoutExpired("synthetic", 5)]

        def launch(args, **kwargs):
            kwargs["stdout"].write(b"PROBE_PARTIAL")
            return process

        with patch.object(probe.subprocess, "Popen", side_effect=launch), \
                patch.object(probe.os, "killpg", create=True) as killpg, \
                patch.object(probe.signal, "SIGKILL", 9, create=True):
            with self.assertRaises(probe.subprocess.TimeoutExpired) as caught:
                probe.run_with_timeout(["synthetic"], 2, {})
            killpg.assert_called_once_with(4321, 9)
        self.assertEqual(caught.exception.stdout, b"PROBE_PARTIAL")
        self.assertEqual([call.kwargs["timeout"] for call in process.wait.call_args_list], [2, 5])

    def test_process_exit_race_does_not_turn_timeout_into_success(self):
        process = MagicMock(pid=4321, returncode=0)
        process.wait.side_effect = [probe.subprocess.TimeoutExpired("synthetic", 2), 0]
        with patch.object(probe.subprocess, "Popen", return_value=process), \
                patch.object(probe.os, "killpg", side_effect=ProcessLookupError, create=True), \
                patch.object(probe.signal, "SIGKILL", 9, create=True):
            with self.assertRaises(probe.subprocess.TimeoutExpired):
                probe.run_with_timeout(["synthetic"], 2, {})

    def test_native_timeout_probe_requires_descendant_marker_and_bounded_duration(self):
        for output, elapsed, expected in ((b"GRANDCHILD_STARTED", 1.1, True),
                                           (b"", 1.1, False),
                                           (b"GRANDCHILD_STARTED", 8.0, False)):
            with self.subTest(output=output, elapsed=elapsed), \
                    patch.object(probe.time, "monotonic", side_effect=[100, 100 + elapsed]), \
                    patch.object(probe, "run_with_timeout", side_effect=
                                 probe.subprocess.TimeoutExpired([], 1, output=output)):
                result = NATIVE_TIMEOUT_PROBE()
                self.assertEqual(result["wrapper_return_bounded_with_descendant_present"], expected)

    def test_native_timeout_probe_rejects_normal_exit(self):
        with patch.object(probe, "run_with_timeout", return_value=
                         probe.subprocess.CompletedProcess([], 0, b"GRANDCHILD_STARTED")):
            result = NATIVE_TIMEOUT_PROBE()
        self.assertFalse(result["wrapper_return_bounded_with_descendant_present"])

    def test_diagnostic_collection_disabled_only_when_help_lists_flag(self):
        self.assertEqual(probe.test_diagnostic_options(
            "Options:\n    -collect-test-diagnostics mode    Collect test diagnostics\n"),
            ["-collect-test-diagnostics", "never"])
        for help_text in ("", "unrelated -collect-test-diagnostics mention",
                          "    -collect-test-diagnostics-invalid option"):
            self.assertEqual(probe.test_diagnostic_options(help_text), [])

    def test_help_gate_keeps_raw_flag_even_when_artifact_is_truncated(self):
        output = b"    -collect-test-diagnostics mode\n" + b"x" * 70000
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(probe, "ARTIFACTS", Path(directory)), \
                patch.object(probe, "command", return_value=
                             probe.subprocess.CompletedProcess([], 0, output, b"")):
            result = probe.collect_xcode_diagnostic({}, "xcode_help", ["xcodebuild", "-help"])
            self.assertEqual(probe.test_diagnostic_options(
                (result.stdout + result.stderr).decode()), ["-collect-test-diagnostics", "never"])
            self.assertEqual(len((probe.ARTIFACTS / "xcode_help.txt").read_text()), 65536)

    def test_ui_timeout_still_attempts_evidence_recovery_without_claiming_pass(self):
        identifier = "ABCDEF01-2345-6789-ABCD-EF0123456789"

        def fake_command(args, **kwargs):
            if args[:2] == ["xcodebuild", "test"]:
                raise probe.subprocess.TimeoutExpired(args, 480, output=b"PROBE_PARTIAL_UI\n")
            if args[:3] == ["xcrun", "xcresulttool", "export"]:
                raise probe.subprocess.TimeoutExpired(args, 60)
            stdout = identifier.encode() if args[1:3] == ["simctl", "create"] else b""
            return probe.subprocess.CompletedProcess(args, 0, stdout, b"")

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(probe, "ROOT", Path(directory) / "probe"), \
                patch.object(probe, "ARTIFACTS", Path(directory) / "artifacts"), \
                patch.object(probe.sys, "platform", "darwin"), \
                patch.dict(probe.os.environ, {"GITHUB_ACTIONS": "true"}), \
                patch.object(probe, "sim_json", side_effect=[
                    self.runtimes, self.devices, self.types]), \
                patch.object(probe, "command", side_effect=fake_command) as command, \
                patch("builtins.print"):
            (Path(directory) / "ProbeResults.xcresult").mkdir()
            self.assertEqual(probe.main(), 1)
            calls = [call.args[0] for call in command.call_args_list]
            self.assertTrue(any(args[:3] == ["xcrun", "xcresulttool", "export"] for args in calls))
            self.assertTrue(any(args[-1].endswith("last-screen.png") for args in calls))
            receipt = json.loads((probe.ARTIFACTS / "receipt.json").read_text())
            self.assertEqual(receipt["failure"], "UI_TEST_COMMAND_TIMEOUT")
            self.assertEqual(receipt["attachment_export_exit"], "unconfirmed")
            self.assertEqual(receipt["last_screenshot_exit"], 0)
            self.assertFalse(receipt["otp_proven"])

    def test_preflight_timeout_does_not_skip_the_ui_test(self):
        identifier = "ABCDEF01-2345-6789-ABCD-EF0123456789"

        def fake_command(args, **kwargs):
            if "-showdestinations" in args:
                raise probe.subprocess.TimeoutExpired(args, 60, output=b"Partial destinations\n")
            stdout = identifier.encode() if args[1:3] == ["simctl", "create"] else b""
            if args[:2] == ["xcodebuild", "test"]:
                stdout = b"PROBE_SYNTHETIC_FILTER_READY=true\nPROBE_SYNTHETIC_LIBRARY_NONEMPTY_AFTER_RELAUNCH=true\n"
            return probe.subprocess.CompletedProcess(args, 0, stdout, b"")

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(probe, "ROOT", Path(directory) / "probe"), \
                patch.object(probe, "ARTIFACTS", Path(directory) / "artifacts"), \
                patch.object(probe.sys, "platform", "darwin"), \
                patch.dict(probe.os.environ, {"GITHUB_ACTIONS": "true"}), \
                patch.object(probe, "sim_json", side_effect=[
                    self.runtimes, self.devices, self.types]), \
                patch.object(probe, "command", side_effect=fake_command) as command, \
                patch("builtins.print"):
            self.assertEqual(probe.main(), 0)
            self.assertTrue(any(call.args[0][:2] == ["xcodebuild", "test"]
                                for call in command.call_args_list))
            receipt = json.loads((probe.ARTIFACTS / "receipt.json").read_text())
            self.assertEqual(receipt["destinations_preboot_diagnostic_exit"], "timeout")
            self.assertIn("Partial destinations", (probe.ARTIFACTS / "destinations_preboot.txt").read_text())

    def test_expired_budget_does_not_start_another_command(self):
        with patch.object(probe, "DEADLINE", 99), \
                patch.object(probe.time, "monotonic", return_value=100), \
                patch.object(probe, "run_with_timeout") as run:
            with self.assertRaisesRegex(RuntimeError, "PROBE_BUDGET_EXHAUSTED"):
                probe.command(["synthetic", "diagnostic"])
            run.assert_not_called()

    def test_cleanup_retains_its_own_budget(self):
        with patch.object(probe, "DEADLINE", 99), \
                patch.object(probe.time, "monotonic", return_value=100), \
                patch.object(probe, "run_with_timeout", return_value=
                             probe.subprocess.CompletedProcess([], 0)) as run, \
                patch("builtins.print"):
            self.assertEqual(probe.cleanup_device("synthetic-id"), [])
            self.assertEqual(run.call_count, 2)
            self.assertTrue(all(call.kwargs["timeout"] == 30 for call in run.call_args_list))

    def test_failure_diagnostics_keep_destination_context_and_redact_paths(self):
        output = (f"{probe.ROOT.parent}/Probe\nxcodebuild: error: Unable to find a device\n"
                  "Provided: { id:ABC }\nAvailable destinations:\n{ platform:iOS Simulator }\n"
                  "/synthetic-home/Library\n")
        with patch.dict(probe.os.environ, {"HOME": "/synthetic-home"}):
            result = probe.xcode_diagnostics(output.encode(), failed=True, simulator_id="ABC")
        self.assertIn("Provided: { id:ABC }", result)
        self.assertIn("{ platform:iOS Simulator }", result)
        self.assertIn("<WORKSPACE>/Probe", result)
        self.assertIn("<HOME>/Library", result)
        self.assertNotIn("/synthetic-home", result)

    def test_diagnostics_are_bounded_and_success_is_filtered(self):
        self.assertEqual(len(probe.xcode_diagnostics(b"x" * 70000, failed=True)), 65536)
        self.assertEqual(probe.xcode_diagnostics(b"noise\nPROBE_OK\n", failed=False), "PROBE_OK")

    def test_diagnostic_ids_preserve_only_our_simulator(self):
        identifier = "ABCDEF01-2345-6789-ABCD-EF0123456789"
        text = ("{ id:" + identifier.lower() + " }\n{ id:unrelated-host }\n").encode()
        result = probe.xcode_diagnostics(text, True, simulator_id=identifier)
        self.assertIn(identifier.lower(), result)
        self.assertNotIn("unrelated-host", result)
        self.assertIn("<OTHER_RUNNER_DESTINATION>", result)

    def test_timeout_preserves_partial_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(probe, "ARTIFACTS", Path(directory)), \
                patch.dict(probe.os.environ, {"HOME": "/synthetic-home"}), \
                patch.object(probe, "command", side_effect=probe.subprocess.TimeoutExpired(
                    ["xcodebuild", "-showdestinations"], 1,
                    output=b"Available destinations:\n{ id:unrelated-host }\n",
                    stderr=b"/synthetic-home/Library\n")):
            with self.assertRaises(probe.subprocess.TimeoutExpired):
                probe.diagnostic_command(["xcodebuild", "-showdestinations"], "destinations.txt")
            result = (probe.ARTIFACTS / "destinations.txt").read_text(encoding="utf-8")
            self.assertIn("Available destinations:", result)
            self.assertIn("<HOME>/Library", result)
            self.assertNotIn("unrelated-host", result)

    def test_timeout_receipt_does_not_serialize_command_paths(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(probe, "ARTIFACTS", Path(directory) / "artifacts"), \
                patch.object(probe.sys, "platform", "darwin"), \
                patch.dict(probe.os.environ, {"GITHUB_ACTIONS": "true"}), \
                patch.object(probe, "sim_json", side_effect=probe.subprocess.TimeoutExpired(
                    ["xcodebuild", "test", "-derivedDataPath", "/private-workspace/DerivedData"], 1)), \
                patch.object(probe, "command", return_value=
                             probe.subprocess.CompletedProcess([], 0, b"", b"")), \
                patch("builtins.print"):
            self.assertEqual(probe.main(), 1)
            text = (probe.ARTIFACTS / "receipt.json").read_text(encoding="utf-8")
            self.assertNotIn("private-workspace", text)
            self.assertEqual(json.loads(text)["failure"], "COMMAND_TIMEOUT")

    def test_normal_macos_session_environment_is_preserved(self):
        expected = {key: "synthetic" for key in (
            "USER", "LOGNAME", "SHELL", "XPC_SERVICE_NAME", "__CF_USER_TEXT_ENCODING",
            "HOME", "PATH", "TMPDIR", "DEVELOPER_DIR")}
        self.assertEqual(probe.simulator_environment(expected), expected)

    def test_credential_and_injection_values_are_not_read_or_forwarded(self):
        blocked = (
            "GITHUB_ACTIONS", "GH_HOST", "ACTIONS_RUNTIME_URL", "RUNNER_TEMP", "CI_DATA",
            "AWS_REGION", "AZURE_DATA", "ARM_DATA", "GOOGLE_DATA", "GCLOUD_DATA",
            "CLOUDFLARE_DATA", "MY_TOKEN", "MY_SECRET", "PASSWORD", "PASSWD",
            "CREDENTIAL", "COOKIE", "AUTH", "API_KEY", "PRIVATE_KEY",
            "BASH_ENV", "ENV", "CDPATH", "GIT_ASKPASS", "SSH_ASKPASS", "SSH_AUTH_SOCK",
            "GPG_AGENT_INFO", "PYTHONPATH", "PYTHONHOME", "RUBYOPT", "PERL5OPT",
            "NODE_OPTIONS", "DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "GIT_CONFIG_COUNT")

        class ProtectedValues(dict):
            def __getitem__(self, key):
                raise AssertionError("A blocked value was accessed")

        self.assertEqual(probe.simulator_environment(ProtectedValues.fromkeys(blocked)), {})


if __name__ == "__main__":
    unittest.main()
