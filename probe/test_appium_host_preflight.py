from __future__ import annotations

from types import SimpleNamespace
import json
import hashlib
import io
import errno
import os
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock

import appium_host_preflight as preflight


class AppiumHostPreflightTests(unittest.TestCase):
    def test_wrong_environment_does_not_run_commands(self) -> None:
        command = mock.Mock()
        with mock.patch.object(preflight.sys, "platform", "win32"), mock.patch.dict("os.environ", {"GITHUB_ACTIONS": "true"}):
            with self.assertRaisesRegex(preflight.AppiumHostPreflightError, "UNSUPPORTED"):
                preflight.run_appium_host_preflight(command, {"GITHUB_ACTIONS": "true"})
        command.assert_not_called()

    def test_bad_node_avoids_install(self) -> None:
        command = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout=b"v18.0.0\n"))
        with mock.patch.object(preflight.sys, "platform", "darwin"), mock.patch.dict("os.environ", {"GITHUB_ACTIONS": "true"}):
            with self.assertRaisesRegex(preflight.AppiumHostPreflightError, "NODE_VERSION"):
                preflight.run_appium_host_preflight(command, {"GITHUB_ACTIONS": "true"})
        self.assertEqual(["node", "--version"], command.call_args.args[0])

    def test_cleanup_returns_false_when_process_will_not_exit(self) -> None:
        process = mock.Mock()
        process.poll.return_value = None
        process.pid = 1
        process.wait.side_effect = __import__("subprocess").TimeoutExpired("x", 1)
        process.kill.side_effect = OSError()
        with mock.patch.object(preflight.os, "killpg", create=True):
            self.assertFalse(preflight._cleanup(process))

    def exercise(self, status=None, cleanup=True, driver_version="12.18.1", process_exited=False, probe=None):
        seen = []

        def command(args, **kwargs):
            seen.append((args, kwargs))
            env = kwargs["env"]
            self.assertNotIn("npm_config_userconfig", env)
            self.assertNotIn("npm_config_registry", env)
            self.assertNotEqual(env["NPM_CONFIG_USERCONFIG"], env["NPM_CONFIG_GLOBALCONFIG"])
            for field in ("NPM_CONFIG_USERCONFIG", "NPM_CONFIG_GLOBALCONFIG"):
                self.assertEqual(Path(env[field]).read_bytes(), b"")
            self.assertNotIn("TOKEN", env)
            root = Path(env["APPIUM_HOME"]).parent
            for field in ("NPM_CONFIG_USERCONFIG", "NPM_CONFIG_GLOBALCONFIG", "NPM_CONFIG_CACHE"):
                self.assertTrue(Path(env[field]).is_relative_to(root))
            if args[0] == "node":
                stdout = b"v22.14.0"
            elif args == ["npm", "--version"]:
                stdout = b"10.9.2"
            elif "--help" in args:
                stdout = b"driver install list --installed --json --address --port --tmp --use-drivers"
            elif "--version" in args:
                stdout = b"3.8.0"
            elif "--json" in args:
                stdout = json.dumps({"xcuitest": {"pkgName": "appium-xcuitest-driver",
                                     "version": driver_version, "installed": True}}).encode()
            else:
                stdout = b""
            return SimpleNamespace(returncode=0, stdout=stdout)

        process = mock.Mock()
        process.poll.return_value = 17 if process_exited else None
        try:
            with mock.patch.object(preflight.sys, "platform", "darwin"), \
                    mock.patch.dict(preflight.os.environ, {"GITHUB_ACTIONS": "true"}), \
                    mock.patch.object(preflight.subprocess, "Popen", return_value=process) as popen, \
                    mock.patch.object(preflight, "_read_status", return_value=status or {
                        "value": {"ready": True, "build": {"version": "3.8.0"}}}) as read, \
                    mock.patch.object(preflight, "_cleanup", return_value=cleanup) as stop, \
                    mock.patch.object(preflight.time, "sleep"):
                try:
                    env = {
                        "PATH": os.environ["PATH"], "npm_config_userconfig": "/private/SENTINEL",
                        "npm_config_registry": "https://sentinel.invalid/"}
                    if probe is None:
                        result = preflight.run_appium_host_preflight(command, env)
                    else:
                        result = preflight.run_appium_with_owned_server(command, env, probe)
                except preflight.AppiumHostPreflightError as error:
                    result = error
            root = Path(seen[0][1]["env"]["APPIUM_HOME"]).parent
            if cleanup is False:
                self.assertTrue(root.exists())
            else:
                self.assertFalse(root.exists())
            return result, seen, popen, read, stop
        finally:
            if seen:
                root = Path(seen[0][1]["env"]["APPIUM_HOME"]).parent
                if root.exists():
                    stat = root.lstat()
                    preflight._remove_owned_root(root, (stat.st_dev, stat.st_ino))

    def test_positive_preflight_uses_only_loopback_status_and_stops_owned_server(self):
        result, seen, popen, read, stop = self.exercise()
        self.assertEqual(result["appium_version"], "3.8.0")
        self.assertEqual(result["xcuitest_version"], "12.18.1")
        self.assertTrue(result["cleanup_exited"])
        read.assert_called_once()
        stop.assert_called_once_with(popen.return_value)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertIn("127.0.0.1", popen.call_args.args[0])
        self.assertNotIn("udid", str(seen).lower())
        self.assertNotIn("simctl", str(seen))
        self.assertNotIn("session", str(result))

    def test_nonready_or_malformed_status_is_red_and_cleans_up(self):
        for status in ({"value": []}, {"value": {"ready": False}},
                       {"value": {"ready": True, "build": {"version": "PRIVATE_SENTINEL"}}}):
            with self.subTest(status=status):
                error, _, _, read, stop = self.exercise(status=status)
                self.assertEqual(error.code, "HOST_PREFLIGHT_STATUS_UNCONFIRMED")
                self.assertTrue(error.cleanup_exited)
                self.assertEqual(read.call_count, 30)
                stop.assert_called_once()
                self.assertNotIn("SENTINEL", str(error))

    def test_probe_runs_only_after_readiness_and_before_teardown(self):
        observed = []

        def probe(url):
            self.assertRegex(url, r"^http://127\.0\.0\.1:\d+$")
            observed.append(url)

        result, _, _, read, stop = self.exercise(probe=probe)
        self.assertEqual(len(observed), 1)
        self.assertTrue(result["cleanup_exited"])
        read.assert_called_once()
        stop.assert_called_once()

    def test_unready_host_never_calls_probe(self):
        probe = mock.Mock()
        error, _, _, _, stop = self.exercise(status={"value": []}, probe=probe)
        self.assertEqual(error.code, "HOST_PREFLIGHT_STATUS_UNCONFIRMED")
        probe.assert_not_called()
        stop.assert_called_once()

    def test_probe_exception_is_sanitized_and_owned_server_stops(self):
        probe = mock.Mock(side_effect=RuntimeError("PRIVATE_SENTINEL"))
        error, _, _, _, stop = self.exercise(probe=probe)
        self.assertEqual(error.code, "HOST_PREFLIGHT_CALLBACK_UNCONFIRMED")
        self.assertTrue(error.cleanup_exited)
        self.assertNotIn("SENTINEL", str(error))
        probe.assert_called_once()
        stop.assert_called_once()

    def test_probe_failure_and_cleanup_failure_preserve_primary(self):
        error, _, _, _, stop = self.exercise(probe=mock.Mock(side_effect=ValueError("PRIVATE_SENTINEL")), cleanup=False)
        self.assertEqual(error.code, "HOST_PREFLIGHT_CLEANUP_UNCONFIRMED")
        self.assertEqual(error.primary_code, "HOST_PREFLIGHT_CALLBACK_UNCONFIRMED")
        self.assertTrue(error.temporary_retained)
        stop.assert_called_once()

    def test_wrong_driver_never_starts_server(self):
        error, _, popen, read, stop = self.exercise(driver_version="12.18.0")
        self.assertEqual(error.code, "HOST_PREFLIGHT_DRIVER_VERSION")
        popen.assert_not_called()
        read.assert_not_called()
        stop.assert_not_called()

    def test_exited_process_cannot_accept_ready_from_another_server(self):
        error, _, _, read, stop = self.exercise(process_exited=True)
        self.assertEqual(error.code, "HOST_PREFLIGHT_SERVER_START")
        read.assert_not_called()
        stop.assert_called_once()

    def test_failed_cleanup_preserves_temporary_and_original_failure(self):
        error, _, _, _, _ = self.exercise(status={"value": []}, cleanup=False)
        self.assertEqual(error.code, "HOST_PREFLIGHT_CLEANUP_UNCONFIRMED")
        self.assertFalse(error.cleanup_exited)
        self.assertTrue(error.temporary_retained)
        self.assertEqual(error.primary_code, "HOST_PREFLIGHT_STATUS_UNCONFIRMED")

    def test_node_engine_range_is_exact(self):
        for version in ("v20.18.9", "v21.9.0", "v22.11.9", "v23.9.0", "v24.0.0-rc1"):
            with self.subTest(version=version), self.assertRaises(preflight.AppiumHostPreflightError):
                preflight._version(version, node=True)
        for version in ("v20.19.0", "v22.12.0", "v24.0.0", "v25.1.0"):
            self.assertEqual(preflight._version(version, node=True), version[1:])

    def test_term_timeout_escalates_only_owned_process_group(self):
        process = mock.Mock(pid=1234)
        process.poll.return_value = None
        process.wait.side_effect = [preflight.subprocess.TimeoutExpired("owned", 5), 0]
        with mock.patch.object(preflight.os, "name", "posix"), \
                mock.patch.object(preflight.signal, "SIGKILL", 9, create=True), \
                mock.patch.object(preflight.os, "killpg", create=True) as killpg:
            self.assertTrue(preflight._cleanup(process))
        self.assertEqual(killpg.call_args_list, [mock.call(1234, preflight.signal.SIGTERM),
                                                mock.call(1234, 9)])

    def test_wda_cleanup_drains_children_even_after_parent_has_exited(self):
        process = mock.Mock(pid=1234)
        process.poll.return_value = 0
        process.wait.return_value = 0
        with mock.patch.object(preflight.os, "name", "posix"), \
                mock.patch.object(preflight.signal, "SIGKILL", 9, create=True), \
                mock.patch.object(preflight.os, "killpg", side_effect=[None, ProcessLookupError()], create=True) as killpg:
            self.assertTrue(preflight._cleanup_wda_launch(process))
        self.assertEqual(killpg.call_args_list, [mock.call(1234, preflight.signal.SIGTERM), mock.call(1234, 0)])

    def test_wda_cleanup_rejects_permanently_live_owned_group(self):
        process = mock.Mock(pid=1234)
        process.poll.return_value = 0
        process.wait.return_value = 0
        with mock.patch.object(preflight.os, "name", "posix"), \
                mock.patch.object(preflight.signal, "SIGKILL", 9, create=True), \
                mock.patch.object(preflight.os, "killpg", return_value=None, create=True) as killpg, \
                mock.patch.object(preflight.time, "sleep"):
            self.assertFalse(preflight._cleanup_wda_launch(process))
        signals = [call.args[1] for call in killpg.call_args_list if call.args[1] != 0]
        self.assertEqual(signals, [preflight.signal.SIGTERM, 9])


class WdaLaunchPreflightTests(unittest.TestCase):
    uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

    class _Response:
        status = 200

        def __init__(self, payload):
            self.payload = payload

        def read(self, limit):
            return self.payload

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    def _launch(self, *, listener=b"p991\nn127.0.0.1:8100\n", command_line=None,
                cleanup=None, prepare=None, status=b'{"value":{"ready":true}}'):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name) / "appium-host-preflight-wda-launch-test"
        root.mkdir()
        package = root / "package"
        config = package / "WebDriverAgentLib" / "Utilities" / "FBConfiguration.m"
        config.parent.mkdir(parents=True)
        config.write_bytes(b"configuration")
        derived = root / "derived"
        products = derived / "Build" / "Products"
        runner = products / "Debug-iphonesimulator" / "WebDriverAgentRunner-Runner.app"
        runner.mkdir(parents=True)
        (runner / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": "com.facebook.WebDriverAgentRunner.xctrunner",
            "CFBundleExecutable": "WebDriverAgentRunner-Runner",
        }))
        run = products / "Runner.xctestrun"
        run.write_bytes(plistlib.dumps({"WebDriverAgentRunner": {"EnvironmentVariables": {}}}))
        container = (root / "CoreSimulator" / "Devices" / self.uuid / "data" / "Containers" /
                     "Bundle" / "Application" / "PRIVATE_SENTINEL" /
                     "WebDriverAgentRunner-Runner.app")
        container.mkdir(parents=True)
        (container / "WebDriverAgentRunner-Runner").write_bytes(b"runner")
        if command_line is None:
            command_line = str(container / "WebDriverAgentRunner-Runner") + " --listen"
        process = mock.Mock(pid=123)
        process.poll.return_value = None
        cleanup = cleanup if cleanup is not None else {"cleanup_errors": []}
        prepare = prepare if prepare is not None else mock.Mock(return_value=self.uuid)
        cleanup_device = mock.Mock(return_value=cleanup)
        responses = [self._Response(status)]

        def run_command(command, args, env, timeout, failure="HOST_PREFLIGHT_NPM_INSTALL"):
            if args[0] == "lsof":
                return SimpleNamespace(returncode=0, stdout=listener)
            if args[:3] == ["xcrun", "simctl", "get_app_container"]:
                return SimpleNamespace(returncode=0, stdout=str(container).encode())
            if args[0] == "ps":
                return SimpleNamespace(returncode=0, stdout=command_line.encode())
            if args == ["node", "--version"]:
                return SimpleNamespace(returncode=0, stdout=b"v22.14.0")
            if args == ["npm", "--version"]:
                return SimpleNamespace(returncode=0, stdout=b"10.9.2")
            return SimpleNamespace(returncode=0, stdout=b"3.8.0")

        opener = mock.Mock()
        opener.open.side_effect = responses
        expected_config = hashlib.sha256(b"configuration").hexdigest()
        wda = {"wda_package_version": "16.15.0", "private_paths": {
            "package_root_path": str(package), "derived_data_path": str(derived),
        }}
        with mock.patch.object(preflight.sys, "platform", "darwin"), \
                mock.patch.dict(preflight.os.environ, {"GITHUB_ACTIONS": "true"}), \
                mock.patch.object(preflight.tempfile, "mkdtemp", return_value=str(root)), \
                mock.patch.object(preflight, "_build_owned_wda", return_value=wda), \
                mock.patch.object(preflight, "_run", side_effect=run_command), \
                mock.patch.object(preflight, "_free_port", return_value=8100), \
                mock.patch.object(preflight, "_WDA_CONFIGURATION_SHA256", expected_config), \
                mock.patch.object(preflight, "build_opener", return_value=opener), \
                mock.patch.object(preflight.subprocess, "Popen", return_value=process) as popen, \
                mock.patch.object(preflight, "_cleanup_wda_launch", return_value=True) as stop, \
                mock.patch.object(preflight, "_wda_endpoint_closed", return_value=True), \
                mock.patch.object(preflight, "_validated_wda_outputs"), \
                mock.patch.object(preflight, "_remove_owned_root"):
            result = preflight.run_owned_wda_launch_preflight(mock.Mock(), {"PATH": os.environ["PATH"]}, prepare, cleanup_device)
        return result, prepare, cleanup_device, popen, stop, opener

    def test_wda_launch_positive_requires_only_local_wda_readiness(self):
        result, prepare, cleanup_device, popen, stop, opener = self._launch()
        self.assertEqual(result["status"], "WDA_READY_ONLY")
        self.assertTrue(result["loopback_verified"])
        self.assertTrue(result["runner_pid_verified"])
        prepare.assert_called_once_with()
        cleanup_device.assert_called_once_with()
        stop.assert_called_once_with(popen.return_value)
        args = popen.call_args.args[0]
        self.assertEqual(args[:2], ["xcodebuild", "test-without-building"])
        self.assertFalse(any("session" in str(value).lower() for value in args))
        self.assertEqual(opener.open.call_count, 1)

    def test_wda_launch_rejects_listener_without_exact_loopback_owner(self):
        for listener in (b"", b"p991\nn0.0.0.0:8100\n", b"p991\nn[::1]:8100\n",
                         b"p991\np992\nn127.0.0.1:8100\n"):
            with self.subTest(listener=listener), self.assertRaises(preflight.AppiumHostPreflightError):
                with mock.patch.object(preflight.time, "monotonic", side_effect=[0, 0, 181]):
                    self._launch(listener=listener)

    def test_wda_launch_rejects_wrong_runner_container_without_leaking_it(self):
        with self.assertRaises(preflight.AppiumHostPreflightError) as caught:
            with mock.patch.object(preflight.time, "monotonic", side_effect=[0, 0, 181, 181, 181]):
                self._launch(command_line="/private/other/runner")
        self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))

    def test_wda_launch_cleanup_failure_preserves_sanitized_primary(self):
        with self.assertRaises(preflight.AppiumHostPreflightError) as caught:
            with mock.patch.object(preflight.time, "monotonic", side_effect=[0, 0, 181, 181, 181]):
                self._launch(cleanup={"cleanup_errors": ["private"]}, status=b"{}")
        self.assertEqual(caught.exception.code, "HOST_WDA_LAUNCH_CLEANUP")
        self.assertIsNotNone(caught.exception.primary_code)
        self.assertNotIn("private", str(caught.exception))

    def test_wda_endpoint_closed_accepts_only_tcp_connection_refused(self):
        refused = OSError(errno.ECONNREFUSED, "refused")
        with mock.patch.object(preflight.socket, "create_connection", side_effect=refused):
            self.assertTrue(preflight._wda_endpoint_closed(8100))
        connected = mock.MagicMock()
        connected.__enter__.return_value = connected
        with mock.patch.object(preflight.socket, "create_connection", return_value=connected), \
                mock.patch.object(preflight.time, "sleep"):
            self.assertFalse(preflight._wda_endpoint_closed(8100))

    def _exercise_wda(self, *, changed=False, bad_output=False, bad_install=False,
                      private_version=False, escape=False, build_failure=None, wrong_bundle=False,
                      prebuilt=False):
        seen = []
        simctl_calls = 0

        def command(args, **kwargs):
            nonlocal simctl_calls
            seen.append((args, kwargs))
            env = kwargs["env"]
            root = Path(env["APPIUM_HOME"]).parent
            if args == ["node", "--version"]:
                stdout = b"v22.14.0"
            elif args == ["npm", "--version"]:
                stdout = b"10.9.2"
            elif "--help" in args:
                stdout = b"driver install list --installed --json --address --port --tmp --use-drivers"
            elif "--version" in args:
                stdout = b"3.8.0"
            elif args[0] == "node" and args[1] == "-e":
                package = Path("/outside/SENTINEL") if escape else (
                    root / "driver" / "node_modules" / "appium-webdriveragent" / "package.json")
                stdout = json.dumps({"resolvedPath": str(package)}).encode()
            elif args[0] == "xcrun":
                simctl_calls += 1
                state = "Booted" if changed and simctl_calls == 2 else "Shutdown"
                stdout = json.dumps({"devices": {"runtime": [{"udid": "opaque-id", "state": state}]}}).encode()
            elif args[0] == "xcodebuild":
                derived = Path(args[args.index("-derivedDataPath") + 1])
                if not bad_output:
                    products = derived / "Build" / "Products"
                    runner = products / "Debug-iphonesimulator" / "WebDriverAgentRunner-Runner.app"
                    bundle = runner / "PlugIns" / "WebDriverAgentRunner.xctest"
                    bundle.mkdir(parents=True)
                    (runner / "Info.plist").write_bytes(plistlib.dumps({"CFBundleExecutable": "WebDriverAgentRunner-Runner"}))
                    (runner / "WebDriverAgentRunner-Runner").write_bytes(b"\xcf\xfa\xed\xfecompiled")
                    bundle_path = "__TESTROOT__/Unrelated.xctest" if wrong_bundle else (
                        "__TESTHOST__/PlugIns/WebDriverAgentRunner.xctest")
                    if wrong_bundle:
                        (products / "Unrelated.xctest").mkdir()
                    (products / "Runner.xctestrun").write_bytes(plistlib.dumps({"WebDriverAgentRunner": {
                        "TestBundlePath": bundle_path,
                        "TestHostPath": "__TESTROOT__/Debug-iphonesimulator/WebDriverAgentRunner-Runner.app",
                    }}))
                if build_failure is not None:
                    return SimpleNamespace(returncode=65, stdout=build_failure, stderr=b"PRIVATE_STDERR")
                stdout = b""
            elif "--json" in args:
                install = root / "driver"
                if not bad_install:
                    package = install / "node_modules" / "appium-webdriveragent"
                    (package / "WebDriverAgent.xcodeproj").mkdir(parents=True)
                    (package / "WebDriverAgent.xcodeproj" / "project.pbxproj").write_text("", encoding="ascii")
                    version = "PRIVATE_VERSION" if private_version else "16.15.0"
                    (package / "package.json").write_text(
                        json.dumps({"name": "appium-webdriveragent", "version": version}), encoding="ascii")
                stdout = json.dumps({"xcuitest": {"pkgName": "appium-xcuitest-driver", "version": "12.18.1", "installed": True,
                                                   "installPath": str(install)}}).encode()
            else:
                stdout = b""
            return SimpleNamespace(returncode=0, stdout=stdout)

        process = mock.Mock()
        process.poll.return_value = None

        def start(*args, **kwargs):
            seen.append((["Popen"], {}))
            return process

        with mock.patch.object(preflight.sys, "platform", "darwin"), \
                mock.patch.dict(preflight.os.environ, {"GITHUB_ACTIONS": "true"}), \
                mock.patch.object(preflight.subprocess, "Popen", side_effect=start) as popen, \
                mock.patch.object(preflight, "_read_status", return_value={"value": {"ready": True, "build": {"version": "3.8.0"}}}), \
                mock.patch.object(preflight, "_cleanup", return_value=True):
            try:
                if prebuilt:
                    callback_events = []

                    def probe(url, paths):
                        callback_events.append((url, paths))
                        self.assertTrue(Path(paths["derived_data_path"]).exists())

                    result = preflight.run_appium_with_prebuilt_owned_server(command, {"PATH": os.environ["PATH"]}, probe)
                    result = (result, callback_events)
                else:
                    result = preflight.run_appium_wda_build_preflight(command, {"PATH": os.environ["PATH"]})
            except preflight.AppiumHostPreflightError as error:
                result = error
        return result, seen, popen

    def test_wda_build_only_positive_has_no_server_session_or_boot(self):
        result, seen, popen = self._exercise_wda()
        self.assertEqual(result["status"], "HOST_WDA_COMPILED_ONLY")
        self.assertEqual(result["build_exit"], 0)
        for key in ("runner_bundle_verified", "xctestrun_verified", "simulator_state_unchanged", "cleanup_exited"):
            self.assertTrue(result[key])
        self.assertEqual(result["wda_package_version"], "16.15.0")
        self.assertRegex(result["wda_package_sha256"], r"^[0-9a-f]{64}$")
        popen.assert_not_called()
        commands = [args for args, _ in seen]
        self.assertEqual(sum(args[:2] == ["xcrun", "simctl"] for args in commands), 2)
        self.assertEqual(sum(args[0] == "xcodebuild" for args in commands), 1)
        build = next(args for args in commands if args[0] == "xcodebuild")
        self.assertIn("build-for-testing", build)
        self.assertIn("generic/platform=iOS Simulator", build)
        self.assertIn("CODE_SIGNING_ALLOWED=NO", build)
        self.assertNotIn("server", str(commands))
        self.assertNotIn("session", str(commands).lower())
        self.assertNotIn("boot", str(commands).lower())

    def test_prebuilt_server_compiles_before_popen_and_keeps_paths_private(self):
        combined, seen, popen = self._exercise_wda(prebuilt=True)
        result, callbacks = combined
        self.assertTrue(result["wda_build"]["runner_bundle_verified"])
        self.assertTrue(result["wda_build"]["xctestrun_verified"])
        self.assertEqual(result["wda_build"]["build_exit"], 0)
        self.assertNotIn("derived_data_path", result)
        self.assertEqual(len(callbacks), 1)
        commands = [args for args, _ in seen]
        self.assertLess(next(index for index, args in enumerate(commands) if args[0] == "xcodebuild"),
                        next(index for index, args in enumerate(commands) if args[0] == "Popen"))
        popen.assert_called_once()

    def test_prebuilt_build_failure_starts_no_server_or_callback(self):
        result, _, popen = self._exercise_wda(prebuilt=True, build_failure=b"PRIVATE_FAILURE")
        self.assertEqual(result.code, "HOST_WDA_BUILD")
        self.assertEqual(result.build_failure_category, "unknown")
        popen.assert_not_called()

    def test_wda_build_rejects_state_change_and_missing_owned_metadata_or_outputs(self):
        changed, _, popen = self._exercise_wda(changed=True)
        self.assertEqual(changed.code, "HOST_WDA_SIMULATOR_STATE_CHANGED")
        popen.assert_not_called()
        for kwargs, code in (({"bad_install": True}, "HOST_WDA_DRIVER_METADATA"),
                             ({"bad_output": True}, "HOST_WDA_OUTPUT"),
                             ({"private_version": True}, "HOST_WDA_PACKAGE"),
                             ({"escape": True}, "HOST_WDA_PACKAGE"),
                             ({"wrong_bundle": True}, "HOST_WDA_OUTPUT")):
            with self.subTest(kwargs=kwargs):
                result, _, popen = self._exercise_wda(**kwargs)
                self.assertEqual(result.code, code)
                popen.assert_not_called()

    def test_wda_build_failure_is_sanitized_and_classified(self):
        result, _, popen = self._exercise_wda(
            build_failure=b"Unable to find a destination matching the provided destination specifier PRIVATE_STDOUT")
        self.assertEqual(result.code, "HOST_WDA_BUILD")
        self.assertEqual(result.build_exit, 65)
        self.assertEqual(result.build_failure_category, "destination_not_supported")
        self.assertEqual(result.build_stdout_bytes, len(
            b"Unable to find a destination matching the provided destination specifier PRIVATE_STDOUT"))
        self.assertNotIn("PRIVATE", str(result))
        self.assertRegex(result.build_stdout_sha256, r"^[0-9a-f]{64}$")
        popen.assert_not_called()

    def test_wda_build_progress_or_unclassified_failure_stays_unknown(self):
        for output in (b"CompileC normal progress", b"PRIVATE_OTHER_FAILURE"):
            with self.subTest(output=output):
                result, _, _ = self._exercise_wda(build_failure=output)
                self.assertEqual(result.code, "HOST_WDA_BUILD")
                self.assertEqual(result.build_failure_category, "unknown")

    def test_owned_regular_rejects_lexical_escape_and_accepts_canonical_ancestry(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            root.mkdir()
            outside = base / "outside"
            outside.write_text("sentinel", encoding="ascii")
            self.assertFalse(preflight._owned_regular(root / "nested" / ".." / ".." / "outside", root, directory=False))
            inside = root / "inside"
            inside.write_text("ok", encoding="ascii")
            self.assertTrue(preflight._owned_regular(root.resolve() / "inside", root, directory=False))

    def test_owned_regular_rejects_internal_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            root.mkdir()
            outside = base / "outside"
            outside.write_text("sentinel", encoding="ascii")
            linked = root / "linked"
            try:
                os.symlink(outside, linked)
            except (NotImplementedError, OSError):
                self.skipTest("symlink creation unavailable")
            self.assertFalse(preflight._owned_regular(linked, root, directory=False))

    def test_macho_accepts_fat_headers_and_reads_only_the_header(self):
        for header in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
            self.assertTrue(preflight._valid_macho_header(header))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "large-bin"
            executable.write_bytes(b"\xca\xfe\xba\xbe" + b"x" * (preflight._JSON_LIMIT + 1))
            original_read = preflight.os.read
            with mock.patch.object(preflight.os, "read", wraps=original_read) as read:
                self.assertTrue(preflight._owned_macho(executable, root))
            self.assertEqual(read.call_args.args[1], 4)

    def test_wda_build_wrong_environment_runs_zero_commands(self):
        command = mock.Mock()
        with mock.patch.object(preflight.sys, "platform", "win32"), mock.patch.dict(preflight.os.environ, {"GITHUB_ACTIONS": "true"}):
            with self.assertRaisesRegex(preflight.AppiumHostPreflightError, "UNSUPPORTED"):
                preflight.run_appium_wda_build_preflight(command, {"PATH": os.environ["PATH"]})
        command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
