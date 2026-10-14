from __future__ import annotations

from types import SimpleNamespace
import json
import os
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
