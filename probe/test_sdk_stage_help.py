from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

import sdk_stage_help as sdk


class SdkStageHelpUnitTests(unittest.TestCase):
    def _bounded_read(self, values):
        def read(_fd, requested):
            value = values.pop(0)
            self.assertLessEqual(len(value), requested)
            return value
        return read

    def test_commands_environment_and_platform_guard_are_exact_and_sanitized(self):
        self.assertEqual(sdk.HELP_COMMANDS, {
            "simctl_spawn_help": ("/usr/bin/xcrun", "simctl", "help", "spawn"),
            "simctl_container_help": ("/usr/bin/xcrun", "simctl", "help", "get_app_container"),
            "log_manual": ("/usr/bin/man", "log"),
        })
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            developer = root / "Developer"
            developer.mkdir()
            env = sdk._help_environment({"PRIVATE": "no", "DEVELOPER_DIR": str(developer)}, root)
        self.assertEqual(env["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
        self.assertEqual(env["PAGER"], "/bin/cat")
        self.assertEqual(env["MANPAGER"], "/bin/cat")
        self.assertNotIn("PRIVATE", env)
        self.assertNotIn("DEVELOPER_DIR", str({key: value for key, value in env.items() if key != "DEVELOPER_DIR"}))

        with mock.patch.object(sdk, "_supported_host", return_value=False):
            result = sdk.run_sdk_stage_help({"PRIVATE": "value"})
        self.assertEqual(result["error_code"], "SDK_HELP_PLATFORM")
        self.assertEqual(result["queries"], {})
        self.assertNotIn("PRIVATE", str(result))

        for platform, os_name, actions, expected in (
                ("darwin", "posix", None, False),
                ("darwin", "posix", "false", False),
                ("darwin", "posix", "true", True),
                ("win32", "nt", "true", False)):
            with self.subTest(platform=platform, os_name=os_name, actions=actions):
                with mock.patch.object(sdk.sys, "platform", platform), \
                        mock.patch.object(sdk.os, "name", os_name), \
                        mock.patch.dict(sdk.os.environ, {}, clear=True):
                    if actions is not None:
                        sdk.os.environ["GITHUB_ACTIONS"] = actions
                    self.assertIs(sdk._supported_host(), expected)

    def test_stream_metadata_has_exact_limit_and_never_hashes_prefixes(self):
        at_limit = sdk._stream_metadata(bytearray(b"x" * sdk.STREAM_LIMIT), True, False)
        self.assertTrue(at_limit["complete"])
        self.assertIn("sha256", at_limit)
        over = sdk._stream_metadata(bytearray(b"x" * (sdk.STREAM_LIMIT + 1)), False, True)
        self.assertEqual(over, {"bytes": sdk.STREAM_LIMIT + 1, "complete": False})
        self.assertNotIn("sha256", over)
        self.assertNotIn("literal_counts", over)

    def test_diagnostic_discards_bad_types_scalars_and_private_fields(self):
        source = {
            "scope": "owned_sdk_help_only", "status": "SDK_HELP_OBSERVED_ONLY",
            "unified_schema_confirmed": False, "cleanup_exited": True,
            "temporary_cleanup_confirmed": True, "PRIVATE": "sentinel",
            "queries": {
                "simctl_spawn_help": {
                    "status": "observed", "exit_code": True, "seconds": float("nan"),
                    "topic_literal_count": True,
                    "stdout": {"bytes": 2, "complete": True, "utf8": True,
                               "sha256": "a" * 64, "literal_counts": {"json": 3, "PRIVATE": 1},
                               "raw": "PRIVATE"},
                },
                "unknown": {"status": "observed"},
            },
        }
        result = sdk.sdk_help_diagnostic(source)
        self.assertEqual(set(result), {"scope", "status", "unified_schema_confirmed", "cleanup_exited",
                                       "temporary_cleanup_confirmed", "queries"})
        query = result["queries"]["simctl_spawn_help"]
        self.assertNotIn("exit_code", query)
        self.assertNotIn("seconds", query)
        self.assertNotIn("topic_literal_count", query)
        self.assertNotIn("PRIVATE", str(result))
        self.assertEqual(query["stdout"]["literal_counts"], {})
        self.assertEqual(result["status"], "SDK_HELP_UNCONFIRMED")

    def test_diagnostic_rejects_nonfinite_large_and_unhashable_values(self):
        for value in ([], {}, float("nan"), 10 ** 30, True):
            with self.subTest(value_type=type(value).__name__):
                source = {"scope": "owned_sdk_help_only", "status": "SDK_HELP_OBSERVED_ONLY",
                          "unified_schema_confirmed": False, "cleanup_exited": True,
                          "temporary_cleanup_confirmed": True, "error_code": value,
                          "queries": {"log_manual": {"status": "observed", "exit_code": value,
                                                      "seconds": value, "topic_literal_count": value,
                                                      "stdout": {"bytes": value}, "stderr": {"bytes": value}}}}
                result = sdk.sdk_help_diagnostic(source)
                self.assertEqual(result["error_code"], "SDK_HELP_QUERY")
                query = result["queries"]["log_manual"]
                self.assertNotIn("exit_code", query)
                self.assertNotIn("seconds", query)
                self.assertNotIn("topic_literal_count", query)
                self.assertNotIn("stdout", query)
                self.assertNotIn("stderr", query)

    def test_capture_rejects_non_allowlisted_command_without_starting_process(self):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(sdk.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(ValueError, "SDK_HELP_QUERY"):
                sdk._capture_help(("/usr/bin/xcrun", "simctl", "spawn"), {}, Path(directory))
        popen.assert_not_called()

    def test_capture_mocked_concurrent_streams_timeout_and_uncertain_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out_pipe, err_pipe = mock.Mock(), mock.Mock()
            out_pipe.fileno.return_value, err_pipe.fileno.return_value = 10, 11
            process = mock.Mock(stdout=out_pipe, stderr=err_pipe)
            process.poll.return_value = 0
            out_key = SimpleNamespace(data="stdout", fd=10, fileobj=out_pipe)
            err_key = SimpleNamespace(data="stderr", fd=11, fileobj=err_pipe)
            selector = mock.Mock()
            selector.select.side_effect = [[(out_key, None), (err_key, None)]] + [[(err_key, None)]] * 9
            with mock.patch.object(sdk.subprocess, "Popen", return_value=process), \
                    mock.patch.object(sdk.selectors, "DefaultSelector", return_value=selector), \
                    mock.patch.object(sdk.os, "set_blocking"), \
                    mock.patch.object(sdk.os, "read", side_effect=self._bounded_read([
                        b"", *([b"e" * 8192] * 8), b"e", b""])), \
                    mock.patch.object(sdk, "_cleanup_wda_launch", return_value=True):
                result = sdk._capture_help(sdk.HELP_COMMANDS["log_manual"], {}, root)
            self.assertEqual(result["status"], "over_limit")
            self.assertTrue(result["over_limit"])
            self.assertEqual(result["stdout"]["bytes"], 0)
            self.assertEqual(result["stderr"]["bytes"], sdk.STREAM_LIMIT)
            self.assertTrue(result["forced_cleanup"])
            self.assertFalse(result["stdout"]["complete"])
            self.assertFalse(result["stderr"]["complete"])
            self.assertNotIn("sha256", result["stdout"])
            self.assertNotIn("sha256", result["stderr"])
            out_pipe.close.assert_called_once()
            err_pipe.close.assert_called_once()

            process = mock.Mock(stdout=out_pipe, stderr=err_pipe)
            process.poll.return_value = None
            selector = mock.Mock()
            selector.select.return_value = []
            with mock.patch.object(sdk.subprocess, "Popen", return_value=process), \
                    mock.patch.object(sdk.selectors, "DefaultSelector", return_value=selector), \
                    mock.patch.object(sdk.os, "set_blocking"), \
                    mock.patch.object(sdk, "QUERY_TIMEOUT", 0.1), \
                    mock.patch.object(sdk, "EOF_TIMEOUT", 0), \
                    mock.patch.object(sdk.time, "monotonic", side_effect=[0, 0, 1, 2]), \
                    mock.patch.object(sdk, "_cleanup_wda_launch", return_value=False):
                timed = sdk._capture_help(sdk.HELP_COMMANDS["log_manual"], {}, root)
            self.assertEqual(timed["status"], "timeout")
            self.assertTrue(timed["timed_out"])
            self.assertFalse(timed["process_group_drained"])

            with mock.patch.object(sdk.subprocess, "Popen", side_effect=OSError("PRIVATE_POPEN")):
                failed = sdk._capture_help(sdk.HELP_COMMANDS["log_manual"], {}, root)
            self.assertEqual(failed["status"], "capture_failed")
            self.assertFalse(failed["process_started"])
            self.assertNotIn("PRIVATE_POPEN", str(failed))

    def test_parent_exit_drain_precedes_cleanup_and_late_eof_stays_forced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def process_and_selector():
                out_pipe, err_pipe = mock.Mock(), mock.Mock()
                out_pipe.fileno.return_value, err_pipe.fileno.return_value = 10, 11
                process = mock.Mock(stdout=out_pipe, stderr=err_pipe)
                process.poll.return_value = 0
                out_key = SimpleNamespace(data="stdout", fd=10, fileobj=out_pipe)
                err_key = SimpleNamespace(data="stderr", fd=11, fileobj=err_pipe)
                return process, out_key, err_key

            process, out_key, err_key = process_and_selector()
            selector = mock.Mock()
            selector.select.side_effect = [[(out_key, None), (err_key, None)], [(out_key, None)]]
            reads = [b"spawn tail", b"", b""]
            cleanup = mock.Mock(side_effect=lambda _: self.assertEqual(len(reads), 0) or True)
            with mock.patch.object(sdk.subprocess, "Popen", return_value=process), \
                    mock.patch.object(sdk.selectors, "DefaultSelector", return_value=selector), \
                    mock.patch.object(sdk.os, "set_blocking"), \
                    mock.patch.object(sdk.os, "read", side_effect=self._bounded_read(reads)), \
                    mock.patch.object(sdk, "_cleanup_wda_launch", cleanup):
                complete = sdk._capture_help(sdk.HELP_COMMANDS["simctl_spawn_help"], {}, root)
            self.assertEqual(complete["status"], "observed")
            self.assertFalse(complete["forced_cleanup"])
            self.assertTrue(complete["eof_confirmed"])
            self.assertIn("sha256", complete["stdout"])
            cleanup.assert_called_once_with(process)

            process, out_key, err_key = process_and_selector()
            selector = mock.Mock()
            selector.select.side_effect = [[(out_key, None), (err_key, None)], [(out_key, None)]]
            with mock.patch.object(sdk.subprocess, "Popen", return_value=process), \
                    mock.patch.object(sdk.selectors, "DefaultSelector", return_value=selector), \
                    mock.patch.object(sdk.os, "set_blocking"), \
                    mock.patch.object(sdk.os, "read", side_effect=self._bounded_read([b"spawn", b"", b""])), \
                    mock.patch.object(sdk.time, "monotonic", side_effect=[0, 0, 0, 3, 3, 4, 5, 6]), \
                    mock.patch.object(sdk, "_cleanup_wda_launch", return_value=True):
                forced = sdk._capture_help(sdk.HELP_COMMANDS["simctl_spawn_help"], {}, root)
            self.assertTrue(forced["forced_cleanup"])
            self.assertTrue(forced["eof_confirmed"])
            self.assertEqual(forced["status"], "capture_failed")
            self.assertFalse(forced["stdout"]["complete"])
            self.assertNotIn("sha256", forced["stdout"])

    def test_run_stops_after_uncertain_cleanup_and_retains_temporary_root(self):
        incomplete = {"status": "capture_failed", "process_group_drained": False,
                      "eof_confirmed": False, "stdout": {"bytes": 0, "complete": False},
                      "stderr": {"bytes": 0, "complete": False}}
        with tempfile.TemporaryDirectory() as directory:
            owned = Path(directory) / "appium-host-preflight-sdk-help-owned"
            owned.mkdir()
            with mock.patch.object(sdk, "_supported_host", return_value=True), \
                    mock.patch.object(sdk.tempfile, "mkdtemp", return_value=str(owned)), \
                    mock.patch.object(sdk, "_capture_help", return_value=incomplete) as capture, \
                    mock.patch.object(sdk, "_remove_owned_root") as remove:
                result = sdk.run_sdk_stage_help({})
        self.assertEqual(capture.call_count, 1)
        self.assertEqual(set(result["queries"]), {"simctl_spawn_help"})
        self.assertFalse(result["cleanup_exited"])
        self.assertFalse(result["temporary_cleanup_confirmed"])
        remove.assert_not_called()

    def test_run_popen_not_started_stops_but_can_remove_owned_temporary_root(self):
        not_started = {"status": "capture_failed", "process_started": False,
                       "process_group_drained": True, "eof_confirmed": False,
                       "stdout": {"bytes": 0, "complete": False},
                       "stderr": {"bytes": 0, "complete": False}}
        with tempfile.TemporaryDirectory() as directory:
            owned = Path(directory) / "appium-host-preflight-sdk-help-owned"
            owned.mkdir()
            with mock.patch.object(sdk, "_supported_host", return_value=True), \
                    mock.patch.object(sdk.tempfile, "mkdtemp", return_value=str(owned)), \
                    mock.patch.object(sdk, "_capture_help", return_value=not_started) as capture, \
                    mock.patch.object(sdk, "_remove_owned_root") as remove:
                result = sdk.run_sdk_stage_help({})
        self.assertEqual(capture.call_count, 1)
        self.assertTrue(result["cleanup_exited"])
        self.assertTrue(result["temporary_cleanup_confirmed"])
        remove.assert_called_once()
        self.assertEqual(result["status"], "SDK_HELP_UNCONFIRMED")

    def test_run_capture_exception_stops_without_removing_temporary_root(self):
        with tempfile.TemporaryDirectory() as directory:
            owned = Path(directory) / "appium-host-preflight-sdk-help-owned"
            owned.mkdir()
            with mock.patch.object(sdk, "_supported_host", return_value=True), \
                    mock.patch.object(sdk.tempfile, "mkdtemp", return_value=str(owned)), \
                    mock.patch.object(sdk, "_capture_help", side_effect=RuntimeError("PRIVATE_CAPTURE")) as capture, \
                    mock.patch.object(sdk, "_remove_owned_root") as remove:
                result = sdk.run_sdk_stage_help({})
        capture.assert_called_once()
        remove.assert_not_called()
        self.assertEqual(result["error_code"], "SDK_HELP_SETUP")
        self.assertFalse(result["cleanup_exited"])
        self.assertEqual(result["queries"], {})
        self.assertNotIn("PRIVATE_CAPTURE", str(result))


@unittest.skipUnless(os.name == "posix", "requires POSIX process groups; intentionally skipped on Windows")
class SdkStageHelpPosixEngineTests(unittest.TestCase):
    def _capture(self, scripts, *, timeout=None):
        real_popen = subprocess.Popen

        def translated(argv, **kwargs):
            self.assertIn(tuple(argv), sdk.HELP_COMMANDS.values())
            return real_popen([sys.executable, "-c", scripts[tuple(argv)]], **kwargs)

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(sdk.subprocess, "Popen", side_effect=translated), \
                mock.patch.object(sdk, "QUERY_TIMEOUT", timeout if timeout is not None else sdk.QUERY_TIMEOUT):
            return sdk._capture_help(next(iter(sdk.HELP_COMMANDS.values())), {"PATH": os.environ["PATH"]}, Path(directory))

    def test_concurrent_stream_flood_is_bounded_without_hashing_partial_output(self):
        flood = "import sys; sys.stdout.write('a'*70000); sys.stdout.flush(); sys.stderr.write('b'*70000); sys.stderr.flush()"
        scripts = {argv: flood for argv in sdk.HELP_COMMANDS.values()}
        result = self._capture(scripts)
        self.assertEqual(result["status"], "over_limit")
        self.assertTrue(result["over_limit"])
        self.assertTrue(result["process_group_drained"])
        self.assertNotIn("sha256", result["stdout"])
        self.assertNotIn("sha256", result["stderr"])
        self.assertLessEqual(result["stdout"]["bytes"], sdk.STREAM_LIMIT)
        self.assertLessEqual(result["stderr"]["bytes"], sdk.STREAM_LIMIT)

    def test_timeout_and_inherited_pipe_children_have_bounded_cleanup_outcomes(self):
        scripts = {argv: "import time; time.sleep(60)" for argv in sdk.HELP_COMMANDS.values()}
        timed = self._capture(scripts, timeout=0.15)
        self.assertEqual(timed["status"], "timeout")
        self.assertTrue(timed["process_group_drained"])

        completed_child = ("import subprocess,sys,time; "
                 "subprocess.Popen([sys.executable,'-c',\"import time; time.sleep(.2); print('spawn rest')\"]); "
                 "print('spawn first'); sys.stdout.flush()")
        scripts = {argv: completed_child if argv[-1] == "spawn" else "print(%r)" % argv[-1]
                   for argv in sdk.HELP_COMMANDS.values()}
        complete = self._capture(scripts)
        self.assertEqual(complete["status"], "observed")
        self.assertFalse(complete["forced_cleanup"])
        self.assertTrue(complete["eof_confirmed"])
        self.assertIn("sha256", complete["stdout"])

        child = ("import subprocess,sys,time,signal; "
                 "subprocess.Popen([sys.executable,'-c',\"import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)\"]); "
                 "print('spawn parent-exits'); sys.stdout.flush()")
        scripts = {argv: child if argv[-1] == "spawn" else "print(%r)" % argv[-1]
                   for argv in sdk.HELP_COMMANDS.values()}
        result = self._capture(scripts)
        self.assertTrue(result["process_group_drained"])
        self.assertTrue(result["eof_confirmed"])
        self.assertTrue(result["forced_cleanup"])
        self.assertEqual(result["status"], "capture_failed")
        self.assertFalse(result["stdout"]["complete"])
        self.assertNotIn("sha256", result["stdout"])
