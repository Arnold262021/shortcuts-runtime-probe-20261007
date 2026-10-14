from pathlib import Path
import shutil
import sys
import tempfile
import textwrap
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).parent


def workflow_source(root):
    published = root.parent / ".github/workflows/shortcuts-simulator.yml"
    return published if published.is_file() else root / "shortcuts-simulator.yml"


class ProbeLayoutTests(unittest.TestCase):
    @staticmethod
    def _workflow_step(workflow, name, next_name):
        body = workflow.split(f"- name: {name}", 1)[1]
        return body.split(f"- name: {next_name}", 1)[0]

    def _assert_focal_step_conditions(self, workflow):
        broad = self._workflow_step(
            workflow, "Test generic probe contracts", "Test focal synthetic POSIX contracts")
        focal = self._workflow_step(
            workflow, "Test focal synthetic POSIX contracts", "Inspect selected generic lab mode")
        inspect = self._workflow_step(
            workflow, "Inspect selected generic lab mode", "Preserve synthetic UI evidence")
        self.assertIn("if: inputs.probe_mode != 'sdk-posix-fixture-preflight'", broad)
        self.assertIn("if: inputs.probe_mode == 'sdk-posix-fixture-preflight'", focal)
        self.assertIn("if: inputs.probe_mode != 'sdk-posix-fixture-preflight'", inspect)

    def _focal_namespace(self):
        workflow = workflow_source(ROOT).read_text(encoding="utf-8")
        block = workflow.split("# POSIX_FIXTURE_INLINE_BEGIN", 1)[1]
        block = block.split("# POSIX_FIXTURE_INLINE_END", 1)[0]
        namespace = {"__name__": "focal_inline"}
        exec(textwrap.dedent(block), namespace)
        return namespace

    def _focal_cases(self, caller, single):
        module = types.ModuleType("test_sdk_stage_help")

        class FakeCaller(unittest.TestCase):
            def test_run_stops_after_uncertain_cleanup_and_retains_temporary_root(self):
                return caller(self)

        class FakeSingle(unittest.TestCase):
            def test_single_term_ignoring_process_is_drained_after_forced_cleanup(self):
                return single(self)

        module.SdkStageHelpUnitTests = FakeCaller
        module.SdkStageHelpPosixEngineTests = FakeSingle
        return module

    def _decorated_focal_cases(self, kind):
        module = self._focal_cases(lambda _case: None, lambda _case: None)

        if kind == "expected":
            def caller(_case):
                raise AssertionError("PRIVATE_SENTINEL_EXPECTED")
            module.SdkStageHelpUnitTests.test_run_stops_after_uncertain_cleanup_and_retains_temporary_root = unittest.expectedFailure(caller)
        elif kind == "unexpected":
            def caller(_case):
                return None
            module.SdkStageHelpUnitTests.test_run_stops_after_uncertain_cleanup_and_retains_temporary_root = unittest.expectedFailure(caller)
        else:
            raise AssertionError("unknown decorated fixture")
        return module

    def _run_focal(self, namespace, module, artifacts):
        with patch.dict(sys.modules, {"test_sdk_stage_help": module}), \
                patch.dict(namespace, {"host_supported": lambda: True}), \
                patch("subprocess.Popen", side_effect=AssertionError("no subprocess")):
            return namespace["run_focal"](artifacts)

    def test_focal_posix_workflow_selects_exactly_two_cases_and_excludes_other_modes(self) -> None:
        workflow = workflow_source(ROOT).read_text(encoding="utf-8")
        self._assert_focal_step_conditions(workflow)
        self.assertIn("- sdk-posix-fixture-preflight", workflow)
        focal = workflow.split("# POSIX_FIXTURE_INLINE_BEGIN", 1)[1]
        focal = focal.split("# POSIX_FIXTURE_INLINE_END", 1)[0]
        self.assertIn("caller_false_cleanup", focal)
        self.assertIn("single_forced_cleanup", focal)
        self.assertIn("test_run_stops_after_uncertain_cleanup_and_retains_temporary_root", focal)
        self.assertIn("test_single_term_ignoring_process_is_drained_after_forced_cleanup", focal)
        self.assertNotIn("discover", focal)
        self.assertNotIn("run_sdk_stage_help", focal)
        self.assertNotIn("inspect_simulator", focal)

    def test_focal_step_conditions_reject_individual_missing_guards(self) -> None:
        workflow = workflow_source(ROOT).read_text(encoding="utf-8")
        conditions = (
            ("Test generic probe contracts", "if: inputs.probe_mode != 'sdk-posix-fixture-preflight'"),
            ("Test focal synthetic POSIX contracts", "if: inputs.probe_mode == 'sdk-posix-fixture-preflight'"),
            ("Inspect selected generic lab mode", "if: inputs.probe_mode != 'sdk-posix-fixture-preflight'"),
        )
        for step, condition in conditions:
            with self.subTest(step=step):
                start = workflow.index(f"- name: {step}")
                condition_start = workflow.index(condition, start)
                mutated = workflow[:condition_start] + workflow[condition_start + len(condition):]
                with self.assertRaises(AssertionError):
                    self._assert_focal_step_conditions(mutated)

    def test_focal_guard_prevents_import_and_records_unconfirmed_receipt(self) -> None:
        namespace = self._focal_namespace()
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(namespace, {"host_supported": lambda: False}), \
                patch.dict(sys.modules, {"test_sdk_stage_help": None}):
            artifacts = Path(directory) / "artifacts"
            code, receipt = namespace["run_focal"](artifacts)
            stored = (artifacts / "posix-fixture-receipt.json").read_text(encoding="utf-8")
        self.assertEqual(code, 1)
        self.assertEqual(receipt["status"], "POSIX_FIXTURE_UNCONFIRMED")
        self.assertFalse(receipt["guard_confirmed"])
        self.assertEqual(receipt["tests_run"], 0)
        self.assertEqual(receipt["outcomes"], {
            "caller_false_cleanup": "not_run", "single_forced_cleanup": "not_run"})
        self.assertNotIn("test_sdk_stage_help", stored)

    def test_focal_host_guard_requires_darwin_posix_and_literal_github_true(self) -> None:
        namespace = self._focal_namespace()
        host = namespace["host_supported"]
        runtime_sys = namespace["sys"]
        runtime_os = namespace["os"]
        cases = (
            ("darwin", "posix", "true", True),
            ("darwin", "posix", "false", False),
            ("darwin", "posix", None, False),
            ("linux", "posix", "true", False),
            ("darwin", "nt", "true", False),
            ("win32", "nt", "true", False),
        )
        for platform, name, actions, expected in cases:
            with self.subTest(platform=platform, name=name, actions=actions), \
                    patch.object(runtime_sys, "platform", platform), \
                    patch.object(runtime_os, "name", name), \
                    patch.dict(runtime_os.environ, {}, clear=True):
                if actions is not None:
                    runtime_os.environ["GITHUB_ACTIONS"] = actions
                self.assertIs(host(), expected)

    def test_focal_import_error_with_true_guard_stops_before_single_and_sanitizes_stored_json(self) -> None:
        namespace = self._focal_namespace()
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(namespace, {"host_supported": lambda: True}), \
                patch.dict(sys.modules, {"test_sdk_stage_help": None}):
            artifacts = Path(directory) / "artifacts"
            code, receipt = namespace["run_focal"](artifacts)
            stored = (artifacts / "posix-fixture-receipt.json").read_text(encoding="utf-8")
        self.assertEqual(code, 1)
        self.assertEqual(receipt["status"], "POSIX_FIXTURE_UNCONFIRMED")
        self.assertTrue(receipt["guard_confirmed"])
        self.assertEqual(receipt["tests_run"], 0)
        self.assertEqual(receipt["outcomes"]["single_forced_cleanup"], "not_run")
        self.assertNotIn("test_sdk_stage_help", stored)
        self.assertNotIn("Traceback", stored)

    def test_focal_passes_only_when_both_frozen_cases_pass_without_processes(self) -> None:
        namespace = self._focal_namespace()
        module = self._focal_cases(lambda _case: None, lambda _case: None)
        with tempfile.TemporaryDirectory() as directory:
            code, receipt = self._run_focal(namespace, module, Path(directory) / "artifacts")
        self.assertEqual(code, 0)
        self.assertEqual(receipt["status"], "POSIX_FIXTURE_ASSERTIONS_PASSED_ONLY")
        self.assertTrue(receipt["guard_confirmed"])
        self.assertEqual(receipt["tests_run"], 2)
        self.assertEqual(receipt["counts"], {
            "failures": 0, "errors": 0, "skipped": 0, "subtest_failures": 0,
            "expected_failures": 0, "unexpected_successes": 0, "unknown_callbacks": 0})
        self.assertEqual(receipt["outcomes"], {
            "caller_false_cleanup": "passed", "single_forced_cleanup": "passed"})
        self.assertFalse(receipt["broad_suite_run"])
        self.assertFalse(receipt["inspector_run"])
        self.assertFalse(receipt["sdk_help_commands_run"])

    def test_focal_first_red_stops_single_and_sanitizes_callback_failures(self) -> None:
        callbacks = {
            "failure": lambda case: case.fail("PRIVATE_SENTINEL_FAILURE"),
            "error": lambda _case: (_ for _ in ()).throw(RuntimeError("PRIVATE_SENTINEL_ERROR")),
            "skip": lambda case: case.skipTest("PRIVATE_SENTINEL_SKIP"),
            "subtest": lambda case: self._failing_subtest(case),
        }
        for name, caller in callbacks.items():
            with self.subTest(callback=name), tempfile.TemporaryDirectory() as directory:
                namespace = self._focal_namespace()
                ran_single = []
                module = self._focal_cases(caller, lambda _case: ran_single.append(True))
                code, receipt = self._run_focal(namespace, module, Path(directory) / "artifacts")
                stored = (Path(directory) / "artifacts" / "posix-fixture-receipt.json").read_text(encoding="utf-8")
                self.assertEqual(code, 1)
                self.assertEqual(receipt["tests_run"], 1)
                self.assertEqual(receipt["outcomes"]["single_forced_cleanup"], "not_run")
                self.assertFalse(ran_single)
                self.assertNotIn("PRIVATE_SENTINEL", str(receipt))
                self.assertNotIn("PRIVATE_SENTINEL", stored)

        for name in ("expected", "unexpected"):
            with self.subTest(callback=name), tempfile.TemporaryDirectory() as directory:
                namespace = self._focal_namespace()
                module = self._decorated_focal_cases(name)
                code, receipt = self._run_focal(namespace, module, Path(directory) / "artifacts")
                stored = (Path(directory) / "artifacts" / "posix-fixture-receipt.json").read_text(encoding="utf-8")
                self.assertEqual(code, 1)
                self.assertEqual(receipt["tests_run"], 1)
                self.assertEqual(receipt["outcomes"]["single_forced_cleanup"], "not_run")
                self.assertNotIn("PRIVATE_SENTINEL", str(receipt))
                self.assertNotIn("PRIVATE_SENTINEL", stored)

    @staticmethod
    def _failing_subtest(case):
        with case.subTest("PRIVATE_SENTINEL_SUBTEST"):
            case.fail("PRIVATE_SENTINEL_SUBTEST")

    def test_focal_result_rejects_unknown_callbacks_and_invalid_counts(self) -> None:
        namespace = self._focal_namespace()
        case_one = unittest.FunctionTestCase(lambda: None)
        case_two = unittest.FunctionTestCase(lambda: None)
        unknown = unittest.FunctionTestCase(lambda: None)
        result = namespace["SanitizedResult"]((case_one, case_two))
        result.startTest(unknown)
        _, passed = result.snapshot()
        self.assertFalse(passed)
        self.assertEqual(result.counts["unknown_callbacks"], 1)
        for callback in (
                lambda value: value.stopTest(unknown),
                lambda value: value.addDuration(unknown, 1.0),
                lambda value: value.addSubTest(case_one, object(), "not-an-exception")):
            result = namespace["SanitizedResult"]((case_one, case_two))
            callback(result)
            _, passed = result.snapshot()
            self.assertFalse(passed)
            self.assertGreater(result.counts["unknown_callbacks"], 0)
        for invalid in (False, float("nan"), -1, 33):
            result = namespace["SanitizedResult"]((case_one, case_two))
            result.testsRun = 2
            result.outcomes = {"caller_false_cleanup": "passed", "single_forced_cleanup": "passed"}
            result.counts["errors"] = invalid
            snapshot, passed = result.snapshot()
            self.assertFalse(passed)
            self.assertEqual(snapshot["counts"]["errors"], 0)
        result = namespace["SanitizedResult"]((case_one, case_two))
        result.testsRun = 1
        result.outcomes = {"caller_false_cleanup": "passed", "single_forced_cleanup": "passed"}
        _, passed = result.snapshot()
        self.assertFalse(passed)
        result = namespace["SanitizedResult"]((case_one, case_two))
        result.testsRun = 2
        result.outcomes["caller_false_cleanup"] = True
        snapshot, passed = result.snapshot()
        self.assertFalse(passed)
        self.assertEqual(snapshot["outcomes"]["caller_false_cleanup"], "not_run")

    def test_focal_callback_precedence_never_allows_late_success_to_clear_a_red_result(self) -> None:
        namespace = self._focal_namespace()
        case_one = unittest.FunctionTestCase(lambda: None)
        case_two = unittest.FunctionTestCase(lambda: None)
        for callback, expected, count in (
                ("addFailure", "failed", "failures"),
                ("addError", "error", "errors")):
            with self.subTest(callback=callback):
                result = namespace["SanitizedResult"]((case_one, case_two))
                result.startTest(case_one)
                getattr(result, callback)(case_one, (AssertionError, AssertionError("PRIVATE_SENTINEL"), None))
                result.addSuccess(case_one)
                result.startTest(case_two)
                result.addSuccess(case_two)
                snapshot, passed = result.snapshot()
                self.assertFalse(passed)
                self.assertEqual(snapshot["tests_run"], 2)
                self.assertEqual(snapshot["outcomes"]["caller_false_cleanup"], expected)
                self.assertEqual(snapshot["outcomes"]["single_forced_cleanup"], "passed")
                self.assertEqual(snapshot["counts"][count], 1)
                self.assertNotIn("PRIVATE_SENTINEL", str(snapshot))

    def test_focal_receipt_write_error_returns_unconfirmed_without_private_error_text(self) -> None:
        namespace = self._focal_namespace()
        module = self._focal_cases(lambda _case: None, lambda _case: None)
        original_open = Path.open

        def deny_receipt(path, *args, **kwargs):
            if path.name == "posix-fixture-receipt.json":
                raise OSError("PRIVATE_SENTINEL_WRITE")
            return original_open(path, *args, **kwargs)

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(Path, "open", autospec=True, side_effect=deny_receipt):
            code, receipt = self._run_focal(namespace, module, Path(directory) / "artifacts")
        self.assertEqual(code, 1)
        self.assertEqual(receipt["status"], "POSIX_FIXTURE_UNCONFIRMED")
        self.assertNotIn("PRIVATE_SENTINEL", str(receipt))

    def test_focal_refuses_to_overwrite_existing_artifact_directory(self) -> None:
        namespace = self._focal_namespace()
        module = self._focal_cases(lambda _case: None, lambda _case: None)
        with tempfile.TemporaryDirectory() as directory:
            artifacts = Path(directory) / "artifacts"
            artifacts.mkdir()
            marker = artifacts / "preexisting-marker"
            marker.write_text("preserve", encoding="utf-8")
            code, receipt = self._run_focal(namespace, module, artifacts)
            self.assertTrue(marker.is_file())
        self.assertEqual(code, 1)
        self.assertEqual(receipt["status"], "POSIX_FIXTURE_UNCONFIRMED")
        self.assertEqual(receipt["tests_run"], 0)

    def test_workflow_contract_also_runs_in_the_published_layout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "probe"
            root.mkdir()
            published = root.parent / ".github/workflows/shortcuts-simulator.yml"
            published.parent.mkdir(parents=True)
            shutil.copyfile(workflow_source(ROOT), published)
            with patch.object(sys.modules[__name__], "ROOT", root):
                self.test_workflow_exposes_only_bounded_lab_modes()

    def test_workflow_exposes_only_bounded_lab_modes(self) -> None:
        workflow = workflow_source(ROOT).read_text(encoding="utf-8")
        self.assertIn("type: choice", workflow)
        self.assertIn("default: open-handles", workflow)
        self.assertIn("- lsof-preflight", workflow)
        self.assertIn("- observed-shortcuts-schema", workflow)
        self.assertIn("- synthetic-action-shape", workflow)
        self.assertIn("- appium-host-preflight", workflow)
        self.assertIn("- appium-session-preflight", workflow)
        self.assertIn("- appium-wda-build-preflight", workflow)
        self.assertIn("- appium-prebuilt-session-preflight", workflow)
        self.assertIn("- wda-launch-preflight", workflow)
        self.assertIn("- sdk-help-preflight", workflow)
        self.assertIn("SHORTCUTS_PROBE_EXECUTION_MODE: ${{ inputs.probe_mode }}", workflow)
        self.assertIn("timeout-minutes: 15", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        tests = workflow.split("- name: Test generic probe contracts", 1)[1]
        tests, inspect = tests.split("- name: Inspect selected generic lab mode", 1)
        self.assertNotIn("env:", tests)
        self.assertNotIn("SHORTCUTS_PROBE_EXECUTION_MODE", tests)
        self.assertEqual(workflow.count("SHORTCUTS_PROBE_EXECUTION_MODE"), 1)
        inspect = inspect.split("- name: Preserve synthetic UI evidence", 1)[0]
        self.assertIn("env:", inspect)
        self.assertIn("SHORTCUTS_PROBE_EXECUTION_MODE", inspect)

    def test_local_fixture_persistence_never_runs_or_exports(self) -> None:
        source = (ROOT / "AppleSimulatorProbeUITests" / "ShortcutsObservationTests.swift").read_text(encoding="utf-8")
        self.assertIn('guard requireEmptySyntheticLibrary(in: shortcuts)', source)
        self.assertIn('application.navigationBars.buttons.matching(identifier: "BackButton")', source)
        self.assertIn('"No Shortcuts"', source)
        self.assertIn('guard empty.count == 0, library.cells.count > 0', source)
        self.assertIn('application.terminate()', source)
        self.assertIn('application.launch()', source)
        self.assertIn('PROBE_SYNTHETIC_LIBRARY_NONEMPTY_AFTER_RELAUNCH=true', source)
        persistence = source.split('private func persistSyntheticFixtureWithoutRunning', 1)[1]
        persistence = persistence.split('private func selectObservedFileFormat', 1)[0]
        self.assertNotIn('"Run"', persistence)
        self.assertNotIn('"Share"', persistence)
        self.assertNotIn('"Save to Files"', persistence)

    def test_active_schema_trial_never_repeats_blocked_export(self) -> None:
        source = (ROOT / "AppleSimulatorProbeUITests" / "ShortcutsObservationTests.swift").read_text(encoding="utf-8")
        method = source.split("func testCreateSyntheticMessageFilterWithoutRunningOrExporting()", 1)[1]
        method = method.split("private func selectObservedFileFormat", 1)[0]
        self.assertIn('mode == "schema-only"', method)
        self.assertIn('PROBE_SYNTHETIC_FILTER_READY=true', method)
        self.assertNotIn('"Share"', method)
        self.assertNotIn('"Save to Files"', method)
        self.assertNotIn('"Options"', method)

    def test_project_declares_a_ui_test_scheme(self) -> None:
        project = (ROOT / "AppleSimulatorProbe.xcodeproj" / "project.pbxproj").read_text(encoding="utf-8")
        scheme = (ROOT / "AppleSimulatorProbe.xcodeproj" / "xcshareddata" / "xcschemes" / "AppleSimulatorProbe.xcscheme").read_text(encoding="utf-8")
        self.assertIn("com.apple.product-type.bundle.ui-testing", project)
        self.assertIn("AppleSimulatorProbeUITests", scheme)

    def test_editor_uses_only_the_synthetic_filter_and_never_runs_or_exports(self) -> None:
        source = (ROOT / "AppleSimulatorProbeUITests" / "ShortcutsObservationTests.swift").read_text(encoding="utf-8")
        self.assertIn('environment["SHORTCUTS_BUNDLE_ID"]', source)
        self.assertIn('environment["TEST_RUNNER_SHORTCUTS_BUNDLE_ID"]', source)
        self.assertIn('XCUIApplication(bundleIdentifier: bundleID)', source)
        self.assertIn('"main.button.newshortcut"', source)
        self.assertIn('syntheticPhrase = "AUTOMATION_TEST_ONLY"', source)
        self.assertIn('dismissKeyboardOnboardingIfPresent', source)
        self.assertIn('dismissShortcutsOnboardingIfPresent', source)
        self.assertIn('"Unified Automations"', source)
        self.assertIn('"What’s New in Shortcuts"', source)
        self.assertIn('Speed up your typing by sliding your finger across the letters to compose a word.', source)
        self.assertIn('if !hasNamedControl("Automation", in: shortcuts)', source)
        self.assertIn('tapNamedControl("Edit"', source)
        self.assertIn('tapNamedControl("Automation"', source)
        self.assertIn('tapNamedControl("Message"', source)
        self.assertIn('"editor.action.WFMessageTrigger.WFMessageConditions"', source)
        self.assertIn('guard conditionContainers.count == 1', source)
        self.assertIn('"enum", "Sender"', source)
        self.assertIn('"enum", "Message"', source)
        self.assertIn('tapNamedControl("Message", in: application, stage: "message-filter-property")', source)
        self.assertIn('var fields = container.textFields', source)
        self.assertIn('var textViews = container.textViews', source)
        self.assertIn('"Text", "enum", "contact"', source)
        self.assertIn('stage: "message-condition-text-editor-hypothesis"', source)
        self.assertNotIn('application.textFields.matching(nonSearch)', source)
        self.assertNotIn('application.textViews.matching(nonSearch)', source)
        self.assertNotIn('placeholderValue == %@', source)
        self.assertIn('"contains"', source)
        self.assertIn('stage: "message-filter-property-menu"', source)
        self.assertIn('guard total == 1', source)
        self.assertIn('guard target.isHittable', source)
        self.assertIn('target.typeText(syntheticPhrase)', source)
        self.assertIn('guard target.value as? String == syntheticPhrase', source)
        self.assertIn('PROBE_NAVIGATION_BLOCKED_AT_', source)
        self.assertIn('PROBE_MESSAGE_FILTER_VALUE_OBSERVED', source)
        self.assertNotIn('PROBE_MESSAGE_FILTER_CONFIGURED', source)
        self.assertIn("PROBE_SHORTCUTS_BUNDLE_ID_MISSING", source)
        self.assertIn("PROBE_SHORTCUTS_BUNDLE_ID_CONFLICT", source)
        self.assertIn("PROBE_SHORTCUTS_LAUNCH_FAILED", source)
        self.assertIn("PROBE_UI_BEGIN", source)
        self.assertIn("PROBE_UI_END", source)
        self.assertIn("XCTAttachment(string: tree)", source)
        self.assertIn("XCTAttachment(screenshot: application.screenshot())", source)
        self.assertIn("@MainActor", source)
        self.assertNotIn('tapNamedControl("Run"', source)
        self.assertNotIn('tapNamedControl("Save"', source)
        self.assertNotIn('tapNamedControl("Export', source)
        self.assertNotIn('tapNamedControl("Sender"', source)
        self.assertNotIn('URLSession', source)
        self.assertNotIn("run-shortcut", source)
        self.assertNotIn("messages", source.lower())
        self.assertNotIn("sms", source.lower())

    def test_test_target_does_not_link_xctest_through_sdkroot(self) -> None:
        project = (ROOT / "AppleSimulatorProbe.xcodeproj" / "project.pbxproj").read_text(encoding="utf-8")
        self.assertNotIn("System/Library/Frameworks/XCTest.framework", project)
        self.assertIn("org.example.AppleSimulatorProbe", project)
        self.assertNotIn("fuxionerd", project.lower())

    def test_observed_editor_mode_uses_scoped_accessibility_label(self) -> None:
        source = (ROOT / "AppleSimulatorProbeUITests" / "ShortcutsObservationTests.swift").read_text(encoding="utf-8")
        self.assertIn('shortcuts.navigationBars.matching(identifier: "New Shortcut")', source)
        self.assertIn('.buttons.matching(NSPredicate(format: "label == %@", "Editor"))', source)
        self.assertIn('tapUnique(editorMode, in: shortcuts, stage: "switch-to-action-editor")', source)
        self.assertLess(source.index('stage: "switch-to-action-editor"'),
                        source.index('tapNamedControl("Edit"'))


if __name__ == "__main__":
    unittest.main(verbosity=2)
