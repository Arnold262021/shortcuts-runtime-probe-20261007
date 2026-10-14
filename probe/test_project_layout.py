from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).parent


def workflow_source(root):
    published = root.parent / ".github/workflows/shortcuts-simulator.yml"
    return published if published.is_file() else root / "shortcuts-simulator.yml"


class ProbeLayoutTests(unittest.TestCase):
    def test_workflow_contract_also_runs_in_the_published_layout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "probe"
            root.mkdir()
            published = root.parent / ".github/workflows/shortcuts-simulator.yml"
            published.parent.mkdir(parents=True)
            shutil.copyfile(workflow_source(ROOT), published)
            with patch(__name__ + ".ROOT", root):
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
