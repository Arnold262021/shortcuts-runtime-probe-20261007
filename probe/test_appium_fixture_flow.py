import json
import itertools
import unittest
from unittest.mock import patch

import appium_synthetic_ui as subject


class _Response:
    def __init__(self, value, url):
        self.value = value
        self.url = url

    def read(self, _limit):
        return json.dumps({"value": self.value}).encode("utf-8")

    def geturl(self):
        return self.url

    def close(self):
        pass


class _FixtureWire:
    endpoint = "http://127.0.0.1:4723"
    session = "synthetic-session"
    uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

    def __init__(self, *, multiple_new=False, wrong_value=False, missing_after_relaunch=False, foreground=4, termination_state=1, fail_new_click=False, shortcuts_onboarding=False, global_done=False, global_back=False, multiple_editor_parents=False, multiple_keyboards=False, multiple_done=False, multiple_navigation=False, multiple_back=False, foreground_sequence=None, termination_sequence=None, hittable_sequences=None, display_sequences=None):
        self.multiple_new = multiple_new
        self.wrong_value = wrong_value
        self.missing_after_relaunch = missing_after_relaunch
        self.foreground = foreground
        self.termination_state = termination_state
        self.fail_new_click = fail_new_click
        self.shortcuts_onboarding = shortcuts_onboarding
        self.global_done = global_done
        self.global_back = global_back
        self.multiple_editor_parents = multiple_editor_parents
        self.multiple_keyboards = multiple_keyboards
        self.multiple_done = multiple_done
        self.multiple_navigation = multiple_navigation
        self.multiple_back = multiple_back
        self.foreground_sequence = list(foreground_sequence or [])
        self.termination_sequence = list(termination_sequence or [])
        self.hittable_sequences = {key: list(values) for key, values in (hittable_sequences or {}).items()}
        self.display_sequences = {key: list(values) for key, values in (display_sequences or {}).items()}
        self.hittable_reads = []
        self.state = "fresh"
        self.keyboard_dismissed = False
        self.calls = []
        self.urls = []
        self.clicked = []
        self.typed = None

    def open(self, request, timeout):
        path = request.full_url.split(self.endpoint, 1)[1]
        body = json.loads(request.data) if request.data else None
        self.urls.append(request.full_url)
        self.calls.append((request.get_method(), path, body, timeout))
        value = self._answer(request.get_method(), path, body)
        return _Response(value, request.full_url)

    @staticmethod
    def _element(name):
        return {subject._ELEMENT: name}

    @staticmethod
    def _selector_kind(selector):
        if "Unified Automations" in selector or "What’s New in Shortcuts" in selector:
            return "shortcuts_intro"
        if 'name == "all_shortcuts_library"' in selector:
            return "library"
        if 'label == "No Shortcuts"' in selector:
            return "empty"
        if 'name == "main.button.newshortcut"' in selector:
            return "new"
        if 'name == "New Shortcut"' in selector:
            return "navbar"
        if "XCUIElementTypeNavigationBar" in selector:
            return "navigation"
        if 'label == "Editor"' in selector:
            return "editor"
        if 'label == "Automation"' in selector:
            return "automation"
        if 'label == "Message"' in selector and 'name == "enum"' not in selector:
            return "message"
        if 'WFMessageConditions' in selector:
            return "container"
        if 'value == "Sender"' in selector:
            return "sender"
        if 'value == "Message"' in selector:
            return "message_property"
        if 'label == "contains"' in selector:
            return "contains"
        if "XCUIElementTypeTextField" in selector or "XCUIElementTypeTextView" in selector:
            return "input"
        if 'label == "Text"' in selector:
            return "text"
        if 'sliding your finger' in selector:
            return "keyboard_intro"
        if 'label == "Continue"' in selector:
            return "continue"
        if 'name == "Done"' in selector:
            return "done"
        if 'name == "BackButton"' in selector:
            return "back"
        if "XCUIElementTypeKeyboard" in selector:
            return "keyboard"
        if "XCUIElementTypeCell" in selector:
            return "cell"
        return "other"

    def _elements(self, path, selector):
        parent = path.split("/element/", 1)[1].split("/elements", 1)[0] if "/element/" in path else None
        kind = self._selector_kind(selector)
        button_only = {"new", "editor", "automation", "message", "sender", "message_property", "text", "continue", "done", "back"}
        if kind in button_only and "XCUIElementTypeCell" in selector:
            return []
        if kind == "input" and "XCUIElementTypeTextView" in selector:
            return []
        if kind == "library":
            return [self._element("library")]
        if kind == "shortcuts_intro":
            return [self._element("shortcuts_intro")] if self.shortcuts_onboarding else []
        if kind == "empty":
            return [self._element("empty")] if parent == "library" and self.state == "fresh" else []
        if kind == "new":
            return [self._element("new"), self._element("new2")] if self.multiple_new else [self._element("new")]
        if kind == "navbar":
            return [self._element("navbar"), self._element("navbar2")] if self.state == "new" and self.multiple_editor_parents else ([self._element("navbar")] if self.state == "new" else [])
        if kind == "navigation":
            return [self._element("navigation"), self._element("navigation2")] if self.state == "done" and self.multiple_navigation else ([self._element("navigation")] if self.state == "done" else [])
        if kind == "editor":
            return [self._element("editor")] if parent in {"navbar", "navbar2"} and self.state == "new" else []
        if kind == "automation":
            return [self._element("automation")] if self.state == "editor" else []
        if kind == "message":
            if self.state == "automation":
                return [self._element("message")]
            if self.state == "property_menu":
                return [self._element("message_menu")]
            return []
        if kind == "container":
            return [self._element("container")] if self.state in {"message", "property_menu", "property_selected", "input_ready", "typed", "done"} else []
        if kind == "sender":
            return [self._element("sender")] if parent == "container" and self.state == "message" else []
        if kind == "message_property":
            return [self._element("message_property")] if parent == "container" and self.state in {"property_selected", "input_ready", "typed", "done"} else []
        if kind == "contains":
            return [self._element("contains")] if parent == "container" and self.state in {"property_selected", "input_ready", "typed", "done"} else []
        if kind == "text":
            return [self._element("text")] if parent == "container" and self.state == "property_selected" else []
        if kind == "input":
            return [self._element("input")] if parent == "container" and self.state in {"input_ready", "typed", "done"} else []
        if kind == "keyboard_intro":
            return [self._element("keyboard_intro")] if self.state == "input_ready" and not self.keyboard_dismissed else []
        if kind == "continue":
            return [self._element("continue")] if self.shortcuts_onboarding or (self.state == "input_ready" and not self.keyboard_dismissed) else []
        if kind == "keyboard":
            return [self._element("keyboard"), self._element("keyboard2")] if self.state == "typed" and self.multiple_keyboards else ([self._element("keyboard")] if self.state == "typed" else [])
        if kind == "done":
            if parent in {"keyboard", "keyboard2"} and self.state == "typed" and not self.global_done:
                return [self._element("done"), self._element("done2")] if self.multiple_done else [self._element("done")]
            return [self._element("global_done")] if self.global_done and parent is None else []
        if kind == "back":
            if parent in {"navigation", "navigation2"} and self.state == "done" and not self.global_back:
                return [self._element("back"), self._element("back2")] if self.multiple_back else [self._element("back")]
            return [self._element("global_back")] if self.global_back and parent is None else []
        if kind == "cell":
            if parent == "library" and self.state in {"saved", "relaunched"}:
                if self.state == "relaunched" and self.missing_after_relaunch:
                    return []
                return [self._element("cell")]
            return []
        return []

    def _answer(self, method, path, body):
        if path == "/session" and method == "POST":
            requested = body["capabilities"]["alwaysMatch"]
            capabilities = {
                "udid": self.uuid,
                "bundleId": "com.apple.shortcuts",
                "automationName": "XCUITest",
                "waitForIdleTimeout": 0,
            }
            if requested.get("appium:usePrebuiltWDA") is True:
                capabilities["usePrebuiltWDA"] = True
                capabilities["derivedDataPath"] = requested["appium:derivedDataPath"]
            return {
                "sessionId": self.session,
                "capabilities": capabilities,
            }
        if path == "/session/" + self.session and method == "DELETE":
            return None
        if path.endswith("/execute/sync") and method == "POST":
            script = body["script"]
            if script == "mobile: queryAppState":
                if self.state == "terminated":
                    if self.termination_sequence:
                        return self.termination_sequence.pop(0)
                    return self.termination_state
                if self.foreground_sequence:
                    return self.foreground_sequence.pop(0)
                return self.foreground
            if script == "mobile: activateApp":
                if self.state == "terminated":
                    self.state = "relaunched"
                return True
            if script == "mobile: terminateApp":
                self.state = "terminated"
                return True
            raise AssertionError("unexpected mobile command")
        if path.endswith("/elements") and method == "POST":
            return self._elements(path, body["value"])
        if "/element/" in path and path.endswith("/displayed"):
            if "/input/" in path and not self.keyboard_dismissed:
                raise AssertionError("input examined before keyboard onboarding was dismissed")
            element = path.split("/element/", 1)[1].split("/displayed", 1)[0]
            sequence = self.display_sequences.get(element)
            if sequence:
                return sequence.pop(0) if len(sequence) > 1 else sequence[0]
            return True
        if "/element/" in path and path.endswith("/enabled"):
            return True
        if "/attribute/hittable" in path:
            element = path.split("/element/", 1)[1].split("/attribute/", 1)[0]
            self.hittable_reads.append(element)
            sequence = self.hittable_sequences.get(element)
            if sequence:
                return sequence.pop(0) if len(sequence) > 1 else sequence[0]
            return "true"
        if "/attribute/value" in path:
            return "WRONG" if self.wrong_value else self.typed
        if path.endswith("/click") and method == "POST":
            element = path.split("/element/", 1)[1].split("/click", 1)[0]
            self.clicked.append(element)
            if element == "new" and self.fail_new_click:
                raise OSError("ambiguous synthetic mutation")
            transitions = {
                "new": "new", "editor": "editor", "automation": "automation", "message": "message",
                "sender": "property_menu", "message_menu": "property_selected", "text": "input_ready",
                "done": "done", "back": "saved",
            }
            if element == "continue":
                if self.shortcuts_onboarding:
                    self.shortcuts_onboarding = False
                else:
                    self.keyboard_dismissed = True
            elif element == "input":
                if not self.keyboard_dismissed:
                    raise AssertionError("input clicked before keyboard onboarding was dismissed")
            elif element in transitions:
                self.state = transitions[element]
            return None
        if path.endswith("/value") and method == "POST":
            element = path.split("/element/", 1)[1].split("/value", 1)[0]
            if element != "input" or not self.keyboard_dismissed:
                raise AssertionError("unexpected text mutation")
            self.typed = body["text"]
            self.state = "typed"
            return None
        raise AssertionError("unexpected wire request")


class FixtureFlowTests(unittest.TestCase):
    def _run(self, wire, **kwargs):
        with patch("urllib.request.build_opener", return_value=wire):
            return subject.run_synthetic_appium_fixture(wire.endpoint, wire.uuid, mode="fixture", **kwargs)

    def _assert_one_cleanup(self, wire):
        cleanup = [call for call in wire.calls if call[0] == "DELETE"]
        self.assertEqual(len(cleanup), 1)
        self.assertEqual(cleanup[0][:3], ("DELETE", "/session/synthetic-session", None))
        timeout = cleanup[0][3]
        self.assertIsInstance(timeout, (int, float))
        self.assertNotIsInstance(timeout, bool)
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 10)

    def test_fixture_flow_executes_the_approved_synthetic_state_machine(self):
        wire = _FixtureWire(shortcuts_onboarding=True)
        result = self._run(wire)
        self.assertEqual(result["stage"], "completed")
        self.assertTrue(result["fresh_library_empty"])
        self.assertTrue(result["filter_ready"])
        self.assertTrue(result["nonempty_after_relaunch"])
        self.assertTrue(wire.keyboard_dismissed)
        self.assertEqual(wire.typed, "AUTOMATION_TEST_ONLY")
        self.assertLess(wire.clicked.index("continue"), wire.clicked.index("new"))
        scripts = [body["script"] for _, path, body, _ in wire.calls if path.endswith("/execute/sync")]
        terminate = scripts.index("mobile: terminateApp")
        self.assertNotIn("mobile: activateApp", scripts[:terminate])
        self.assertEqual(scripts[terminate + 1:].count("mobile: activateApp"), 1)
        self._assert_one_cleanup(wire)

    def test_fixture_flow_supports_prebuilt_wda_only_when_requested(self):
        private_path = "/private/var/folders/PRIVATE_SENTINEL/DerivedData"
        wire = _FixtureWire(shortcuts_onboarding=True)
        result = self._run(wire, prebuilt_wda={"derived_data_path": private_path})
        requested = wire.calls[0][2]["capabilities"]["alwaysMatch"]
        self.assertTrue(requested["appium:usePrebuiltWDA"])
        self.assertEqual(requested["appium:derivedDataPath"], private_path)
        self.assertTrue(result["prebuilt_wda_requested"])
        self.assertTrue(result["prebuilt_wda_verified"])
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(result))
        forbidden = ("Run", "Share", "SaveToFiles", "SMS", "source")
        self.assertFalse(any(any(word in path or word in json.dumps(body) for word in forbidden) for _, path, body, _ in wire.calls))
        self.assertTrue(all(url_path.startswith("/session") for _, url_path, _, _ in wire.calls))
        self.assertTrue(all(url.startswith(wire.endpoint + "/session") for url in wire.urls))

    def test_multiple_control_blocks_before_mutation(self):
        wire = _FixtureWire(multiple_new=True)
        result = self._run(wire)
        self.assertEqual(result["failure_code"], "target_not_unique")
        self.assertNotIn("new", wire.clicked)
        self._assert_one_cleanup(wire)

    def test_wrong_marker_value_blocks_before_done(self):
        wire = _FixtureWire(wrong_value=True)
        result = self._run(wire)
        self.assertEqual(result["failure_code"], "filter_value_unconfirmed")
        self.assertNotIn("done", wire.clicked)

    def test_missing_library_after_relaunch_blocks_persistence_claim(self):
        wire = _FixtureWire(missing_after_relaunch=True)
        result = self._run(wire)
        self.assertEqual(result["failure_code"], "library_nonempty_unconfirmed")
        self.assertFalse(result["nonempty_after_relaunch"])

    def test_foreground_state_three_blocks_before_ui_gesture(self):
        wire = _FixtureWire(foreground=3)
        with patch.object(subject, "_STAGE_SECONDS", 0):
            result = self._run(wire)
        self.assertEqual(result["failure_code"], "app_not_foreground")
        self.assertEqual(wire.clicked, [])

    def test_ambiguous_new_shortcut_click_is_not_retried(self):
        wire = _FixtureWire(fail_new_click=True)
        result = self._run(wire)
        self.assertEqual(result["failure_code"], "http_ambiguous")
        self.assertEqual(wire.clicked.count("new"), 1)
        self._assert_one_cleanup(wire)

    def test_termination_must_be_confirmed_before_reactivate(self):
        for observed in (False, 3, 4):
            with self.subTest(observed=observed):
                wire = _FixtureWire(termination_state=observed)
                with patch.object(subject, "_STAGE_SECONDS", 0):
                    result = self._run(wire)
                self.assertEqual(result["failure_code"], "invalid_app_state" if observed is False else "app_not_terminated")
                scripts = [body["script"] for _, path, body, _ in wire.calls if path.endswith("/execute/sync")]
                terminate = scripts.index("mobile: terminateApp")
                self.assertNotIn("mobile: activateApp", scripts[terminate + 1:])

    def test_global_done_outside_keyboard_is_not_clicked(self):
        wire = _FixtureWire(global_done=True)
        with patch.object(subject, "_STAGE_SECONDS", 0):
            result = self._run(wire)
        self.assertEqual(result["failure_code"], "target_not_unique")
        self.assertNotIn("global_done", wire.clicked)

    def test_global_back_outside_navigation_bar_is_not_clicked(self):
        wire = _FixtureWire(global_back=True)
        with patch.object(subject, "_STAGE_SECONDS", 0):
            result = self._run(wire)
        self.assertEqual(result["failure_code"], "target_not_unique")
        self.assertNotIn("global_back", wire.clicked)

    def test_transient_read_states_wait_without_repeating_mutations(self):
        wire = _FixtureWire(
            foreground_sequence=[3, 4],
            termination_sequence=[4, 1],
            hittable_sequences={"new": ["false", "true"]},
        )
        result = self._run(wire)
        self.assertEqual(result["stage"], "completed")
        self.assertEqual(wire.clicked.count("new"), 1)
        self.assertEqual(wire.hittable_reads.count("new"), 2)
        scripts = [body["script"] for _, path, body, _ in wire.calls if path.endswith("/execute/sync")]
        self.assertEqual(scripts.count("mobile: activateApp"), 1)

    def test_permanent_false_hittable_blocks_without_click(self):
        wire = _FixtureWire(hittable_sequences={"new": ["false"]})
        with patch.object(subject, "_STAGE_SECONDS", 0):
            result = self._run(wire)
        self.assertEqual(result["failure_code"], "target_not_hittable")
        self.assertNotIn("new", wire.clicked)

    def test_invalid_hittable_type_fails_without_polling_it_away(self):
        wire = _FixtureWire(hittable_sequences={"new": [{"not": "boolean"}, "true"]})
        result = self._run(wire)
        self.assertEqual(result["failure_code"], "invalid_element_state")
        self.assertEqual(wire.hittable_reads.count("new"), 1)

    def test_visible_then_nonhittable_timeout_reports_hittable(self):
        wire = _FixtureWire(display_sequences={"new": [False, True]}, hittable_sequences={"new": ["false"]})
        with patch.object(subject, "_STAGE_SECONDS", 0.11):
            result = self._run(wire)
        self.assertEqual(result["failure_code"], "target_not_hittable")
        self.assertNotIn("new", wire.clicked)

    def test_multiple_parents_with_one_deduplicated_control_pass(self):
        wire = _FixtureWire(multiple_editor_parents=True, multiple_keyboards=True, multiple_navigation=True)
        result = self._run(wire)
        self.assertEqual(result["stage"], "completed")
        self.assertEqual(wire.clicked.count("editor"), 1)
        self.assertEqual(wire.clicked.count("done"), 1)
        self.assertEqual(wire.clicked.count("back"), 1)

    def test_two_done_or_back_controls_block_without_clicking_them(self):
        for option in ("multiple_done", "multiple_back"):
            with self.subTest(option=option):
                wire = _FixtureWire(**{option: True})
                with patch.object(subject, "_STAGE_SECONDS", 0):
                    result = self._run(wire)
                self.assertEqual(result["failure_code"], "target_not_unique")
                self.assertNotIn("done" if option == "multiple_done" else "back", wire.clicked)

    def test_cleanup_timeout_accepts_monotonic_submicrosecond_drift(self):
        wire = _FixtureWire()
        ticks = itertools.count(1000.0, 0.0000001)
        with patch.object(subject.time, "monotonic", side_effect=lambda: next(ticks)):
            result = self._run(wire)
        self.assertEqual(result["stage"], "completed")
        self._assert_one_cleanup(wire)

    def test_cleanup_helper_rejects_any_second_delete(self):
        wire = _FixtureWire()
        result = self._run(wire)
        self.assertEqual(result["stage"], "completed")
        wire.calls.append(("DELETE", "/session/synthetic-session", {}, 1.0))
        with self.assertRaises(AssertionError):
            self._assert_one_cleanup(wire)


if __name__ == "__main__":
    unittest.main()
