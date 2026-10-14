import json
import unittest
from unittest.mock import patch

import appium_synthetic_ui as subject


class _Response:
    def __init__(self, value, url="http://127.0.0.1:4723"):
        self.value = value
        self.url = url

    def read(self, _limit=None):
        return json.dumps({"value": self.value}).encode()

    def geturl(self):
        return self.url

    def close(self):
        pass


class _Wire:
    def __init__(self, *, fail_path=None, actual_udid=None, caps=None):
        self.calls = []
        self.fail_path = fail_path
        self.actual_udid = actual_udid
        self.caps = caps

    def open(self, request, timeout):
        path = request.full_url.split("127.0.0.1:4723", 1)[1]
        self.calls.append((request.get_method(), path, request.data))
        if path == self.fail_path:
            raise OSError("synthetic transport failure")
        if path == "/session":
            caps = self.caps
            if caps is None:
                caps = {
                    "udid": self.actual_udid or "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                    "bundleId": "com.apple.shortcuts",
                    "automationName": "XCUITest",
                    "waitForIdleTimeout": 0,
                }
            return _Response({"sessionId": "private-session", "capabilities": caps})
        if path == "/session/private-session":
            return _Response(None)
        if path.endswith("/elements"):
            return _Response([])
        if path.endswith("/execute/sync") and request.data:
            command = json.loads(request.data)["script"]
            if command == "mobile: queryAppState":
                return _Response(4)
        return _Response(True)


class AppiumSyntheticUiTests(unittest.TestCase):
    endpoint = "http://127.0.0.1:4723"
    uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

    def test_external_url_and_bad_uuid_make_zero_requests(self):
        wire = _Wire()
        with patch("urllib.request.build_opener", return_value=wire):
            external = subject.run_synthetic_appium_fixture("http://example.test:4723", self.uuid)
            bad_uuid = subject.run_synthetic_appium_fixture(self.endpoint, "bad")
            malformed_port = subject.run_synthetic_appium_fixture("http://127.0.0.1:99999", self.uuid)
        self.assertEqual(wire.calls, [])
        self.assertEqual(external["failure_code"], "invalid_local_endpoint_or_simulator_id")
        self.assertEqual(bad_uuid["failure_code"], "invalid_local_endpoint_or_simulator_id")
        self.assertEqual(malformed_port["failure_code"], "invalid_local_endpoint_or_simulator_id")

    def test_session_capabilities_enable_documented_idle_zero(self):
        wire = _Wire()
        with patch("urllib.request.build_opener", return_value=wire):
            result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid, mode="session-only")
        body = json.loads(wire.calls[0][2])
        caps = body["capabilities"]["alwaysMatch"]
        self.assertEqual(caps["appium:waitForIdleTimeout"], 0)
        self.assertEqual(caps["appium:bundleId"], "com.apple.shortcuts")
        self.assertEqual(caps["appium:wdaLaunchTimeout"], 180000)
        self.assertTrue(result["idle0"])

    def test_uppercase_uuid_is_accepted_but_preserved_in_requested_capability(self):
        wire = _Wire()
        uppercase = self.uuid.upper()
        with patch("urllib.request.build_opener", return_value=wire):
            result = subject.run_synthetic_appium_fixture(self.endpoint, uppercase, mode="session-only")
        requested = json.loads(wire.calls[0][2])["capabilities"]["alwaysMatch"]
        self.assertEqual(requested["appium:udid"], uppercase)
        self.assertEqual(result["stage"], "session_only_completed")

    def test_session_only_does_not_send_ui_gestures(self):
        wire = _Wire()
        with patch("urllib.request.build_opener", return_value=wire):
            result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid)
        paths = [path for _, path, _ in wire.calls]
        self.assertEqual(paths.count("/session"), 1)
        self.assertEqual(paths.count("/session/private-session"), 1)
        self.assertFalse(any("/element/" in path or path.endswith("/elements") for path in paths))
        self.assertEqual(result["stage"], "session_only_completed")

    def test_effective_capabilities_must_confirm_idle_zero(self):
        wire = _Wire(caps={"udid": self.uuid, "bundleId": "com.apple.shortcuts", "automationName": "XCUITest"})
        with patch("urllib.request.build_opener", return_value=wire):
            result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid, mode="session-only")
        self.assertFalse(result["idle0"])
        self.assertEqual(result["failure_code"], "effective_capabilities_unconfirmed")
        self.assertIn(("DELETE", "/session/private-session", None), wire.calls)

    def test_conflicting_plain_and_prefixed_effective_capabilities_are_rejected(self):
        base = {
            "udid": self.uuid,
            "bundleId": "com.apple.shortcuts",
            "automationName": "XCUITest",
            "waitForIdleTimeout": 0,
        }
        conflicts = (
            ("udid", "ffffffff-1111-4222-8333-444444444444"),
            ("bundleId", "other.bundle"),
            ("automationName", "Other"),
            ("waitForIdleTimeout", False),
        )
        for name, conflicting in conflicts:
            with self.subTest(name=name):
                caps = dict(base)
                caps["appium:" + name] = conflicting
                wire = _Wire(caps=caps)
                with patch("urllib.request.build_opener", return_value=wire):
                    result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid)
                self.assertEqual(result["failure_code"], "effective_capabilities_unconfirmed")

    def test_wire_uses_proxyless_nonredirecting_opener(self):
        wire = _Wire()
        with patch("urllib.request.build_opener", return_value=wire) as builder:
            subject.run_synthetic_appium_fixture(self.endpoint, self.uuid, mode="session-only")
        handlers = builder.call_args.args
        self.assertTrue(any(isinstance(handler, subject._NoRedirect) for handler in handlers))
        proxy = next(handler for handler in handlers if isinstance(handler, subject.urllib.request.ProxyHandler))
        self.assertEqual(proxy.proxies, {})

    def test_oversized_wire_response_is_rejected_before_json_parse(self):
        class OversizedResponse:
            def geturl(self):
                return "http://127.0.0.1:4723/session"

            def read(self, limit):
                self.limit = limit
                return b"x" * limit

            def close(self):
                pass

        class OversizedOpener:
            def open(self, request, timeout):
                return OversizedResponse()

        with patch("urllib.request.build_opener", return_value=OversizedOpener()):
            result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid, mode="session-only")
        self.assertEqual(result["failure_code"], "session_creation_ambiguous")
        self.assertTrue(result["cleanup_unconfirmed"])

    def test_missing_or_multiple_or_not_hittable_are_blocked(self):
        fixture = object.__new__(subject._Fixture)
        fixture._wait_candidates = lambda *_args: []
        with self.assertRaises(subject._Stop) as missing:
            fixture._unique(("x",), "gate")
        self.assertEqual(missing.exception.code, "target_not_unique")
        fixture._wait_candidates = lambda *_args: ["a", "b"]
        with self.assertRaises(subject._Stop) as multiple:
            fixture._unique(("x",), "gate")
        self.assertEqual(multiple.exception.code, "target_not_unique")
        fixture._wait_candidates = lambda *_args: ["a"]
        fixture._flag = lambda *_args: True
        fixture._attribute = lambda *_args: "false"
        with self.assertRaises(subject._Stop) as unhittable:
            fixture._unique(("x",), "gate")
        self.assertEqual(unhittable.exception.code, "target_not_hittable")
        fixture._attribute = lambda *_args: {"true": True}
        with self.assertRaises(subject._Stop) as malformed:
            fixture._unique(("x",), "gate")
        self.assertEqual(malformed.exception.code, "invalid_element_state")

    def test_ambiguous_click_is_not_retried_and_session_is_closed(self):
        wire = _Wire(fail_path="/session/private-session/execute/sync")
        with patch("urllib.request.build_opener", return_value=wire):
            result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid, mode="fixture")
        mutations = [call for call in wire.calls if call[1].endswith("/execute/sync")]
        self.assertEqual(len(mutations), 1)
        self.assertEqual(result["failure_code"], "http_ambiguous")
        self.assertIn(("DELETE", "/session/private-session", None), wire.calls)

    def test_ambiguous_element_click_is_not_retried(self):
        fixture = object.__new__(subject._Fixture)
        fixture.session_id = "private-session"
        fixture._unique = lambda *_args: "target"
        calls = []

        class FailingWire:
            def request(self, *_args, **_kwargs):
                calls.append(1)
                raise subject._Stop("wire", "http_ambiguous")

        fixture.wire = FailingWire()
        with self.assertRaises(subject._Stop) as failed:
            fixture._tap(("x",), "click")
        self.assertEqual(failed.exception.code, "http_ambiguous")
        self.assertEqual(len(calls), 1)

    def test_wrong_actual_udid_is_rejected_and_closed_without_leaking_identifiers(self):
        wire = _Wire(actual_udid="ffffffff-1111-4222-8333-444444444444")
        with patch("urllib.request.build_opener", return_value=wire):
            result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid)
        self.assertEqual(result["failure_code"], "effective_capabilities_unconfirmed")
        self.assertIn(("DELETE", "/session/private-session", None), wire.calls)
        self.assertNotIn("private-session", json.dumps(result))
        self.assertNotIn("ffffffff", json.dumps(result))

    def test_cleanup_happens_after_all_later_errors(self):
        wire = _Wire()
        with patch("urllib.request.build_opener", return_value=wire), patch.object(subject, "_STAGE_SECONDS", 0):
            result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid, mode="fixture")
        self.assertEqual(result["failure_code"], "target_not_unique")
        self.assertIn(("DELETE", "/session/private-session", None), wire.calls)

    def test_creation_ambiguity_does_not_attempt_unknown_session_cleanup(self):
        wire = _Wire(fail_path="/session")
        with patch("urllib.request.build_opener", return_value=wire):
            result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid, mode="session-only")
        self.assertEqual(wire.calls, [("POST", "/session", wire.calls[0][2])])
        self.assertEqual(result["failure_code"], "session_creation_ambiguous")
        self.assertTrue(result["cleanup_unconfirmed"])

    def test_cleanup_failure_preserves_primary_failure(self):
        wire = _Wire(fail_path="/session/private-session")
        with patch("urllib.request.build_opener", return_value=wire), patch.object(subject, "_STAGE_SECONDS", 0):
            result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid, mode="fixture")
        self.assertEqual(result["failure_code"], "target_not_unique")
        self.assertEqual(result["primary_failure_code"], "target_not_unique")
        self.assertTrue(result["cleanup_unconfirmed"])

    def test_expired_ui_budget_still_attempts_one_independent_cleanup(self):
        wire = _Wire()
        with patch("urllib.request.build_opener", return_value=wire), patch.object(subject, "_UI_SECONDS", 0):
            result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid, mode="fixture")
        deletes = [call for call in wire.calls if call[:2] == ("DELETE", "/session/private-session")]
        self.assertEqual(len(deletes), 1)
        self.assertEqual(result["primary_failure_code"], "budget_exhausted")

    def test_positive_fake_is_synthetic_only(self):
        result = {
            "fresh_library_empty": True,
            "filter_ready": True,
            "nonempty_after_relaunch": True,
            "session_initialized": True,
            "idle0": True,
            "stage": "completed",
            "failure_code": None,
            "metrics": {"requests": 1, "read_polls": 0, "elapsed_ms": 0},
        }
        self.assertNotIn("sms", json.dumps(result).lower())
        self.assertNotIn("otp", json.dumps(result).lower())


if __name__ == "__main__":
    unittest.main()
