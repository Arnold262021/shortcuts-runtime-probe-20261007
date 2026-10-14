import io
import json
import time
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

    def test_prebuilt_wda_opt_in_is_requested_verified_and_redacted(self):
        private_path = "/private/var/folders/PRIVATE_SENTINEL/DerivedData"
        wire = _Wire(caps={
            "udid": self.uuid,
            "bundleId": "com.apple.shortcuts",
            "automationName": "XCUITest",
            "waitForIdleTimeout": 0,
            "usePrebuiltWDA": True,
            "derivedDataPath": private_path,
        })
        with patch("urllib.request.build_opener", return_value=wire):
            result = subject.run_synthetic_appium_fixture(
                self.endpoint, self.uuid, prebuilt_wda={"derived_data_path": private_path}
            )
        requested = json.loads(wire.calls[0][2])["capabilities"]["alwaysMatch"]
        self.assertTrue(requested["appium:usePrebuiltWDA"])
        self.assertEqual(requested["appium:derivedDataPath"], private_path)
        self.assertTrue(result["prebuilt_wda_requested"])
        self.assertTrue(result["prebuilt_wda_verified"])
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(result))

    def test_prebuilt_wda_rejects_malformed_paths_without_requests(self):
        malformed = (
            {},
            {"derived_data_path": "relative/path"},
            {"derived_data_path": "/private/../escape"},
            {"derived_data_path": ""},
            {"derived_data_path": 3},
            {"derived_data_path": "/private/ok", "extra": True},
        )
        for value in malformed:
            with self.subTest(value=value):
                wire = _Wire()
                with patch("urllib.request.build_opener", return_value=wire):
                    result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid, prebuilt_wda=value)
                self.assertEqual(result["failure_code"], "invalid_prebuilt_wda")
                self.assertFalse(result["prebuilt_wda_requested"])
                self.assertFalse(result["prebuilt_wda_verified"])
                self.assertEqual(wire.calls, [])

    def test_prebuilt_wda_effective_capabilities_must_confirm_requested_values(self):
        private_path = "/private/var/folders/PRIVATE_SENTINEL/DerivedData"
        base = {
            "udid": self.uuid,
            "bundleId": "com.apple.shortcuts",
            "automationName": "XCUITest",
            "waitForIdleTimeout": 0,
        }
        variants = (
            base,
            {**base, "usePrebuiltWDA": True, "derivedDataPath": "/private/other"},
            {**base, "usePrebuiltWDA": True, "appium:usePrebuiltWDA": False, "derivedDataPath": private_path},
        )
        for caps in variants:
            with self.subTest(caps=caps):
                wire = _Wire(caps=caps)
                with patch("urllib.request.build_opener", return_value=wire):
                    result = subject.run_synthetic_appium_fixture(
                        self.endpoint, self.uuid, prebuilt_wda={"derived_data_path": private_path}
                    )
                self.assertEqual(result["failure_code"], "effective_capabilities_unconfirmed")
                self.assertTrue(result["prebuilt_wda_requested"])
                self.assertFalse(result["prebuilt_wda_verified"])
                self.assertIn(("DELETE", "/session/private-session", None), wire.calls)
                self.assertNotIn("PRIVATE_SENTINEL", json.dumps(result))

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

    def test_http_error_retains_only_allowed_w3c_category(self):
        sentinel = "PRIVATE_SENTINEL_DO_NOT_RETAIN"

        class ErrorOpener:
            def open(self, request, timeout):
                body = json.dumps({"value": {"error": "session not created", "message": sentinel, "stacktrace": sentinel}}).encode()
                raise subject.urllib.error.HTTPError(request.full_url, 500, "failure", None, io.BytesIO(body))

        with patch("urllib.request.build_opener", return_value=ErrorOpener()):
            result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid)
        self.assertEqual(result["failure_code"], "session_creation_ambiguous")
        self.assertEqual(result["webdriver_error_category"], "session not created")
        self.assertNotIn(sentinel, json.dumps(result))

    def test_http_error_unknown_or_oversized_body_retains_no_category(self):
        for error_name, oversized in (("not allowlisted", False), ("unknown error", True)):
            with self.subTest(error_name=error_name, oversized=oversized):
                class ErrorOpener:
                    def open(self, request, timeout):
                        body = json.dumps({"value": {"error": error_name, "message": "PRIVATE_SENTINEL"}}).encode()
                        if oversized:
                            body = body + b"x" * (subject._MAX_RESPONSE_BYTES + 1)
                        raise subject.urllib.error.HTTPError(request.full_url, 500, "failure", None, io.BytesIO(body))

                with patch("urllib.request.build_opener", return_value=ErrorOpener()):
                    result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid)
                self.assertEqual(result["webdriver_error_category"], None)
                self.assertNotIn("PRIVATE_SENTINEL", json.dumps(result))

    def test_http_error_nonstring_categories_are_sanitized_and_closed(self):
        sentinel = "PRIVATE_SENTINEL_NONSTRING"
        for category in ({}, [], None, 7):
            with self.subTest(category=type(category).__name__):
                class TrackingBody(io.BytesIO):
                    def __init__(self, payload):
                        super().__init__(payload)
                        self.was_closed = False

                    def close(self):
                        self.was_closed = True
                        super().close()

                body = TrackingBody(json.dumps({"value": {"error": category, "message": sentinel, "stacktrace": sentinel}}).encode())

                class ErrorOpener:
                    def open(self, request, timeout):
                        raise subject.urllib.error.HTTPError(request.full_url, 500, "failure", None, body)

                with patch("urllib.request.build_opener", return_value=ErrorOpener()):
                    result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid)
                self.assertEqual(result["failure_code"], "session_creation_ambiguous")
                self.assertIsNone(result["webdriver_error_category"])
                self.assertTrue(body.was_closed)
                self.assertNotIn(sentinel, json.dumps(result))

    def test_deep_error_or_success_json_cannot_escape_the_sanitized_result(self):
        deep = b'{"value":' + b"[" * 1500 + b"]" * 1500 + b"}"
        self.assertLess(len(deep), subject._MAX_RESPONSE_BYTES)

        class TrackingBody(io.BytesIO):
            def __init__(self, payload):
                super().__init__(payload)
                self.was_closed = False

            def close(self):
                self.was_closed = True
                super().close()

        error_body = TrackingBody(deep)

        class ErrorOpener:
            def open(self, request, timeout):
                raise subject.urllib.error.HTTPError(request.full_url, 500, "failure", None, error_body)

        with patch("urllib.request.build_opener", return_value=ErrorOpener()):
            error_result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid)
        self.assertEqual(error_result["failure_code"], "session_creation_ambiguous")
        self.assertIsNone(error_result["webdriver_error_category"])
        self.assertTrue(error_body.was_closed)

        class DeepResponse:
            def __init__(self):
                self.was_closed = False

            def geturl(self):
                return "http://127.0.0.1:4723/session"

            def read(self, limit):
                self.assert_limit = limit
                return deep

            def close(self):
                self.was_closed = True

        response = DeepResponse()

        class SuccessOpener:
            def open(self, request, timeout):
                return response

        with patch("urllib.request.build_opener", return_value=SuccessOpener()):
            success_result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid)
        self.assertEqual(success_result["failure_code"], "session_creation_ambiguous")
        self.assertIsNone(success_result["webdriver_error_category"])
        self.assertTrue(response.was_closed)

    def test_w3c_error_key_is_failure_even_when_value_is_falsy(self):
        sentinel = "PRIVATE_SENTINEL_FALSY"
        for category in ({}, [], None, 0, False, ""):
            with self.subTest(category=type(category).__name__):
                class Response:
                    def geturl(self):
                        return "http://127.0.0.1:4723/session"

                    def read(self, limit):
                        return json.dumps({"value": {"error": category, "message": sentinel}}).encode()

                    def close(self):
                        pass

                class Opener:
                    def open(self, request, timeout):
                        return Response()

                with patch("urllib.request.build_opener", return_value=Opener()):
                    result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid)
                self.assertEqual(result["failure_code"], "session_creation_ambiguous")
                self.assertNotIn(sentinel, json.dumps(result))

    def test_falsy_w3c_error_key_stops_wire_for_mutation_and_read(self):
        sentinel = "PRIVATE_SENTINEL_WIRE"

        class Response:
            def __init__(self):
                self.was_closed = False

            def geturl(self):
                return "http://127.0.0.1:4723/session"

            def read(self, limit):
                return json.dumps({"value": {"error": {}, "message": sentinel}}).encode()

            def close(self):
                self.was_closed = True

        class Opener:
            def __init__(self):
                self.responses = []

            def open(self, request, timeout):
                response = Response()
                self.responses.append(response)
                return response

        opener = Opener()
        with patch("urllib.request.build_opener", return_value=opener):
            wire = subject._Wire(self.endpoint, {"requests": 0, "read_polls": 0}, time.monotonic() + 1)
            with self.assertRaises(subject._Stop) as mutation:
                wire.request("POST", "/session", {}, mutation=True, setup=True)
            wire.begin_commands()
            with self.assertRaises(subject._Stop) as read:
                wire.request("GET", "/status")
        self.assertEqual(mutation.exception.code, "http_ambiguous")
        self.assertEqual(read.exception.code, "webdriver_read_failed")
        self.assertTrue(all(response.was_closed for response in opener.responses))
        self.assertNotIn(sentinel, str(mutation.exception.__dict__))
        self.assertNotIn(sentinel, str(read.exception.__dict__))

    def test_falsy_w3c_error_on_read_is_not_a_success(self):
        class Response:
            def __init__(self, value):
                self.value = value

            def geturl(self):
                return "http://127.0.0.1:4723/session"

            def read(self, limit):
                return json.dumps({"value": self.value}).encode()

            def close(self):
                pass

        class Opener:
            def __init__(self):
                self.calls = 0

            def open(self, request, timeout):
                self.calls += 1
                if self.calls == 1:
                    return Response({"sessionId": "private-session", "capabilities": {"udid": self_uuid, "bundleId": "com.apple.shortcuts", "automationName": "XCUITest", "waitForIdleTimeout": 0}})
                return Response({"error": {}})

        self_uuid = self.uuid
        opener = Opener()
        with patch("urllib.request.build_opener", return_value=opener):
            result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid)
        self.assertEqual(result["failure_code"], "webdriver_read_failed")

    def test_http_error_close_oserror_does_not_escape(self):
        class BrokenClose(io.BytesIO):
            def close(self):
                raise OSError("PRIVATE_SENTINEL_CLOSE")

        body = BrokenClose(json.dumps({"value": {"error": "unknown error"}}).encode())

        class ErrorOpener:
            def open(self, request, timeout):
                raise subject.urllib.error.HTTPError(request.full_url, 500, "failure", None, body)

        with patch("urllib.request.build_opener", return_value=ErrorOpener()):
            result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid)
        self.assertEqual(result["failure_code"], "session_creation_ambiguous")
        self.assertEqual(result["webdriver_error_category"], "unknown error")
        self.assertNotIn("PRIVATE_SENTINEL_CLOSE", json.dumps(result))

    def test_missing_or_multiple_or_not_hittable_are_blocked(self):
        fixture = object.__new__(subject._Fixture)
        fixture.wire = type("Wire", (), {"command_deadline": time.monotonic()})()
        fixture.metrics = {"read_polls": 0}
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

    def test_foreground_read_failure_closes_session(self):
        wire = _Wire(fail_path="/session/private-session/execute/sync")
        with patch("urllib.request.build_opener", return_value=wire):
            result = subject.run_synthetic_appium_fixture(self.endpoint, self.uuid, mode="fixture")
        state_reads = [call for call in wire.calls if call[1].endswith("/execute/sync")]
        self.assertEqual(len(state_reads), 1)
        self.assertEqual(result["failure_code"], "http_read_failed")
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
