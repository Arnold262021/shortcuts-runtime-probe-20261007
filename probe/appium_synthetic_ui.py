"""Bounded Appium/WDA execution of the synthetic Shortcuts fixture only."""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


_BUNDLE_ID = "com.apple.shortcuts"
_PHRASE = "AUTOMATION_TEST_ONLY"
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_ELEMENT = "element-6066-11e4-a52e-4f735466cecf"
_STAGE_SECONDS = 12.0
_COMMAND_HTTP_SECONDS = 20.0
_SETUP_SECONDS = 180.0
_UI_SECONDS = 180.0
_CLEANUP_SECONDS = 10.0
_MAX_RESPONSE_BYTES = 64 * 1024


class _Stop(Exception):
    def __init__(self, stage: str, code: str):
        self.stage = stage
        self.code = code


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class _Wire:
    def __init__(self, base_url: str, metrics: dict[str, int], setup_deadline: float):
        self.base_url = base_url.rstrip("/")
        self.metrics = metrics
        self.setup_deadline = setup_deadline
        self.command_deadline: float | None = None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def begin_commands(self) -> None:
        self.command_deadline = time.monotonic() + _UI_SECONDS

    def _budget(self, *, setup: bool, cleanup: bool) -> tuple[float, float]:
        if cleanup:
            return time.monotonic() + _CLEANUP_SECONDS, _CLEANUP_SECONDS
        if setup:
            return self.setup_deadline, _SETUP_SECONDS
        if self.command_deadline is None:
            raise _Stop("wire", "command_budget_uninitialized")
        return self.command_deadline, _COMMAND_HTTP_SECONDS

    def request(self, method: str, path: str, body: dict[str, Any] | None = None, *, mutation: bool = False, setup: bool = False, cleanup: bool = False) -> Any:
        deadline, maximum = self._budget(setup=setup, cleanup=cleanup)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _Stop("session_setup" if setup else "ui_budget", "budget_exhausted")
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"} if data is not None else {},
        )
        self.metrics["requests"] += 1
        try:
            response = self.opener.open(request, timeout=min(maximum, remaining))
            try:
                final_url = getattr(response, "geturl", lambda: request.full_url)()
                if not _is_local_response(final_url):
                    raise _Stop("wire", "nonlocal_wire_response")
                payload = response.read(_MAX_RESPONSE_BYTES + 1)
            finally:
                close = getattr(response, "close", None)
                if close is not None:
                    close()
        except _Stop:
            raise
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
            raise _Stop("wire", "http_ambiguous" if mutation else "http_read_failed") from None
        if len(payload) > _MAX_RESPONSE_BYTES:
            raise _Stop("wire", "wire_response_too_large")
        try:
            decoded = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise _Stop("wire", "invalid_wire_response") from None
        if not isinstance(decoded, dict):
            raise _Stop("wire", "invalid_wire_response")
        value = decoded.get("value")
        if isinstance(value, dict) and value.get("error"):
            raise _Stop("wire", "http_ambiguous" if mutation else "webdriver_read_failed")
        return value


def _valid_inputs(base_url: str, simulator_id: str) -> bool:
    if not isinstance(base_url, str) or not isinstance(simulator_id, str) or not _UUID.fullmatch(simulator_id):
        return False
    try:
        parsed = urllib.parse.urlsplit(base_url)
        port = parsed.port
    except ValueError:
        return False
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or port is None:
        return False
    if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        return False
    return parsed.path in ("", "/") and 1 <= port <= 65535


def _is_local_response(url: object) -> bool:
    if not isinstance(url, str):
        return False
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError:
        return False
    return (parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and port is not None
            and parsed.username is None and parsed.password is None and not parsed.query and not parsed.fragment)


def _element_id(item: Any) -> str | None:
    if not isinstance(item, dict):
        return None
    value = item.get(_ELEMENT)
    return value if isinstance(value, str) and value else None


class _Fixture:
    def __init__(self, wire: _Wire, session_id: str, metrics: dict[str, int]):
        self.wire = wire
        self.session_id = session_id
        self.metrics = metrics

    @property
    def root(self) -> str:
        return "/session/" + urllib.parse.quote(self.session_id, safe="")

    def _find(self, selector: str, parent: str | None = None) -> list[str]:
        prefix = self.root if parent is None else self.root + "/element/" + urllib.parse.quote(parent, safe="")
        value = self.wire.request("POST", prefix + "/elements", {"using": "-ios predicate string", "value": selector})
        if not isinstance(value, list):
            raise _Stop("wire", "invalid_wire_response")
        result: list[str] = []
        for item in value:
            element = _element_id(item)
            if element is None:
                raise _Stop("wire", "invalid_wire_response")
            result.append(element)
        return result

    def _wait_candidates(self, selectors: tuple[str, ...], stage: str, parent: str | None = None) -> list[str]:
        command_deadline = self.wire.command_deadline
        if command_deadline is None:
            raise _Stop("wire", "command_budget_uninitialized")
        deadline = min(time.monotonic() + _STAGE_SECONDS, command_deadline)
        while True:
            candidates: list[str] = []
            for selector in selectors:
                candidates.extend(self._find(selector, parent))
            if candidates or time.monotonic() >= deadline:
                return candidates
            self.metrics["read_polls"] += 1
            time.sleep(0.1)

    def _flag(self, element: str, endpoint: str, stage: str) -> bool:
        value = self.wire.request("GET", self.root + "/element/" + urllib.parse.quote(element, safe="") + endpoint)
        if not isinstance(value, bool):
            raise _Stop(stage, "invalid_element_state")
        return value

    def _attribute(self, element: str, name: str, stage: str) -> Any:
        return self.wire.request("GET", self.root + "/element/" + urllib.parse.quote(element, safe="") + "/attribute/" + urllib.parse.quote(name, safe=""))

    def _unique(self, selectors: tuple[str, ...], stage: str, parent: str | None = None) -> str:
        candidates = self._wait_candidates(selectors, stage, parent)
        if len(candidates) != 1:
            raise _Stop(stage, "target_not_unique")
        element = candidates[0]
        if not self._flag(element, "/displayed", stage):
            raise _Stop(stage, "target_not_visible")
        if not self._flag(element, "/enabled", stage):
            raise _Stop(stage, "target_not_enabled")
        if not self._hittable(element, stage):
            raise _Stop(stage, "target_not_hittable")
        return element

    def _hittable(self, element: str, stage: str) -> bool:
        value = self._attribute(element, "hittable", stage)
        if value is True or (isinstance(value, str) and value.lower() == "true"):
            return True
        if value is False or (isinstance(value, str) and value.lower() == "false"):
            return False
        raise _Stop(stage, "invalid_element_state")

    def _tap(self, selectors: tuple[str, ...], stage: str, parent: str | None = None) -> None:
        element = self._unique(selectors, stage, parent)
        self.wire.request("POST", self.root + "/element/" + urllib.parse.quote(element, safe="") + "/click", {}, mutation=True)

    def _one(self, selector: str, stage: str, parent: str | None = None) -> str:
        candidates = self._wait_candidates((selector,), stage, parent)
        if len(candidates) != 1:
            raise _Stop(stage, "target_not_unique")
        return candidates[0]

    def _activate(self, active: bool) -> None:
        command = "mobile: activateApp" if active else "mobile: terminateApp"
        self.wire.request("POST", self.root + "/execute/sync", {"script": command, "args": [{"bundleId": _BUNDLE_ID}]}, mutation=True)

    def _require_foreground(self) -> None:
        value = self.wire.request(
            "POST", self.root + "/execute/sync",
            {"script": "mobile: queryAppState", "args": [{"bundleId": _BUNDLE_ID}]},
            mutation=False,
        )
        if type(value) is not int or value != 4:
            raise _Stop("foreground", "app_not_foreground")

    def _has_named_control(self, label: str) -> bool:
        quoted = json.dumps(label)
        buttons = self._find("type == 'XCUIElementTypeButton' AND label == " + quoted)
        cells = self._find("type == 'XCUIElementTypeCell' AND label == " + quoted)
        return bool(buttons or cells)

    def _named(self, label: str, stage: str) -> None:
        quoted = json.dumps(label)
        self._tap((
            "type == 'XCUIElementTypeButton' AND label == " + quoted,
            "type == 'XCUIElementTypeCell' AND label == " + quoted,
        ), stage)

    def run(self) -> dict[str, bool]:
        outcome = {"fresh_library_empty": False, "filter_ready": False, "nonempty_after_relaunch": False}
        self._activate(True)
        self._require_foreground()
        onboarding = self._find("type == 'XCUIElementTypeStaticText' AND (label == \"Unified Automations\" OR label == \"What’s New in Shortcuts\")")
        if onboarding:
            self._tap(("type == 'XCUIElementTypeButton' AND label == \"Continue\"",), "continue_shortcuts_onboarding")
        library = self._one("type == 'XCUIElementTypeOther' AND name == \"all_shortcuts_library\"", "fixture_empty_library")
        no_shortcuts = self._find("type == 'XCUIElementTypeStaticText' AND label == \"No Shortcuts\"", library)
        if len(no_shortcuts) != 1:
            raise _Stop("fixture_empty_library", "fresh_library_empty_unconfirmed")
        outcome["fresh_library_empty"] = True
        self._tap(("type == 'XCUIElementTypeButton' AND name == \"main.button.newshortcut\"",), "new_shortcut")
        if not self._has_named_control("Automation"):
            editor = self._find("type == 'XCUIElementTypeNavigationBar' AND name == \"New Shortcut\"")
            if len(editor) > 1:
                raise _Stop("switch_to_action_editor", "target_not_unique")
            if len(editor) == 1:
                editors = self._find("type == 'XCUIElementTypeButton' AND label == \"Editor\"", editor[0])
                if len(editors) > 1:
                    raise _Stop("switch_to_action_editor", "target_not_unique")
                if len(editors) == 1:
                    self._tap(("type == 'XCUIElementTypeButton' AND label == \"Editor\"",), "switch_to_action_editor", editor[0])
        if not self._has_named_control("Automation"):
            self._named("Edit", "edit_shortcut")
        self._named("Automation", "automation")
        self._named("Message", "message")
        container = self._one("type == 'XCUIElementTypeOther' AND name == \"editor.action.WFMessageTrigger.WFMessageConditions\"", "message_condition_container")
        self._tap(("type == 'XCUIElementTypeButton' AND name == \"enum\" AND value == \"Sender\"",), "message_filter_property_menu", container)
        self._named("Message", "message_filter_property")
        container = self._one("type == 'XCUIElementTypeOther' AND name == \"editor.action.WFMessageTrigger.WFMessageConditions\"", "message_condition_container")
        message_property = self._find("type == 'XCUIElementTypeButton' AND name == \"enum\" AND value == \"Message\"", container)
        if len(message_property) != 1:
            raise _Stop("message_filter_property_confirmation", "message_property_unconfirmed")
        contains = []
        for typ in ("StaticText", "Button", "Cell"):
            contains.extend(self._find("type == 'XCUIElementType" + typ + "' AND label == \"contains\"", container))
        if not contains:
            raise _Stop("message_contains_operator", "contains_unconfirmed")
        fields = self._find("type == 'XCUIElementTypeTextField'", container)
        views = self._find("type == 'XCUIElementTypeTextView'", container)
        if not fields and not views:
            self._tap(("type == 'XCUIElementTypeButton' AND label == \"Text\" AND name != \"enum\" AND name != \"contact\"",), "message_condition_text_editor", container)
            container = self._one("type == 'XCUIElementTypeOther' AND name == \"editor.action.WFMessageTrigger.WFMessageConditions\"", "message_condition_container")
            fields = self._find("type == 'XCUIElementTypeTextField'", container)
            views = self._find("type == 'XCUIElementTypeTextView'", container)
        keyboard_onboarding = self._find("type == 'XCUIElementTypeStaticText' AND label == \"Speed up your typing by sliding your finger across the letters to compose a word.\"")
        keyboard_continue = self._find("type == 'XCUIElementTypeButton' AND label == \"Continue\"")
        if keyboard_onboarding or keyboard_continue:
            if len(keyboard_onboarding) != 1 or len(keyboard_continue) != 1:
                raise _Stop("keyboard_onboarding", "target_not_unique")
            self._tap(("type == 'XCUIElementTypeButton' AND label == \"Continue\"",), "continue_keyboard_onboarding")
            container = self._one("type == 'XCUIElementTypeOther' AND name == \"editor.action.WFMessageTrigger.WFMessageConditions\"", "message_condition_container")
        input_element = self._unique(("type == 'XCUIElementTypeTextField'", "type == 'XCUIElementTypeTextView'"), "message_contains", container)
        self.wire.request("POST", self.root + "/element/" + urllib.parse.quote(input_element, safe="") + "/click", {}, mutation=True)
        self.wire.request("POST", self.root + "/element/" + urllib.parse.quote(input_element, safe="") + "/value", {"text": _PHRASE}, mutation=True)
        if self._attribute(input_element, "value", "message_contains_value") != _PHRASE:
            raise _Stop("message_contains_value", "filter_value_unconfirmed")
        self._tap(("type == 'XCUIElementTypeButton' AND name == \"Done\"",), "finish_filter_editing")
        outcome["filter_ready"] = True
        self._tap(("type == 'XCUIElementTypeButton' AND name == \"BackButton\" AND label == \"Back\"",), "fixture_local_save_back")
        self._require_nonempty("fixture_library_after_save")
        self._activate(False)
        self._activate(True)
        self._require_foreground()
        self._require_nonempty("fixture_library_after_relaunch")
        outcome["nonempty_after_relaunch"] = True
        return outcome

    def _require_nonempty(self, stage: str) -> None:
        library = self._one("type == 'XCUIElementTypeOther' AND name == \"all_shortcuts_library\"", stage)
        empty = self._find("type == 'XCUIElementTypeStaticText' AND label == \"No Shortcuts\"", library)
        cells = self._find("type == 'XCUIElementTypeCell'", library)
        if empty or not cells:
            raise _Stop(stage, "library_nonempty_unconfirmed")


def _effective_capabilities_match(value: Any, simulator_id: str) -> bool:
    if not isinstance(value, dict):
        return False

    missing = object()

    def cap(name: str) -> tuple[bool, Any]:
        plain = value.get(name, missing)
        alias = value.get("appium:" + name, missing)
        if plain is not missing and alias is not missing:
            if type(plain) is not type(alias) or plain != alias:
                return False, missing
            return True, plain
        if plain is not missing:
            return True, plain
        if alias is not missing:
            return True, alias
        return False, missing

    udid_ok, actual_udid = cap("udid")
    bundle_ok, bundle_id = cap("bundleId")
    automation_ok, automation_name = cap("automationName")
    idle_ok, idle_timeout = cap("waitForIdleTimeout")
    return (
        udid_ok
        and bundle_ok
        and automation_ok
        and idle_ok
        and isinstance(actual_udid, str)
        and _UUID.fullmatch(actual_udid) is not None
        and actual_udid.lower() == simulator_id.lower()
        and bundle_id == _BUNDLE_ID
        and automation_name == "XCUITest"
        and type(idle_timeout) is int
        and idle_timeout == 0
    )


def run_synthetic_appium_fixture(base_url: str, own_simulator_id: str, *, mode: str = "session-only") -> dict[str, object]:
    """Run the approved fixture or its session-only gate on caller-owned resources."""
    started = time.monotonic()
    metrics = {"requests": 0, "read_polls": 0}
    result: dict[str, object] = {
        "fresh_library_empty": False,
        "filter_ready": False,
        "nonempty_after_relaunch": False,
        "session_initialized": False,
        "idle0": False,
        "stage": "input_validation",
        "failure_code": None,
        "primary_stage": None,
        "primary_failure_code": None,
        "cleanup_unconfirmed": False,
        "metrics": metrics,
    }
    if mode not in ("session-only", "fixture") or not _valid_inputs(base_url, own_simulator_id):
        result["failure_code"] = "invalid_local_endpoint_or_simulator_id"
        metrics["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        return result
    wire = _Wire(base_url, metrics, started + _SETUP_SECONDS)
    session_id: str | None = None
    primary_failure: _Stop | None = None
    session_create_attempted = False
    try:
        capabilities = {
            "platformName": "iOS",
            "appium:automationName": "XCUITest",
            "appium:udid": own_simulator_id,
            "appium:bundleId": _BUNDLE_ID,
            "appium:noReset": True,
            "appium:waitForIdleTimeout": 0,
            "appium:newCommandTimeout": 60,
            "appium:wdaLaunchTimeout": 180000,
        }
        session_create_attempted = True
        created = wire.request("POST", "/session", {"capabilities": {"alwaysMatch": capabilities, "firstMatch": [{}]}}, mutation=True, setup=True)
        if not isinstance(created, dict):
            raise _Stop("session", "invalid_wire_response")
        candidate = created.get("sessionId")
        actual_caps = created.get("capabilities")
        if not isinstance(candidate, str) or not candidate or len(candidate) > 128 or not candidate.isascii():
            raise _Stop("session", "invalid_wire_response")
        if not _effective_capabilities_match(actual_caps, own_simulator_id):
            session_id = candidate
            raise _Stop("session", "effective_capabilities_unconfirmed")
        session_id = candidate
        result["session_initialized"] = True
        result["idle0"] = True
        wire.begin_commands()
        fixture = _Fixture(wire, session_id, metrics)
        if mode == "session-only":
            fixture._require_foreground()
            result["stage"] = "session_only_completed"
        else:
            result.update(fixture.run())
            result["stage"] = "completed"
    except _Stop as failure:
        if session_id is None and session_create_attempted:
            failure = _Stop("session", "session_creation_ambiguous")
            result["cleanup_unconfirmed"] = True
        primary_failure = failure
        result["stage"] = failure.stage
        result["failure_code"] = failure.code
        result["primary_stage"] = failure.stage
        result["primary_failure_code"] = failure.code
    finally:
        if session_id is not None:
            try:
                wire.request("DELETE", "/session/" + urllib.parse.quote(session_id, safe=""), mutation=True, cleanup=True)
            except _Stop:
                result["cleanup_unconfirmed"] = True
                if primary_failure is None:
                    result["stage"] = "session_cleanup"
                    result["failure_code"] = "session_cleanup_unconfirmed"
    metrics["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    return result
