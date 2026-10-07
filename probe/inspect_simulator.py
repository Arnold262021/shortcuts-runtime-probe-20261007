"""Inspect Shortcuts only in a new, account-free GitHub-hosted simulator."""

import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import uuid
import time
import signal
import tempfile


ROOT = Path(__file__).resolve().parent
ARTIFACTS = ROOT.parent / "artifacts"
def simulator_environment(source):
    blocked_prefixes = (
        "GITHUB_", "GH_", "ACTIONS_", "RUNNER_", "CI_", "AWS_", "AZURE_",
        "ARM_", "GOOGLE_", "GCLOUD_", "CLOUDFLARE_", "SSH_", "DYLD_", "LD_",
        "GIT_CONFIG_"
    )
    blocked_words = ("TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL",
                     "COOKIE", "AUTH", "API_KEY", "PRIVATE_KEY")
    blocked_names = {"BASH_ENV", "ENV", "CDPATH", "GIT_ASKPASS", "GPG_AGENT_INFO",
                     "PYTHONPATH", "PYTHONHOME", "RUBYOPT", "PERL5OPT", "NODE_OPTIONS"}
    return {key: source[key] for key in source
            if not key.upper().startswith(blocked_prefixes)
            and not any(word in key.upper() for word in blocked_words)
            and key.upper() not in blocked_names}


SAFE_ENV = simulator_environment(os.environ)
TIMINGS = []
DEADLINE = None
PROJECT_ARGS = ["-project", "AppleSimulatorProbe.xcodeproj", "-scheme", "AppleSimulatorProbe"]


def run_with_timeout(args, timeout, env):
    # Files avoid waiting for pipe EOF from descendants after the parent exits.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(args, stdout=stdout, stderr=stderr, env=env,
                                   cwd=ROOT, start_new_session=True)
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        stdout.seek(0)
        stderr.seek(0)
        output, error = stdout.read(), stderr.read()
        if timed_out:
            raise subprocess.TimeoutExpired(args, timeout, output=output, stderr=error)
        return subprocess.CompletedProcess(args, process.returncode, output, error)


def native_timeout_probe():
    script = ("import os,time\n"
              "child = os.fork()\n"
              "if child:\n"
              " print('GRANDCHILD_STARTED', flush=True)\n"
              "time.sleep(30)\n")
    started = time.monotonic()
    marker_seen = False
    timed_out = False
    try:
        run_with_timeout([sys.executable, "-c", script], timeout=1, env=SAFE_ENV)
    except subprocess.TimeoutExpired as error:
        timed_out = True
        marker_seen = b"GRANDCHILD_STARTED" in (error.stdout or b"")
    elapsed = time.monotonic() - started
    return {"wrapper_return_bounded_with_descendant_present":
            timed_out and marker_seen and elapsed < 8,
            "descendant_marker_seen": marker_seen,
            "seconds": round(elapsed, 3)}


def command(args, timeout=60, check=True, env=None, honor_budget=True):
    started = time.monotonic()
    if honor_budget and DEADLINE is not None:
        remaining = DEADLINE - started
        if remaining <= 0:
            raise RuntimeError("PROBE_BUDGET_EXHAUSTED")
        timeout = min(timeout, remaining)
    stage = " ".join(args[:3])
    print(f"PROBE_COMMAND_START={stage}", flush=True)
    try:
        result = run_with_timeout(args, timeout=timeout, env=env or SAFE_ENV)
    except subprocess.TimeoutExpired:
        TIMINGS.append({"command": stage, "seconds": round(time.monotonic() - started, 2),
                        "timed_out": True})
        raise
    TIMINGS.append({"command": stage, "seconds": round(time.monotonic() - started, 2),
                    "exit_code": result.returncode})
    print("PROBE_COMMAND_END=" + json.dumps(TIMINGS[-1]), flush=True)
    if check and result.returncode:
        detail = result.stderr.decode("utf-8", "replace")[-3000:]
        detail = detail.replace(str(ROOT.parent), "<WORKSPACE>")
        detail = detail.replace(os.environ.get("HOME", "/no-home"), "<HOME>")
        raise RuntimeError(f"COMMAND_FAILED {args[0:3]} exit={result.returncode}: {detail}")
    return result


def sim_json(*args):
    return json.loads(command(["xcrun", "simctl", *args, "--json"]).stdout)


def choose_device(runtimes, devices, types):
    type_ids = {item["name"]: item["identifier"] for item in types["devicetypes"]
                if item.get("productFamily") == "iPhone"}
    eligible = [r for r in runtimes["runtimes"]
                if r.get("isAvailable") and r.get("version", "").split(".")[0] == "27"
                and ".iOS-" in r["identifier"]]
    for runtime in sorted(eligible, key=lambda r: r["version"], reverse=True):
        for device in devices["devices"].get(runtime["identifier"], []):
            if device.get("isAvailable") and device.get("name") in type_ids:
                return runtime["identifier"], type_ids[device["name"]]
    raise RuntimeError("IOS27_IPHONE_TEMPLATE_ABSENT")


def validated_device_id(output):
    identifier = output.decode("ascii").strip()
    if str(uuid.UUID(identifier)).casefold() != identifier.casefold():
        raise ValueError("NONCANONICAL_SIMULATOR_ID")
    # Validate the UUID without changing the identifier returned by CoreSimulator.
    return identifier


def xcode_diagnostics(output, failed, simulator_id=None):
    text = output.decode("utf-8", "replace")
    text = text.replace(str(ROOT.parent), "<WORKSPACE>")
    text = text.replace(os.environ.get("HOME", "/no-home"), "<HOME>")
    def redact_identifier(match):
        identifier = match.group(2)
        if simulator_id and identifier.casefold() == simulator_id.casefold():
            return match.group(0)
        return match.group(1) + "<OTHER_RUNNER_DESTINATION>"
    text = re.sub(r"(\bid\s*:\s*)([^,}\s]+)", redact_identifier, text, flags=re.IGNORECASE)
    if not failed:
        text = "\n".join(line for line in text.splitlines()
                         if any(marker in line for marker in (
                             "error:", "PROBE_", "Test Case", "TEST SUCCEEDED", "TEST FAILED")))
    # A failure's destination lists are context, even without an "error:" marker.
    return text[-65536:]


def diagnostic_command(args, filename, timeout=60, env=None, full=False, simulator_id=None):
    try:
        result = command(args, timeout=timeout, check=False, env=env)
    except subprocess.TimeoutExpired as error:
        output = (error.stdout or b"") + (error.stderr or b"")
        (ARTIFACTS / filename).write_text(
            xcode_diagnostics(output, True, simulator_id), encoding="utf-8")
        raise
    (ARTIFACTS / filename).write_text(
        xcode_diagnostics(result.stdout + result.stderr, full or result.returncode != 0,
                          simulator_id), encoding="utf-8")
    return result


def collect_xcode_diagnostic(receipt, name, args, simulator_id=None):
    try:
        result = diagnostic_command(args, name + ".txt", full=True, simulator_id=simulator_id)
        receipt[name + "_diagnostic_exit"] = result.returncode
        return result
    except subprocess.TimeoutExpired:
        receipt[name + "_diagnostic_exit"] = "timeout"
        return None


def test_diagnostic_options(help_text):
    if re.search(r"(?m)^\s*-collect-test-diagnostics(?:\s|$)", help_text):
        return ["-collect-test-diagnostics", "never"]
    return []


def cleanup_device(device_id):
    errors = []
    for action in ("shutdown", "delete"):
        try:
            result = command(["xcrun", "simctl", action, device_id], timeout=30,
                             check=False, honor_budget=False)
            if result.returncode:
                errors.append(f"{action}:exit{result.returncode}")
        except (subprocess.TimeoutExpired, OSError):
            errors.append(f"{action}:cleanup_unconfirmed")
    return errors


def main():
    global DEADLINE
    if sys.platform != "darwin" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("GITHUB_MACOS_RUNNER_REQUIRED")
    ARTIFACTS.mkdir(exist_ok=False)
    TIMINGS.clear()
    # Reserve three minutes of the job for bounded cleanup and artifact upload.
    DEADLINE = time.monotonic() + 720
    device_id = None
    receipt = {"scope": "fresh_account_free_simulator", "message_access": False,
               "otp_proven": False, "automation_created": False}
    try:
        receipt["native_timeout_probe"] = native_timeout_probe()
        print("PROBE_NATIVE_TIMEOUT=" + json.dumps(receipt["native_timeout_probe"]), flush=True)
        if not receipt["native_timeout_probe"]["wrapper_return_bounded_with_descendant_present"]:
            raise RuntimeError("NATIVE_TIMEOUT_PROBE_UNCONFIRMED")
        collect_xcode_diagnostic(receipt, "sdks", ["xcodebuild", "-showsdks"])
        help_result = collect_xcode_diagnostic(receipt, "xcode_help", ["xcodebuild", "-help"])
        help_text = ((help_result.stdout + help_result.stderr).decode("utf-8", "replace")
                     if help_result is not None else "")
        diagnostic_options = test_diagnostic_options(help_text)
        receipt["system_diagnostics_policy"] = "never" if diagnostic_options else "default"
        runtime, device_type = choose_device(
            sim_json("list", "runtimes"), sim_json("list", "devices", "available"),
            sim_json("list", "devicetypes"))
        receipt.update(runtime=runtime, device_type=device_type)
        created = command(["xcrun", "simctl", "create", "Synthetic-Shortcuts-Probe",
                           device_type, runtime]).stdout
        device_id = validated_device_id(created)
        receipt["synthetic_simulator_id"] = device_id
        collect_xcode_diagnostic(receipt, "destinations_preboot",
                                 ["xcodebuild", *PROJECT_ARGS, "-showdestinations"], device_id)
        command(["xcrun", "simctl", "boot", device_id])
        boot_status = command(["xcrun", "simctl", "bootstatus", device_id, "-b"], timeout=300)
        receipt["bootstatus_exit"] = boot_status.returncode
        bundle = "com.apple.shortcuts"
        receipt["shortcuts_bundle_candidate"] = bundle
        try:
            before = command(["xcrun", "simctl", "io", device_id, "screenshot",
                              str(ARTIFACTS / "before-ui-test.png")], timeout=20, check=False)
            receipt["before_screenshot_exit"] = before.returncode
        except subprocess.TimeoutExpired:
            receipt["before_screenshot_exit"] = "timeout"
        env = dict(SAFE_ENV, TEST_RUNNER_SHORTCUTS_BUNDLE_ID=bundle)
        result_path = ROOT.parent / "ProbeResults.xcresult"
        build_args = [
            "xcodebuild", "test", *PROJECT_ARGS,
            "-destination", f"platform=iOS Simulator,id={device_id}",
            "-derivedDataPath", str(ROOT.parent / "DerivedData"),
            "-resultBundlePath", str(result_path), "-parallel-testing-enabled", "NO",
            "-maximum-concurrent-test-simulator-destinations", "1",
            "-test-timeouts-enabled", "YES", "-default-test-execution-time-allowance", "120",
            "-maximum-test-execution-time-allowance", "180", *diagnostic_options,
            "CODE_SIGNING_ALLOWED=NO"
        ]
        try:
            build = diagnostic_command(build_args, "test-diagnostics.txt", timeout=480,
                                       env=env, simulator_id=device_id)
            receipt["xcodebuild_exit"] = build.returncode
        except subprocess.TimeoutExpired:
            receipt["xcodebuild_exit"] = "timeout"
        diagnostics = (ARTIFACTS / "test-diagnostics.txt").read_text(encoding="utf-8")
        print("\n".join(diagnostics.splitlines()[-80:]), flush=True)
        if result_path.exists():
            attachments = ROOT.parent / "ExportedAttachments"
            try:
                exported = command(["xcrun", "xcresulttool", "export", "attachments", "--path",
                                    str(result_path), "--output-path", str(attachments)],
                                   timeout=60, check=False)
                receipt["attachment_export_exit"] = exported.returncode
            except (subprocess.TimeoutExpired, RuntimeError):
                receipt["attachment_export_exit"] = "unconfirmed"
            for index, file in enumerate(sorted(attachments.rglob("*"))):
                if file.is_file() and file.suffix.lower() in (".txt", ".png"):
                    shutil.copyfile(file, ARTIFACTS / f"ui-{index}{file.suffix.lower()}")
        try:
            screen = command(["xcrun", "simctl", "io", device_id, "screenshot",
                              str(ARTIFACTS / "last-screen.png")], check=False)
            receipt["last_screenshot_exit"] = screen.returncode
        except (subprocess.TimeoutExpired, RuntimeError):
            receipt["last_screenshot_exit"] = "unconfirmed"
        if receipt["xcodebuild_exit"] == "timeout":
            raise RuntimeError("UI_TEST_COMMAND_TIMEOUT")
        if receipt["xcodebuild_exit"] != 0:
            raise RuntimeError("UI_TEST_FAILED")
        receipt["status"] = "UI_TEST_PASSED_ONLY"
        return 0
    except (RuntimeError, subprocess.TimeoutExpired, ValueError) as error:
        receipt["status"] = "blocked"
        receipt["failure"] = "COMMAND_TIMEOUT" if isinstance(error, subprocess.TimeoutExpired) else str(error)
        print("PROBE_FAILURE=" + receipt["failure"], flush=True)
        return 1
    finally:
        if device_id:
            receipt["cleanup_errors"] = cleanup_device(device_id)
        receipt["command_timings"] = TIMINGS
        (ARTIFACTS / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        print("PROBE_RECEIPT=" + json.dumps(receipt), flush=True)
        DEADLINE = None


if __name__ == "__main__":
    sys.exit(main())
