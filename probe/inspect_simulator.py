"""Inspect Shortcuts only in a new, account-free GitHub-hosted simulator."""

import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import uuid


ROOT = Path(__file__).resolve().parent
ARTIFACTS = ROOT.parent / "artifacts"
SAFE_ENV = {key: os.environ[key] for key in (
    "PATH", "HOME", "TMPDIR", "DEVELOPER_DIR", "LANG", "LC_ALL"
) if key in os.environ}


def command(args, timeout=60, check=True, env=None):
    result = subprocess.run(args, capture_output=True, timeout=timeout,
                            env=env or SAFE_ENV, cwd=ROOT)
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


def find_shortcuts(apps):
    candidates = [bundle for bundle, info in apps.items()
                  if bundle == "com.apple.shortcuts"]
    if len(candidates) != 1:
        raise RuntimeError("SIMULATOR_SHORTCUTS_APP_ABSENT")
    return candidates[0]


def cleanup_device(device_id):
    errors = []
    for action in ("shutdown", "delete"):
        try:
            result = command(["xcrun", "simctl", action, device_id], timeout=30, check=False)
            if result.returncode:
                errors.append(f"{action}:exit{result.returncode}")
        except (subprocess.TimeoutExpired, OSError):
            errors.append(f"{action}:cleanup_unconfirmed")
    return errors


def main():
    if sys.platform != "darwin" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("GITHUB_MACOS_RUNNER_REQUIRED")
    ARTIFACTS.mkdir(exist_ok=False)
    device_id = None
    receipt = {"scope": "fresh_account_free_simulator", "message_access": False,
               "otp_proven": False, "automation_created": False}
    try:
        runtime, device_type = choose_device(
            sim_json("list", "runtimes"), sim_json("list", "devices", "available"),
            sim_json("list", "devicetypes"))
        receipt.update(runtime=runtime, device_type=device_type)
        created = command(["xcrun", "simctl", "create", "Synthetic-Shortcuts-Probe",
                           device_type, runtime]).stdout.decode().strip()
        device_id = str(uuid.UUID(created))
        command(["xcrun", "simctl", "boot", device_id])
        command(["xcrun", "simctl", "bootstatus", device_id, "-b"], timeout=300)
        apps = plistlib.loads(command(["xcrun", "simctl", "listapps", device_id]).stdout)
        bundle = find_shortcuts(apps)
        receipt["shortcuts_bundle"] = bundle
        env = dict(SAFE_ENV, TEST_RUNNER_SHORTCUTS_BUNDLE_ID=bundle)
        result_path = ROOT.parent / "ProbeResults.xcresult"
        build = command([
            "xcodebuild", "test", "-project", "AppleSimulatorProbe.xcodeproj",
            "-scheme", "AppleSimulatorProbe", "-destination", f"platform=iOS Simulator,id={device_id}",
            "-derivedDataPath", str(ROOT.parent / "DerivedData"),
            "-resultBundlePath", str(result_path), "-parallel-testing-enabled", "NO",
            "-maximum-concurrent-test-simulator-destinations", "1",
            "-test-timeouts-enabled", "YES", "-default-test-execution-time-allowance", "120",
            "-maximum-test-execution-time-allowance", "180", "CODE_SIGNING_ALLOWED=NO"
        ], timeout=480, check=False, env=env)
        receipt["xcodebuild_exit"] = build.returncode
        output = (build.stdout + build.stderr).decode("utf-8", "replace")
        output = output.replace(str(ROOT.parent), "<WORKSPACE>")
        output = output.replace(os.environ.get("HOME", "/no-home"), "<HOME>")
        relevant = [line for line in output.splitlines()
                    if "error:" in line or "PROBE_" in line
                    or "Test Case" in line or "TEST SUCCEEDED" in line or "TEST FAILED" in line]
        (ARTIFACTS / "test-diagnostics.txt").write_text("\n".join(relevant), encoding="utf-8")
        print("\n".join(relevant[-80:]), flush=True)
        if result_path.exists():
            attachments = ROOT.parent / "ExportedAttachments"
            exported = command(["xcrun", "xcresulttool", "export", "attachments", "--path",
                                str(result_path), "--output-path", str(attachments)],
                               timeout=60, check=False)
            receipt["attachment_export_exit"] = exported.returncode
            for index, file in enumerate(sorted(attachments.rglob("*"))):
                if file.is_file() and file.suffix.lower() in (".txt", ".png"):
                    shutil.copyfile(file, ARTIFACTS / f"ui-{index}{file.suffix.lower()}")
        screen = command(["xcrun", "simctl", "io", device_id, "screenshot",
                          str(ARTIFACTS / "last-screen.png")], check=False)
        receipt["last_screenshot_exit"] = screen.returncode
        if build.returncode:
            raise RuntimeError("UI_TEST_FAILED")
        receipt["status"] = "UI_TEST_PASSED_ONLY"
        return 0
    except (RuntimeError, subprocess.TimeoutExpired, ValueError) as error:
        receipt["status"] = "blocked"
        receipt["failure"] = str(error)
        print(f"PROBE_FAILURE={error}", flush=True)
        return 1
    finally:
        if device_id:
            receipt["cleanup_errors"] = cleanup_device(device_id)
        (ARTIFACTS / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        print("PROBE_RECEIPT=" + json.dumps(receipt), flush=True)


if __name__ == "__main__":
    sys.exit(main())
