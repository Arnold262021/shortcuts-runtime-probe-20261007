"""Ephemeral owned Appium server; the host-only entry point has no session API."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import plistlib
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Callable, Sequence
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener


APPIUM_VERSION = "3.8.0"
XCUITEST_VERSION = "12.18.1"
_REGISTRY = "https://registry.npmjs.org/"
_SEMVER = re.compile(r"v?(\d+)\.(\d+)\.(\d+)\Z")
_ERRORS = frozenset({
    "HOST_PREFLIGHT_UNSUPPORTED_ENVIRONMENT", "HOST_PREFLIGHT_NODE_VERSION", "HOST_PREFLIGHT_NPM_VERSION",
    "HOST_PREFLIGHT_NPM_INSTALL", "HOST_PREFLIGHT_CLI_VERSION", "HOST_PREFLIGHT_HELP_UNSUPPORTED",
    "HOST_PREFLIGHT_DRIVER_INSTALL", "HOST_PREFLIGHT_SERVER_START", "HOST_PREFLIGHT_STATUS_UNCONFIRMED",
    "HOST_PREFLIGHT_CLEANUP_UNCONFIRMED",
    "HOST_PREFLIGHT_NODE_COMMAND", "HOST_PREFLIGHT_NPM_COMMAND", "HOST_PREFLIGHT_DRIVER_VERSION",
    "HOST_PREFLIGHT_CALLBACK_UNCONFIRMED",
    "HOST_WDA_DRIVER_METADATA", "HOST_WDA_RESOLVE", "HOST_WDA_PACKAGE", "HOST_WDA_SIMCTL",
    "HOST_WDA_BUILD", "HOST_WDA_OUTPUT", "HOST_WDA_SIMULATOR_STATE_CHANGED", "HOST_WDA_CLEANUP_UNCONFIRMED",
})

_WDA_RESOLVE_SCRIPT = (
    "const p=require.resolve('appium-webdriveragent/package.json',{paths:[process.argv[1]]});"
    "process.stdout.write(JSON.stringify({resolvedPath:p}));"
)
_JSON_LIMIT = 64 * 1024


class AppiumHostPreflightError(RuntimeError):
    def __init__(self, code: str, *, cleanup_exited: bool | None = None,
                 temporary_retained: bool = False, primary_code: str | None = None,
                 build_exit: int | None = None, build_stdout_bytes: int | None = None,
                 build_stderr_bytes: int | None = None, build_failure_category: str | None = None,
                 build_stdout_sha256: str | None = None, build_stderr_sha256: str | None = None,
                 wda_build: dict[str, object] | None = None):
        if code not in _ERRORS:
            raise ValueError("unknown appium host preflight code")
        super().__init__(code)
        self.code = code
        self.cleanup_exited = cleanup_exited
        self.temporary_retained = temporary_retained
        self.primary_code = primary_code
        self.build_exit = build_exit
        self.build_stdout_bytes = build_stdout_bytes
        self.build_stderr_bytes = build_stderr_bytes
        self.build_failure_category = build_failure_category
        self.build_stdout_sha256 = build_stdout_sha256
        self.build_stderr_sha256 = build_stderr_sha256
        self.wda_build = wda_build


def _text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value if isinstance(value, str) else ""


def _version(value: object, *, node: bool = False) -> str:
    text = _text(value).strip()
    match = _SEMVER.fullmatch(text)
    if match is None:
        raise AppiumHostPreflightError("HOST_PREFLIGHT_NODE_VERSION" if node else "HOST_PREFLIGHT_CLI_VERSION")
    major, minor, patch = map(int, match.groups())
    if node and not ((major == 20 and (minor, patch) >= (19, 0)) or (major == 22 and (minor, patch) >= (12, 0)) or major >= 24):
        raise AppiumHostPreflightError("HOST_PREFLIGHT_NODE_VERSION")
    return ".".join(match.group(index) for index in (1, 2, 3))


def _run(command: Callable[..., object], args: Sequence[str], env: dict[str, str], timeout: int,
         failure: str = "HOST_PREFLIGHT_NPM_INSTALL") -> object:
    try:
        result = command(list(args), timeout=timeout, check=False, env=env)
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        raise AppiumHostPreflightError(failure) from None
    if getattr(result, "returncode", 1) != 0:
        raise AppiumHostPreflightError(failure)
    return result


def _build_failure(result: object) -> AppiumHostPreflightError:
    def output(name: str) -> bytes:
        value = getattr(result, name, b"")
        if isinstance(value, bytes):
            return value
        return value.encode("utf-8", "replace") if isinstance(value, str) else b""

    stdout, stderr = output("stdout"), output("stderr")
    combined = (stdout + b"\n" + stderr)[:_JSON_LIMIT].lower()
    if b"unable to find a destination matching the provided destination specifier" in combined:
        category = "destination_not_supported"
    elif b"clang: error:" in combined or b"swiftc: error:" in combined:
        category = "compiler_error"
    elif b"codesign error:" in combined or b"code signing error:" in combined:
        category = "signing_error"
    else:
        category = "unknown"
    exit_code = getattr(result, "returncode", None)
    exit_value = exit_code if isinstance(exit_code, int) and not isinstance(exit_code, bool) else None
    return AppiumHostPreflightError(
        "HOST_WDA_BUILD", build_exit=exit_value, build_stdout_bytes=len(stdout),
        build_stderr_bytes=len(stderr), build_failure_category=category,
        build_stdout_sha256=hashlib.sha256(stdout).hexdigest() if len(stdout) <= _JSON_LIMIT else None,
        build_stderr_sha256=hashlib.sha256(stderr).hexdigest() if len(stderr) <= _JSON_LIMIT else None,
    )


def _run_wda_build(command: Callable[..., object], args: Sequence[str], env: dict[str, str]) -> object:
    try:
        result = command(list(args), timeout=300, check=False, env=env)
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        raise AppiumHostPreflightError("HOST_WDA_BUILD") from None
    if getattr(result, "returncode", 1) != 0:
        raise _build_failure(result)
    return result


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _cleanup(process: subprocess.Popen[bytes]) -> bool:
    if process.poll() is not None:
        return True
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=5)
        return True
    except (OSError, subprocess.TimeoutExpired):
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait(timeout=3)
            return True
        except (OSError, subprocess.TimeoutExpired):
            return False


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _read_status(port: int) -> object:
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    with opener.open(f"http://127.0.0.1:{port}/status", timeout=5) as response:
        raw = response.read(16 * 1024 + 1)
    if len(raw) > 16 * 1024:
        raise ValueError("host status size limit")
    return json.loads(raw.decode("utf-8"))


def _driver_version(raw: object) -> str:
    text = _text(raw)
    if len(text) > 64 * 1024:
        raise AppiumHostPreflightError("HOST_PREFLIGHT_DRIVER_VERSION")
    try:
        installed = json.loads(text)
        driver = installed["xcuitest"]
        if not isinstance(driver, dict) or driver.get("pkgName") != "appium-xcuitest-driver" or driver.get("installed") is not True:
            raise ValueError("driver mismatch")
        version = driver["version"]
        if version != XCUITEST_VERSION:
            raise ValueError("driver version mismatch")
    except (ValueError, KeyError, TypeError):
        raise AppiumHostPreflightError("HOST_PREFLIGHT_DRIVER_VERSION") from None
    return version


def _driver_install_metadata(raw: object) -> tuple[str, str]:
    text = _text(raw)
    if len(text.encode("utf-8", "replace")) > _JSON_LIMIT:
        raise AppiumHostPreflightError("HOST_WDA_DRIVER_METADATA")
    try:
        installed = json.loads(text)
        driver = installed["xcuitest"]
        version = driver["version"]
        install_path = driver["installPath"]
        if (not isinstance(driver, dict) or driver.get("pkgName") != "appium-xcuitest-driver"
                or driver.get("installed") is not True or version != XCUITEST_VERSION
                or not isinstance(install_path, str) or not install_path):
            raise ValueError("metadata")
    except (ValueError, KeyError, TypeError, json.JSONDecodeError, RecursionError):
        raise AppiumHostPreflightError("HOST_WDA_DRIVER_METADATA") from None
    return version, install_path


def _bounded_json(raw: object, code: str) -> object:
    text = _text(raw)
    if len(text.encode("utf-8", "replace")) > _JSON_LIMIT:
        raise AppiumHostPreflightError(code)
    try:
        return json.loads(text)
    except (ValueError, TypeError, json.JSONDecodeError, RecursionError):
        raise AppiumHostPreflightError(code) from None


def _owned_regular(path: Path, root: Path, *, directory: bool) -> bool:
    try:
        lexical_root = root.absolute()
        canonical_root = root.resolve(strict=True)
        try:
            relative = path.relative_to(lexical_root)
            walk_root = lexical_root
        except ValueError:
            relative = path.relative_to(canonical_root)
            walk_root = canonical_root
        if ".." in relative.parts:
            return False
        if lexical_root.stat() != canonical_root.stat():
            return False
        current = walk_root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                return False
        resolved = path.resolve(strict=True)
        resolved.relative_to(canonical_root)
        return resolved.is_dir() if directory else resolved.is_file()
    except (OSError, ValueError):
        return False


def _read_owned_bounded(path: Path, root: Path, code: str) -> bytes:
    if not _owned_regular(path, root, directory=False):
        raise AppiumHostPreflightError(code)
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError("not regular")
            content = os.read(descriptor, _JSON_LIMIT + 1)
        finally:
            os.close(descriptor)
    except OSError:
        raise AppiumHostPreflightError(code) from None
    if len(content) > _JSON_LIMIT:
        raise AppiumHostPreflightError(code)
    return content


def _validated_wda_package(package_data: bytes) -> tuple[str, str]:
    package = _bounded_json(package_data, "HOST_WDA_PACKAGE")
    try:
        name = package["name"]
        version = package["version"]
        match = _SEMVER.fullmatch(version) if isinstance(version, str) else None
        if name != "appium-webdriveragent" or match is None:
            raise ValueError("package")
        major, minor, patch = map(int, match.groups())
        if major != 16 or (minor, patch) < (15, 0):
            raise ValueError("version")
    except (KeyError, TypeError, ValueError):
        raise AppiumHostPreflightError("HOST_WDA_PACKAGE") from None
    return version, hashlib.sha256(package_data).hexdigest()


def _valid_macho_header(content: bytes) -> bool:
    return content[:4] in {
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
    }


def _owned_macho(path: Path, root: Path) -> bool:
    if not _owned_regular(path, root, directory=False):
        return False
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(descriptor)
            return stat.S_ISREG(metadata.st_mode) and metadata.st_size > 0 and _valid_macho_header(os.read(descriptor, 4))
        finally:
            os.close(descriptor)
    except OSError:
        return False


def _owned_xctestrun_path(value: object, products: Path, runner: Path, root: Path,
                          *, expected: Path | None = None) -> Path:
    if not isinstance(value, str):
        raise AppiumHostPreflightError("HOST_WDA_OUTPUT")
    if value.startswith("__TESTROOT__/"):
        relative = Path(value.removeprefix("__TESTROOT__/"))
        candidate = products / relative
    elif value.startswith("__TESTHOST__/"):
        relative = Path(value.removeprefix("__TESTHOST__/"))
        candidate = runner / relative
    else:
        raise AppiumHostPreflightError("HOST_WDA_OUTPUT")
    if ".." in relative.parts or not _owned_regular(candidate, root, directory=True):
        raise AppiumHostPreflightError("HOST_WDA_OUTPUT")
    if expected is not None and candidate.resolve() != expected.resolve():
        raise AppiumHostPreflightError("HOST_WDA_OUTPUT")
    return candidate


def _validated_wda_outputs(derived: Path, root: Path) -> None:
    products = derived / "Build" / "Products"
    runner = products / "Debug-iphonesimulator" / "WebDriverAgentRunner-Runner.app"
    info = runner / "Info.plist"
    info_data = _read_owned_bounded(info, root, "HOST_WDA_OUTPUT")
    try:
        bundle = plistlib.loads(info_data)
        executable = bundle["CFBundleExecutable"]
        if not isinstance(executable, str) or not executable or Path(executable).name != executable:
            raise ValueError("executable")
    except (ValueError, TypeError, KeyError, plistlib.InvalidFileException, RecursionError):
        raise AppiumHostPreflightError("HOST_WDA_OUTPUT") from None
    if not _owned_macho(runner / executable, root):
        raise AppiumHostPreflightError("HOST_WDA_OUTPUT")
    try:
        runs = [path for path in products.iterdir() if path.suffix == ".xctestrun"]
    except OSError:
        raise AppiumHostPreflightError("HOST_WDA_OUTPUT") from None
    if len(runs) != 1 or len(runs) > 8:
        raise AppiumHostPreflightError("HOST_WDA_OUTPUT")
    run_data = _read_owned_bounded(runs[0], root, "HOST_WDA_OUTPUT")
    try:
        run = plistlib.loads(run_data)
        targets: list[object]
        legacy = run.get("WebDriverAgentRunner") if isinstance(run, dict) else None
        if isinstance(legacy, dict):
            targets = [legacy]
        else:
            configurations = run.get("TestConfigurations") if isinstance(run, dict) else None
            if not isinstance(configurations, list):
                raise ValueError("run")
            targets = [target for configuration in configurations if isinstance(configuration, dict)
                       for target in configuration.get("TestTargets", [])
                       if isinstance(target, dict) and target.get("BlueprintName") == "WebDriverAgentRunner"]
        if len(targets) != 1:
            raise ValueError("run")
        target = targets[0]
        bundle_path = target["TestBundlePath"]
        host_path = target["TestHostPath"]
        _owned_xctestrun_path(bundle_path, products, runner, root,
                              expected=runner / "PlugIns" / "WebDriverAgentRunner.xctest")
        _owned_xctestrun_path(host_path, products, runner, root, expected=runner)
    except (ValueError, TypeError, KeyError, plistlib.InvalidFileException, RecursionError):
        raise AppiumHostPreflightError("HOST_WDA_OUTPUT") from None


def _simulator_states(raw: object) -> dict[str, str]:
    body = _bounded_json(raw, "HOST_WDA_SIMCTL")
    try:
        devices = body["devices"]
        if not isinstance(devices, dict):
            raise ValueError("devices")
        states: dict[str, str] = {}
        for records in devices.values():
            if not isinstance(records, list):
                raise ValueError("records")
            for record in records:
                identity = record["udid"]
                state = record["state"]
                if not isinstance(identity, str) or not isinstance(state, str) or identity in states:
                    raise ValueError("record")
                states[identity] = state
        return states
    except (KeyError, TypeError, ValueError):
        raise AppiumHostPreflightError("HOST_WDA_SIMCTL") from None


def _remove_owned_root(root: Path, identity: tuple[int, int]) -> None:
    status = root.lstat()
    if root.is_symlink() or (status.st_dev, status.st_ino) != identity or not root.name.startswith("appium-host-preflight-"):
        raise AppiumHostPreflightError("HOST_PREFLIGHT_CLEANUP_UNCONFIRMED")
    if root.resolve(strict=True).parent != Path(tempfile.gettempdir()).resolve(strict=True):
        raise AppiumHostPreflightError("HOST_PREFLIGHT_CLEANUP_UNCONFIRMED")
    shutil.rmtree(root)


def _build_owned_wda(command: Callable[..., object], appium: Path, env: dict[str, str], root: Path) -> dict[str, object]:
    """Compile and validate WDA in `root`; no server, session, boot, or test command."""
    _run(command, [str(appium), "driver", "install", f"xcuitest@{XCUITEST_VERSION}"], env, 180,
         "HOST_PREFLIGHT_DRIVER_INSTALL")
    driver = _run(command, [str(appium), "driver", "list", "--installed", "--json"], env, 30,
                  "HOST_WDA_DRIVER_METADATA")
    xcuitest_version, install_text = _driver_install_metadata(getattr(driver, "stdout", b""))
    install_path = Path(install_text)
    if not install_path.is_absolute() or not _owned_regular(install_path, root, directory=True):
        raise AppiumHostPreflightError("HOST_WDA_DRIVER_METADATA")
    resolved = _run(command, ["node", "-e", _WDA_RESOLVE_SCRIPT, str(install_path)], env, 30,
                    "HOST_WDA_RESOLVE")
    resolve_body = _bounded_json(getattr(resolved, "stdout", b""), "HOST_WDA_RESOLVE")
    try:
        resolved_text = resolve_body["resolvedPath"]
        if not isinstance(resolved_text, str) or not resolved_text:
            raise ValueError("resolved")
    except (KeyError, TypeError, ValueError):
        raise AppiumHostPreflightError("HOST_WDA_RESOLVE") from None
    package_json = Path(resolved_text)
    if not package_json.is_absolute() or not _owned_regular(package_json, root, directory=False):
        raise AppiumHostPreflightError("HOST_WDA_PACKAGE")
    package_root = package_json.parent
    project = package_root / "WebDriverAgent.xcodeproj"
    pbxproj = project / "project.pbxproj"
    if not (_owned_regular(package_root, root, directory=True)
            and _owned_regular(project, root, directory=True)
            and _owned_regular(pbxproj, root, directory=False)):
        raise AppiumHostPreflightError("HOST_WDA_PACKAGE")
    package_version, package_sha256 = _validated_wda_package(
        _read_owned_bounded(package_json, root, "HOST_WDA_PACKAGE"))
    before = _run(command, ["xcrun", "simctl", "list", "devices", "--json"], env, 30, "HOST_WDA_SIMCTL")
    before_states = _simulator_states(getattr(before, "stdout", b""))
    derived = root / "derived"
    _run_wda_build(command, ["xcodebuild", "build-for-testing", "-project", str(project),
                             "-derivedDataPath", str(derived), "-scheme", "WebDriverAgentRunner",
                             "-sdk", "iphonesimulator", "-destination", "generic/platform=iOS Simulator",
                             "CODE_SIGNING_ALLOWED=NO"], env)
    after = _run(command, ["xcrun", "simctl", "list", "devices", "--json"], env, 30, "HOST_WDA_SIMCTL")
    after_states = _simulator_states(getattr(after, "stdout", b""))
    if before_states != after_states:
        raise AppiumHostPreflightError("HOST_WDA_SIMULATOR_STATE_CHANGED")
    _validated_wda_outputs(derived, root)
    return {
        "xcuitest_version": xcuitest_version, "wda_package_version": package_version,
        "wda_package_sha256": package_sha256, "build_exit": 0,
        "runner_bundle_verified": True, "xctestrun_verified": True,
        "simulator_state_unchanged": True, "simulator_device_count": len(after_states),
        "private_paths": {"derived_data_path": str(derived)},
    }


def _safe_wda_build(result: dict[str, object] | None) -> dict[str, object] | None:
    if result is None:
        return None
    return {key: value for key, value in result.items() if key != "private_paths"}


def run_appium_host_preflight(command: Callable[..., object], safe_env: dict[str, str]) -> dict[str, object]:
    """Install pinned Appium temporarily, check localhost readiness, then stop it.

    `command` must be the caller's bounded command wrapper. This API has no
    UDID, capability, session, simulator, or UI input.
    """
    return _run_owned_server(command, safe_env)


def run_appium_with_owned_server(command: Callable[..., object], safe_env: dict[str, str],
                                probe: Callable[[str], None]) -> dict[str, object]:
    """Call a trusted probe after readiness and always tear down owned resources.

    The probe receives only the loopback URL. It must bound its own requests and
    retain a sanitized result in its caller, including any ambiguous session.
    """
    if not callable(probe):
        raise AppiumHostPreflightError("HOST_PREFLIGHT_CALLBACK_UNCONFIRMED")
    return _run_owned_server(command, safe_env, probe)


def run_appium_with_prebuilt_owned_server(command: Callable[..., object], safe_env: dict[str, str],
                                          probe: Callable[[str, dict[str, str]], None]) -> dict[str, object]:
    """Compile owned WDA before starting Appium, then call `probe` with private in-memory paths."""
    if not callable(probe):
        raise AppiumHostPreflightError("HOST_PREFLIGHT_CALLBACK_UNCONFIRMED")
    return _run_owned_server(command, safe_env, probe, prebuild_wda=True)


def _run_owned_server(command: Callable[..., object], safe_env: dict[str, str],
                      on_ready: Callable[..., None] | None = None, *, prebuild_wda: bool = False) -> dict[str, object]:
    if sys.platform != "darwin" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise AppiumHostPreflightError("HOST_PREFLIGHT_UNSUPPORTED_ENVIRONMENT")
    env = {key: value for key, value in safe_env.items() if not key.upper().startswith("NPM_CONFIG_")}
    started = time.monotonic()
    root = Path(tempfile.mkdtemp(prefix="appium-host-preflight-"))
    status = root.lstat()
    identity = (status.st_dev, status.st_ino)
    process = None
    cleanup_exited = None
    primary = None
    wda_result: dict[str, object] | None = None
    try:
        npm_prefix = root / "npm"
        appium_home = root / "appium-home"
        tmp_dir = root / "tmp"
        empty_config = root / "npmrc"
        global_config = root / "npm-globalrc"
        empty_config.write_text("", encoding="ascii")
        global_config.write_text("", encoding="ascii")
        tmp_dir.mkdir()
        env.update({
            "APPIUM_HOME": str(appium_home), "TMPDIR": str(tmp_dir),
            "NPM_CONFIG_USERCONFIG": str(empty_config), "NPM_CONFIG_GLOBALCONFIG": str(global_config),
            "NPM_CONFIG_CACHE": str(root / "npm-cache"),
        })
        node = _run(command, ["node", "--version"], env, 30, "HOST_PREFLIGHT_NODE_COMMAND")
        node_version = _version(getattr(node, "stdout", b""), node=True)
        npm = _run(command, ["npm", "--version"], env, 30, "HOST_PREFLIGHT_NPM_COMMAND")
        try:
            npm_version = _version(getattr(npm, "stdout", b""))
        except AppiumHostPreflightError:
            raise AppiumHostPreflightError("HOST_PREFLIGHT_NPM_VERSION") from None
        if int(npm_version.split(".")[0]) < 10:
            raise AppiumHostPreflightError("HOST_PREFLIGHT_NPM_VERSION")
        env["NPM_CONFIG_REGISTRY"] = _REGISTRY
        _run(command, ["npm", "install", "--prefix", str(npm_prefix), "--no-save", "--registry", _REGISTRY, f"appium@{APPIUM_VERSION}"], env, 180)
        appium = npm_prefix / "node_modules" / ".bin" / "appium"
        for args, needed in (([str(appium), "--help"], "driver"),
                             ([str(appium), "driver", "--help"], "install list"),
                             ([str(appium), "driver", "list", "--help"], "--installed --json"),
                             ([str(appium), "server", "--help"], "--address --port --tmp --use-drivers")):
            result = _run(command, args, env, 30, "HOST_PREFLIGHT_HELP_UNSUPPORTED")
            help_text = _text(getattr(result, "stdout", b""))
            if not all(flag in help_text for flag in needed.split()):
                raise AppiumHostPreflightError("HOST_PREFLIGHT_HELP_UNSUPPORTED")
        version_result = _run(command, [str(appium), "--version"], env, 30, "HOST_PREFLIGHT_CLI_VERSION")
        if _version(getattr(version_result, "stdout", b"")) != APPIUM_VERSION:
            raise AppiumHostPreflightError("HOST_PREFLIGHT_CLI_VERSION")
        if prebuild_wda:
            wda_result = _build_owned_wda(command, appium, env, root)
            installed_version = wda_result["xcuitest_version"]
        else:
            _run(command, [str(appium), "driver", "install", f"xcuitest@{XCUITEST_VERSION}"], env, 180,
                 "HOST_PREFLIGHT_DRIVER_INSTALL")
            driver = _run(command, [str(appium), "driver", "list", "--installed", "--json"], env, 30,
                          "HOST_PREFLIGHT_DRIVER_VERSION")
            installed_version = _driver_version(getattr(driver, "stdout", b""))
        port = _free_port()
        server_args = [str(appium), "server", "--address", "127.0.0.1", "--port", str(port), "--tmp", str(tmp_dir), "--use-drivers", "xcuitest"]
        with (root / "server.stdout").open("wb") as stdout, (root / "server.stderr").open("wb") as stderr:
            try:
                process = subprocess.Popen(server_args, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=env, start_new_session=True)
            except OSError:
                raise AppiumHostPreflightError("HOST_PREFLIGHT_SERVER_START") from None
            ready = False
            status_version_ok = False
            deadline = time.monotonic() + 30
            requests = 0
            try:
                while time.monotonic() < deadline and requests < 30:
                    if process.poll() is not None:
                        raise AppiumHostPreflightError("HOST_PREFLIGHT_SERVER_START")
                    requests += 1
                    try:
                        body = _read_status(port)
                        value = body.get("value", {}) if isinstance(body, dict) else {}
                        ready = isinstance(value, dict) and value.get("ready") is True
                        build = value.get("build") if isinstance(value, dict) else None
                        status_version_ok = isinstance(build, dict) and build.get("version") == APPIUM_VERSION
                        if ready and status_version_ok and process.poll() is None:
                            break
                    except (OSError, ValueError):
                        pass
                    time.sleep(1)
                if not (ready and status_version_ok):
                    raise AppiumHostPreflightError("HOST_PREFLIGHT_STATUS_UNCONFIRMED")
            except AppiumHostPreflightError:
                raise
            if on_ready is not None:
                try:
                    if prebuild_wda:
                        private_paths = wda_result["private_paths"] if wda_result is not None else None
                        if not isinstance(private_paths, dict):
                            raise ValueError("prebuilt paths")
                        on_ready(f"http://127.0.0.1:{port}", private_paths)
                    else:
                        on_ready(f"http://127.0.0.1:{port}")
                except Exception:
                    raise AppiumHostPreflightError("HOST_PREFLIGHT_CALLBACK_UNCONFIRMED") from None
    except AppiumHostPreflightError as error:
        primary = error
    except OSError:
        primary = AppiumHostPreflightError("HOST_PREFLIGHT_SERVER_START")
    finally:
        cleanup_exited = _cleanup(process) if process is not None else None
        if cleanup_exited is not False:
            try:
                _remove_owned_root(root, identity)
            except (OSError, AppiumHostPreflightError):
                cleanup_exited = False
    if cleanup_exited is False:
        raise AppiumHostPreflightError("HOST_PREFLIGHT_CLEANUP_UNCONFIRMED", cleanup_exited=False,
                                      temporary_retained=True,
                                      primary_code=primary.code if primary else None,
                                      build_exit=primary.build_exit if primary else None,
                                      build_stdout_bytes=primary.build_stdout_bytes if primary else None,
                                      build_stderr_bytes=primary.build_stderr_bytes if primary else None,
                                      build_failure_category=primary.build_failure_category if primary else None,
                                      build_stdout_sha256=primary.build_stdout_sha256 if primary else None,
                                      build_stderr_sha256=primary.build_stderr_sha256 if primary else None,
                                      wda_build=_safe_wda_build(wda_result)) from None
    if primary is not None:
        raise AppiumHostPreflightError(
            primary.code, cleanup_exited=cleanup_exited, build_exit=primary.build_exit,
            build_stdout_bytes=primary.build_stdout_bytes, build_stderr_bytes=primary.build_stderr_bytes,
            build_failure_category=primary.build_failure_category,
            build_stdout_sha256=primary.build_stdout_sha256, build_stderr_sha256=primary.build_stderr_sha256,
            wda_build=_safe_wda_build(wda_result),
        ) from None
    result = {"node_version": node_version, "npm_version": npm_version, "appium_version": APPIUM_VERSION,
            "xcuitest_version": installed_version, "status_ready": True, "status_version_match": True,
            "cleanup_exited": True, "duration_ms": int((time.monotonic() - started) * 1000)}
    if wda_result is not None:
        result["wda_build"] = _safe_wda_build(wda_result)
    return result


def run_appium_wda_build_preflight(command: Callable[..., object], safe_env: dict[str, str]) -> dict[str, object]:
    """Build the pinned WDA test bundle only; issues no explicit boot, session, or test command."""
    if sys.platform != "darwin" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise AppiumHostPreflightError("HOST_PREFLIGHT_UNSUPPORTED_ENVIRONMENT")
    env = {key: value for key, value in safe_env.items() if not key.upper().startswith("NPM_CONFIG_")}
    started = time.monotonic()
    root = Path(tempfile.mkdtemp(prefix="appium-host-preflight-wda-"))
    status = root.lstat()
    identity = (status.st_dev, status.st_ino)
    primary: AppiumHostPreflightError | None = None
    cleanup_exited: bool | None = None
    try:
        npm_prefix = root / "npm"
        appium_home = root / "appium-home"
        tmp_dir = root / "tmp"
        user_config = root / "npmrc"
        global_config = root / "npm-globalrc"
        user_config.write_text("", encoding="ascii")
        global_config.write_text("", encoding="ascii")
        tmp_dir.mkdir()
        env.update({
            "APPIUM_HOME": str(appium_home), "TMPDIR": str(tmp_dir),
            "NPM_CONFIG_USERCONFIG": str(user_config), "NPM_CONFIG_GLOBALCONFIG": str(global_config),
            "NPM_CONFIG_CACHE": str(root / "npm-cache"), "NPM_CONFIG_REGISTRY": _REGISTRY,
        })
        node = _run(command, ["node", "--version"], env, 30, "HOST_PREFLIGHT_NODE_COMMAND")
        node_version = _version(getattr(node, "stdout", b""), node=True)
        npm = _run(command, ["npm", "--version"], env, 30, "HOST_PREFLIGHT_NPM_COMMAND")
        npm_version = _version(getattr(npm, "stdout", b""))
        if int(npm_version.split(".")[0]) < 10:
            raise AppiumHostPreflightError("HOST_PREFLIGHT_NPM_VERSION")
        _run(command, ["npm", "install", "--prefix", str(npm_prefix), "--no-save", "--registry", _REGISTRY,
                       f"appium@{APPIUM_VERSION}"], env, 180)
        appium = npm_prefix / "node_modules" / ".bin" / "appium"
        for args, needed in (([str(appium), "--help"], "driver"),
                             ([str(appium), "driver", "--help"], "install list"),
                             ([str(appium), "driver", "list", "--help"], "--installed --json")):
            help_result = _run(command, args, env, 30, "HOST_PREFLIGHT_HELP_UNSUPPORTED")
            if not all(flag in _text(getattr(help_result, "stdout", b"")) for flag in needed.split()):
                raise AppiumHostPreflightError("HOST_PREFLIGHT_HELP_UNSUPPORTED")
        version_result = _run(command, [str(appium), "--version"], env, 30, "HOST_PREFLIGHT_CLI_VERSION")
        if _version(getattr(version_result, "stdout", b"")) != APPIUM_VERSION:
            raise AppiumHostPreflightError("HOST_PREFLIGHT_CLI_VERSION")
        wda_result = _build_owned_wda(command, appium, env, root)
        result = {
            "status": "HOST_WDA_COMPILED_ONLY", "build_exit": 0,
            "runner_bundle_verified": True, "xctestrun_verified": True,
            "simulator_state_unchanged": True, "simulator_device_count": wda_result["simulator_device_count"],
            "wda_package_version": wda_result["wda_package_version"],
            "wda_package_sha256": wda_result["wda_package_sha256"],
            "xcuitest_version": wda_result["xcuitest_version"], "cleanup_exited": True,
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
    except AppiumHostPreflightError as error:
        primary = error
    except (OSError, ValueError):
        primary = AppiumHostPreflightError("HOST_WDA_PACKAGE")
    finally:
        try:
            _remove_owned_root(root, identity)
            cleanup_exited = True
        except (OSError, AppiumHostPreflightError):
            cleanup_exited = False
    if cleanup_exited is False:
        raise AppiumHostPreflightError("HOST_WDA_CLEANUP_UNCONFIRMED", cleanup_exited=False,
                                      temporary_retained=True,
                                      primary_code=primary.code if primary else None) from None
    if primary is not None:
        raise AppiumHostPreflightError(
            primary.code, cleanup_exited=True, build_exit=primary.build_exit,
            build_stdout_bytes=primary.build_stdout_bytes, build_stderr_bytes=primary.build_stderr_bytes,
            build_failure_category=primary.build_failure_category,
            build_stdout_sha256=primary.build_stdout_sha256, build_stderr_sha256=primary.build_stderr_sha256,
        ) from None
    return result
