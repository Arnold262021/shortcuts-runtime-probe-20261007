"""Ephemeral owned Appium server; the host-only entry point has no session API."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
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
})


class AppiumHostPreflightError(RuntimeError):
    def __init__(self, code: str, *, cleanup_exited: bool | None = None,
                 temporary_retained: bool = False, primary_code: str | None = None):
        if code not in _ERRORS:
            raise ValueError("unknown appium host preflight code")
        super().__init__(code)
        self.code = code
        self.cleanup_exited = cleanup_exited
        self.temporary_retained = temporary_retained
        self.primary_code = primary_code


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


def _remove_owned_root(root: Path, identity: tuple[int, int]) -> None:
    status = root.lstat()
    if root.is_symlink() or (status.st_dev, status.st_ino) != identity or not root.name.startswith("appium-host-preflight-"):
        raise AppiumHostPreflightError("HOST_PREFLIGHT_CLEANUP_UNCONFIRMED")
    if root.resolve(strict=True).parent != Path(tempfile.gettempdir()).resolve(strict=True):
        raise AppiumHostPreflightError("HOST_PREFLIGHT_CLEANUP_UNCONFIRMED")
    shutil.rmtree(root)


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


def _run_owned_server(command: Callable[..., object], safe_env: dict[str, str],
                      on_ready: Callable[[str], None] | None = None) -> dict[str, object]:
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
                                      primary_code=primary.code if primary else None) from None
    if primary is not None:
        raise AppiumHostPreflightError(primary.code, cleanup_exited=cleanup_exited) from None
    return {"node_version": node_version, "npm_version": npm_version, "appium_version": APPIUM_VERSION,
            "xcuitest_version": installed_version, "status_ready": True, "status_version_match": True,
            "cleanup_exited": True, "duration_ms": int((time.monotonic() - started) * 1000)}
