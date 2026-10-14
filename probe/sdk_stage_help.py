"""Bounded installed documentation only; never execute simctl spawn or query logs."""

import hashlib
import math
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import tempfile
import time

from appium_host_preflight import _cleanup_wda_launch, _remove_owned_root


HELP_COMMANDS = {
    "simctl_spawn_help": ("/usr/bin/xcrun", "simctl", "help", "spawn"),
    "simctl_container_help": ("/usr/bin/xcrun", "simctl", "help", "get_app_container"),
    "log_manual": ("/usr/bin/man", "log"),
}
STREAM_LIMIT = 65536
DISCARD_LIMIT = 65536
QUERY_TIMEOUT = 10
EOF_TIMEOUT = 2
LITERALS = ("--style", "json", "--predicate", "show", "stream", "process",
            "processImagePath", "eventMessage")
QUERY_STATUSES = {"not_attempted", "observed", "exit_nonzero", "timeout",
                  "over_limit", "invalid_document", "capture_failed"}
ERROR_CODES = {"SDK_HELP_PLATFORM", "SDK_HELP_SETUP", "SDK_HELP_QUERY", "SDK_HELP_CLEANUP"}


def _supported_host():
    return (sys.platform == "darwin" and os.name == "posix"
            and os.environ.get("GITHUB_ACTIONS") == "true")


def _help_environment(source, root):
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(root / "home"),
           "TMPDIR": str(root / "tmp"), "LANG": "C", "LC_ALL": "C",
           "PAGER": "/bin/cat", "MANPAGER": "/bin/cat", "TERM": "dumb"}
    developer = source.get("DEVELOPER_DIR")
    if developer is not None:
        if (not isinstance(developer, str) or not 0 < len(developer) <= 4096
                or any(c in developer for c in "\0\r\n")
                or not Path(developer).is_absolute() or not Path(developer).is_dir()):
            raise ValueError("SDK_HELP_SETUP")
        env["DEVELOPER_DIR"] = developer
    return env


def _stream_metadata(raw, eof, overflow):
    result = {"bytes": len(raw), "complete": eof and not overflow}
    if not result["complete"]:
        return result
    result["sha256"] = hashlib.sha256(raw).hexdigest()
    try:
        text = bytes(raw).decode("utf-8", "strict")
        result["utf8"] = "\0" not in text
    except UnicodeError:
        result["utf8"] = False
        return result
    # Literal observations are not a format, capability, or schema contract.
    result["literal_counts"] = {key: text.count(key) for key in LITERALS}
    return result


def _capture_help(argv, env, root):
    if tuple(argv) not in HELP_COMMANDS.values():
        raise ValueError("SDK_HELP_QUERY")
    started = time.monotonic()
    deadline = started + QUERY_TIMEOUT
    process = None
    selector = None
    pipes = {}
    raw = {"stdout": bytearray(), "stderr": bytearray()}
    eof = {"stdout": False, "stderr": False}
    overflow = {"stdout": False, "stderr": False}
    discarded = {"stdout": 0, "stderr": 0}
    observed = {"status": "capture_failed", "timed_out": False, "over_limit": False,
                "eof_confirmed": False, "process_group_drained": True, "process_started": False,
                "discard_limit_reached": False, "forced_cleanup": False}
    capture_failed = False

    def drain_once(wait, discard_overflow=False):
        for key, _events in selector.select(wait):
            name = key.data
            remaining = STREAM_LIMIT - len(raw[name])
            discarding = discard_overflow and overflow[name]
            discard_remaining = DISCARD_LIMIT - discarded[name]
            try:
                chunk = os.read(key.fd, min(8192, discard_remaining + 1) if discarding
                                else min(8192, remaining + 1))
            except BlockingIOError:
                continue
            if not chunk:
                eof[name] = True
                selector.unregister(key.fileobj)
                continue
            if discarding:
                discarded[name] += min(len(chunk), discard_remaining)
                if len(chunk) > discard_remaining:
                    observed["discard_limit_reached"] = True
                    selector.unregister(key.fileobj)
                continue
            raw[name].extend(chunk[:remaining])
            if len(chunk) > remaining:
                overflow[name] = True

    try:
        process = subprocess.Popen(tuple(argv), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=root, env=env,
            start_new_session=True, close_fds=True)
        observed["process_group_drained"] = False
        observed["process_started"] = True
        pipes = {"stdout": process.stdout, "stderr": process.stderr}
        selector = selectors.DefaultSelector()
        for name, pipe in pipes.items():
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        while True:
            now = time.monotonic()
            if now >= deadline:
                observed["timed_out"] = True
                break
            drain_once(min(0.1, deadline - now))
            if any(overflow.values()):
                observed["over_limit"] = True
                break
            exit_code = process.poll()
            if exit_code is not None:
                observed["exit_code"] = exit_code
                break
    except Exception:
        capture_failed = True
    finally:
        # A reaped parent does not close pipes inherited by its descendants.
        if process is not None:
            if selector is not None and "exit_code" in observed and not capture_failed:
                grace_deadline = min(deadline, time.monotonic() + EOF_TIMEOUT)
                try:
                    while not all(eof.values()) and not any(overflow.values()):
                        remaining = grace_deadline - time.monotonic()
                        if remaining <= 0 or not selector.get_map():
                            break
                        drain_once(min(0.1, remaining))
                except Exception:
                    capture_failed = True
                if not all(eof.values()) and time.monotonic() >= deadline:
                    observed["timed_out"] = True
            observed["forced_cleanup"] = not all(eof.values())
            try:
                observed["process_group_drained"] = _cleanup_wda_launch(process) is True
            except Exception:
                observed["process_group_drained"] = False
            if selector is not None and observed["process_group_drained"]:
                eof_deadline = time.monotonic() + EOF_TIMEOUT
                try:
                    while not all(eof.values()):
                        if not selector.get_map():
                            break
                        remaining = eof_deadline - time.monotonic()
                        if remaining <= 0:
                            break
                        drain_once(min(0.1, remaining), discard_overflow=True)
                except Exception:
                    capture_failed = True
        if selector is not None:
            try:
                selector.close()
            except Exception:
                capture_failed = True
        for pipe in pipes.values():
            try:
                pipe.close()
            except Exception:
                capture_failed = True
    observed["over_limit"] = any(overflow.values())
    observed["eof_confirmed"] = all(eof.values())
    observed["seconds"] = round(time.monotonic() - started, 3)
    for name in raw:
        observed[name] = _stream_metadata(raw[name], eof[name] and not observed["forced_cleanup"], overflow[name])
        observed[name]["post_cleanup_discard_bytes"] = discarded[name]
    if all(eof.values()) and not any(overflow.values()):
        topic = argv[-1].lower()
        observed["topic_literal_count"] = sum(bytes(data).decode("utf-8", "replace").lower().count(topic)
                                               for data in raw.values())
    if observed["over_limit"]:
        observed["status"] = "over_limit"
    elif observed["timed_out"]:
        observed["status"] = "timeout"
    elif (capture_failed or observed["forced_cleanup"]
          or not observed["process_group_drained"] or not observed["eof_confirmed"]):
        observed["status"] = "capture_failed"
    elif observed.get("exit_code") != 0:
        observed["status"] = "exit_nonzero"
    elif (any(not observed[name].get("utf8") for name in raw) or not any(raw.values())
          or observed.get("topic_literal_count", 0) < 1):
        observed["status"] = "invalid_document"
    else:
        observed["status"] = "observed"
    return observed


def sdk_help_diagnostic(source):
    """Positive metadata allowlist also guards the inspector receipt boundary."""
    result = {"scope": "owned_sdk_help_only", "status": "SDK_HELP_UNCONFIRMED",
              "unified_schema_confirmed": False, "cleanup_exited": False,
              "temporary_cleanup_confirmed": False, "queries": {}}
    if not isinstance(source, dict):
        return result
    for key in ("cleanup_exited", "temporary_cleanup_confirmed"):
        if type(source.get(key)) is bool:
            result[key] = source[key]
    if source.get("error_code") is not None:
        result["error_code"] = (source["error_code"]
            if isinstance(source["error_code"], str) and source["error_code"] in ERROR_CODES
            else "SDK_HELP_QUERY")
    queries = source.get("queries")
    if not isinstance(queries, dict):
        return result
    for name in HELP_COMMANDS:
        query = queries.get(name)
        if not isinstance(query, dict):
            continue
        clean = {}
        if isinstance(query.get("status"), str) and query["status"] in QUERY_STATUSES:
            clean["status"] = query["status"]
        for key in ("timed_out", "over_limit", "eof_confirmed", "process_group_drained",
                    "process_started", "discard_limit_reached", "forced_cleanup"):
            if type(query.get(key)) is bool:
                clean[key] = query[key]
        code = query.get("exit_code")
        if type(code) is int and -255 <= code <= 255:
            clean["exit_code"] = code
        seconds = query.get("seconds")
        if type(seconds) in (int, float) and 0 <= seconds <= 1e6 and math.isfinite(seconds):
            clean["seconds"] = seconds
        topic_count = query.get("topic_literal_count")
        if type(topic_count) is int and 0 <= topic_count <= 2 * STREAM_LIMIT:
            clean["topic_literal_count"] = topic_count
        for stream in ("stdout", "stderr"):
            record = query.get(stream)
            if not isinstance(record, dict):
                continue
            size = record.get("bytes")
            if type(size) is not int or not 0 <= size <= STREAM_LIMIT:
                continue
            safe = {"bytes": size}
            count = record.get("post_cleanup_discard_bytes")
            if type(count) is int and 0 <= count <= DISCARD_LIMIT:
                safe["post_cleanup_discard_bytes"] = count
            if type(record.get("complete")) is bool:
                safe["complete"] = record["complete"]
            if safe.get("complete") is True:
                if type(record.get("utf8")) is bool:
                    safe["utf8"] = record["utf8"]
                sha = record.get("sha256")
                if isinstance(sha, str) and re.fullmatch(r"[a-f0-9]{64}", sha):
                    safe["sha256"] = sha
                counts = record.get("literal_counts")
                if isinstance(counts, dict):
                    safe["literal_counts"] = {key: counts[key] for key in LITERALS
                        if type(counts.get(key)) is int and 0 <= counts[key] <= size}
            clean[stream] = safe
        result["queries"][name] = clean
    complete = (set(result["queries"]) == set(HELP_COMMANDS)
        and result["cleanup_exited"] and result["temporary_cleanup_confirmed"]
        and not result.get("error_code")
        and all(query.get("status") == "observed" and query.get("exit_code") == 0
            and query.get("timed_out") is False and query.get("over_limit") is False
            and query.get("eof_confirmed") is True and query.get("process_group_drained") is True
            and query.get("process_started") is True and query.get("discard_limit_reached") is False
            and query.get("forced_cleanup") is False
            and query.get("topic_literal_count", 0) > 0
            and "seconds" in query
            and all(query.get(stream, {}).get("complete") is True
                and query[stream].get("utf8") is True and "sha256" in query[stream]
                and set(query[stream].get("literal_counts", {})) == set(LITERALS)
                for stream in ("stdout", "stderr"))
            and query["stdout"]["bytes"] + query["stderr"]["bytes"] > 0
            for query in result["queries"].values()))
    if (source.get("scope") == result["scope"]
            and source.get("status") == "SDK_HELP_OBSERVED_ONLY"
            and source.get("unified_schema_confirmed") is False and complete):
        result["status"] = "SDK_HELP_OBSERVED_ONLY"
    return result


def run_sdk_stage_help(safe_env):
    result = {"scope": "owned_sdk_help_only", "status": "SDK_HELP_UNCONFIRMED",
              "unified_schema_confirmed": False, "queries": {},
              "cleanup_exited": True, "temporary_cleanup_confirmed": False}
    if not _supported_host():
        result["error_code"] = "SDK_HELP_PLATFORM"
        return sdk_help_diagnostic(result)
    root = None
    identity = None
    try:
        root = Path(tempfile.mkdtemp(prefix="appium-host-preflight-sdk-help-"))
        status = root.lstat()
        identity = (status.st_dev, status.st_ino)
        (root / "home").mkdir()
        (root / "tmp").mkdir()
        env = _help_environment(safe_env, root)
        for name, argv in HELP_COMMANDS.items():
            result["cleanup_exited"] = False
            query = _capture_help(argv, env, root)
            result["queries"][name] = query
            drained = query.get("process_group_drained") is True
            if not drained or query.get("eof_confirmed") is not True:
                result["cleanup_exited"] = drained and query.get("process_started") is False
                break
            result["cleanup_exited"] = True
    except Exception:
        result["error_code"] = "SDK_HELP_SETUP"
    finally:
        if root is not None and identity is not None and result["cleanup_exited"]:
            try:
                _remove_owned_root(root, identity)
                result["temporary_cleanup_confirmed"] = True
            except Exception:
                result["error_code"] = "SDK_HELP_CLEANUP"
    if not result.get("error_code"):
        result["status"] = "SDK_HELP_OBSERVED_ONLY"
    return sdk_help_diagnostic(result)
