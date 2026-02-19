import os
import sys
import json
import ctypes
import shutil
import argparse
import http.client
import tempfile
import traceback
import difflib
import threading
import time
import itertools
import tomllib
import tomli_w
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlparse
import glob

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp import McpServer
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcResponse, JsonRpcRequest
else:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import McpServer
    from zeromcp.jsonrpc import JsonRpcResponse, JsonRpcRequest

    sys.path.pop(0)  # Clean up

IDA_HOST = "127.0.0.1"
IDA_PORT = 13337
IDA_PATH = "/mcp"
IDA_INSTANCES: dict[str, dict[str, str | int]] = {}
IDA_CURRENT_INSTANCE = "default"
STATE_LOCK = threading.RLock()
SESSION_ACTIVE_INSTANCES: dict[str, str] = {}
REQUEST_SESSION_CONTEXT = threading.local()
REQUEST_ID_LOCK = threading.Lock()
REQUEST_ID_COUNTER = itertools.count(1)


class InstanceExecutor:
    def __init__(self):
        self.exec_lock = threading.Lock()
        self.metric_lock = threading.Lock()
        self.queued = 0
        self.running = 0
        self.completed = 0
        self.timed_out = 0
        self.queue_timestamps: list[float] = []
        self.running_method: str | None = None
        self.running_request_id: Any = None
        self.last_start = 0.0
        self.last_end = 0.0

    def snapshot(self) -> dict[str, Any]:
        with self.metric_lock:
            oldest_age = None
            if self.queue_timestamps:
                oldest_age = max(time.monotonic() - self.queue_timestamps[0], 0.0)
            return {
                "queued": self.queued,
                "running": self.running,
                "completed": self.completed,
                "timed_out": self.timed_out,
                "oldest_queued_age_seconds": oldest_age,
                "in_flight_method": self.running_method,
                "in_flight_request_id": self.running_request_id,
                "last_start": self.last_start,
                "last_end": self.last_end,
            }


INSTANCE_EXECUTORS: dict[str, InstanceExecutor] = {}
REMOTE_TOOLS_CACHE: dict[str, list[dict[str, Any]]] = {}
REMOTE_TOOLS_GLOBAL_CACHE: list[dict[str, Any]] = []
INSTANCE_METADATA_CACHE: dict[str, dict[str, Any]] = {}


LOCAL_TOOL_NAMES = {
    "list_instances",
    "current_instance",
    "use_instance",
    "refresh_instances",
    "queue_status",
    "compare_funcs_cross",
    "collect_function_bundle",
    "trace_start",
    "trace_stop",
    "trace_status",
    "trace_export",
}

AUTO_DISCOVERY_ENABLED = False
AUTO_INSTANCE_DIR: str | None = None

TRACE_LOCK = threading.Lock()
TRACE_ENABLED = False
TRACE_CAPTURE_NOTIFICATIONS = False
TRACE_EVENTS: list[dict[str, Any]] = []
TRACE_MAX_EVENTS = 5000
TRACE_OUTPUT_PATH: str | None = None
TRACE_STARTED_AT = 0.0


def _parse_bool_env(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    value = value.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


def _parse_float_env(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _parse_int_env(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value, 0)
    except ValueError:
        return default


QUEUE_AUTOSCALE_ENABLED = _parse_bool_env("IDA_MCP_QUEUE_AUTOSCALE", True)
QUEUE_AUTOSCALE_HEADROOM = max(
    _parse_float_env("IDA_MCP_QUEUE_AUTOSCALE_HEADROOM_SECONDS", 15.0), 0.0
)
QUEUE_AUTOSCALE_MAX = _parse_float_env("IDA_MCP_QUEUE_AUTOSCALE_MAX_SECONDS", 0.0)
AUTO_FAILOVER_ENABLED = _parse_bool_env("IDA_MCP_AUTO_FAILOVER", True)
AUTO_FAILOVER_PROBE_TIMEOUT_SECONDS = max(
    _parse_float_env("IDA_MCP_AUTO_FAILOVER_PROBE_TIMEOUT_SECONDS", 2.0), 0.1
)
AUTO_FAILOVER_MAX_CANDIDATES = max(
    _parse_int_env("IDA_MCP_AUTO_FAILOVER_MAX_CANDIDATES", 8), 1
)
WRONG_INSTANCE_HINT_CANDIDATES = max(
    _parse_int_env("IDA_MCP_WRONG_INSTANCE_HINT_CANDIDATES", 3), 1
)
SESSION_ROUTING_ENABLED = _parse_bool_env("IDA_MCP_SESSION_ROUTING", True)
LIST_METADATA_TIMEOUT_SECONDS = max(
    _parse_float_env("IDA_MCP_LIST_METADATA_TIMEOUT_SECONDS", 2.0), 0.1
)
LIST_METADATA_CACHE_TTL_SECONDS = max(
    _parse_float_env("IDA_MCP_LIST_METADATA_CACHE_TTL_SECONDS", 10.0), 0.0
)
LIST_PARALLEL_PROBE = _parse_bool_env("IDA_MCP_LIST_PARALLEL_PROBE", True)
LIST_PROBE_MAX_WORKERS = max(_parse_int_env("IDA_MCP_LIST_PROBE_MAX_WORKERS", 4), 1)
AUTO_REQUIRE_LIVE = _parse_bool_env("IDA_MCP_AUTO_REQUIRE_LIVE", True)
AUTO_PROBE_TIMEOUT_SECONDS = max(
    _parse_float_env("IDA_MCP_AUTO_PROBE_TIMEOUT_SECONDS", 0.5), 0.05
)
AUTO_PROBE_MAX_WORKERS = max(_parse_int_env("IDA_MCP_AUTO_PROBE_MAX_WORKERS", 8), 1)
AUTO_STALE_GRACE_SECONDS = max(
    _parse_float_env("IDA_MCP_AUTO_STALE_GRACE_SECONDS", 90.0), 0.0
)
AUTO_HEARTBEAT_MULTIPLIER = max(
    _parse_float_env("IDA_MCP_AUTO_HEARTBEAT_MULTIPLIER", 3.0), 1.0
)
AUTO_PRUNE = _parse_bool_env("IDA_MCP_AUTO_PRUNE", False)
AUTO_INCLUDE_UNREACHABLE = _parse_bool_env("IDA_MCP_AUTO_INCLUDE_UNREACHABLE", False)

mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch


def _parse_request_obj(request: dict | str | bytes | bytearray) -> JsonRpcRequest:
    if not isinstance(request, dict):
        request_obj: JsonRpcRequest = json.loads(request)
    else:
        request_obj: JsonRpcRequest = request  # type: ignore
    return request_obj


def _rpc_path(ida_rpc) -> str:
    path = ida_rpc.path or "/mcp"
    if ida_rpc.query:
        path = f"{path}?{ida_rpc.query}"
    return path


def _default_state_dir() -> str:
    env_value = os.environ.get("IDA_MCP_STATE_DIR")
    if env_value:
        return env_value

    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return os.path.join(appdata, "ida-pro-mcp")

    return os.path.join(os.path.expanduser("~"), ".ida-pro-mcp")


def _remote_tools_cache_path() -> str:
    env_value = os.environ.get("IDA_MCP_TOOLS_CACHE_PATH")
    if env_value:
        return env_value

    return os.path.join(_default_state_dir(), "remote_tools_cache.json")


def _default_instance_dir() -> str:
    env_value = os.environ.get("IDA_MCP_INSTANCE_DIR")
    if env_value:
        return env_value

    return os.path.join(_default_state_dir(), "instances")


def _normalize_bound_host(host: str) -> str:
    if host in ("0.0.0.0", "::"):
        return "127.0.0.1"
    return host


def _select_unique_instance_name(base_name: str) -> str:
    with STATE_LOCK:
        candidate = base_name
        suffix = 2
        while candidate in IDA_INSTANCES:
            candidate = f"{base_name}_{suffix}"
            suffix += 1
        return candidate


def _get_or_create_executor(instance_name: str) -> InstanceExecutor:
    with STATE_LOCK:
        executor = INSTANCE_EXECUTORS.get(instance_name)
        if executor is None:
            executor = InstanceExecutor()
            INSTANCE_EXECUTORS[instance_name] = executor
        return executor


def _cache_remote_tools(instance_name: str, tools: list[dict[str, Any]]) -> None:
    snapshot = [dict(tool) for tool in tools if isinstance(tool, dict)]
    if not snapshot:
        return

    with STATE_LOCK:
        REMOTE_TOOLS_CACHE[instance_name] = snapshot
        REMOTE_TOOLS_GLOBAL_CACHE.clear()
        REMOTE_TOOLS_GLOBAL_CACHE.extend(snapshot)

    _save_remote_tools_cache()


def _cached_remote_tools(instance_name: str) -> list[dict[str, Any]]:
    with STATE_LOCK:
        cached = REMOTE_TOOLS_CACHE.get(instance_name)
        if isinstance(cached, list) and cached:
            return [dict(tool) for tool in cached]

        return [dict(tool) for tool in REMOTE_TOOLS_GLOBAL_CACHE]


def _save_remote_tools_cache() -> None:
    with STATE_LOCK:
        payload = {
            "updated_at": time.time(),
            "instances": {
                name: [dict(tool) for tool in tools]
                for name, tools in REMOTE_TOOLS_CACHE.items()
                if isinstance(tools, list) and tools
            },
            "global": [dict(tool) for tool in REMOTE_TOOLS_GLOBAL_CACHE],
        }

    try:
        cache_path = _remote_tools_cache_path()
        cache_dir = os.path.dirname(cache_path)
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)
        tmp_path = cache_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp_path, cache_path)
    except Exception:
        pass


def _load_remote_tools_cache() -> None:
    try:
        cache_path = _remote_tools_cache_path()
        if not os.path.exists(cache_path):
            return
        with open(cache_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception:
        return

    if not isinstance(payload, dict):
        return

    loaded_instances: dict[str, list[dict[str, Any]]] = {}
    instance_payload = payload.get("instances")
    if isinstance(instance_payload, dict):
        for name, tools in instance_payload.items():
            if not isinstance(name, str) or not isinstance(tools, list):
                continue
            snapshot = [dict(tool) for tool in tools if isinstance(tool, dict)]
            if snapshot:
                loaded_instances[name] = snapshot

    loaded_global: list[dict[str, Any]] = []
    global_payload = payload.get("global")
    if isinstance(global_payload, list):
        loaded_global = [
            dict(tool) for tool in global_payload if isinstance(tool, dict)
        ]

    with STATE_LOCK:
        if loaded_instances:
            REMOTE_TOOLS_CACHE.clear()
            REMOTE_TOOLS_CACHE.update(loaded_instances)
        if loaded_global:
            REMOTE_TOOLS_GLOBAL_CACHE.clear()
            REMOTE_TOOLS_GLOBAL_CACHE.extend(loaded_global)


def _resolve_instance_and_endpoint(
    instance_name: str | None,
) -> tuple[str, dict[str, Any]]:
    with STATE_LOCK:
        resolved = instance_name or IDA_CURRENT_INSTANCE
        endpoint = IDA_INSTANCES.get(resolved)
        if endpoint is None:
            raise Exception(f"Unknown IDA instance: {resolved}")
        return resolved, dict(endpoint)


def _extract_request_meta(request_obj: JsonRpcRequest) -> dict[str, Any] | None:
    params = request_obj.get("params")
    if not isinstance(params, dict):
        return None
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        return None
    return meta


def _extract_session_key_from_meta(meta: dict[str, Any] | None) -> str | None:
    if not isinstance(meta, dict):
        return None

    for field_name in ("mcpSessionId", "sessionId", "sseSessionId"):
        value = meta.get(field_name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _extract_session_key(request_obj: JsonRpcRequest) -> str | None:
    return _extract_session_key_from_meta(_extract_request_meta(request_obj))


def _get_request_session_key() -> str | None:
    session_key = getattr(REQUEST_SESSION_CONTEXT, "session_key", None)
    if isinstance(session_key, str) and session_key:
        return session_key
    return None


def _set_request_session_key(session_key: str | None) -> None:
    if isinstance(session_key, str) and session_key:
        REQUEST_SESSION_CONTEXT.session_key = session_key
    else:
        REQUEST_SESSION_CONTEXT.session_key = None


def _session_bound_instance(session_key: str | None) -> str | None:
    if (
        not SESSION_ROUTING_ENABLED
        or not isinstance(session_key, str)
        or not session_key
    ):
        return None

    with STATE_LOCK:
        instance_name = SESSION_ACTIVE_INSTANCES.get(session_key)
        if not isinstance(instance_name, str):
            return None
        if instance_name not in IDA_INSTANCES:
            del SESSION_ACTIVE_INSTANCES[session_key]
            return None
        return instance_name


def _effective_instance_name(session_key: str | None = None) -> str:
    session_instance = _session_bound_instance(session_key)
    if session_instance is not None:
        return session_instance

    with STATE_LOCK:
        return IDA_CURRENT_INSTANCE


def _bind_session_instance(session_key: str, instance_name: str) -> bool:
    if not SESSION_ROUTING_ENABLED:
        return False
    if not session_key or not instance_name:
        return False

    with STATE_LOCK:
        if instance_name not in IDA_INSTANCES:
            return False
        SESSION_ACTIVE_INSTANCES[session_key] = instance_name
        return True


def _list_instances_snapshot() -> tuple[str, list[tuple[str, dict[str, Any]]]]:
    with STATE_LOCK:
        current = IDA_CURRENT_INSTANCE
        pairs = [(name, dict(endpoint)) for name, endpoint in IDA_INSTANCES.items()]
        return current, pairs


def _next_internal_request_id() -> int:
    with REQUEST_ID_LOCK:
        return next(REQUEST_ID_COUNTER)


def _metadata_timeout_budget(timeout: float | int | None = None) -> float:
    budget = LIST_METADATA_TIMEOUT_SECONDS
    if timeout is not None:
        try:
            timeout_value = float(timeout)
            if timeout_value > 0:
                budget = min(budget, timeout_value)
        except (TypeError, ValueError):
            pass
    return max(budget, 0.1)


def _metadata_cache_get(instance_name: str) -> dict[str, Any] | None:
    now = time.monotonic()
    with STATE_LOCK:
        entry = INSTANCE_METADATA_CACHE.get(instance_name)
        if not isinstance(entry, dict):
            return None
        expires_at = entry.get("expires_at")
        metadata = entry.get("metadata")
        if not isinstance(expires_at, (int, float)) or now >= float(expires_at):
            INSTANCE_METADATA_CACHE.pop(instance_name, None)
            return None
        if not isinstance(metadata, dict):
            INSTANCE_METADATA_CACHE.pop(instance_name, None)
            return None
        return dict(metadata)


def _metadata_cache_put(instance_name: str, metadata: dict[str, Any]) -> None:
    ttl = LIST_METADATA_CACHE_TTL_SECONDS
    if ttl <= 0:
        return
    with STATE_LOCK:
        INSTANCE_METADATA_CACHE[instance_name] = {
            "metadata": dict(metadata),
            "expires_at": time.monotonic() + ttl,
        }


def _instance_started_at(endpoint: dict[str, Any]) -> float:
    value = endpoint.get("started_at")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return 0.0
    return 0.0


def _is_unreachable_dispatch_error(error: Exception) -> bool:
    if isinstance(error, TimeoutError):
        return False
    if isinstance(
        error,
        (
            ConnectionRefusedError,
            ConnectionResetError,
            ConnectionAbortedError,
            BrokenPipeError,
            http.client.RemoteDisconnected,
        ),
    ):
        return True

    text = str(error).lower()
    unreachable_markers = (
        "connection refused",
        "actively refused",
        "forcibly closed",
        "connection reset by peer",
        "remote end closed connection",
        "[winerror 10061]",
        "[winerror 10054]",
        "[errno 111]",
    )
    return any(marker in text for marker in unreachable_markers)


def _ordered_failover_candidates(
    failed_instance: str | None,
) -> list[tuple[str, dict[str, Any]]]:
    current, pairs = _list_instances_snapshot()

    failed_endpoint: dict[str, Any] | None = None
    if isinstance(failed_instance, str):
        for name, endpoint in pairs:
            if name == failed_instance:
                failed_endpoint = endpoint
                break

    failed_module = (
        failed_endpoint.get("module") if isinstance(failed_endpoint, dict) else None
    )
    failed_idb = (
        failed_endpoint.get("idb_path") if isinstance(failed_endpoint, dict) else None
    )

    candidates = [
        (name, endpoint) for name, endpoint in pairs if name != failed_instance
    ]

    def candidate_key(item: tuple[str, dict[str, Any]]) -> tuple[int, int, float, str]:
        name, endpoint = item
        same_module = (
            isinstance(failed_module, str)
            and failed_module != ""
            and endpoint.get("module") == failed_module
        )
        same_idb = (
            isinstance(failed_idb, str)
            and failed_idb != ""
            and endpoint.get("idb_path") == failed_idb
        )
        if same_module and same_idb:
            match_rank = 0
        elif same_module:
            match_rank = 1
        elif same_idb:
            match_rank = 2
        else:
            match_rank = 3

        active_rank = 0 if name == current else 1
        started_rank = -_instance_started_at(endpoint)
        return (match_rank, active_rank, started_rank, name)

    candidates.sort(key=candidate_key)
    return candidates


def _select_reachable_failover_instance(failed_instance: str | None) -> str | None:
    probe_timeout = min(max(AUTO_FAILOVER_PROBE_TIMEOUT_SECONDS, 0.1), 30.0)
    tested = 0
    for name, _endpoint in _ordered_failover_candidates(failed_instance):
        if tested >= AUTO_FAILOVER_MAX_CANDIDATES:
            break
        tested += 1
        error = _ping_instance(name, timeout=probe_timeout)
        if error is None:
            return name
    return None


def _extract_pinned_instance(request_obj: JsonRpcRequest) -> str | None:
    if request_obj.get("method") != "tools/call":
        return None
    params = request_obj.get("params")
    if not isinstance(params, dict):
        return None
    arguments = params.get("arguments")
    if not isinstance(arguments, dict):
        return None
    pinned = arguments.get("_instance")
    if isinstance(pinned, str) and pinned.strip():
        return pinned.strip()
    return None


def _reachable_instances_for_hint(
    failed_instance: str | None,
) -> list[tuple[str, dict[str, Any]]]:
    probe_timeout = min(max(AUTO_FAILOVER_PROBE_TIMEOUT_SECONDS, 0.1), 1.0)
    max_candidates = max(AUTO_FAILOVER_MAX_CANDIDATES, WRONG_INSTANCE_HINT_CANDIDATES)

    reachable: list[tuple[str, dict[str, Any]]] = []
    tested = 0
    for name, endpoint in _ordered_failover_candidates(failed_instance):
        if tested >= max_candidates:
            break
        tested += 1
        if _ping_instance(name, timeout=probe_timeout) is None:
            reachable.append((name, endpoint))
            if len(reachable) >= WRONG_INSTANCE_HINT_CANDIDATES:
                break

    return reachable


def _wrong_instance_hint(
    request_obj: JsonRpcRequest,
    failed_instance: str | None,
) -> str | None:
    reachable = _reachable_instances_for_hint(failed_instance)
    if not reachable:
        return None

    pinned_instance = _extract_pinned_instance(request_obj)
    recommended_name, recommended_endpoint = reachable[0]
    recommended_module = recommended_endpoint.get("module")
    reachable_names = ", ".join(name for name, _ in reachable)

    if isinstance(recommended_module, str) and recommended_module:
        target_display = f"{recommended_name} ({recommended_module})"
    else:
        target_display = recommended_name

    if pinned_instance is not None:
        intro = f"This call was pinned to _instance='{pinned_instance}', which appears unreachable."
    else:
        intro = "The selected instance appears unreachable."

    return (
        f"{intro} Reachable instances now: {reachable_names}. "
        f"Try use_instance(name='{recommended_name}') or pin calls with _instance='{recommended_name}'. "
        f"Suggested target: {target_display}."
    )


def _request_label(request_obj: JsonRpcRequest) -> str:
    method = str(request_obj.get("method", "unknown"))
    if method == "tools/call":
        params = request_obj.get("params")
        if isinstance(params, dict):
            name = params.get("name")
            if isinstance(name, str):
                return f"tools/call:{name}"
    return method


HEAVY_IDA_TOOLS = {
    "decompile",
    "bulk_decompile",
    "analyze_funcs",
    "find_text",
    "find_regex",
    "find_bytes",
    "find_insns",
    "disasm",
}


def _timeouts_for_request(request_obj: JsonRpcRequest) -> tuple[float, float]:
    method = request_obj.get("method")
    queue_timeout = 45.0
    request_timeout = 45.0

    if method == "tools/call":
        params = request_obj.get("params")
        tool_name = None
        if isinstance(params, dict):
            maybe_name = params.get("name")
            if isinstance(maybe_name, str):
                tool_name = maybe_name

        if tool_name in HEAVY_IDA_TOOLS:
            queue_timeout = 180.0
            request_timeout = 240.0
        elif tool_name in {"list_instances", "current_instance", "use_instance"}:
            queue_timeout = 15.0
            request_timeout = 15.0
    elif method in {"tools/list", "resources/list"}:
        queue_timeout = 20.0
        request_timeout = 20.0
    elif method == "resources/read":
        queue_timeout = 45.0
        request_timeout = 60.0

    return queue_timeout, request_timeout


def _effective_queue_wait_timeout(
    executor: InstanceExecutor,
    *,
    base_wait_timeout: float,
    io_timeout: float,
) -> float:
    if not QUEUE_AUTOSCALE_ENABLED:
        return base_wait_timeout

    with executor.metric_lock:
        # queued includes the current request after enqueue.
        depth = executor.queued + executor.running

    if depth <= 1:
        return base_wait_timeout

    estimated_wait = (depth - 1) * io_timeout + QUEUE_AUTOSCALE_HEADROOM
    effective_timeout = max(base_wait_timeout, estimated_wait)
    if QUEUE_AUTOSCALE_MAX > 0:
        effective_timeout = min(effective_timeout, QUEUE_AUTOSCALE_MAX)
    return effective_timeout


def _remove_instances_by_source(source: str):
    with STATE_LOCK:
        stale = [
            name
            for name, endpoint in IDA_INSTANCES.items()
            if str(endpoint.get("source", "manual")) == source
        ]
        for name in stale:
            del IDA_INSTANCES[name]
            REMOTE_TOOLS_CACHE.pop(name, None)
            INSTANCE_METADATA_CACHE.pop(name, None)
            executor = INSTANCE_EXECUTORS.get(name)
            if executor is not None:
                snapshot = executor.snapshot()
                if snapshot["queued"] == 0 and snapshot["running"] == 0:
                    del INSTANCE_EXECUTORS[name]

        if stale:
            stale_names = set(stale)
            stale_sessions = [
                session_key
                for session_key, instance_name in SESSION_ACTIVE_INSTANCES.items()
                if instance_name in stale_names
            ]
            for session_key in stale_sessions:
                del SESSION_ACTIVE_INSTANCES[session_key]

            if IDA_CURRENT_INSTANCE in stale_names:
                replacement = next(iter(IDA_INSTANCES.keys()), None)
                if isinstance(replacement, str):
                    _set_active_instance(replacement)

    if stale:
        _save_remote_tools_cache()


_WIN32_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_WIN32_PROCESS_QUERY_INFORMATION = 0x0400
_WIN32_ERROR_ACCESS_DENIED = 5
_WIN32_ERROR_INVALID_PARAMETER = 87
_WIN32_STILL_ACTIVE = 259


def _win32_open_process(desired_access: int, pid: int) -> Any:
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        raise OSError("ctypes.windll unavailable")
    kernel32 = getattr(windll, "kernel32", None)
    if kernel32 is None:
        raise OSError("kernel32 unavailable")
    return kernel32.OpenProcess(desired_access, False, pid)


def _win32_get_exit_code_process(process_handle: Any) -> int | None:
    exit_code = ctypes.c_ulong()
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        raise OSError("ctypes.windll unavailable")
    kernel32 = getattr(windll, "kernel32", None)
    if kernel32 is None:
        raise OSError("kernel32 unavailable")
    ok = kernel32.GetExitCodeProcess(process_handle, ctypes.byref(exit_code))
    if not ok:
        return None
    return int(exit_code.value)


def _win32_close_handle(process_handle: Any) -> None:
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        raise OSError("ctypes.windll unavailable")
    kernel32 = getattr(windll, "kernel32", None)
    if kernel32 is None:
        raise OSError("kernel32 unavailable")
    kernel32.CloseHandle(process_handle)


def _win32_get_last_error() -> int:
    get_last_error = getattr(ctypes, "get_last_error", None)
    if callable(get_last_error):
        return int(cast(Any, get_last_error)())

    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return 0
    kernel32 = getattr(windll, "kernel32", None)
    if kernel32 is None:
        return 0
    get_last_error_api = getattr(kernel32, "GetLastError", None)
    if callable(get_last_error_api):
        return int(cast(Any, get_last_error_api)())
    return 0


def _pid_is_alive_windows(pid: int) -> bool | None:
    access_denied = False
    invalid_parameter = False

    for desired_access in (
        _WIN32_PROCESS_QUERY_LIMITED_INFORMATION,
        _WIN32_PROCESS_QUERY_INFORMATION,
    ):
        process_handle = _win32_open_process(desired_access, pid)
        if process_handle:
            try:
                exit_code = _win32_get_exit_code_process(process_handle)
            finally:
                _win32_close_handle(process_handle)

            if exit_code is None:
                return None
            if exit_code == _WIN32_STILL_ACTIVE:
                return True
            return False

        last_error = _win32_get_last_error()
        if last_error == _WIN32_ERROR_ACCESS_DENIED:
            access_denied = True
        elif last_error == _WIN32_ERROR_INVALID_PARAMETER:
            invalid_parameter = True

    if access_denied:
        return True
    if invalid_parameter:
        return False
    return None


def _pid_is_alive(pid: Any) -> bool | None:
    if isinstance(pid, str):
        try:
            pid = int(pid, 0)
        except ValueError:
            return None
    if not isinstance(pid, int):
        return None
    if pid <= 0:
        return None

    if sys.platform == "win32":
        try:
            return _pid_is_alive_windows(pid)
        except Exception:
            return None

    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None


def _coerce_float(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _parse_registration_payload(
    path: str, payload: dict[str, Any]
) -> tuple[dict[str, Any] | None, str | None]:
    host = payload.get("host")
    if not isinstance(host, str) or not host.strip():
        return None, "Missing host"
    host = _normalize_bound_host(host.strip())

    port: Any = payload.get("port")
    if isinstance(port, str):
        try:
            port = int(port, 0)
        except ValueError:
            port = None
    if not isinstance(port, int):
        return None, "Missing/invalid port"

    path_value = payload.get("path")
    if not isinstance(path_value, str) or not path_value:
        path_value = "/mcp"

    name = (
        payload.get("name")
        or payload.get("registration_id")
        or payload.get("instance_id")
        or payload.get("module")
    )
    if not isinstance(name, str) or not name.strip():
        name = f"ida_{port}"
    name = name.strip()

    started_at = _coerce_float(payload.get("started_at"))
    if started_at is None:
        started_at = 0.0

    heartbeat_interval = _coerce_float(payload.get("heartbeat_interval_sec"))
    if heartbeat_interval is None or heartbeat_interval <= 0:
        heartbeat_interval = AUTO_STALE_GRACE_SECONDS

    last_heartbeat = _coerce_float(payload.get("last_heartbeat_at"))
    if last_heartbeat is None:
        last_heartbeat = started_at

    if last_heartbeat is None:
        last_heartbeat = 0.0

    now = time.time()
    heartbeat_age = (
        max(now - last_heartbeat, 0.0) if last_heartbeat > 0 else float("inf")
    )
    stale_by_grace = heartbeat_age > AUTO_STALE_GRACE_SECONDS
    stale_by_multiplier = heartbeat_age > (
        heartbeat_interval * AUTO_HEARTBEAT_MULTIPLIER
    )
    stale = stale_by_grace and stale_by_multiplier

    pid_alive = _pid_is_alive(payload.get("pid"))
    if pid_alive is False:
        stale = True

    registration_id = payload.get("registration_id") or payload.get("instance_id")
    if isinstance(registration_id, str):
        registration_id = registration_id.strip()
    else:
        registration_id = None

    parsed = {
        "name": name,
        "host": host,
        "port": port,
        "path": path_value,
        "source_file": path,
        "pid": payload.get("pid"),
        "pid_alive": pid_alive,
        "module": payload.get("module"),
        "idb_path": payload.get("idb_path"),
        "instance_id": payload.get("instance_id"),
        "registration_id": registration_id,
        "schema_version": payload.get("schema_version"),
        "started_at": started_at,
        "last_heartbeat_at": last_heartbeat,
        "heartbeat_interval_sec": heartbeat_interval,
        "heartbeat_age_seconds": heartbeat_age,
        "stale": stale,
        "sort_timestamp": max(last_heartbeat, started_at),
    }
    return parsed, None


def _ping_endpoint(host: str, port: int, path: str, *, timeout: float) -> str | None:
    conn = http.client.HTTPConnection(host, int(port), timeout=max(timeout, 0.05))
    try:
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "ping",
                "id": _next_internal_request_id(),
            }
        ).encode("utf-8")
        conn.request("POST", path, payload, {"Content-Type": "application/json"})
        response = conn.getresponse()
        data = response.read().decode("utf-8", errors="replace")
        body = json.loads(data)
    except Exception as e:
        return str(e)
    finally:
        conn.close()

    if not isinstance(body, dict):
        return "Invalid ping payload"
    if "error" in body:
        error = body.get("error")
        if isinstance(error, dict):
            return str(error.get("message", "Unknown error"))
        return "Unknown error"
    return None


def _auto_discovery_probe(parsed: dict[str, Any]) -> tuple[str, str | None]:
    if parsed.get("stale"):
        return "stale", "heartbeat/pid check failed"

    error = _ping_endpoint(
        str(parsed["host"]),
        int(parsed["port"]),
        str(parsed["path"]),
        timeout=AUTO_PROBE_TIMEOUT_SECONDS,
    )
    if error is None:
        return "alive", None
    return "unreachable", error


def _refresh_auto_instances(instance_dir: str | None = None) -> dict:
    global AUTO_INSTANCE_DIR

    if instance_dir is not None:
        AUTO_INSTANCE_DIR = instance_dir
    if AUTO_INSTANCE_DIR is None:
        AUTO_INSTANCE_DIR = _default_instance_dir()

    with STATE_LOCK:
        previous_active = IDA_CURRENT_INSTANCE
    _remove_instances_by_source("auto")

    discovered = 0
    loaded = 0
    errors = []
    skipped: list[dict[str, Any]] = []
    pruned: list[str] = []
    alive_count = 0
    unreachable_count = 0
    stale_count = 0
    invalid_count = 0

    parsed_entries: list[dict[str, Any]] = []

    if os.path.isdir(AUTO_INSTANCE_DIR):
        for path in sorted(glob.glob(os.path.join(AUTO_INSTANCE_DIR, "*.json"))):
            discovered += 1
            try:
                with open(path, "r", encoding="utf-8") as f:
                    payload = json.load(f)
            except Exception as e:
                errors.append({"file": path, "error": str(e)})
                continue

            if not isinstance(payload, dict):
                invalid_count += 1
                errors.append({"file": path, "error": "Invalid payload type"})
                continue

            parsed, parse_error = _parse_registration_payload(path, payload)
            if parsed is None:
                invalid_count += 1
                errors.append({"file": path, "error": parse_error or "Invalid payload"})
                continue
            parsed_entries.append(parsed)

    probe_results: dict[str, tuple[str, str | None]] = {}

    if parsed_entries:
        max_workers = min(AUTO_PROBE_MAX_WORKERS, len(parsed_entries))
        if max_workers <= 1:
            for entry in parsed_entries:
                source_file = str(entry.get("source_file"))
                probe_results[source_file] = _auto_discovery_probe(entry)
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_map = {
                    executor.submit(_auto_discovery_probe, entry): str(
                        entry.get("source_file")
                    )
                    for entry in parsed_entries
                }
                for future in as_completed(future_map):
                    source_file = future_map[future]
                    try:
                        probe_results[source_file] = future.result()
                    except Exception as e:
                        probe_results[source_file] = ("unreachable", str(e))

    status_rank = {"alive": 0, "unreachable": 1, "stale": 2, "invalid": 3}
    deduped: dict[str, dict[str, Any]] = {}
    for entry in parsed_entries:
        source_file = str(entry.get("source_file"))
        status, detail = probe_results.get(
            source_file, ("invalid", "Missing probe result")
        )
        entry["auto_status"] = status
        entry["auto_status_error"] = detail

        dedupe_key = (
            str(entry.get("registration_id") or "")
            or str(entry.get("instance_id") or "")
            or str(entry.get("name") or "")
        )
        previous = deduped.get(dedupe_key)
        if previous is None:
            deduped[dedupe_key] = entry
            continue

        previous_rank = status_rank.get(str(previous.get("auto_status")), 99)
        current_rank = status_rank.get(status, 99)
        previous_ts = float(previous.get("sort_timestamp", 0.0))
        current_ts = float(entry.get("sort_timestamp", 0.0))

        if (current_rank, -current_ts) < (previous_rank, -previous_ts):
            kept, dropped = entry, previous
            deduped[dedupe_key] = entry
        else:
            kept, dropped = previous, entry

        skipped.append(
            {
                "file": dropped.get("source_file"),
                "reason": "duplicate",
                "registration_id": dedupe_key,
                "kept": kept.get("source_file"),
            }
        )
        if AUTO_PRUNE:
            drop_file = dropped.get("source_file")
            if isinstance(drop_file, str):
                try:
                    os.remove(drop_file)
                    pruned.append(drop_file)
                except OSError:
                    pass

    selected_entries = list(deduped.values())

    for entry in selected_entries:
        source_file = str(entry.get("source_file"))
        status = str(entry.get("auto_status") or "invalid")
        detail = entry.get("auto_status_error")
        if not isinstance(detail, str):
            detail = None

        if status == "alive":
            alive_count += 1
        elif status == "unreachable":
            unreachable_count += 1
        elif status == "stale":
            stale_count += 1
            if AUTO_PRUNE:
                try:
                    os.remove(source_file)
                    pruned.append(source_file)
                except OSError:
                    pass
        else:
            invalid_count += 1

        should_route = status == "alive"
        if status == "unreachable" and AUTO_INCLUDE_UNREACHABLE:
            should_route = True
        if (
            AUTO_REQUIRE_LIVE
            and status != "alive"
            and not (status == "unreachable" and AUTO_INCLUDE_UNREACHABLE)
        ):
            should_route = False

        if not should_route:
            skipped.append(
                {
                    "file": source_file,
                    "reason": status,
                    "error": detail,
                }
            )
            continue

        endpoint_url = f"http://{entry['host']}:{entry['port']}{entry['path']}"
        try:
            _register_ida_instance(
                str(entry["name"]),
                endpoint_url,
                source="auto",
                extra={
                    "source_file": source_file,
                    "pid": entry.get("pid"),
                    "pid_alive": entry.get("pid_alive"),
                    "module": entry.get("module"),
                    "idb_path": entry.get("idb_path"),
                    "instance_id": entry.get("instance_id"),
                    "registration_id": entry.get("registration_id"),
                    "schema_version": entry.get("schema_version"),
                    "started_at": entry.get("started_at"),
                    "last_heartbeat_at": entry.get("last_heartbeat_at"),
                    "heartbeat_interval_sec": entry.get("heartbeat_interval_sec"),
                    "auto_status": status,
                },
            )
            loaded += 1
        except Exception as e:
            errors.append({"file": source_file, "error": str(e)})

    with STATE_LOCK:
        has_previous = previous_active in IDA_INSTANCES
        has_any = bool(IDA_INSTANCES)
        first_name = next(iter(IDA_INSTANCES.keys())) if has_any else None

    if has_previous:
        _set_active_instance(previous_active)
    elif first_name is not None:
        _set_active_instance(first_name)

    with STATE_LOCK:
        current_instance = IDA_CURRENT_INSTANCE if IDA_INSTANCES else None

    return {
        "auto_discovery_enabled": AUTO_DISCOVERY_ENABLED,
        "instance_dir": AUTO_INSTANCE_DIR,
        "discovered_files": discovered,
        "loaded_instances": loaded,
        "alive_count": alive_count,
        "unreachable_count": unreachable_count,
        "stale_count": stale_count,
        "invalid_count": invalid_count,
        "skipped": skipped,
        "current_instance": current_instance,
        "errors": errors,
        **({"pruned": pruned} if pruned else {}),
    }


def _register_ida_instance(
    name: str,
    value: str,
    *,
    source: str = "manual",
    extra: dict[str, Any] | None = None,
):
    ida_rpc = urlparse(value)
    if ida_rpc.hostname is None or ida_rpc.port is None:
        raise Exception(f"Invalid IDA RPC server: {value}")

    if not name.strip():
        name = "ida"
    name = _select_unique_instance_name(name.strip())

    path = _rpc_path(ida_rpc)
    endpoint = {
        "name": name,
        "host": _normalize_bound_host(ida_rpc.hostname),
        "port": ida_rpc.port,
        "path": path,
        "url": f"http://{_normalize_bound_host(ida_rpc.hostname)}:{ida_rpc.port}{path}",
        "source": source,
    }

    if extra:
        endpoint.update(extra)

    with STATE_LOCK:
        IDA_INSTANCES[name] = endpoint
        if name not in INSTANCE_EXECUTORS:
            INSTANCE_EXECUTORS[name] = InstanceExecutor()
    return name


def _set_active_instance(name: str):
    global IDA_HOST, IDA_PORT, IDA_PATH, IDA_CURRENT_INSTANCE

    with STATE_LOCK:
        endpoint = IDA_INSTANCES.get(name)
        if endpoint is None:
            raise Exception(f"Unknown IDA instance: {name}")

        IDA_HOST = str(endpoint["host"])
        IDA_PORT = int(endpoint["port"])
        IDA_PATH = str(endpoint["path"])
        IDA_CURRENT_INSTANCE = name


def _dispatch_to_ida(
    request_obj: JsonRpcRequest,
    *,
    instance_name: str | None = None,
    timeout: float = 30,
    queue_timeout: float | None = None,
    request_timeout: float | None = None,
) -> JsonRpcResponse | None:
    instance, endpoint = _resolve_instance_and_endpoint(instance_name)
    executor = _get_or_create_executor(instance)

    timeout_seconds = max(float(timeout), 0.0)
    queue_wait_timeout = (
        timeout_seconds if queue_timeout is None else max(float(queue_timeout), 0.0)
    )
    io_timeout = (
        timeout_seconds if request_timeout is None else max(float(request_timeout), 0.0)
    )

    queue_incremented = False
    acquired = False
    request_label = _request_label(request_obj)

    with executor.metric_lock:
        executor.queued += 1
        executor.queue_timestamps.append(time.monotonic())
        queue_incremented = True

    queue_started = time.monotonic()

    try:
        wait_timeout = _effective_queue_wait_timeout(
            executor,
            base_wait_timeout=queue_wait_timeout,
            io_timeout=io_timeout,
        )
        if wait_timeout <= 0:
            raise TimeoutError(
                f"Timed out before queue acquire for instance '{instance}'"
            )

        acquired = executor.exec_lock.acquire(timeout=wait_timeout)
        if not acquired:
            queue_waited = time.monotonic() - queue_started
            raise TimeoutError(
                f"Timed out waiting in queue for instance '{instance}' after {queue_waited:.3f}s"
            )

        with executor.metric_lock:
            if queue_incremented:
                executor.queued -= 1
                if executor.queue_timestamps:
                    executor.queue_timestamps.pop(0)
                queue_incremented = False
            executor.running = 1
            executor.running_method = request_label
            executor.running_request_id = request_obj.get("id")
            executor.last_start = time.time()

        if io_timeout <= 0:
            raise TimeoutError(
                f"Timed out before dispatch to instance '{instance}': request timeout budget is 0"
            )

        conn = http.client.HTTPConnection(
            str(endpoint["host"]),
            int(endpoint["port"]),
            timeout=io_timeout,
        )
        try:
            payload = json.dumps(request_obj).encode("utf-8")
            conn.request(
                "POST",
                str(endpoint["path"]),
                payload,
                {"Content-Type": "application/json"},
            )
            response = conn.getresponse()
            data = response.read().decode()
            return json.loads(data)
        finally:
            conn.close()
    except TimeoutError:
        with executor.metric_lock:
            executor.timed_out += 1
        raise
    except Exception as e:
        if "timed out" in str(e).lower():
            with executor.metric_lock:
                executor.timed_out += 1
        raise
    finally:
        if queue_incremented:
            with executor.metric_lock:
                if executor.queued > 0:
                    executor.queued -= 1
                if executor.queue_timestamps:
                    executor.queue_timestamps.pop(0)

        if acquired:
            with executor.metric_lock:
                executor.running = 0
                executor.running_method = None
                executor.running_request_id = None
                executor.completed += 1
                executor.last_end = time.time()
            executor.exec_lock.release()


def _error_response(
    request_obj: JsonRpcRequest,
    e: Exception,
    *,
    instance_name: str | None = None,
) -> JsonRpcResponse | None:
    req_id = request_obj.get("id")
    if req_id is None:
        return None

    full_info = traceback.format_exc()
    if sys.platform == "darwin":
        shortcut = "Ctrl+Option+M"
    else:
        shortcut = "Ctrl+Alt+M"

    try:
        resolved, endpoint = _resolve_instance_and_endpoint(instance_name)
        endpoint_desc = f"{resolved} ({endpoint.get('host')}:{endpoint.get('port')}{endpoint.get('path')})"
    except Exception:
        endpoint_desc = f"{instance_name or IDA_CURRENT_INSTANCE} (unresolved endpoint)"

    if isinstance(e, TimeoutError):
        message = (
            f"IDA request timed out on instance '{endpoint_desc}'. "
            "The per-instance queue is busy or execution exceeded timeout. "
            "Use queue_status() to inspect queue depth and in-flight method."
        )
    else:
        message = (
            f"Failed to connect to IDA Pro instance '{endpoint_desc}'! "
            f"Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?\n{full_info}"
        )
        if _is_unreachable_dispatch_error(e):
            hint = _wrong_instance_hint(request_obj, instance_name)
            if hint:
                message += f"\nHint: {hint}"

    return JsonRpcResponse(
        {
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": message,
                "data": str(e),
            },
            "id": req_id,
        }
    )


def _extract_tools(response: JsonRpcResponse | None) -> list[dict]:
    if response is None:
        return []
    result = response.get("result")
    if not isinstance(result, dict):
        return []
    tools = result.get("tools")
    if not isinstance(tools, list):
        return []
    return [tool for tool in tools if isinstance(tool, dict)]


def _read_instance_metadata(
    instance_name: str, *, timeout: float = 5
) -> tuple[dict | None, str | None]:
    last_error = "Unknown error"
    for uri in ("ida://idb/metadata_fast", "ida://idb/metadata"):
        try:
            response = _dispatch_to_ida(
                {
                    "jsonrpc": "2.0",
                    "method": "resources/read",
                    "params": {"uri": uri},
                    "id": _next_internal_request_id(),
                },
                instance_name=instance_name,
                timeout=timeout,
            )
        except Exception as e:
            last_error = str(e)
            continue

        if response is None:
            last_error = "No response"
            continue
        if "error" in response:
            error = response["error"]
            if isinstance(error, dict):
                last_error = str(error.get("message", "Unknown error"))
            else:
                last_error = "Unknown error"
            continue

        result = response.get("result")
        if not isinstance(result, dict):
            last_error = "Invalid result payload"
            continue

        contents = result.get("contents")
        if not isinstance(contents, list) or not contents:
            last_error = "Missing resource contents"
            continue

        first = contents[0]
        if not isinstance(first, dict):
            last_error = "Invalid resource content"
            continue

        text = first.get("text")
        if not isinstance(text, str):
            last_error = "Metadata response missing text payload"
            continue

        try:
            metadata = json.loads(text)
        except json.JSONDecodeError as e:
            last_error = f"Metadata parse failed: {e}"
            continue

        if not isinstance(metadata, dict):
            last_error = "Metadata payload is not an object"
            continue
        return metadata, None
    return None, last_error


def _read_instance_metadata_cached(
    instance_name: str,
    *,
    timeout: float | int | None = None,
    use_cache: bool = True,
) -> tuple[dict | None, str | None]:
    if use_cache:
        cached = _metadata_cache_get(instance_name)
        if cached is not None:
            return cached, None

    metadata, error = _read_instance_metadata(
        instance_name, timeout=_metadata_timeout_budget(timeout)
    )
    if metadata is not None:
        _metadata_cache_put(instance_name, metadata)
    return metadata, error


def _ping_instance(instance_name: str, *, timeout: float = 5) -> str | None:
    try:
        response = _dispatch_to_ida(
            {
                "jsonrpc": "2.0",
                "method": "ping",
                "id": _next_internal_request_id(),
            },
            instance_name=instance_name,
            timeout=timeout,
        )
    except Exception as e:
        return str(e)

    if response is None:
        return "No response"
    if "error" in response:
        error = response["error"]
        if isinstance(error, dict):
            return str(error.get("message", "Unknown error"))
        return "Unknown error"
    return None


def _trace_preview(value: Any, max_chars: int = 2000) -> Any:
    try:
        serialized = json.dumps(value, default=str)
    except Exception:
        serialized = repr(value)

    if len(serialized) <= max_chars:
        return value

    return {
        "truncated": True,
        "max_chars": max_chars,
        "preview": serialized[:max_chars],
    }


def _trace_append(event: dict[str, Any]) -> None:
    with TRACE_LOCK:
        if len(TRACE_EVENTS) >= TRACE_MAX_EVENTS:
            TRACE_EVENTS.pop(0)
        TRACE_EVENTS.append(event)
        output_path = TRACE_OUTPUT_PATH

    if output_path:
        try:
            with open(output_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, default=str) + "\n")
        except Exception:
            pass


def _trace_record(
    request_obj: JsonRpcRequest,
    response_obj: JsonRpcResponse | None,
    *,
    route: str,
    instance_name: str | None = None,
    error: str | None = None,
) -> None:
    if not TRACE_ENABLED:
        return
    if "id" not in request_obj and not TRACE_CAPTURE_NOTIFICATIONS:
        return

    method = request_obj.get("method")
    event: dict[str, Any] = {
        "timestamp": time.time(),
        "route": route,
        "instance": instance_name or IDA_CURRENT_INSTANCE,
        "method": method,
        "id": request_obj.get("id"),
        "params": _trace_preview(request_obj.get("params")),
    }

    if error is not None:
        event["error"] = error

    if response_obj is None:
        event["response"] = None
    elif "error" in response_obj:
        event["response_error"] = _trace_preview(response_obj.get("error"))
    else:
        event["response_result"] = _trace_preview(response_obj.get("result"))

    _trace_append(event)


def _extract_tool_payload(response: JsonRpcResponse | None) -> tuple[Any, str | None]:
    if response is None:
        return None, "No response"
    if "error" in response:
        error = response["error"]
        if isinstance(error, dict):
            return None, str(error.get("message", "Unknown error"))
        return None, "Unknown error"

    result = response.get("result")
    if not isinstance(result, dict):
        return None, "Invalid tool response payload"

    if result.get("isError"):
        content = result.get("content")
        if isinstance(content, list) and content:
            first = content[0]
            if isinstance(first, dict):
                text = first.get("text")
                if isinstance(text, str):
                    return None, text
        return None, "Tool execution failed"

    if "structuredContent" in result:
        return result.get("structuredContent"), None

    content = result.get("content")
    if isinstance(content, list) and content:
        first = content[0]
        if isinstance(first, dict):
            text = first.get("text")
            if isinstance(text, str):
                try:
                    return json.loads(text), None
                except Exception:
                    return text, None

    return result, None


def _remote_tool_call(
    instance_name: str,
    tool_name: str,
    arguments: dict[str, Any],
    *,
    timeout: int = 30,
) -> tuple[Any, str | None]:
    request_obj: JsonRpcRequest = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        },
        "id": _next_internal_request_id(),
    }

    try:
        response = _dispatch_to_ida(
            request_obj, instance_name=instance_name, timeout=timeout
        )
    except Exception as e:
        _trace_record(
            request_obj,
            None,
            route="internal_remote_tool_error",
            instance_name=instance_name,
            error=str(e),
        )
        return None, str(e)

    _trace_record(
        request_obj,
        response,
        route="internal_remote_tool",
        instance_name=instance_name,
    )

    return _extract_tool_payload(response)


def _function_snapshot(instance_name: str, addr: str) -> dict[str, Any]:
    snapshot: dict[str, Any] = {
        "instance": instance_name,
        "query_addr": addr,
        "resolved_addr": None,
        "name": None,
        "pseudocode": None,
        "strings": [],
        "callees": [],
        "errors": [],
    }

    lookup, lookup_err = _remote_tool_call(
        instance_name, "lookup_funcs", {"queries": [addr]}, timeout=20
    )
    if lookup_err:
        snapshot["errors"].append(f"lookup_funcs: {lookup_err}")
    elif isinstance(lookup, list) and lookup:
        first = lookup[0]
        if isinstance(first, dict):
            fn = first.get("fn")
            if isinstance(fn, dict):
                snapshot["resolved_addr"] = fn.get("addr")
                snapshot["name"] = fn.get("name")

    decomp, decomp_err = _remote_tool_call(
        instance_name,
        "bulk_decompile",
        {
            "addrs": [addr],
            "include_strings": True,
        },
        timeout=90,
    )
    if decomp_err:
        snapshot["errors"].append(f"bulk_decompile: {decomp_err}")
    elif isinstance(decomp, list) and decomp:
        entry = decomp[0] if isinstance(decomp[0], dict) else None
        if entry is not None:
            if snapshot["resolved_addr"] is None:
                snapshot["resolved_addr"] = entry.get("addr")
            if snapshot["name"] is None:
                snapshot["name"] = entry.get("name")
            snapshot["pseudocode"] = entry.get("pseudocode")
            strings = entry.get("strings")
            if isinstance(strings, list):
                snapshot["strings"] = [
                    s.get("string")
                    for s in strings
                    if isinstance(s, dict) and isinstance(s.get("string"), str)
                ]

    callees, callees_err = _remote_tool_call(
        instance_name,
        "callees",
        {
            "addrs": [addr],
            "limit": 500,
        },
        timeout=30,
    )
    if callees_err:
        snapshot["errors"].append(f"callees: {callees_err}")
    elif isinstance(callees, list) and callees:
        entry = callees[0] if isinstance(callees[0], dict) else None
        if entry is not None:
            entries = entry.get("callees")
            if isinstance(entries, list):
                names = []
                for callee in entries:
                    if isinstance(callee, dict):
                        name = callee.get("name")
                        if isinstance(name, str):
                            names.append(name)
                snapshot["callees"] = names

    return snapshot


@mcp.tool
def list_instances(
    probe: bool = False,
    probe_timeout: int = 5,
    include_metadata: bool = False,
) -> dict:
    """List configured IDA instances and current active instance.

    Set probe=True for liveness checks. Metadata reads are optional because they
    are heavier and can generate noise when many IDA instances are running.
    """
    instances = []
    current, instance_pairs = _list_instances_snapshot()

    if probe_timeout <= 0:
        probe_timeout = 1
    if probe_timeout > 30:
        probe_timeout = 30

    def build_entry(name: str, endpoint: dict[str, Any]) -> dict[str, Any]:
        error = None
        metadata = None
        metadata_error = None
        if probe:
            error = _ping_instance(name, timeout=probe_timeout)
            if error is None and include_metadata:
                metadata, metadata_error = _read_instance_metadata_cached(
                    name,
                    timeout=probe_timeout,
                    use_cache=True,
                )

        entry: dict[str, Any] = {
            "name": name,
            "active": name == current,
            "url": str(endpoint["url"]),
            "host": str(endpoint["host"]),
            "port": int(endpoint["port"]),
            "path": str(endpoint["path"]),
            "source": str(endpoint.get("source", "manual")),
        }
        for field_name in (
            "pid",
            "module",
            "idb_path",
            "instance_id",
            "started_at",
            "source_file",
        ):
            if field_name in endpoint:
                entry[field_name] = endpoint[field_name]

        if probe and error is None:
            entry["status"] = "online"
            if isinstance(metadata, dict):
                entry["module"] = metadata.get("module")
                entry["input_path"] = metadata.get("path")
                entry["base"] = metadata.get("base")
            elif metadata_error is not None:
                entry["metadata_error"] = metadata_error
        elif probe:
            entry["status"] = "unreachable"
            entry["error"] = error
        else:
            entry["status"] = "registered"
        return entry

    if probe and LIST_PARALLEL_PROBE and len(instance_pairs) > 1:
        max_workers = min(LIST_PROBE_MAX_WORKERS, len(instance_pairs))
        results: list[dict[str, Any] | None] = [None] * len(instance_pairs)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(build_entry, name, endpoint): idx
                for idx, (name, endpoint) in enumerate(instance_pairs)
            }
            for future in as_completed(future_map):
                idx = future_map[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    name, endpoint = instance_pairs[idx]
                    failed = build_entry(name, endpoint)
                    failed["status"] = "unreachable"
                    failed["error"] = str(e)
                    results[idx] = failed
        instances = [entry for entry in results if isinstance(entry, dict)]
    else:
        for name, endpoint in instance_pairs:
            instances.append(build_entry(name, endpoint))

    return {
        "current_instance": current,
        "instances": instances,
    }


@mcp.tool
def current_instance(_meta: dict | None = None) -> dict:
    """Show the currently selected IDA instance and metadata if reachable."""
    session_key = _extract_session_key_from_meta(_meta)
    if session_key is None:
        session_key = _get_request_session_key()

    with STATE_LOCK:
        global_current = IDA_CURRENT_INSTANCE
    current = _effective_instance_name(session_key)

    with STATE_LOCK:
        endpoint = IDA_INSTANCES.get(current)
        endpoint_snapshot = dict(endpoint) if endpoint is not None else None

    endpoint = endpoint_snapshot
    if endpoint is None:
        response = {
            "current_instance": current,
            "status": "invalid",
            "error": "Current instance is not configured",
        }
        if SESSION_ROUTING_ENABLED and session_key is not None:
            response["session_key"] = session_key
            response["global_instance"] = global_current
            response["scope"] = "session"
        return response

    metadata, error = _read_instance_metadata_cached(current, use_cache=True)
    response = {
        "current_instance": current,
        "url": str(endpoint["url"]),
        "host": str(endpoint["host"]),
        "port": int(endpoint["port"]),
        "path": str(endpoint["path"]),
        "source": str(endpoint.get("source", "manual")),
    }
    if metadata is not None:
        response["status"] = "online"
        response["metadata"] = metadata
    else:
        response["status"] = "unreachable"
        response["error"] = error

    if SESSION_ROUTING_ENABLED and session_key is not None:
        response["session_key"] = session_key
        response["global_instance"] = global_current
        response["scope"] = "session"
    return response


@mcp.tool
def use_instance(name: str, _meta: dict | None = None) -> dict:
    """Switch active IDA instance by configured instance name."""
    session_key = _extract_session_key_from_meta(_meta)
    if session_key is None:
        session_key = _get_request_session_key()

    with STATE_LOCK:
        exists = name in IDA_INSTANCES
        available_instances = sorted(IDA_INSTANCES.keys())

    if not exists:
        return {
            "success": False,
            "error": f"Unknown instance: {name}",
            "available_instances": available_instances,
        }

    previous = _effective_instance_name(session_key)
    bound_to_session = False
    if SESSION_ROUTING_ENABLED and session_key is not None:
        bound_to_session = _bind_session_instance(session_key, name)

    if not bound_to_session:
        _set_active_instance(name)

    with STATE_LOCK:
        endpoint = dict(IDA_INSTANCES[name])
        global_current = IDA_CURRENT_INSTANCE

    metadata, error = _read_instance_metadata_cached(name, use_cache=True)

    response = {
        "success": True,
        "previous_instance": previous,
        "current_instance": name,
        "url": str(endpoint["url"]),
    }
    if metadata is not None:
        response["status"] = "online"
        response["module"] = metadata.get("module")
        response["input_path"] = metadata.get("path")
    else:
        response["status"] = "unreachable"
        response["warning"] = error

    if SESSION_ROUTING_ENABLED and session_key is not None:
        response["session_key"] = session_key
        response["global_instance"] = global_current
        response["scope"] = "session" if bound_to_session else "global"
    return response


@mcp.tool
def refresh_instances(instance_dir: str | None = None) -> dict:
    """Refresh auto-discovered IDA instances from instance registration files."""
    if not AUTO_DISCOVERY_ENABLED and instance_dir is None:
        with STATE_LOCK:
            current = IDA_CURRENT_INSTANCE if IDA_INSTANCES else None
            instances = sorted(IDA_INSTANCES.keys())
        return {
            "auto_discovery_enabled": False,
            "message": "Auto discovery is disabled (use --ida-rpc auto)",
            "current_instance": current,
            "instances": instances,
        }

    return _refresh_auto_instances(instance_dir)


@mcp.tool
def queue_status(instance: str | None = None) -> dict:
    """Show per-instance queue and in-flight execution status."""
    current, instance_pairs = _list_instances_snapshot()
    instance_map = {name: endpoint for name, endpoint in instance_pairs}

    if instance is not None and instance not in instance_map:
        return {
            "ok": False,
            "error": f"Unknown instance: {instance}",
            "available_instances": sorted(instance_map.keys()),
        }

    targets = [instance] if instance is not None else sorted(instance_map.keys())
    queues = []
    for name in targets:
        endpoint = instance_map.get(name)
        executor = _get_or_create_executor(name)
        queue_metrics = executor.snapshot()
        queues.append(
            {
                "name": name,
                "active": name == current,
                "endpoint": str(endpoint.get("url")) if endpoint else None,
                "source": str(endpoint.get("source", "manual")) if endpoint else None,
                "metrics": queue_metrics,
            }
        )

    return {
        "ok": True,
        "current_instance": current,
        "instance_count": len(instance_map),
        "queue_autoscale": {
            "enabled": QUEUE_AUTOSCALE_ENABLED,
            "headroom_seconds": QUEUE_AUTOSCALE_HEADROOM,
            "max_seconds": QUEUE_AUTOSCALE_MAX,
        },
        "queues": queues,
    }


@mcp.tool
def compare_funcs_cross(
    instance_a: str,
    addr_a: str,
    instance_b: str,
    addr_b: str,
) -> dict:
    """Compare two functions across two configured IDA instances."""
    with STATE_LOCK:
        has_a = instance_a in IDA_INSTANCES
        has_b = instance_b in IDA_INSTANCES
        available_instances = sorted(IDA_INSTANCES.keys())

    if not has_a:
        return {
            "ok": False,
            "error": f"Unknown instance: {instance_a}",
            "available_instances": available_instances,
        }
    if not has_b:
        return {
            "ok": False,
            "error": f"Unknown instance: {instance_b}",
            "available_instances": available_instances,
        }

    snap_a = _function_snapshot(instance_a, addr_a)
    snap_b = _function_snapshot(instance_b, addr_b)

    strings_a = set(snap_a.get("strings") or [])
    strings_b = set(snap_b.get("strings") or [])
    callees_a = set(snap_a.get("callees") or [])
    callees_b = set(snap_b.get("callees") or [])

    pseudo_a = snap_a.get("pseudocode") or ""
    pseudo_b = snap_b.get("pseudocode") or ""
    pseudo_diff = list(
        difflib.unified_diff(
            str(pseudo_a).splitlines(),
            str(pseudo_b).splitlines(),
            fromfile=f"{instance_a}:{snap_a.get('name') or addr_a}",
            tofile=f"{instance_b}:{snap_b.get('name') or addr_b}",
            lineterm="",
        )
    )

    return {
        "ok": True,
        "instance_a": snap_a,
        "instance_b": snap_b,
        "strings": {
            "only_in_a": sorted(strings_a - strings_b),
            "only_in_b": sorted(strings_b - strings_a),
            "shared": sorted(strings_a & strings_b),
        },
        "callees": {
            "only_in_a": sorted(callees_a - callees_b),
            "only_in_b": sorted(callees_b - callees_a),
            "shared": sorted(callees_a & callees_b),
        },
        "pseudocode_diff": "\n".join(pseudo_diff) if pseudo_diff else "(identical)",
    }


@mcp.tool
def collect_function_bundle(
    addrs: list[str] | str,
    instance: str | None = None,
    include_decompile: bool = True,
    include_strings: bool = True,
    include_callees: bool = True,
    include_xrefs: bool = True,
) -> dict:
    """Collect common function analysis artifacts in one queued request bundle."""

    if isinstance(addrs, str):
        queries = [part.strip() for part in addrs.split(",") if part.strip()]
    else:
        queries = [str(addr).strip() for addr in addrs if str(addr).strip()]

    deduped_queries = list(dict.fromkeys(queries))
    if not deduped_queries:
        return {
            "ok": False,
            "error": "No function addresses provided",
        }

    with STATE_LOCK:
        target_instance = instance or IDA_CURRENT_INSTANCE
        exists = target_instance in IDA_INSTANCES
        available_instances = sorted(IDA_INSTANCES.keys())

    if not exists:
        return {
            "ok": False,
            "error": f"Unknown instance: {target_instance}",
            "available_instances": available_instances,
        }

    result: dict[str, Any] = {
        "ok": True,
        "instance": target_instance,
        "queries": deduped_queries,
        "lookup": None,
        "decompile": None,
        "callees": None,
        "xrefs_to": None,
        "errors": [],
    }

    lookup, lookup_err = _remote_tool_call(
        target_instance,
        "lookup_funcs",
        {"queries": deduped_queries},
        timeout=90,
    )
    if lookup_err:
        result["errors"].append(f"lookup_funcs: {lookup_err}")
    else:
        result["lookup"] = lookup

    if include_decompile:
        decompile, decompile_err = _remote_tool_call(
            target_instance,
            "bulk_decompile",
            {
                "addrs": deduped_queries,
                "include_strings": include_strings,
            },
            timeout=240,
        )
        if decompile_err:
            result["errors"].append(f"bulk_decompile: {decompile_err}")
        else:
            result["decompile"] = decompile

    if include_callees:
        callees, callees_err = _remote_tool_call(
            target_instance,
            "callees",
            {"addrs": deduped_queries, "limit": 500},
            timeout=120,
        )
        if callees_err:
            result["errors"].append(f"callees: {callees_err}")
        else:
            result["callees"] = callees

    if include_xrefs:
        xrefs, xrefs_err = _remote_tool_call(
            target_instance,
            "xrefs_to",
            {"addrs": deduped_queries, "limit": 1000},
            timeout=120,
        )
        if xrefs_err:
            result["errors"].append(f"xrefs_to: {xrefs_err}")
        else:
            result["xrefs_to"] = xrefs

    return result


@mcp.tool
def trace_start(
    path: str | None = None,
    capture_notifications: bool = False,
    max_events: int = 5000,
    clear_existing: bool = True,
) -> dict:
    """Start request/response tracing for MCP dispatch and remote calls."""
    global TRACE_ENABLED, TRACE_CAPTURE_NOTIFICATIONS, TRACE_MAX_EVENTS
    global TRACE_OUTPUT_PATH, TRACE_STARTED_AT

    if max_events <= 0:
        max_events = 5000

    output_path = path.strip() if isinstance(path, str) and path.strip() else None
    if output_path and clear_existing:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("")

    with TRACE_LOCK:
        TRACE_ENABLED = True
        TRACE_CAPTURE_NOTIFICATIONS = capture_notifications
        TRACE_MAX_EVENTS = max_events
        TRACE_OUTPUT_PATH = output_path
        TRACE_STARTED_AT = time.time()
        if clear_existing:
            TRACE_EVENTS.clear()

    return {
        "ok": True,
        "enabled": True,
        "capture_notifications": TRACE_CAPTURE_NOTIFICATIONS,
        "max_events": TRACE_MAX_EVENTS,
        "output_path": TRACE_OUTPUT_PATH,
        "started_at": TRACE_STARTED_AT,
    }


@mcp.tool
def trace_stop() -> dict:
    """Stop request/response tracing."""
    global TRACE_ENABLED
    with TRACE_LOCK:
        TRACE_ENABLED = False
        event_count = len(TRACE_EVENTS)
        started_at = TRACE_STARTED_AT

    duration = max(0.0, time.time() - started_at) if started_at else 0.0
    return {
        "ok": True,
        "enabled": False,
        "event_count": event_count,
        "duration_seconds": round(duration, 3),
    }


@mcp.tool
def trace_status() -> dict:
    """Show current tracing status and in-memory event count."""
    with TRACE_LOCK:
        enabled = TRACE_ENABLED
        capture_notifications = TRACE_CAPTURE_NOTIFICATIONS
        max_events = TRACE_MAX_EVENTS
        output_path = TRACE_OUTPUT_PATH
        started_at = TRACE_STARTED_AT
        event_count = len(TRACE_EVENTS)

    duration = max(0.0, time.time() - started_at) if started_at else 0.0
    return {
        "enabled": enabled,
        "capture_notifications": capture_notifications,
        "max_events": max_events,
        "output_path": output_path,
        "started_at": started_at,
        "duration_seconds": round(duration, 3),
        "event_count": event_count,
    }


@mcp.tool
def trace_export(path: str | None = None, clear_after_export: bool = False) -> dict:
    """Export captured trace events to a JSON file."""
    output_path = path.strip() if isinstance(path, str) and path.strip() else None
    if output_path is None:
        fd, output_path = tempfile.mkstemp(
            suffix=".json", prefix="ida_mcp_trace_", text=True
        )
        os.close(fd)

    with TRACE_LOCK:
        payload = {
            "exported_at": time.time(),
            "enabled": TRACE_ENABLED,
            "capture_notifications": TRACE_CAPTURE_NOTIFICATIONS,
            "max_events": TRACE_MAX_EVENTS,
            "event_count": len(TRACE_EVENTS),
            "events": list(TRACE_EVENTS),
        }
        if clear_after_export:
            TRACE_EVENTS.clear()

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    return {
        "ok": True,
        "path": output_path,
        "event_count": payload["event_count"],
        "cleared": clear_after_export,
    }


def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
    """Dispatch JSON-RPC requests to the MCP server registry"""
    request_obj = _parse_request_obj(request)
    session_key = _extract_session_key(request_obj)

    if request_obj["method"] == "initialize":
        response = dispatch_original(dict(request_obj))
        _trace_record(request_obj, response, route="local", instance_name="local")
        return response
    elif request_obj["method"].startswith("notifications/"):
        response = dispatch_original(dict(request_obj))
        _trace_record(request_obj, response, route="local", instance_name="local")
        return response

    method = request_obj.get("method")
    forward_request_obj: JsonRpcRequest = cast(JsonRpcRequest, dict(request_obj))
    target_instance: str | None = None
    instance_pinned = False

    if AUTO_DISCOVERY_ENABLED and method in {
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/read",
    }:
        _refresh_auto_instances()

    if method == "tools/list":
        local_response = dispatch_original(dict(request_obj))
        queue_timeout, request_timeout = _timeouts_for_request(forward_request_obj)
        with STATE_LOCK:
            target_instance = IDA_CURRENT_INSTANCE

        remote_response: JsonRpcResponse | None = None
        remote_tools: list[dict[str, Any]] = []
        cache_used = False
        try:
            remote_response = _dispatch_to_ida(
                forward_request_obj,
                instance_name=target_instance,
                queue_timeout=queue_timeout,
                request_timeout=request_timeout,
            )
            remote_result = (
                remote_response.get("result")
                if isinstance(remote_response, dict)
                else None
            )
            if (
                isinstance(remote_result, dict)
                and isinstance(remote_result.get("tools"), list)
                and isinstance(remote_response, dict)
                and "error" not in remote_response
            ):
                remote_tools = _extract_tools(remote_response)
                _cache_remote_tools(target_instance, remote_tools)
            else:
                remote_tools = _cached_remote_tools(target_instance)
                cache_used = bool(remote_tools)
        except Exception:
            remote_tools = _cached_remote_tools(target_instance)
            cache_used = bool(remote_tools)

        merged_tools = []
        seen_names = set()
        for tool in remote_tools + _extract_tools(local_response):
            name = tool.get("name")
            if not isinstance(name, str) or name in seen_names:
                continue
            merged_tools.append(tool)
            seen_names.add(name)

        response = JsonRpcResponse(
            {
                "jsonrpc": "2.0",
                "result": {"tools": merged_tools},
                "id": request_obj.get("id"),
            }
        )
        _trace_record(
            request_obj,
            response,
            route="mixed_cached" if cache_used else "mixed",
            instance_name=target_instance,
        )
        return response

    if method == "tools/call":
        params = request_obj.get("params")
        if isinstance(params, dict):
            name = params.get("name")
            if isinstance(name, str) and name in LOCAL_TOOL_NAMES:
                _set_request_session_key(session_key)
                try:
                    response = dispatch_original(dict(request_obj))
                finally:
                    _set_request_session_key(None)
                _trace_record(
                    request_obj, response, route="local", instance_name="local"
                )
                return response

            arguments = params.get("arguments")
            if isinstance(arguments, dict):
                instance_override = arguments.get("_instance")
                if isinstance(instance_override, str) and instance_override.strip():
                    target_instance = instance_override.strip()
                    instance_pinned = True
                    sanitized_args = dict(arguments)
                    sanitized_args.pop("_instance", None)
                    sanitized_params = dict(params)
                    sanitized_params["arguments"] = sanitized_args
                    forward_request_obj = cast(JsonRpcRequest, dict(request_obj))
                    forward_request_obj["params"] = sanitized_params

    if target_instance is None:
        target_instance = _effective_instance_name(session_key)

    queue_timeout, request_timeout = _timeouts_for_request(forward_request_obj)

    try:
        response = _dispatch_to_ida(
            forward_request_obj,
            instance_name=target_instance,
            queue_timeout=queue_timeout,
            request_timeout=request_timeout,
        )
        _trace_record(
            request_obj,
            response,
            route="remote",
            instance_name=target_instance,
        )
        return response
    except Exception as e:
        last_error = e
        if AUTO_DISCOVERY_ENABLED:
            _refresh_auto_instances()

        retry_plan: list[tuple[str, str, str]] = []
        with STATE_LOCK:
            target_missing = target_instance not in IDA_INSTANCES
            current_after_refresh = IDA_CURRENT_INSTANCE

        if target_missing and isinstance(current_after_refresh, str):
            retry_plan.append(
                (current_after_refresh, "remote_after_auto_refresh", "target_missing")
            )

        if (
            AUTO_FAILOVER_ENABLED
            and not instance_pinned
            and _is_unreachable_dispatch_error(last_error)
        ):
            failover_instance = _select_reachable_failover_instance(target_instance)
            if (
                isinstance(failover_instance, str)
                and failover_instance
                and failover_instance != target_instance
            ):
                retry_plan.append(
                    (
                        failover_instance,
                        "remote_after_failover",
                        f"failed_instance={target_instance}",
                    )
                )

        seen_instances: set[str] = set()
        for retry_instance, route, reason in retry_plan:
            if retry_instance in seen_instances:
                continue
            seen_instances.add(retry_instance)

            try:
                response = _dispatch_to_ida(
                    forward_request_obj,
                    instance_name=retry_instance,
                    queue_timeout=queue_timeout,
                    request_timeout=request_timeout,
                )
                target_instance = retry_instance
                if route == "remote_after_failover":
                    try:
                        if (
                            SESSION_ROUTING_ENABLED
                            and isinstance(session_key, str)
                            and session_key
                        ):
                            _bind_session_instance(session_key, retry_instance)
                        else:
                            _set_active_instance(retry_instance)
                    except Exception:
                        pass
                _trace_record(
                    request_obj,
                    response,
                    route=route,
                    instance_name=retry_instance,
                    error=reason,
                )
                return response
            except Exception as retry_error:
                last_error = retry_error
                target_instance = retry_instance

        response = _error_response(
            request_obj,
            last_error,
            instance_name=target_instance,
        )
        _trace_record(
            request_obj,
            response,
            route="remote_error",
            instance_name=target_instance,
            error=str(last_error),
        )
        return response


mcp.registry.dispatch = dispatch_proxy


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
IDA_PLUGIN_PKG = os.path.join(SCRIPT_DIR, "ida_mcp")
IDA_PLUGIN_LOADER = os.path.join(SCRIPT_DIR, "ida_mcp.py")

# NOTE: This is in the global scope on purpose
if not os.path.exists(IDA_PLUGIN_PKG):
    raise RuntimeError(
        f"IDA plugin package not found at {IDA_PLUGIN_PKG} (did you move it?)"
    )
if not os.path.exists(IDA_PLUGIN_LOADER):
    raise RuntimeError(
        f"IDA plugin loader not found at {IDA_PLUGIN_LOADER} (did you move it?)"
    )


def get_python_executable():
    """Get the path to the Python executable"""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        if sys.platform == "win32":
            python = os.path.join(venv, "Scripts", "python.exe")
        else:
            python = os.path.join(venv, "bin", "python3")
        if os.path.exists(python):
            return python

    for path in sys.path:
        if sys.platform == "win32":
            path = path.replace("/", "\\")

        split = path.split(os.sep)
        if split[-1].endswith(".zip"):
            path = os.path.dirname(path)
            if sys.platform == "win32":
                python_executable = os.path.join(path, "python.exe")
            else:
                python_executable = os.path.join(path, "..", "bin", "python3")
            python_executable = os.path.abspath(python_executable)

            if os.path.exists(python_executable):
                return python_executable
    return sys.executable


def copy_python_env(env: dict[str, str]):
    # Reference: https://docs.python.org/3/using/cmdline.html#environment-variables
    python_vars = [
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
    ]
    # MCP servers are run without inheriting the environment, so we need to forward
    # the environment variables that affect Python's dependency resolution by hand.
    # Issue: https://github.com/mrexodia/ida-pro-mcp/issues/111
    result = False
    for var in python_vars:
        value = os.environ.get(var)
        if value:
            result = True
            env[var] = value
    return result


def generate_mcp_config(*, stdio: bool):
    if stdio:
        args = [__file__]
        if AUTO_DISCOVERY_ENABLED:
            if AUTO_INSTANCE_DIR and AUTO_INSTANCE_DIR != _default_instance_dir():
                args.extend(["--ida-rpc", f"auto={AUTO_INSTANCE_DIR}"])
            else:
                args.extend(["--ida-rpc", "auto"])
        else:
            args.extend(["--ida-rpc", f"http://{IDA_HOST}:{IDA_PORT}{IDA_PATH}"])

        mcp_config = {
            "command": get_python_executable(),
            "args": args,
        }
        env = {}
        if copy_python_env(env):
            print("[WARNING] Custom Python environment variables detected")
            mcp_config["env"] = env
        return mcp_config
    else:
        return {"type": "http", "url": f"http://{IDA_HOST}:{IDA_PORT}{IDA_PATH}"}


def print_mcp_config():
    print("[HTTP MCP CONFIGURATION]")
    print(
        json.dumps(
            {"mcpServers": {mcp.name: generate_mcp_config(stdio=False)}}, indent=2
        )
    )
    print("\n[STDIO MCP CONFIGURATION]")
    print(
        json.dumps(
            {"mcpServers": {mcp.name: generate_mcp_config(stdio=True)}}, indent=2
        )
    )


def install_mcp_servers(*, stdio: bool = False, uninstall=False, quiet=False):
    # Map client names to their JSON key paths for clients that don't use "mcpServers"
    # Format: client_name -> (top_level_key, nested_key)
    # None means use default "mcpServers" at top level
    special_json_structures = {
        "VS Code": ("mcp", "servers"),
        "VS Code Insiders": ("mcp", "servers"),
        "Visual Studio 2022": (None, "servers"),  # servers at top level
    }

    if sys.platform == "win32":
        configs = {
            "Cline": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Claude": (
                os.path.join(os.getenv("APPDATA", ""), "Claude"),
                "claude_desktop_config.json",
            ),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Zed": (
                os.path.join(os.getenv("APPDATA", ""), "Zed"),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "VS Code Insiders": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code - Insiders",
                    "User",
                ),
                "settings.json",
            ),
        }
    elif sys.platform == "darwin":
        configs = {
            "Cline": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Claude": (
                os.path.join(
                    os.path.expanduser("~"), "Library", "Application Support", "Claude"
                ),
                "claude_desktop_config.json",
            ),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Zed": (
                os.path.join(
                    os.path.expanduser("~"), "Library", "Application Support", "Zed"
                ),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "BoltAI": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "BoltAI",
                ),
                "config.json",
            ),
            "Perplexity": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Perplexity",
                ),
                "mcp_config.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "VS Code Insiders": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code - Insiders",
                    "User",
                ),
                "settings.json",
            ),
        }
    elif sys.platform == "linux":
        configs = {
            "Cline": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            # Claude not supported on Linux
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Zed": (
                os.path.join(os.path.expanduser("~"), ".config", "zed"),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "VS Code Insiders": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code - Insiders",
                    "User",
                ),
                "settings.json",
            ),
        }
    else:
        print(f"Unsupported platform: {sys.platform}")
        return

    installed = 0
    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)
        is_toml = config_file.endswith(".toml")

        if not os.path.exists(config_dir):
            action = "uninstall" if uninstall else "installation"
            if not quiet:
                print(f"Skipping {name} {action}\n  Config: {config_path} (not found)")
            continue

        # Read existing config
        if not os.path.exists(config_path):
            config = {}
        else:
            with open(
                config_path,
                "rb" if is_toml else "r",
                encoding=None if is_toml else "utf-8",
            ) as f:
                if is_toml:
                    data = f.read()
                    if len(data) == 0:
                        config = {}
                    else:
                        try:
                            config = tomllib.loads(data.decode("utf-8"))
                        except tomllib.TOMLDecodeError:
                            if not quiet:
                                print(
                                    f"Skipping {name} uninstall\n  Config: {config_path} (invalid TOML)"
                                )
                            continue
                else:
                    data = f.read().strip()
                    if len(data) == 0:
                        config = {}
                    else:
                        try:
                            config = json.loads(data)
                        except json.decoder.JSONDecodeError:
                            if not quiet:
                                print(
                                    f"Skipping {name} uninstall\n  Config: {config_path} (invalid JSON)"
                                )
                            continue

        # Handle TOML vs JSON structure
        if is_toml:
            if "mcp_servers" not in config:
                config["mcp_servers"] = {}
            mcp_servers = config["mcp_servers"]
        else:
            # Check if this client uses a special JSON structure
            if name in special_json_structures:
                top_key, nested_key = special_json_structures[name]
                if top_key is None:
                    # servers at top level (e.g., Visual Studio 2022)
                    if nested_key not in config:
                        config[nested_key] = {}
                    mcp_servers = config[nested_key]
                else:
                    # nested structure (e.g., VS Code uses mcp.servers)
                    if top_key not in config:
                        config[top_key] = {}
                    if nested_key not in config[top_key]:
                        config[top_key][nested_key] = {}
                    mcp_servers = config[top_key][nested_key]
            else:
                # Default: mcpServers at top level
                if "mcpServers" not in config:
                    config["mcpServers"] = {}
                mcp_servers = config["mcpServers"]

        # Migrate old name
        old_name = "github.com/mrexodia/ida-pro-mcp"
        if old_name in mcp_servers:
            mcp_servers[mcp.name] = mcp_servers[old_name]
            del mcp_servers[old_name]

        if uninstall:
            if mcp.name not in mcp_servers:
                if not quiet:
                    print(
                        f"Skipping {name} uninstall\n  Config: {config_path} (not installed)"
                    )
                continue
            del mcp_servers[mcp.name]
        else:
            mcp_servers[mcp.name] = generate_mcp_config(stdio=stdio)

        # Atomic write: temp file + rename
        suffix = ".toml" if is_toml else ".json"
        fd, temp_path = tempfile.mkstemp(
            dir=config_dir, prefix=".tmp_", suffix=suffix, text=True
        )
        try:
            with os.fdopen(
                fd, "wb" if is_toml else "w", encoding=None if is_toml else "utf-8"
            ) as f:
                if is_toml:
                    f.write(tomli_w.dumps(config).encode("utf-8"))
                else:
                    json.dump(config, f, indent=2)
            os.replace(temp_path, config_path)
        except:
            os.unlink(temp_path)
            raise

        if not quiet:
            action = "Uninstalled" if uninstall else "Installed"
            print(
                f"{action} {name} MCP server (restart required)\n  Config: {config_path}"
            )
        installed += 1
    if not uninstall and installed == 0:
        print(
            "No MCP servers installed. For unsupported MCP clients, use the following config:\n"
        )
        print_mcp_config()


def install_ida_plugin(
    *, uninstall: bool = False, quiet: bool = False, allow_ida_free: bool = False
):
    if sys.platform == "win32":
        ida_folder = os.path.join(os.environ["APPDATA"], "Hex-Rays", "IDA Pro")
    else:
        ida_folder = os.path.join(os.path.expanduser("~"), ".idapro")
    if not allow_ida_free:
        free_licenses = glob.glob(os.path.join(ida_folder, "idafree_*.hexlic"))
        if len(free_licenses) > 0:
            print(
                "IDA Free does not support plugins and cannot be used. Purchase and install IDA Pro instead."
            )
            sys.exit(1)
    ida_plugin_folder = os.path.join(ida_folder, "plugins")

    # Install both the loader file and package directory
    loader_source = IDA_PLUGIN_LOADER
    loader_destination = os.path.join(ida_plugin_folder, "ida_mcp.py")

    pkg_source = IDA_PLUGIN_PKG
    pkg_destination = os.path.join(ida_plugin_folder, "ida_mcp")

    # Clean up old plugin if it exists
    old_plugin = os.path.join(ida_plugin_folder, "mcp-plugin.py")

    if uninstall:
        # Remove loader
        if os.path.lexists(loader_destination):
            os.remove(loader_destination)
            if not quiet:
                print(f"Uninstalled IDA plugin loader\n  Path: {loader_destination}")

        # Remove package
        if os.path.exists(pkg_destination):
            if os.path.isdir(pkg_destination) and not os.path.islink(pkg_destination):
                shutil.rmtree(pkg_destination)
            else:
                os.remove(pkg_destination)
            if not quiet:
                print(f"Uninstalled IDA plugin package\n  Path: {pkg_destination}")

        # Remove old plugin if it exists
        if os.path.lexists(old_plugin):
            os.remove(old_plugin)
            if not quiet:
                print(f"Removed old plugin\n  Path: {old_plugin}")
    else:
        # Create IDA plugins folder
        if not os.path.exists(ida_plugin_folder):
            os.makedirs(ida_plugin_folder)

        # Remove old plugin if it exists
        if os.path.lexists(old_plugin):
            os.remove(old_plugin)
            if not quiet:
                print(f"Removed old plugin file\n  Path: {old_plugin}")

        installed_items = []

        # Install loader file
        loader_realpath = (
            os.path.realpath(loader_destination)
            if os.path.lexists(loader_destination)
            else None
        )
        if loader_realpath != loader_source:
            if os.path.lexists(loader_destination):
                os.remove(loader_destination)

            try:
                os.symlink(loader_source, loader_destination)
                installed_items.append(f"loader: {loader_destination}")
            except OSError:
                shutil.copy(loader_source, loader_destination)
                installed_items.append(f"loader: {loader_destination}")

        # Install package directory
        pkg_realpath = (
            os.path.realpath(pkg_destination)
            if os.path.lexists(pkg_destination)
            else None
        )
        if pkg_realpath != pkg_source:
            if os.path.lexists(pkg_destination):
                if os.path.isdir(pkg_destination) and not os.path.islink(
                    pkg_destination
                ):
                    shutil.rmtree(pkg_destination)
                else:
                    os.remove(pkg_destination)

            try:
                os.symlink(pkg_source, pkg_destination)
                installed_items.append(f"package: {pkg_destination}")
            except OSError:
                shutil.copytree(pkg_source, pkg_destination)
                installed_items.append(f"package: {pkg_destination}")

        if not quiet:
            if installed_items:
                print("Installed IDA Pro plugin (IDA restart required)")
                for item in installed_items:
                    print(f"  {item}")
            else:
                print("Skipping IDA plugin installation (already up to date)")


def main():
    global IDA_HOST, IDA_PORT
    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument(
        "--install", action="store_true", help="Install the MCP Server and IDA plugin"
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Uninstall the MCP Server and IDA plugin",
    )
    parser.add_argument(
        "--allow-ida-free",
        action="store_true",
        help="Allow installation despite IDA Free being installed",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        help="MCP transport protocol to use (stdio or http://127.0.0.1:8744)",
    )
    parser.add_argument(
        "--ida-rpc",
        type=str,
        action="append",
        default=None,
        help=(
            "IDA RPC server(s) to use. Can be repeated. "
            "Formats: auto, auto=/path/to/instances, http://127.0.0.1:13337, "
            "or name=http://127.0.0.1:13337"
        ),
    )
    parser.add_argument(
        "--config", action="store_true", help="Generate MCP config JSON"
    )
    args = parser.parse_args()

    # Parse IDA RPC server argument(s)
    rpc_values = args.ida_rpc or [f"http://{IDA_HOST}:{IDA_PORT}{IDA_PATH}"]
    with STATE_LOCK:
        IDA_INSTANCES.clear()
        INSTANCE_EXECUTORS.clear()
        REMOTE_TOOLS_CACHE.clear()
        REMOTE_TOOLS_GLOBAL_CACHE.clear()

    _load_remote_tools_cache()

    manual_values = []
    auto_requested = False
    auto_dir_override = None

    for raw_value in rpc_values:
        value = raw_value.strip()
        lowered = value.lower()
        if lowered == "auto":
            auto_requested = True
            continue
        if lowered.startswith("auto="):
            auto_requested = True
            auto_dir_override = value.split("=", 1)[1].strip()
            continue
        manual_values.append(value)

    global AUTO_DISCOVERY_ENABLED, AUTO_INSTANCE_DIR
    AUTO_DISCOVERY_ENABLED = auto_requested
    if auto_dir_override:
        AUTO_INSTANCE_DIR = auto_dir_override

    if AUTO_DISCOVERY_ENABLED:
        _refresh_auto_instances(AUTO_INSTANCE_DIR)

    for index, value in enumerate(manual_values, start=1):
        name = ""
        if "=" in value:
            maybe_name, maybe_url = value.split("=", 1)
            if "://" not in maybe_name:
                name = maybe_name.strip()
                value = maybe_url.strip()
        if not name:
            name = "default" if len(manual_values) == 1 else f"ida{index}"
        _register_ida_instance(name, value, source="manual")

    with STATE_LOCK:
        first_instance = next(iter(IDA_INSTANCES.keys())) if IDA_INSTANCES else None

    if first_instance is not None:
        _set_active_instance(first_instance)

    if args.install and args.uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if args.install:
        install_ida_plugin(allow_ida_free=args.allow_ida_free)
        install_mcp_servers(stdio=(args.transport == "stdio"))
        return

    if args.uninstall:
        install_ida_plugin(uninstall=True, allow_ida_free=args.allow_ida_free)
        install_mcp_servers(uninstall=True)
        return

    if args.config:
        print_mcp_config()
        return

    try:
        if args.transport == "stdio":
            mcp.stdio()
        else:
            url = urlparse(args.transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            # NOTE: npx -y @modelcontextprotocol/inspector for debugging
            mcp.serve(url.hostname, url.port)
            input("Server is running, press Enter or Ctrl+C to stop.")
    except (KeyboardInterrupt, EOFError):
        pass


if __name__ == "__main__":
    main()
