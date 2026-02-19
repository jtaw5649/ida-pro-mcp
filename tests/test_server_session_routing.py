import importlib
import sys
import types
from pathlib import Path
from typing import Any


def _load_server_module() -> Any:
    if "tomli_w" not in sys.modules:
        tomli_w = types.ModuleType("tomli_w")
        setattr(tomli_w, "dump", lambda *args, **kwargs: None)
        setattr(tomli_w, "dumps", lambda *_args, **_kwargs: "")
        sys.modules["tomli_w"] = tomli_w

    root = Path(__file__).resolve().parents[1]
    src_root = root / "src"
    sys.path.insert(0, str(src_root))
    try:
        return importlib.import_module("ida_pro_mcp.server")
    finally:
        sys.path.pop(0)


server: Any = _load_server_module()


def _endpoint(name: str, port: int) -> dict[str, str | int]:
    return {
        "name": name,
        "host": "127.0.0.1",
        "port": port,
        "path": "/mcp",
        "url": f"http://127.0.0.1:{port}/mcp",
        "source": "manual",
    }


def _seed_instances() -> None:
    with server.STATE_LOCK:
        server.IDA_INSTANCES.clear()
        server.IDA_INSTANCES.update(
            {
                "ida1": _endpoint("ida1", 13337),
                "ida2": _endpoint("ida2", 13338),
                "ida3": _endpoint("ida3", 13339),
            }
        )
        setattr(server, "IDA_CURRENT_INSTANCE", "ida1")
        server.SESSION_ACTIVE_INSTANCES.clear()
        server.INSTANCE_METADATA_CACHE.clear()


def test_dispatch_precedence_instance_override_then_session_then_global(monkeypatch):
    _seed_instances()
    monkeypatch.setattr(server, "SESSION_ROUTING_ENABLED", True)

    with server.STATE_LOCK:
        server.SESSION_ACTIVE_INSTANCES["sess-1"] = "ida2"

    called_instances: list[str] = []

    def fake_dispatch_to_ida(*args, **kwargs):
        called_instances.append(kwargs["instance_name"])
        return {"jsonrpc": "2.0", "result": {"ok": True}, "id": 1}

    monkeypatch.setattr(server, "_dispatch_to_ida", fake_dispatch_to_ida)

    request = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "lookup_funcs",
            "arguments": {"queries": ["0x401000"], "_instance": "ida3"},
            "_meta": {"mcpSessionId": "sess-1"},
        },
        "id": 1,
    }

    response = server.dispatch_proxy(request)

    assert response is not None
    assert called_instances == ["ida3"]


def test_dispatch_uses_session_bound_instance_when_no_override(monkeypatch):
    _seed_instances()
    monkeypatch.setattr(server, "SESSION_ROUTING_ENABLED", True)

    with server.STATE_LOCK:
        server.SESSION_ACTIVE_INSTANCES["sess-1"] = "ida2"

    called_instances: list[str] = []

    def fake_dispatch_to_ida(*args, **kwargs):
        called_instances.append(kwargs["instance_name"])
        return {"jsonrpc": "2.0", "result": {"ok": True}, "id": 2}

    monkeypatch.setattr(server, "_dispatch_to_ida", fake_dispatch_to_ida)

    request = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "lookup_funcs",
            "arguments": {"queries": ["0x401000"]},
            "_meta": {"mcpSessionId": "sess-1"},
        },
        "id": 2,
    }

    server.dispatch_proxy(request)

    assert called_instances == ["ida2"]


def test_failover_updates_session_scope_without_touching_global(monkeypatch):
    _seed_instances()
    monkeypatch.setattr(server, "SESSION_ROUTING_ENABLED", True)
    monkeypatch.setattr(server, "AUTO_FAILOVER_ENABLED", True)
    monkeypatch.setattr(server, "AUTO_DISCOVERY_ENABLED", False)

    with server.STATE_LOCK:
        setattr(server, "IDA_CURRENT_INSTANCE", "ida1")
        server.SESSION_ACTIVE_INSTANCES["sess-1"] = "ida1"

    calls = {"count": 0}

    def flaky_dispatch(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise ConnectionRefusedError("connection refused")
        return {"jsonrpc": "2.0", "result": {"ok": True}, "id": 3}

    monkeypatch.setattr(server, "_dispatch_to_ida", flaky_dispatch)
    monkeypatch.setattr(server, "_select_reachable_failover_instance", lambda _: "ida2")

    request = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "lookup_funcs",
            "arguments": {"queries": ["0x401000"]},
            "_meta": {"mcpSessionId": "sess-1"},
        },
        "id": 3,
    }

    response = server.dispatch_proxy(request)

    assert response is not None
    assert "error" not in response
    with server.STATE_LOCK:
        assert server.SESSION_ACTIVE_INSTANCES["sess-1"] == "ida2"
        assert server.IDA_CURRENT_INSTANCE == "ida1"


def test_current_and_use_instance_honor_session_scope(monkeypatch):
    _seed_instances()
    monkeypatch.setattr(server, "SESSION_ROUTING_ENABLED", True)
    monkeypatch.setattr(
        server,
        "_read_instance_metadata",
        lambda *_args, **_kwargs: ({"module": "test"}, None),
    )

    with server.STATE_LOCK:
        setattr(server, "IDA_CURRENT_INSTANCE", "ida2")
        server.SESSION_ACTIVE_INSTANCES["sess-1"] = "ida1"

    current = server.current_instance(_meta={"mcpSessionId": "sess-1"})
    assert current["current_instance"] == "ida1"
    assert current["global_instance"] == "ida2"
    assert current["scope"] == "session"

    switched = server.use_instance("ida3", _meta={"mcpSessionId": "sess-1"})
    assert switched["success"] is True
    assert switched["current_instance"] == "ida3"
    assert switched["global_instance"] == "ida2"
    assert switched["scope"] == "session"
    with server.STATE_LOCK:
        assert server.SESSION_ACTIVE_INSTANCES["sess-1"] == "ida3"
        assert server.IDA_CURRENT_INSTANCE == "ida2"
