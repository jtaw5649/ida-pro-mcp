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


def _seed_instances(count: int = 3) -> None:
    names = [f"ida{i}" for i in range(1, count + 1)]
    ports = [13336 + i for i in range(1, count + 1)]
    with server.STATE_LOCK:
        server.IDA_INSTANCES.clear()
        for name, port in zip(names, ports):
            server.IDA_INSTANCES[name] = _endpoint(name, port)
        server.IDA_CURRENT_INSTANCE = names[0]
        server.INSTANCE_METADATA_CACHE.clear()


def test_list_instances_metadata_error_keeps_online_when_ping_ok(monkeypatch):
    _seed_instances(count=1)
    monkeypatch.setattr(server, "LIST_PARALLEL_PROBE", False)
    monkeypatch.setattr(server, "_ping_instance", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        server,
        "_read_instance_metadata",
        lambda *_args, **_kwargs: (None, "metadata timeout"),
    )

    result = server.list_instances(probe=True, probe_timeout=10, include_metadata=True)

    entry = result["instances"][0]
    assert entry["status"] == "online"
    assert entry["metadata_error"] == "metadata timeout"
    assert "error" not in entry


def test_list_instances_metadata_timeout_is_bounded(monkeypatch):
    _seed_instances(count=2)
    monkeypatch.setattr(server, "LIST_PARALLEL_PROBE", False)
    monkeypatch.setattr(server, "LIST_METADATA_TIMEOUT_SECONDS", 1.25)
    monkeypatch.setattr(server, "_ping_instance", lambda *_args, **_kwargs: None)

    seen_timeouts: list[float] = []

    def fake_read(_instance_name: str, *, timeout: float = 5):
        seen_timeouts.append(timeout)
        return {"module": "m", "path": "p", "base": "0x1"}, None

    monkeypatch.setattr(server, "_read_instance_metadata", fake_read)

    result = server.list_instances(probe=True, probe_timeout=9, include_metadata=True)

    assert [entry["status"] for entry in result["instances"]] == ["online", "online"]
    assert seen_timeouts == [1.25, 1.25]


def test_metadata_cache_avoids_repeated_fetches_within_ttl(monkeypatch):
    _seed_instances(count=1)
    monkeypatch.setattr(server, "LIST_PARALLEL_PROBE", False)
    monkeypatch.setattr(server, "LIST_METADATA_CACHE_TTL_SECONDS", 60.0)
    monkeypatch.setattr(server, "_ping_instance", lambda *_args, **_kwargs: None)

    calls = {"count": 0}

    def fake_read(_instance_name: str, *, timeout: float = 5):
        calls["count"] += 1
        return {"module": "sample", "path": "/tmp/a", "base": "0x1000"}, None

    monkeypatch.setattr(server, "_read_instance_metadata", fake_read)

    first = server.list_instances(probe=True, include_metadata=True)
    second = server.list_instances(probe=True, include_metadata=True)

    assert first["instances"][0]["module"] == "sample"
    assert second["instances"][0]["module"] == "sample"
    assert calls["count"] == 1


def test_list_instances_probe_works_with_parallel_toggle(monkeypatch):
    _seed_instances(count=3)
    monkeypatch.setattr(server, "LIST_PROBE_MAX_WORKERS", 2)
    monkeypatch.setattr(server, "LIST_METADATA_CACHE_TTL_SECONDS", 0.0)

    ping_errors = {"ida1": None, "ida2": "connection refused", "ida3": None}
    monkeypatch.setattr(
        server,
        "_ping_instance",
        lambda instance_name, **_kwargs: ping_errors[instance_name],
    )
    monkeypatch.setattr(
        server,
        "_read_instance_metadata",
        lambda *_args, **_kwargs: (
            {"module": "ok", "path": "/tmp/bin", "base": "0x1"},
            None,
        ),
    )

    monkeypatch.setattr(server, "LIST_PARALLEL_PROBE", False)
    serial = server.list_instances(probe=True, include_metadata=True)

    monkeypatch.setattr(server, "LIST_PARALLEL_PROBE", True)
    parallel = server.list_instances(probe=True, include_metadata=True)

    serial_status = {entry["name"]: entry["status"] for entry in serial["instances"]}
    parallel_status = {
        entry["name"]: entry["status"] for entry in parallel["instances"]
    }

    assert serial_status == {"ida1": "online", "ida2": "unreachable", "ida3": "online"}
    assert parallel_status == serial_status
