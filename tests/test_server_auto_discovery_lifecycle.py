import importlib
import json
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


def _write_registration(tmp_path: Path, name: str, payload: dict[str, Any]) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _reset_server_state() -> None:
    with server.STATE_LOCK:
        server.IDA_INSTANCES.clear()
        server.SESSION_ACTIVE_INSTANCES.clear()
        server.INSTANCE_METADATA_CACHE.clear()
        server.REMOTE_TOOLS_CACHE.clear()
        server.IDA_CURRENT_INSTANCE = "default"


def test_refresh_excludes_stale_dead_pid_when_require_live(monkeypatch, tmp_path):
    _reset_server_state()
    now = 2000.0
    monkeypatch.setattr(server.time, "time", lambda: now)
    monkeypatch.setattr(server, "AUTO_REQUIRE_LIVE", True)
    monkeypatch.setattr(server, "AUTO_INCLUDE_UNREACHABLE", False)
    monkeypatch.setattr(server, "AUTO_STALE_GRACE_SECONDS", 90.0)
    monkeypatch.setattr(server, "AUTO_HEARTBEAT_MULTIPLIER", 3.0)
    monkeypatch.setattr(server, "AUTO_PROBE_TIMEOUT_SECONDS", 0.25)
    monkeypatch.setattr(server, "AUTO_PROBE_MAX_WORKERS", 1)
    monkeypatch.setattr(server, "AUTO_PRUNE", False)
    monkeypatch.setattr(server, "AUTO_DISCOVERY_ENABLED", True)
    monkeypatch.setattr(
        server, "_pid_is_alive", lambda pid: False if pid == 999 else None
    )
    monkeypatch.setattr(server, "_ping_endpoint", lambda *_args, **_kwargs: None)

    _write_registration(
        tmp_path,
        "stale.json",
        {
            "name": "dead-instance",
            "host": "127.0.0.1",
            "port": 33333,
            "pid": 999,
            "started_at": 1000.0,
            "last_heartbeat_at": 1000.0,
            "heartbeat_interval_sec": 10.0,
        },
    )
    _write_registration(
        tmp_path,
        "alive.json",
        {
            "name": "alive-instance",
            "host": "127.0.0.1",
            "port": 33334,
            "started_at": now,
            "last_heartbeat_at": now,
            "heartbeat_interval_sec": 10.0,
        },
    )

    result = server._refresh_auto_instances(str(tmp_path))

    assert result["discovered_files"] == 2
    assert result["alive_count"] == 1
    assert result["stale_count"] == 1
    assert result["loaded_instances"] == 1
    assert any(item["reason"] == "stale" for item in result["skipped"])


def test_refresh_unreachable_toggle_controls_routability(monkeypatch, tmp_path):
    _reset_server_state()
    payload = {
        "name": "offline-instance",
        "host": "127.0.0.1",
        "port": 35555,
        "started_at": 2000.0,
        "last_heartbeat_at": 2000.0,
        "heartbeat_interval_sec": 15.0,
    }
    _write_registration(tmp_path, "offline.json", payload)

    monkeypatch.setattr(server.time, "time", lambda: 2000.0)
    monkeypatch.setattr(server, "AUTO_REQUIRE_LIVE", True)
    monkeypatch.setattr(server, "AUTO_STALE_GRACE_SECONDS", 90.0)
    monkeypatch.setattr(server, "AUTO_HEARTBEAT_MULTIPLIER", 3.0)
    monkeypatch.setattr(server, "AUTO_PROBE_MAX_WORKERS", 1)
    monkeypatch.setattr(server, "AUTO_DISCOVERY_ENABLED", True)
    monkeypatch.setattr(server, "_pid_is_alive", lambda _pid: None)
    monkeypatch.setattr(server, "_ping_endpoint", lambda *_args, **_kwargs: "refused")

    monkeypatch.setattr(server, "AUTO_INCLUDE_UNREACHABLE", False)
    excluded = server._refresh_auto_instances(str(tmp_path))
    assert excluded["unreachable_count"] == 1
    assert excluded["loaded_instances"] == 0

    monkeypatch.setattr(server, "AUTO_INCLUDE_UNREACHABLE", True)
    included = server._refresh_auto_instances(str(tmp_path))
    assert included["unreachable_count"] == 1
    assert included["loaded_instances"] == 1


def test_refresh_accepts_legacy_registration_payload(monkeypatch, tmp_path):
    _reset_server_state()
    _write_registration(
        tmp_path,
        "legacy.json",
        {
            "name": "legacy-instance",
            "host": "127.0.0.1",
            "port": "0x8215",
            "path": "/mcp",
            "module": "legacy.bin",
            "started_at": 3000.0,
        },
    )

    monkeypatch.setattr(server.time, "time", lambda: 3000.0)
    monkeypatch.setattr(server, "AUTO_REQUIRE_LIVE", True)
    monkeypatch.setattr(server, "AUTO_INCLUDE_UNREACHABLE", False)
    monkeypatch.setattr(server, "AUTO_STALE_GRACE_SECONDS", 90.0)
    monkeypatch.setattr(server, "AUTO_HEARTBEAT_MULTIPLIER", 3.0)
    monkeypatch.setattr(server, "AUTO_PROBE_MAX_WORKERS", 1)
    monkeypatch.setattr(server, "AUTO_DISCOVERY_ENABLED", True)
    monkeypatch.setattr(server, "_pid_is_alive", lambda _pid: None)
    monkeypatch.setattr(server, "_ping_endpoint", lambda *_args, **_kwargs: None)

    result = server._refresh_auto_instances(str(tmp_path))

    assert result["loaded_instances"] == 1
    assert result["alive_count"] == 1
    assert result["invalid_count"] == 0
    assert result["errors"] == []
    with server.STATE_LOCK:
        assert "legacy-instance" in server.IDA_INSTANCES


def test_refresh_reports_diagnostics_counters(monkeypatch, tmp_path):
    _reset_server_state()
    _write_registration(
        tmp_path,
        "alive.json",
        {
            "name": "alive",
            "host": "127.0.0.1",
            "port": 40001,
            "started_at": 1000.0,
            "last_heartbeat_at": 1000.0,
            "heartbeat_interval_sec": 5.0,
        },
    )
    _write_registration(
        tmp_path,
        "unreachable.json",
        {
            "name": "unreachable",
            "host": "127.0.0.1",
            "port": 40002,
            "started_at": 1000.0,
            "last_heartbeat_at": 1000.0,
            "heartbeat_interval_sec": 5.0,
        },
    )
    _write_registration(
        tmp_path,
        "stale.json",
        {
            "name": "stale",
            "host": "127.0.0.1",
            "port": 40003,
            "started_at": 1.0,
            "last_heartbeat_at": 1.0,
            "heartbeat_interval_sec": 2.0,
        },
    )
    _write_registration(tmp_path, "invalid.json", {"port": 40004})

    monkeypatch.setattr(server.time, "time", lambda: 1000.0)
    monkeypatch.setattr(server, "AUTO_REQUIRE_LIVE", True)
    monkeypatch.setattr(server, "AUTO_INCLUDE_UNREACHABLE", False)
    monkeypatch.setattr(server, "AUTO_STALE_GRACE_SECONDS", 10.0)
    monkeypatch.setattr(server, "AUTO_HEARTBEAT_MULTIPLIER", 2.0)
    monkeypatch.setattr(server, "AUTO_PROBE_MAX_WORKERS", 1)
    monkeypatch.setattr(server, "AUTO_DISCOVERY_ENABLED", True)
    monkeypatch.setattr(server, "_pid_is_alive", lambda _pid: None)
    monkeypatch.setattr(
        server,
        "_ping_endpoint",
        lambda _host, port, _path, timeout=0.5: None if port == 40001 else "refused",
    )

    result = server._refresh_auto_instances(str(tmp_path))

    assert result["alive_count"] == 1
    assert result["unreachable_count"] == 1
    assert result["stale_count"] == 1
    assert result["invalid_count"] == 1
    assert result["loaded_instances"] == 1
