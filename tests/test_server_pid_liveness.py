import importlib
import sys
import types
from pathlib import Path
from typing import Any

import pytest


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


def test_pid_is_alive_windows_does_not_call_os_kill(monkeypatch):
    monkeypatch.setattr(server.sys, "platform", "win32")

    def _fail_kill(_pid, _sig):
        raise AssertionError("os.kill should not be used on Windows")

    monkeypatch.setattr(server.os, "kill", _fail_kill)
    monkeypatch.setattr(server, "_win32_open_process", lambda _access, _pid: 123)
    monkeypatch.setattr(
        server,
        "_win32_get_exit_code_process",
        lambda _handle: server._WIN32_STILL_ACTIVE,
    )
    monkeypatch.setattr(server, "_win32_close_handle", lambda _handle: None)

    assert server._pid_is_alive(1000) is True


@pytest.mark.parametrize(
    "exit_code, expected",
    [
        (259, True),
        (0, False),
        (None, None),
    ],
)
def test_pid_is_alive_windows_wrapper_outcomes(monkeypatch, exit_code, expected):
    monkeypatch.setattr(server.sys, "platform", "win32")
    monkeypatch.setattr(
        server.os,
        "kill",
        lambda _pid, _sig: (_ for _ in ()).throw(AssertionError("unexpected os.kill")),
    )

    close_calls = []
    monkeypatch.setattr(server, "_win32_open_process", lambda _access, _pid: 123)
    monkeypatch.setattr(
        server, "_win32_get_exit_code_process", lambda _handle: exit_code
    )
    monkeypatch.setattr(
        server, "_win32_close_handle", lambda handle: close_calls.append(handle)
    )

    assert server._pid_is_alive(2000) is expected
    assert close_calls == [123]


@pytest.mark.parametrize(
    "error, expected",
    [
        (None, True),
        (ProcessLookupError(), False),
        (PermissionError(), True),
        (OSError(), None),
    ],
)
def test_pid_is_alive_non_windows_uses_os_kill(monkeypatch, error, expected):
    monkeypatch.setattr(server.sys, "platform", "linux")

    calls = []

    def _fake_kill(pid, sig):
        calls.append((pid, sig))
        if error is not None:
            raise error

    monkeypatch.setattr(server.os, "kill", _fake_kill)

    assert server._pid_is_alive(3000) is expected
    assert calls == [(3000, 0)]
