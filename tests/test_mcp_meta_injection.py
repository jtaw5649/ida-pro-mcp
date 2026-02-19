import json
import importlib
import sys
import types
from pathlib import Path


def _load_mcp_module():
    root = Path(__file__).resolve().parents[1]
    zeromcp_root = root / "src" / "ida_pro_mcp" / "ida_mcp" / "zeromcp"
    pkg_name = "test_zeromcp"

    pkg = types.ModuleType(pkg_name)
    setattr(pkg, "__path__", [str(zeromcp_root)])
    sys.modules[pkg_name] = pkg

    importlib.import_module(f"{pkg_name}.jsonrpc")
    return importlib.import_module(f"{pkg_name}.mcp")


_MCP_MODULE = _load_mcp_module()
_inject_request_meta = _MCP_MODULE._inject_request_meta
_merge_request_meta = _MCP_MODULE._merge_request_meta


def test_merge_request_meta_merges_without_overwriting_existing_keys():
    request = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "lookup_funcs",
            "arguments": {"queries": ["0x401000"]},
            "_meta": {"sessionId": "existing", "client": "x"},
        },
        "id": 1,
    }

    merged = _merge_request_meta(request, {"sessionId": "new", "mcpSessionId": "abc"})

    assert isinstance(merged, dict)
    meta = merged["params"]["_meta"]
    assert meta["sessionId"] == "existing"
    assert meta["mcpSessionId"] == "abc"
    assert meta["client"] == "x"


def test_inject_request_meta_creates_params_when_missing():
    request = {"jsonrpc": "2.0", "method": "ping", "id": 7}

    injected_body = _inject_request_meta(
        json.dumps(request).encode("utf-8"), {"mcpSessionId": "sess-1"}
    )
    injected = json.loads(injected_body)

    assert injected["params"]["_meta"]["mcpSessionId"] == "sess-1"


def test_inject_request_meta_keeps_non_dict_params_unchanged():
    request = {
        "jsonrpc": "2.0",
        "method": "some_method",
        "params": ["a", "b"],
        "id": 2,
    }
    body = json.dumps(request).encode("utf-8")

    injected_body = _inject_request_meta(body, {"sseSessionId": "sse-1"})

    assert injected_body == body
