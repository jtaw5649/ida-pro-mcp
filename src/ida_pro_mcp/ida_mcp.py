"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.
"""

import json
import os
import sys
import time
import idaapi
import ida_kernwin
import ida_nalt
import idc
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


CONFIG_ACTION_ID = "mcp:configure"
CONFIG_ACTION_LABEL = "MCP Configuration"


class MCPConfigHandler(idaapi.action_handler_t):
    def __init__(self, plugin: "MCP"):
        idaapi.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        host = ida_kernwin.ask_str(self.plugin.host, 0, "MCP server host:")
        if host is None:
            return 0

        host = host.strip()
        if not host:
            print("[MCP] Host cannot be empty")
            return 0

        port = ida_kernwin.ask_long(
            self.plugin.port, "MCP server port (0-65535, 0 = auto):"
        )
        if port is None:
            return 0
        if port < 0 or port > 65535:
            print(f"[MCP] Invalid port: {port}")
            return 0

        self.plugin.host = host
        self.plugin.port = port
        try:
            self.plugin._save_config()
        except Exception as e:
            print(f"[MCP] Failed to persist config: {e}")

        if self.plugin.port == 0:
            print(
                f"[MCP] Configuration updated: {self.plugin.host}:auto (OS-assigned port)"
            )
        else:
            print(f"[MCP] Configuration updated: {self.plugin.host}:{self.plugin.port}")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 0

    @staticmethod
    def _appdata_root() -> str:
        appdata = os.environ.get("APPDATA")
        if appdata:
            return appdata
        return os.path.expanduser("~")

    @classmethod
    def _state_root(cls) -> str:
        return os.path.join(cls._appdata_root(), "ida-pro-mcp")

    @classmethod
    def _config_path(cls) -> str:
        return os.path.join(cls._state_root(), "plugin_config.json")

    @classmethod
    def _instance_dir(cls) -> str:
        return os.path.join(cls._state_root(), "instances")

    @classmethod
    def _instance_file_path(cls) -> str:
        return os.path.join(cls._instance_dir(), f"{os.getpid()}.json")

    def _load_config(self):
        config_path = self._config_path()
        if not os.path.exists(config_path):
            return

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[MCP] Failed to load config: {e}")
            return

        if not isinstance(data, dict):
            return

        host = data.get("host")
        if isinstance(host, str) and host.strip():
            self.host = host.strip()

        port = data.get("port")
        if isinstance(port, int) and 0 <= port <= 65535:
            self.port = port

    def _save_config(self):
        config = {"host": self.host, "port": self.port}
        config_path = self._config_path()
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        tmp_path = config_path + ".tmp"

        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        os.replace(tmp_path, config_path)

    @staticmethod
    def _normalize_bound_host(host: str) -> str:
        if host in ("0.0.0.0", "::"):
            return "127.0.0.1"
        return host

    def _resolve_bound_endpoint(self, server) -> tuple[str, int]:
        host = self.host
        port = self.port

        http_server = getattr(server, "_http_server", None)
        if http_server is not None:
            server_address = getattr(http_server, "server_address", None)
            if isinstance(server_address, tuple) and len(server_address) >= 2:
                host = str(server_address[0])
                port = int(server_address[1])

        host = self._normalize_bound_host(host)
        return host, port

    def _write_instance_registration(self, host: str, port: int):
        module = ida_nalt.get_root_filename() or "unknown"
        try:
            idb_path = idc.get_idb_path()
        except Exception:
            idb_path = ""

        try:
            input_path = ida_nalt.get_input_file_path()
        except Exception:
            input_path = ""

        payload = {
            "name": f"{module}-{os.getpid()}",
            "pid": os.getpid(),
            "host": host,
            "port": int(port),
            "path": "/mcp",
            "module": module,
            "idb_path": idb_path,
            "input_path": input_path,
            "imagebase": hex(idaapi.get_imagebase()),
            "started_at": time.time(),
        }

        os.makedirs(self._instance_dir(), exist_ok=True)
        instance_path = self._instance_file_path()
        tmp_path = instance_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp_path, instance_path)

        self.instance_registration_path = instance_path

    def _clear_instance_registration(self):
        instance_path = self.instance_registration_path or self._instance_file_path()
        try:
            if os.path.exists(instance_path):
                os.remove(instance_path)
        except Exception as e:
            print(f"[MCP] Failed to remove instance registration: {e}")

    def _stop_server(self):
        self._clear_instance_registration()
        if self.mcp:
            self.mcp.stop()
            self.mcp = None

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        print(
            f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
        )
        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self.instance_registration_path: str | None = None
        self.host = self.DEFAULT_HOST
        self.port = self.DEFAULT_PORT
        self._load_config()

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                CONFIG_ACTION_ID,
                CONFIG_ACTION_LABEL,
                MCPConfigHandler(self),
                None,
                "Configure MCP host and port",
            )
        )
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/", CONFIG_ACTION_ID, idaapi.SETMENU_APP
        )

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self._stop_server()

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches

        try:
            init_caches()
        except Exception as e:
            print(f"[MCP] Cache init failed: {e}")

        try:
            MCP_SERVER.serve(
                self.host, self.port, request_handler=IdaMcpHttpRequestHandler
            )
            actual_host, actual_port = self._resolve_bound_endpoint(MCP_SERVER)
            print(f"  Config: http://{actual_host}:{actual_port}/config.html")
            self._write_instance_registration(actual_host, actual_port)
            self.mcp = MCP_SERVER
        except OSError as e:
            if e.errno in (48, 98, 10048):  # Address already in use
                if self.port == 0:
                    print("[MCP] Error: Failed to auto-bind MCP port")
                else:
                    print(f"[MCP] Error: Port {self.port} is already in use")
            else:
                raise

    def term(self):
        try:
            ida_kernwin.detach_action_from_menu("Edit/Plugins/", CONFIG_ACTION_ID)
        except Exception:
            pass
        try:
            ida_kernwin.unregister_action(CONFIG_ACTION_ID)
        except Exception:
            pass

        self._stop_server()


def PLUGIN_ENTRY():
    return MCP()


# IDA plugin flags
PLUGIN_FLAGS = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
