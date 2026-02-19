import ast
from pathlib import Path


def _ida_mcp_ast() -> ast.Module:
    path = Path(__file__).resolve().parents[1] / "src" / "ida_pro_mcp" / "ida_mcp.py"
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _find_class(module: ast.Module, class_name: str) -> ast.ClassDef:
    for node in module.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return node
    raise AssertionError(f"class {class_name} not found")


def _find_method(class_node: ast.ClassDef, method_name: str) -> ast.FunctionDef:
    for node in class_node.body:
        if isinstance(node, ast.FunctionDef) and node.name == method_name:
            return node
    raise AssertionError(f"method {method_name} not found")


def test_registration_payload_includes_v2_fields():
    module = _ida_mcp_ast()
    mcp_class = _find_class(module, "MCP")
    builder = _find_method(mcp_class, "_build_registration_payload")

    return_dict = None
    for node in ast.walk(builder):
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict):
            return_dict = node.value
            break
    assert isinstance(return_dict, ast.Dict)

    keys = {
        key.value
        for key in return_dict.keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }
    for required_key in (
        "schema_version",
        "instance_id",
        "registration_id",
        "last_heartbeat_at",
        "heartbeat_interval_sec",
    ):
        assert required_key in keys


def test_heartbeat_loop_updates_registration_timestamp():
    module = _ida_mcp_ast()
    mcp_class = _find_class(module, "MCP")
    loop = _find_method(mcp_class, "_registration_heartbeat_loop")

    found_update = False
    for node in ast.walk(loop):
        if not isinstance(node, ast.Assign):
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Subscript):
            continue
        if not isinstance(target.slice, ast.Constant):
            continue
        if target.slice.value == "last_heartbeat_at":
            found_update = True
            break

    assert found_update


def test_heartbeat_interval_default_is_defined():
    module = _ida_mcp_ast()
    mcp_class = _find_class(module, "MCP")

    default_value = None
    for node in mcp_class.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id == "DEFAULT_HEARTBEAT_INTERVAL_SEC"
                ):
                    if isinstance(node.value, ast.Constant) and isinstance(
                        node.value.value, (int, float)
                    ):
                        default_value = float(node.value.value)

    assert default_value is not None
    assert default_value > 0
