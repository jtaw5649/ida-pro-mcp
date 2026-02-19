import ast
from pathlib import Path


def test_metadata_fast_resource_shape():
    path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "ida_pro_mcp"
        / "ida_mcp"
        / "api_resources.py"
    )
    module = ast.parse(path.read_text(encoding="utf-8"))

    target = None
    for node in module.body:
        if (
            isinstance(node, ast.FunctionDef)
            and node.name == "idb_metadata_fast_resource"
        ):
            target = node
            break

    assert target is not None

    resource_uris = []
    for decorator in target.decorator_list:
        if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name):
            if decorator.func.id == "resource" and decorator.args:
                arg = decorator.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    resource_uris.append(arg.value)

    assert "ida://idb/metadata_fast" in resource_uris

    returns = [node for node in ast.walk(target) if isinstance(node, ast.Return)]
    assert returns
    return_node = returns[-1].value
    assert isinstance(return_node, ast.Call)
    assert isinstance(return_node.func, ast.Name)
    assert return_node.func.id == "Metadata"

    keyword_values = {
        kw.arg: kw.value
        for kw in return_node.keywords
        if isinstance(kw, ast.keyword) and isinstance(kw.arg, str)
    }
    expected_fields = {
        "path",
        "module",
        "base",
        "size",
        "md5",
        "sha256",
        "crc32",
        "filesize",
    }
    assert expected_fields.issubset(keyword_values.keys())

    for hash_field in ("md5", "sha256", "crc32", "filesize"):
        value = keyword_values[hash_field]
        assert isinstance(value, ast.Constant)
        assert value.value == "unavailable"
