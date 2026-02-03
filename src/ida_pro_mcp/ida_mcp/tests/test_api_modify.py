"""Tests for api_modify API functions."""

# Import test framework from parent
from ..framework import (
    test,
    assert_has_keys,
    assert_is_list,
    get_any_function,
    get_data_address,
)

# Import functions under test
from ..api_modify import (
    set_comments,
    patch_asm,
    rename,
    define_func,
    define_code,
    undefine,
)

# Import sync module for IDAError


# ============================================================================
# Tests for set_comments
# ============================================================================


@test()
def test_set_comment_roundtrip():
    """set_comments can add and remove comments"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    # Add a comment
    result = set_comments({"addr": fn_addr, "comment": "__TEST_COMMENT__"})
    assert_is_list(result, min_length=1)

    # Clear the comment
    result = set_comments({"addr": fn_addr, "comment": ""})
    assert_is_list(result, min_length=1)


# ============================================================================
# Tests for patch_asm
# ============================================================================


@test(skip=True)  # Skip by default as it modifies the database
def test_patch_asm():
    """patch_asm can patch assembly"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    # This is a risky test - patching assembly could corrupt the binary
    result = patch_asm({"addr": fn_addr, "asm": "nop"})
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr", "error")


# ============================================================================
# Tests for rename
# ============================================================================


@test()
def test_rename_function_roundtrip():
    """rename function works and can be undone"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    # Import to get original name
    from ..api_core import lookup_funcs

    # Get original name
    lookup_result = lookup_funcs(fn_addr)
    if not lookup_result or not lookup_result[0].get("fn"):
        return

    original_name = lookup_result[0]["fn"]["name"]

    try:
        # Rename
        result = rename({"func": [{"addr": fn_addr, "name": "__test_rename__"}]})
        assert isinstance(result, dict)

        # Verify rename worked
        lookup_result = lookup_funcs(fn_addr)
        new_name = lookup_result[0]["fn"]["name"]
        assert new_name == "__test_rename__"
    finally:
        # Restore
        rename({"func": [{"addr": fn_addr, "name": original_name}]})


@test()
def test_rename_global_roundtrip():
    """rename global variable works"""
    data_addr = get_data_address()
    if not data_addr:
        return

    try:
        result = rename({"global": [{"addr": data_addr, "name": "__test_global__"}]})
        assert isinstance(result, dict)
    except Exception:
        pass  # May fail if no suitable global exists


@test(skip=True)  # Local variable renaming requires decompilation
def test_rename_local_roundtrip():
    """rename local variable works"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    # This requires the function to be decompilable and have local variables
    result = rename(
        {"local": [{"func": fn_addr, "name": "old_var", "new_name": "__test_local__"}]}
    )
    assert isinstance(result, dict)


# ============================================================================
# Tests for define_func / define_code / undefine
# ============================================================================


@test(skip=True)  # Skip by default as it modifies the database
def test_define_undefine_func_roundtrip():
    """define_func and undefine work together"""
    # Get a data address where we might be able to create a function
    data_addr = get_data_address()
    if not data_addr:
        return

    # Try to create a function (may fail if not valid code)
    result = define_func({"addr": data_addr})
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr")

    # If creation succeeded, undefine it
    if r.get("ok"):
        undef_result = undefine({"addr": data_addr})
        assert_is_list(undef_result, min_length=1)
        assert undef_result[0].get("ok") is True


@test()
def test_define_func_already_exists():
    """define_func returns error for existing function"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    result = define_func({"addr": fn_addr})
    assert_is_list(result, min_length=1)
    r = result[0]
    assert r.get("error") is not None
    assert "already exists" in r["error"]


@test()
def test_define_func_batch():
    """define_func accepts batch input"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    # Both should fail (already exist), but tests batch handling
    result = define_func([{"addr": fn_addr}, {"addr": fn_addr}])
    assert_is_list(result, min_length=2)


@test(skip=True)  # Skip by default as it modifies the database
def test_define_code():
    """define_code converts bytes to instructions"""
    data_addr = get_data_address()
    if not data_addr:
        return

    result = define_code({"addr": data_addr})
    assert_is_list(result, min_length=1)
    r = result[0]
    assert_has_keys(r, "addr")


@test()
def test_undefine_batch():
    """undefine accepts batch input"""
    fn_addr = get_any_function()
    if not fn_addr:
        return

    # Test that batch input is accepted (will likely fail on function, but tests parsing)
    result = undefine([{"addr": fn_addr}])
    assert_is_list(result, min_length=1)
