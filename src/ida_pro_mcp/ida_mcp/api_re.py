"""Reverse Engineering Acceleration Tools for IDA Pro MCP.

Specialized tools for large-scale binary reverse engineering workflows:
bulk string extraction, function statistics, unnamed reference discovery,
per-function string extraction, raw segment reads, batch decompilation,
and structural function comparison.
"""

import difflib
import re
from typing import Annotated, Optional

import ida_bytes
import ida_funcs
import ida_lines
import ida_nalt
import ida_segment
import idaapi
import idautils
import idc

from .rpc import tool
from .sync import idasync, tool_timeout, IDAError
from .utils import (
    Page,
    String,
    decompile_function_safe,
    extract_function_strings,
    extract_function_constants,
    get_callees,
    get_function,
    normalize_list_input,
    paginate,
    parse_address,
    pattern_filter,
)
from .api_core import _get_strings_cache


# ============================================================================
# 1. list_strings — Bulk string extraction with xref counts
# ============================================================================


@tool
@idasync
@tool_timeout(60.0)
def list_strings(
    segment: Annotated[Optional[str], "Filter to segment name (e.g. '.rdata')"] = None,
    filter: Annotated[Optional[str], "Glob or /regex/ filter on string content"] = None,
    offset: Annotated[int, "Pagination offset (default: 0)"] = 0,
    count: Annotated[int, "Max results (default: 100, 0 for all)"] = 100,
) -> Page:
    """List strings in the IDB with xref counts, filterable by segment and content"""
    strings_cache = _get_strings_cache()

    results = []
    for ea, text in strings_cache:
        if segment:
            seg = idaapi.getseg(ea)
            if not seg:
                continue
            seg_name = ida_segment.get_segm_name(seg)
            if seg_name != segment:
                continue

        xref_count = sum(1 for _ in idautils.XrefsTo(ea, 0))
        results.append(
            {
                "addr": hex(ea),
                "string": text,
                "xref_count": xref_count,
            }
        )

    if filter:
        results = pattern_filter(results, filter, "string")

    return paginate(results, offset, count)


def _build_text_matcher(query: str, *, regex: bool, case_sensitive: bool):
    if regex:
        flags = 0 if case_sensitive else re.IGNORECASE
        compiled = re.compile(query, flags)

        def _match(text: str) -> bool:
            return bool(compiled.search(text))

        return _match

    needle = query if case_sensitive else query.lower()

    def _match(text: str) -> bool:
        haystack = text if case_sensitive else text.lower()
        return needle in haystack

    return _match


@tool
@idasync
@tool_timeout(120.0)
def find_text(
    query: Annotated[str, "Text or regex to search for"],
    sources: Annotated[
        list[str] | str,
        "Search sources: strings,names,comments,disasm (default: strings,names,comments)",
    ] = "strings,names,comments",
    regex: Annotated[
        bool, "Treat query as regular expression (default: false)"
    ] = False,
    case_sensitive: Annotated[bool, "Case-sensitive matching (default: false)"] = False,
    offset: Annotated[int, "Pagination offset (default: 0)"] = 0,
    count: Annotated[int, "Max results (default: 100, 0 for all)"] = 100,
) -> Page:
    """Search text across strings, names, comments, and disassembly"""
    if not query:
        raise IDAError("query must not be empty")

    offset = max(offset, 0)
    if count < 0:
        count = 0
    if count > 5000:
        count = 5000

    selected_sources = {
        src.strip().lower() for src in normalize_list_input(sources) if src.strip()
    }
    if not selected_sources:
        selected_sources = {"strings", "names", "comments"}

    valid_sources = {"strings", "names", "comments", "disasm"}
    invalid_sources = sorted(selected_sources - valid_sources)
    if invalid_sources:
        raise IDAError(
            "Invalid source(s): "
            + ", ".join(invalid_sources)
            + ". Valid: strings,names,comments,disasm"
        )

    match = _build_text_matcher(query, regex=regex, case_sensitive=case_sensitive)

    max_needed = None if count == 0 else offset + count + 1
    results = []

    def add_result(kind: str, ea: int, text: str, **extra) -> bool:
        if not match(text):
            return False

        item = {
            "kind": kind,
            "addr": hex(ea),
            "text": text,
        }
        item.update(extra)
        results.append(item)

        if max_needed is not None and len(results) >= max_needed:
            return True
        return False

    stop = False

    if "strings" in selected_sources:
        for ea, text in _get_strings_cache():
            if add_result("string", ea, text):
                stop = True
                break

    if not stop and "names" in selected_sources:
        for ea, name in idautils.Names():
            if add_result("name", ea, name):
                stop = True
                break

    need_comments = "comments" in selected_sources
    need_disasm = "disasm" in selected_sources
    if not stop and (need_comments or need_disasm):
        for func_start in idautils.Functions():
            func_name = ida_funcs.get_func_name(func_start) or hex(func_start)
            for item_ea in idautils.FuncItems(func_start):
                if need_comments:
                    cmt = idc.get_cmt(item_ea, False)
                    if cmt and add_result(
                        "comment", item_ea, cmt, function=func_name, repeatable=False
                    ):
                        stop = True
                        break

                    rcmt = idc.get_cmt(item_ea, True)
                    if rcmt and add_result(
                        "comment", item_ea, rcmt, function=func_name, repeatable=True
                    ):
                        stop = True
                        break

                if need_disasm:
                    line = ida_lines.generate_disasm_line(item_ea, 0)
                    if line:
                        disasm_text = ida_lines.tag_remove(line)
                        if add_result(
                            "disasm", item_ea, disasm_text, function=func_name
                        ):
                            stop = True
                            break

            if stop:
                break

    return paginate(results, offset, count)


# ============================================================================
# 2. function_stats — Named/unnamed function counts and segment breakdown
# ============================================================================


@tool
@idasync
@tool_timeout(30.0)
def function_stats() -> dict:
    """Get function naming statistics: total, named, unnamed counts and segment breakdown"""
    total = 0
    named = 0
    unnamed = 0
    segment_breakdown: dict[str, dict[str, int]] = {}

    for func_ea in idautils.Functions():
        total += 1
        func_name = ida_funcs.get_func_name(func_ea) or ""

        is_unnamed = (
            func_name.startswith("sub_")
            or func_name.startswith("nullsub_")
            or func_name.startswith("j_")
            or not func_name
        )

        if is_unnamed:
            unnamed += 1
        else:
            named += 1

        seg = idaapi.getseg(func_ea)
        seg_name = ida_segment.get_segm_name(seg) if seg else "<unknown>"
        if seg_name not in segment_breakdown:
            segment_breakdown[seg_name] = {"total": 0, "named": 0, "unnamed": 0}
        segment_breakdown[seg_name]["total"] += 1
        if is_unnamed:
            segment_breakdown[seg_name]["unnamed"] += 1
        else:
            segment_breakdown[seg_name]["named"] += 1

    pct = (named / total * 100) if total > 0 else 0.0

    return {
        "total": total,
        "named": named,
        "unnamed": unnamed,
        "named_pct": round(pct, 1),
        "segments": segment_breakdown,
    }


# ============================================================================
# 3. find_unnamed_refs — Find unnamed functions referencing a known function
# ============================================================================


@tool
@idasync
@tool_timeout(30.0)
def find_unnamed_refs(
    addr: Annotated[str, "Address of the known function (hex or decimal)"],
    limit: Annotated[int, "Max results (default: 100)"] = 100,
) -> dict:
    """Find all unnamed (sub_*) functions that call or reference a given function"""
    target_ea = parse_address(addr)

    target_func = idaapi.get_func(target_ea)
    if not target_func:
        raise IDAError(f"No function at {hex(target_ea)}")

    target_name = ida_funcs.get_func_name(target_func.start_ea) or hex(target_ea)

    callers: dict[int, dict] = {}
    for xref_ea in idautils.CodeRefsTo(target_ea, 0):
        if len(callers) >= limit:
            break

        caller_func = idaapi.get_func(xref_ea)
        if not caller_func:
            continue

        caller_start = caller_func.start_ea
        if caller_start in callers:
            continue

        caller_name = ida_funcs.get_func_name(caller_start) or ""
        if not (
            caller_name.startswith("sub_")
            or caller_name.startswith("nullsub_")
            or not caller_name
        ):
            continue

        callers[caller_start] = {
            "addr": hex(caller_start),
            "name": caller_name,
            "size": hex(caller_func.end_ea - caller_start),
            "call_site": hex(xref_ea),
        }

    return {
        "target": {"addr": hex(target_ea), "name": target_name},
        "unnamed_callers": list(callers.values()),
        "count": len(callers),
        "limit_reached": len(callers) >= limit,
    }


# ============================================================================
# 4. strings_in_func — All string literals referenced by a function
# ============================================================================


@tool
@idasync
def strings_in_func(
    addr: Annotated[str, "Function address (hex or decimal)"],
) -> dict:
    """Get all string literals referenced by a function via data xrefs"""
    ea = parse_address(addr)

    func = idaapi.get_func(ea)
    if not func:
        raise IDAError(f"No function at {hex(ea)}")

    func_name = ida_funcs.get_func_name(func.start_ea) or hex(func.start_ea)
    strings = extract_function_strings(func.start_ea)

    return {
        "function": {"addr": hex(func.start_ea), "name": func_name},
        "strings": strings,
        "count": len(strings),
    }


# ============================================================================
# 5. segment_bytes — Read raw bytes from a named segment
# ============================================================================


@tool
@idasync
@tool_timeout(30.0)
def segment_bytes(
    name: Annotated[str, "Segment name (e.g. '.text', '.rdata', '.data')"],
    offset: Annotated[int, "Byte offset from segment start (default: 0)"] = 0,
    size: Annotated[int, "Number of bytes to read (default: 256, max: 4096)"] = 256,
) -> dict:
    """Read raw bytes from a named segment"""
    if size > 4096:
        size = 4096
    if size <= 0:
        raise IDAError("size must be positive")

    seg = None
    for seg_ea in idautils.Segments():
        s = idaapi.getseg(seg_ea)
        if s and ida_segment.get_segm_name(s) == name:
            seg = s
            break

    if seg is None:
        available = []
        for seg_ea in idautils.Segments():
            s = idaapi.getseg(seg_ea)
            if s:
                available.append(ida_segment.get_segm_name(s))
        raise IDAError(f"Segment '{name}' not found. Available: {', '.join(available)}")

    seg_size = seg.end_ea - seg.start_ea
    if offset >= seg_size:
        raise IDAError(
            f"Offset {offset} exceeds segment size {seg_size} ({hex(seg_size)})"
        )

    read_addr = seg.start_ea + offset
    actual_size = min(size, seg_size - offset)
    raw = ida_bytes.get_bytes(read_addr, actual_size)

    if raw is None:
        raise IDAError(f"Failed to read {actual_size} bytes at {hex(read_addr)}")

    return {
        "segment": name,
        "start": hex(seg.start_ea),
        "end": hex(seg.end_ea),
        "read_addr": hex(read_addr),
        "size_read": actual_size,
        "hex": raw.hex(" "),
        "printable": "".join(chr(b) if 32 <= b < 127 else "." for b in raw),
    }


# ============================================================================
# 6. bulk_decompile — Lightweight batch decompile
# ============================================================================


@tool
@idasync
@tool_timeout(120.0)
def bulk_decompile(
    addrs: Annotated[
        list[str] | str,
        "Function address(es) to decompile (hex or comma-separated)",
    ],
    include_strings: Annotated[
        bool, "Also extract string refs per function (default: false)"
    ] = False,
) -> list[dict]:
    """Batch decompile multiple functions, returning pseudocode for each"""
    from .utils import normalize_list_input

    addr_list = normalize_list_input(addrs)

    if len(addr_list) > 50:
        raise IDAError(f"Too many addresses ({len(addr_list)}); max is 50")

    results = []
    for addr_str in addr_list:
        try:
            ea = parse_address(addr_str)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {
                        "addr": addr_str,
                        "name": None,
                        "pseudocode": None,
                        "error": f"No function at {addr_str}",
                    }
                )
                continue

            func_name = ida_funcs.get_func_name(func.start_ea) or hex(func.start_ea)
            pseudocode = decompile_function_safe(func.start_ea)

            entry = {
                "addr": hex(func.start_ea),
                "name": func_name,
                "pseudocode": pseudocode,
                "error": None if pseudocode else "Decompilation failed",
            }

            if include_strings:
                entry["strings"] = extract_function_strings(func.start_ea)

            results.append(entry)

        except Exception as e:
            results.append(
                {
                    "addr": addr_str,
                    "name": None,
                    "pseudocode": None,
                    "error": str(e),
                }
            )

    return results


# ============================================================================
# 7. diff_funcs — Structural comparison of two functions
# ============================================================================


@tool
@idasync
@tool_timeout(60.0)
def diff_funcs(
    addr1: Annotated[str, "First function address (hex or decimal)"],
    addr2: Annotated[str, "Second function address (hex or decimal)"],
) -> dict:
    """Compare two functions structurally: callees, constants, strings, and pseudocode diff"""
    ea1 = parse_address(addr1)
    ea2 = parse_address(addr2)

    func1 = idaapi.get_func(ea1)
    func2 = idaapi.get_func(ea2)

    if not func1:
        raise IDAError(f"No function at {hex(ea1)}")
    if not func2:
        raise IDAError(f"No function at {hex(ea2)}")

    name1 = ida_funcs.get_func_name(func1.start_ea) or hex(func1.start_ea)
    name2 = ida_funcs.get_func_name(func2.start_ea) or hex(func2.start_ea)

    callees1 = get_callees(hex(func1.start_ea))
    callees2 = get_callees(hex(func2.start_ea))

    callee_names1 = sorted({c["name"] for c in callees1 if "name" in c})
    callee_names2 = sorted({c["name"] for c in callees2 if "name" in c})

    strings1 = extract_function_strings(func1.start_ea)
    strings2 = extract_function_strings(func2.start_ea)

    str_vals1 = sorted({s["string"] for s in strings1})
    str_vals2 = sorted({s["string"] for s in strings2})

    constants1 = extract_function_constants(func1.start_ea)
    constants2 = extract_function_constants(func2.start_ea)

    const_vals1 = sorted({c["value"] for c in constants1})
    const_vals2 = sorted({c["value"] for c in constants2})

    pseudo1 = decompile_function_safe(func1.start_ea) or ""
    pseudo2 = decompile_function_safe(func2.start_ea) or ""

    diff_lines = list(
        difflib.unified_diff(
            pseudo1.splitlines(),
            pseudo2.splitlines(),
            fromfile=name1,
            tofile=name2,
            lineterm="",
        )
    )

    return {
        "func1": {
            "addr": hex(func1.start_ea),
            "name": name1,
            "size": func1.end_ea - func1.start_ea,
        },
        "func2": {
            "addr": hex(func2.start_ea),
            "name": name2,
            "size": func2.end_ea - func2.start_ea,
        },
        "callees": {
            "only_in_func1": sorted(set(callee_names1) - set(callee_names2)),
            "only_in_func2": sorted(set(callee_names2) - set(callee_names1)),
            "shared": sorted(set(callee_names1) & set(callee_names2)),
        },
        "strings": {
            "only_in_func1": sorted(set(str_vals1) - set(str_vals2)),
            "only_in_func2": sorted(set(str_vals2) - set(str_vals1)),
            "shared": sorted(set(str_vals1) & set(str_vals2)),
        },
        "constants": {
            "only_in_func1": sorted(set(const_vals1) - set(const_vals2)),
            "only_in_func2": sorted(set(const_vals2) - set(const_vals1)),
            "shared": sorted(set(const_vals1) & set(const_vals2)),
        },
        "pseudocode_diff": "\n".join(diff_lines) if diff_lines else "(identical)",
    }
