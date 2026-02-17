from typing import Annotated

import ida_typeinf
import ida_hexrays
import ida_nalt
import ida_bytes
import ida_frame
import ida_ida
import idaapi
import idc

from .rpc import tool
from .sync import idasync, ida_major
from .utils import (
    normalize_list_input,
    normalize_dict_list,
    parse_address,
    get_type_by_name,
    parse_decls_ctypes,
    paginate,
    my_modifier_t,
    StructRead,
    TypeEdit,
)


# ============================================================================
# Type Declaration
# ============================================================================


@tool
@idasync
def declare_type(
    decls: Annotated[list[str] | str, "C type declarations"],
) -> list[dict]:
    """Declare types"""
    decls = normalize_list_input(decls)
    results = []

    for decl in decls:
        try:
            flags = ida_typeinf.PT_SIL | ida_typeinf.PT_EMPTY | ida_typeinf.PT_TYP
            errors, messages = parse_decls_ctypes(decl, flags)

            pretty_messages = "\n".join(messages)
            if errors > 0:
                results.append(
                    {"decl": decl, "error": f"Failed to parse:\n{pretty_messages}"}
                )
            else:
                results.append({"decl": decl, "ok": True})
        except Exception as e:
            results.append({"decl": decl, "error": str(e)})

    return results


# ============================================================================
# Structure Operations
# ============================================================================


@tool
@idasync
def read_struct(queries: list[StructRead] | StructRead) -> list[dict]:
    """Reads struct type definition and parses actual memory values at the
    given address as instances of that struct type.

    If struct name is not provided, attempts to auto-detect from address.
    Auto-detection only works if IDA already has type information applied
    at that address

    Returns struct layout with actual memory values for each field.
    """

    queries = normalize_dict_list(queries)

    results = []
    for query in queries:
        addr_str = query.get("addr", "")
        struct_name = query.get("struct", "")

        try:
            # Parse address - this is required
            if not addr_str:
                results.append(
                    {
                        "addr": None,
                        "struct": struct_name,
                        "members": None,
                        "error": "Address is required for reading struct fields",
                    }
                )
                continue

            # Try to parse as address, then try name resolution
            try:
                addr = parse_address(addr_str)
            except Exception:
                addr = idaapi.get_name_ea(idaapi.BADADDR, addr_str)
                if addr == idaapi.BADADDR:
                    results.append(
                        {
                            "addr": addr_str,
                            "struct": struct_name,
                            "members": None,
                            "error": f"Failed to resolve address: {addr_str}",
                        }
                    )
                    continue

            # Auto-detect struct type from address if not provided
            if not struct_name:
                tif_auto = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(tif_auto, addr) and tif_auto.is_udt():
                    struct_name = tif_auto.get_type_name()

            if not struct_name:
                results.append(
                    {
                        "addr": addr_str,
                        "struct": None,
                        "members": None,
                        "error": "No struct specified and could not auto-detect from address",
                    }
                )
                continue

            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(None, struct_name):
                results.append(
                    {
                        "addr": addr_str,
                        "struct": struct_name,
                        "members": None,
                        "error": f"Struct '{struct_name}' not found",
                    }
                )
                continue

            udt_data = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt_data):
                results.append(
                    {
                        "addr": addr_str,
                        "struct": struct_name,
                        "members": None,
                        "error": "Failed to get struct details",
                    }
                )
                continue

            members = []
            for member in udt_data:
                offset = member.begin() // 8
                member_type = member.type._print()
                member_name = member.name
                member_size = member.type.get_size()

                # Read memory value at member address
                member_addr = addr + offset
                try:
                    if member.type.is_ptr():
                        is_64bit = (
                            ida_ida.inf_is_64bit()
                            if ida_major >= 9
                            else idaapi.get_inf_structure().is_64bit()
                        )
                        if is_64bit:
                            value = idaapi.get_qword(member_addr)
                            value_str = f"0x{value:016X}"
                        else:
                            value = idaapi.get_dword(member_addr)
                            value_str = f"0x{value:08X}"
                    elif member_size == 1:
                        value = idaapi.get_byte(member_addr)
                        value_str = f"0x{value:02X} ({value})"
                    elif member_size == 2:
                        value = idaapi.get_word(member_addr)
                        value_str = f"0x{value:04X} ({value})"
                    elif member_size == 4:
                        value = idaapi.get_dword(member_addr)
                        value_str = f"0x{value:08X} ({value})"
                    elif member_size == 8:
                        value = idaapi.get_qword(member_addr)
                        value_str = f"0x{value:016X} ({value})"
                    else:
                        bytes_data = []
                        for i in range(min(member_size, 16)):
                            try:
                                bytes_data.append(
                                    f"{idaapi.get_byte(member_addr + i):02X}"
                                )
                            except Exception:
                                break
                        value_str = f"[{' '.join(bytes_data)}{'...' if member_size > 16 else ''}]"
                except Exception:
                    value_str = "<failed to read>"

                member_info = {
                    "offset": f"0x{offset:08X}",
                    "type": member_type,
                    "name": member_name,
                    "size": member_size,
                    "value": value_str,
                }

                members.append(member_info)

            results.append(
                {"addr": addr_str, "struct": struct_name, "members": members}
            )
        except Exception as e:
            results.append(
                {
                    "addr": addr_str,
                    "struct": struct_name,
                    "members": None,
                    "error": str(e),
                }
            )

    return results


@tool
@idasync
def search_structs(
    filter: Annotated[
        str, "Case-insensitive substring to search for in structure names"
    ],
) -> list[dict]:
    """Search structs"""
    results = []
    limit = ida_typeinf.get_ordinal_limit()

    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(None, ordinal):
            type_name: str = tif.get_type_name()
            if type_name and filter.lower() in type_name.lower():
                if tif.is_udt():
                    udt_data = ida_typeinf.udt_type_data_t()
                    cardinality = 0
                    if tif.get_udt_details(udt_data):
                        cardinality = udt_data.size()

                    results.append(
                        {
                            "name": type_name,
                            "size": tif.get_size(),
                            "cardinality": cardinality,
                            "is_union": (
                                udt_data.is_union
                                if tif.get_udt_details(udt_data)
                                else False
                            ),
                            "ordinal": ordinal,
                        }
                    )

    return results


# ============================================================================
# Enum Operations
# ============================================================================


def _resolve_enum_id(query: str | int) -> tuple[int, str | None]:
    enum_id = idc.BADADDR
    enum_name: str | None = None

    if isinstance(query, int):
        enum_id = query
        enum_name = idc.get_enum_name(enum_id)
        return enum_id, enum_name

    text = query.strip()
    if not text:
        return idc.BADADDR, None

    try:
        enum_id = int(text, 0)
        enum_name = idc.get_enum_name(enum_id)
        if enum_name:
            return enum_id, enum_name
    except ValueError:
        pass

    enum_id = idc.get_enum(text)
    if enum_id != idc.BADADDR:
        enum_name = idc.get_enum_name(enum_id) or text
        return enum_id, enum_name

    return idc.BADADDR, None


def _iter_enum_members(enum_id: int, max_members: int = 10000) -> list[dict]:
    members = []

    value = idc.get_first_enum_member(enum_id, -1)
    while value != idc.BADADDR and len(members) < max_members:
        serial = 0
        while len(members) < max_members:
            const_id = idc.get_enum_member(enum_id, value, serial, -1)
            if const_id == idc.BADADDR:
                break

            bmask = idc.get_enum_member_bmask(const_id)
            if bmask is None:
                bmask = -1

            members.append(
                {
                    "name": idc.get_enum_member_name(const_id) or f"<member_{serial}>",
                    "value": idc.get_enum_member_value(const_id),
                    "value_hex": hex(idc.get_enum_member_value(const_id)),
                    "serial": serial,
                    "bmask": bmask,
                    "bmask_hex": hex(bmask & 0xFFFFFFFFFFFFFFFF),
                    "comment": idc.get_enum_member_cmt(const_id, False),
                }
            )
            serial += 1

        next_value = idc.get_next_enum_member(enum_id, value, -1)
        if next_value == value:
            break
        value = next_value

    return members


@tool
@idasync
def list_enums(
    filter: Annotated[str, "Optional case-insensitive name filter"] = "",
    offset: Annotated[int, "Starting index (default: 0)"] = 0,
    count: Annotated[int, "Maximum number of results (default: 100, 0 for all)"] = 100,
) -> object:
    """List enums in local types with pagination"""
    offset = max(offset, 0)
    if count < 0:
        count = 0

    out = []
    limit = ida_typeinf.get_ordinal_limit()
    needle = filter.lower().strip()

    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(None, ordinal):
            continue
        if not tif.is_enum():
            continue

        enum_name = tif.get_type_name() or f"<enum_{ordinal}>"
        if needle and needle not in enum_name.lower():
            continue

        enum_id = idc.get_enum(enum_name)
        out.append(
            {
                "name": enum_name,
                "ordinal": ordinal,
                "enum_id": hex(enum_id) if enum_id != idc.BADADDR else None,
                "width": tif.get_enum_width(),
                "member_count": tif.get_enum_nmembers(),
                "is_bitfield": tif.is_bitmask_enum(),
            }
        )

    return paginate(out, offset, count)


@tool
@idasync
def get_enum(
    query: Annotated[str, "Enum name or enum id (hex/decimal)"],
    include_members: Annotated[bool, "Include enum members (default: true)"] = True,
    max_members: Annotated[int, "Maximum members to return (default: 5000)"] = 5000,
) -> dict:
    """Get enum details by name or id"""
    enum_id, enum_name = _resolve_enum_id(query)

    if enum_id == idc.BADADDR or enum_name is None:
        return {"query": query, "enum": None, "error": f"Enum not found: {query}"}

    tif = ida_typeinf.tinfo_t()
    has_tif = tif.get_named_type(None, enum_name) and tif.is_enum()

    members = []
    if include_members:
        if max_members <= 0:
            max_members = 5000
        members = _iter_enum_members(enum_id, max_members=max_members)

    return {
        "query": query,
        "enum": {
            "id": hex(enum_id),
            "name": enum_name,
            "width": tif.get_enum_width() if has_tif else idc.get_enum_width(enum_id),
            "member_count": (tif.get_enum_nmembers() if has_tif else len(members)),
            "is_bitfield": (
                tif.is_bitmask_enum() if has_tif else bool(idc.get_enum_flag(enum_id))
            ),
            "comment": idc.get_enum_cmt(enum_id, False),
            "members": members,
        },
    }


@tool
@idasync
def set_enum_member(
    enum: Annotated[str, "Enum name or id to modify"],
    name: Annotated[str, "Member name"],
    value: Annotated[str | int, "Member value (decimal or 0x...)"],
    bmask: Annotated[str | int, "Bitmask for bitfield enums (default: -1)"] = "-1",
    replace_existing: Annotated[
        bool, "Replace existing same-name member in the same enum (default: true)"
    ] = True,
) -> dict:
    """Create or update an enum member"""
    enum_id, enum_name = _resolve_enum_id(enum)
    if enum_id == idc.BADADDR:
        enum_name = enum.strip()
        if not enum_name:
            return {"ok": False, "error": "enum name is required"}
        enum_id = idc.add_enum(-1, enum_name, 0)
        if enum_id == idc.BADADDR:
            return {
                "ok": False,
                "error": f"Failed to create enum '{enum_name}'",
            }

    try:
        value_int = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return {"ok": False, "error": f"Invalid value: {value}"}

    try:
        bmask_int = int(bmask, 0) if isinstance(bmask, str) else int(bmask)
    except (TypeError, ValueError):
        return {"ok": False, "error": f"Invalid bmask: {bmask}"}

    existing_const = idc.get_enum_member_by_name(name)
    if existing_const != idc.BADADDR:
        owner_enum = idc.get_enum_member_enum(existing_const)
        if owner_enum != enum_id:
            return {
                "ok": False,
                "error": (
                    f"Member name '{name}' is already used by another enum "
                    f"({idc.get_enum_name(owner_enum) or hex(owner_enum)})"
                ),
            }

        if replace_existing:
            existing_value = idc.get_enum_member_value(existing_const)
            found_serial = 0
            for serial in range(256):
                cid = idc.get_enum_member(enum_id, existing_value, serial, -1)
                if cid == idc.BADADDR:
                    break
                if cid == existing_const:
                    found_serial = serial
                    break

            if not idc.del_enum_member(enum_id, existing_value, found_serial, -1):
                return {
                    "ok": False,
                    "error": f"Failed to remove existing member '{name}'",
                }
        else:
            return {
                "ok": False,
                "error": f"Member '{name}' already exists (set replace_existing=true to overwrite)",
            }

    add_result = idc.add_enum_member(enum_id, name, value_int, bmask_int)
    if add_result != 0:
        return {
            "ok": False,
            "error": f"add_enum_member failed with code {add_result}",
            "enum": idc.get_enum_name(enum_id) or hex(enum_id),
            "member": name,
        }

    return {
        "ok": True,
        "enum": idc.get_enum_name(enum_id) or hex(enum_id),
        "enum_id": hex(enum_id),
        "member": {
            "name": name,
            "value": value_int,
            "value_hex": hex(value_int),
            "bmask": bmask_int,
        },
    }


@tool
@idasync
def apply_enum(
    addr: Annotated[str, "Address to apply enum representation to"],
    enum: Annotated[str, "Enum name or id"],
    operand: Annotated[int, "Operand index (default: 0)"] = 0,
    serial: Annotated[int, "Enum serial (default: 0)"] = 0,
) -> dict:
    """Apply enum representation to an operand at an address"""
    enum_id, enum_name = _resolve_enum_id(enum)
    if enum_id == idc.BADADDR:
        return {"ok": False, "error": f"Enum not found: {enum}"}

    ea = parse_address(addr)
    success = idc.op_enum(ea, operand, enum_id, serial)
    if not success:
        return {
            "ok": False,
            "error": f"Failed to apply enum at {hex(ea)} operand {operand}",
            "enum": enum_name or hex(enum_id),
        }

    return {
        "ok": True,
        "addr": hex(ea),
        "operand": operand,
        "serial": serial,
        "enum": enum_name or hex(enum_id),
        "enum_id": hex(enum_id),
    }


# ============================================================================
# Type Inference & Application
# ============================================================================


@tool
@idasync
def set_type(edits: list[TypeEdit] | TypeEdit) -> list[dict]:
    """Apply types (function/global/local/stack)"""

    def parse_addr_type(s: str) -> dict:
        # Support "addr:typename" format (auto-detects kind)
        if ":" in s:
            parts = s.split(":", 1)
            return {"addr": parts[0].strip(), "ty": parts[1].strip()}
        # Just typename without address (invalid)
        return {"ty": s.strip()}

    edits = normalize_dict_list(edits, parse_addr_type)
    results = []

    for edit in edits:
        try:
            # Auto-detect kind if not provided
            kind = edit.get("kind")
            if not kind:
                if "signature" in edit:
                    kind = "function"
                elif "variable" in edit:
                    kind = "local"
                elif "addr" in edit:
                    # Check if address points to a function
                    try:
                        addr = parse_address(edit["addr"])
                        func = idaapi.get_func(addr)
                        if func and "name" in edit and "ty" in edit:
                            kind = "stack"
                        else:
                            kind = "global"
                    except Exception:
                        kind = "global"
                else:
                    kind = "global"

            if kind == "function":
                func = idaapi.get_func(parse_address(edit["addr"]))
                if not func:
                    results.append({"edit": edit, "error": "Function not found"})
                    continue

                tif = ida_typeinf.tinfo_t(edit["signature"], None, ida_typeinf.PT_SIL)
                if not tif.is_func():
                    results.append({"edit": edit, "error": "Not a function type"})
                    continue

                success = ida_typeinf.apply_tinfo(
                    func.start_ea, tif, ida_typeinf.PT_SIL
                )
                results.append(
                    {
                        "edit": edit,
                        "ok": success,
                        "error": None if success else "Failed to apply type",
                    }
                )

            elif kind == "global":
                ea = idaapi.get_name_ea(idaapi.BADADDR, edit.get("name", ""))
                if ea == idaapi.BADADDR:
                    ea = parse_address(edit["addr"])

                tif = get_type_by_name(edit["ty"])
                success = ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.PT_SIL)
                results.append(
                    {
                        "edit": edit,
                        "ok": success,
                        "error": None if success else "Failed to apply type",
                    }
                )

            elif kind == "local":
                func = idaapi.get_func(parse_address(edit["addr"]))
                if not func:
                    results.append({"edit": edit, "error": "Function not found"})
                    continue

                new_tif = ida_typeinf.tinfo_t(edit["ty"], None, ida_typeinf.PT_SIL)
                modifier = my_modifier_t(edit["variable"], new_tif)
                success = ida_hexrays.modify_user_lvars(func.start_ea, modifier)
                results.append(
                    {
                        "edit": edit,
                        "ok": success,
                        "error": None if success else "Failed to apply type",
                    }
                )

            elif kind == "stack":
                func = idaapi.get_func(parse_address(edit["addr"]))
                if not func:
                    results.append({"edit": edit, "error": "No function found"})
                    continue

                frame_tif = ida_typeinf.tinfo_t()
                if not ida_frame.get_func_frame(frame_tif, func):
                    results.append({"edit": edit, "error": "No frame"})
                    continue

                idx, udm = frame_tif.get_udm(edit["name"])
                if not udm:
                    results.append({"edit": edit, "error": f"{edit['name']} not found"})
                    continue

                tid = frame_tif.get_udm_tid(idx)
                udm = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm, tid)
                offset = udm.offset // 8

                tif = get_type_by_name(edit["ty"])
                success = ida_frame.set_frame_member_type(func, offset, tif)
                results.append(
                    {
                        "edit": edit,
                        "ok": success,
                        "error": None if success else "Failed to set type",
                    }
                )

            else:
                results.append({"edit": edit, "error": f"Unknown kind: {kind}"})

        except Exception as e:
            results.append({"edit": edit, "error": str(e)})

    return results


@tool
@idasync
def infer_types(
    addrs: Annotated[list[str] | str, "Addresses to infer types for"],
) -> list[dict]:
    """Infer types"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            tif = ida_typeinf.tinfo_t()

            # Try Hex-Rays inference
            if ida_hexrays.init_hexrays_plugin() and ida_hexrays.guess_tinfo(tif, ea):
                results.append(
                    {
                        "addr": addr,
                        "inferred_type": str(tif),
                        "method": "hexrays",
                        "confidence": "high",
                    }
                )
                continue

            # Try getting existing type info
            if ida_nalt.get_tinfo(tif, ea):
                results.append(
                    {
                        "addr": addr,
                        "inferred_type": str(tif),
                        "method": "existing",
                        "confidence": "high",
                    }
                )
                continue

            # Try to guess from size
            size = ida_bytes.get_item_size(ea)
            if size > 0:
                type_guess = {
                    1: "uint8_t",
                    2: "uint16_t",
                    4: "uint32_t",
                    8: "uint64_t",
                }.get(size, f"uint8_t[{size}]")

                results.append(
                    {
                        "addr": addr,
                        "inferred_type": type_guess,
                        "method": "size_based",
                        "confidence": "low",
                    }
                )
                continue

            results.append(
                {
                    "addr": addr,
                    "inferred_type": None,
                    "method": None,
                    "confidence": "none",
                }
            )

        except Exception as e:
            results.append(
                {
                    "addr": addr,
                    "inferred_type": None,
                    "method": None,
                    "confidence": "none",
                    "error": str(e),
                }
            )

    return results
