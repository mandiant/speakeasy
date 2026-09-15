#!/usr/bin/env python3
"""
Generate speakeasy's Win32 API signature database from win32json.

win32json (https://github.com/marlersoft/win32json) is a JSON export of
Microsoft's win32metadata project. It is vendored as a git submodule at
``deps/win32json``. This script flattens the ~17k function declarations it
contains into a compact table keyed by function name, resolving every
parameter and return type down to a handful of type codes that the emulator
can act on without walking the metadata type graph at runtime.

The output (``speakeasy/resources/win32/signatures.json.gz``) is a build
artifact: it is regenerated on every build and is not committed.

Usage::

    python scripts/gen_win32_signatures.py [--win32json DIR] [--overrides FILE]
                                           [--output FILE] [--stats]

Output format (``format`` = 2)::

    {
      "format": 2,
      "source": "win32json",
      "version": "<deps/win32json/version.txt>",
      "commit": "<submodule commit, when available>",
      "dll_aliases": {"psapi": "kernel32", ...},
      "name_prefixes": {"kernel32": ["K32"], ...},
      "enums": {
        "<NAME>": {
          "f": true,                       # only for [Flags] enums
          "v": [["<member>", <value>], ...]  # values masked to the enum's size
        },
        ...
      },
      "structs": {
        "<NAME>": {                          # anonymous nested types: "OUTER.INNER"
          "s": [<size on x86>, <size on x64>],
          "u": true,                         # only for unions
          "f": [["<field>", "<type code>", <offset on x86>, <offset on x64>], ...]
        },                                   # "f" absent when a field cannot be resolved
        ...
      },
      "functions": {
        "<Name>": [
          {
            "dll": "kernel32",               # lower-case DllImport, no extension
            "ret": "<type code>",
            "params": [["<name>", "<type code>", "<attr flags>"], ...],
            "conv": "cdecl",                 # only when not stdcall
            "variadic": true,                # only for '...' functions
            "arch": ["x86"],                 # only when restricted
            "sle": true,                     # only when SetLastError applies
            "skip": "<reason>"               # present when unsupported
          },
          ...
        ]
      }
    }

Type codes (``kind`` or ``kind:qualifier``):

    v                 void (return only)
    i8 u8 i16 u16 i32 u32 i64 u64   sized integers
    u32:NAME          (any integer kind) value drawn from enum NAME in ``enums``
    f32 f64           floating point
    p                 pointer-sized opaque value (IntPtr, void*, COM, callbacks)
    p:CODE            pointer to a value of type CODE (p:u32, p:h, p:p, p:S)
    ps:NAME           pointer to struct/union NAME (see ``structs``)
    a:CODE            array/buffer of CODE elements; its length, if declared, is in
                      the parameter's 4th element (see below)
    arr:N:CODE        inline array of N CODE elements (struct fields only)
    s                 pointer to NUL-terminated narrow string (PSTR)
    S                 pointer to NUL-terminated wide string (PWSTR)
    b                 BOOL (4 bytes)
    B                 BOOLEAN (1 byte)
    h                 handle (pointer-sized)
    g                 GUID by value (16 bytes)
    st:NAME:SIZE      struct/union NAME passed by value, SIZE bytes

Attr flags are a string drawn from ``i`` (In), ``o`` (Out), ``?`` (Optional),
``c`` (Const), ``r`` (Reserved).

A parameter may carry a 4th element describing the size of the buffer it
points at: ``{"n": IDX}`` (parameter IDX holds the byte count), ``{"c": IDX}``
(parameter IDX holds the element count) or ``{"k": N}`` (fixed element count).
"""

from __future__ import annotations

import argparse
import collections
import glob
import gzip
import json
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_WIN32JSON = os.path.join(REPO_ROOT, "deps", "win32json")
DEFAULT_OVERRIDES = os.path.join(REPO_ROOT, "scripts", "win32_overrides.json")
DEFAULT_OUTPUT = os.path.join(REPO_ROOT, "speakeasy", "resources", "win32", "signatures.json.gz")

FORMAT_VERSION = 2

# win32metadata "Native" type names -> (type code, size in bytes). A size of
# None means pointer-sized.
NATIVE_TYPES = {
    "Void": ("v", 0),
    "Byte": ("u8", 1),
    "SByte": ("i8", 1),
    "Boolean": ("B", 1),
    "Char": ("u16", 2),
    "UInt16": ("u16", 2),
    "Int16": ("i16", 2),
    "UInt32": ("u32", 4),
    "Int32": ("i32", 4),
    "UInt64": ("u64", 8),
    "Int64": ("i64", 8),
    "Single": ("f32", 4),
    "Double": ("f64", 8),
    "IntPtr": ("p", None),
    "UIntPtr": ("p", None),
    "Guid": ("g", 16),
}

# NativeTypedefs that carry meaning beyond their underlying integer.
SPECIAL_TYPEDEFS = {
    "PSTR": "s",
    "PWSTR": "S",
    "BOOL": "b",
    "BOOLEAN": "B",
}

# Parameter attribute -> flag character.
ATTR_FLAGS = {
    "In": "i",
    "Out": "o",
    "Optional": "?",
    "Const": "c",
    "Reserved": "r",
}

ARCH_NAMES = {"X86": "x86", "X64": "x64", "Arm64": "arm64"}


class UnsupportedType(Exception):
    pass


class TypeResolver:
    """Resolves win32metadata type references to compact type codes."""

    def __init__(self, namespaces: dict[str, dict[str, dict]]):
        # namespaces: api namespace -> type name -> type definition
        self.namespaces = namespaces
        self._layout_cache: dict[tuple, tuple[int, int]] = {}
        self._offset_cache: dict[tuple, list[int]] = {}
        # enum name -> definition, for every enum referenced by a resolved type
        self.used_enums: dict[str, dict] = {}
        # struct name -> (api, definition), for every struct some pointer targets
        self.used_structs: dict[str, tuple[str, dict]] = {}

    def lookup(self, api: str, name: str) -> dict | None:
        return self.namespaces.get(api, {}).get(name)

    # -- struct layout ---------------------------------------------------

    def struct_size(self, api: str, name: str, ptr_size: int) -> int:
        """
        Compute sizeof() for a struct or union using C layout rules and the
        metadata's PackingSize. Only needed for the rare by-value struct
        parameters; raises UnsupportedType for anything it cannot lay out.
        """
        td = self.lookup(api, name)
        if td is None or td["Kind"] not in ("Struct", "Union"):
            raise UnsupportedType(f"unknown struct {api}.{name}")
        size, _ = self._layout_struct(td, api, ptr_size, ())
        return size

    def _layout_struct(self, td: dict, api: str, ptr_size: int, seen: tuple) -> tuple[int, int]:
        """Return (size, alignment) of a Struct/Union type definition."""
        key = (api, td["Name"], ptr_size, id(td))
        if key in self._layout_cache:
            return self._layout_cache[key]
        if key in seen:
            raise UnsupportedType(f"recursive struct {td['Name']}")

        nested = {t["Name"]: t for t in td.get("NestedTypes", [])}
        pack = td.get("PackingSize") or 0
        size = 0
        align = 1
        offsets = []
        for field in td["Fields"]:
            fsize, falign = self._layout_field(field["Type"], api, ptr_size, seen + (key,), nested)
            if pack:
                falign = min(falign, pack)
            align = max(align, falign)
            if td["Kind"] == "Union":
                offsets.append(0)
                size = max(size, fsize)
            else:
                size = _align_up(size, falign)
                offsets.append(size)
                size += fsize
        result = (_align_up(size, align), align)
        self._layout_cache[key] = result
        self._offset_cache[key] = offsets
        return result

    def field_offsets(self, td: dict, api: str, ptr_size: int) -> list[int]:
        """Byte offset of every field of a Struct/Union definition."""
        self._layout_struct(td, api, ptr_size, ())
        return self._offset_cache[(api, td["Name"], ptr_size, id(td))]

    def _layout_field(self, t: dict, api: str, ptr_size: int, seen: tuple, nested: dict) -> tuple[int, int]:
        """Return (size, alignment) of a struct field type."""
        kind = t["Kind"]
        if kind in ("PointerTo", "LPArray"):
            return ptr_size, ptr_size
        if kind == "Native":
            code, size = NATIVE_TYPES.get(t["Name"], (None, None))
            if code is None:
                raise UnsupportedType(f"native {t['Name']}")
            if size is None:
                size = ptr_size
            if code == "g":
                return 16, 4
            return size, max(size, 1)
        if kind == "Array":
            count = t["Shape"]["Size"] if t.get("Shape") else 0
            esize, ealign = self._layout_field(t["Child"], api, ptr_size, seen, nested)
            return esize * count, ealign
        if kind == "ApiRef":
            if t["TargetKind"] in ("Com", "FunctionPointer"):
                return ptr_size, ptr_size
            target_api = t["Api"]
            target_name = t["Name"]
            # Anonymous nested types (_Anonymous_e__Union) live in the
            # enclosing type's NestedTypes rather than the namespace.
            td = nested.get(target_name)
            if td is None:
                td = self.lookup(target_api, target_name)
            if td is None:
                raise UnsupportedType(f"unknown type {target_api}.{target_name}")
            if td["Kind"] == "NativeTypedef":
                return self._layout_field(td["Def"], target_api, ptr_size, seen, nested)
            if td["Kind"] == "Enum":
                _, size = NATIVE_TYPES[td.get("IntegerBase") or "Int32"]
                return size, size
            if td["Kind"] in ("Struct", "Union"):
                return self._layout_struct(td, target_api, ptr_size, seen)
            if td["Kind"] in ("Com", "FunctionPointer", "ComClassID"):
                return ptr_size, ptr_size
        raise UnsupportedType(f"field kind {kind}")

    # -- parameter / return types ------------------------------------------

    def resolve(self, t: dict) -> str:
        """Resolve a parameter or return type to a type code."""
        kind = t["Kind"]
        if kind == "LPArray":
            # Sized buffers (even LPArray<Byte>) are not C strings; the element
            # type rides along so buffers can be sized from their count.
            try:
                return f"a:{self.resolve(t['Child'])}"
            except UnsupportedType:
                return "a"
        if kind == "PointerTo":
            child = t["Child"]
            if child["Kind"] == "Native":
                if child["Name"] == "Byte":
                    return "s"
                if child["Name"] == "Char":
                    return "S"
                if child["Name"] == "Void":
                    return "p"
            if child["Kind"] == "ApiRef" and child["TargetKind"] == "Default":
                td = self.lookup(child["Api"], child["Name"])
                if td and td["Kind"] in ("Struct", "Union"):
                    self.used_structs.setdefault(child["Name"], (child["Api"], td))
                    return f"ps:{child['Name']}"
            # Pointer to anything else: keep the pointee's code as qualifier
            # (p:u32, p:h, p:p, p:S) so the emulator knows how big it is.
            try:
                return f"p:{self.resolve(child)}"
            except UnsupportedType:
                return "p"
        if kind == "Native":
            code, _ = NATIVE_TYPES.get(t["Name"], (None, None))
            if code is None:
                raise UnsupportedType(f"native {t['Name']}")
            return code
        if kind == "ApiRef":
            if t["TargetKind"] in ("Com", "FunctionPointer"):
                return "p"
            special = SPECIAL_TYPEDEFS.get(t["Name"])
            if special:
                return special
            td = self.lookup(t["Api"], t["Name"])
            if td is None:
                raise UnsupportedType(f"unknown type {t['Api']}.{t['Name']}")
            if td["Kind"] == "NativeTypedef":
                base = self.resolve(td["Def"])
                if base == "p" and _is_handle_typedef(td):
                    return "h"
                return base
            if td["Kind"] == "Enum":
                return self._enum_code(td)
            if td["Kind"] in ("Struct", "Union"):
                size32 = self.struct_size(t["Api"], t["Name"], 4)
                size64 = self.struct_size(t["Api"], t["Name"], 8)
                if size32 != size64:
                    # pointer-bearing struct by value; encode both sizes
                    return f"st:{t['Name']}:{size32}/{size64}"
                return f"st:{t['Name']}:{size32}"
            if td["Kind"] in ("Com", "FunctionPointer", "ComClassID"):
                return "p"
        raise UnsupportedType(f"type kind {kind}")

    # -- struct fields ----------------------------------------------------

    def resolve_field(self, t: dict, api: str, nested: dict, scope: str, wanted: list) -> str:
        """
        Resolve a struct field type to a type code. Anonymous nested types are
        keyed as ``OUTER.INNER`` in the struct table; ``wanted`` collects
        (key, api, definition) of every struct the field refers to so callers
        can emit those too.
        """
        kind = t["Kind"]
        if kind == "Array":
            count = t["Shape"]["Size"] if t.get("Shape") else 0
            return f"arr:{count}:{self.resolve_field(t['Child'], api, nested, scope, wanted)}"
        if kind == "PointerTo":
            child = t["Child"]
            if child["Kind"] == "ApiRef" and child["TargetKind"] == "Default":
                td = nested.get(child["Name"])
                if td is not None and td["Kind"] in ("Struct", "Union"):
                    key = f"{scope}.{child['Name']}"
                    wanted.append((key, api, td))
                    return f"ps:{key}"
                td = self.lookup(child["Api"], child["Name"])
                if td is not None and td["Kind"] in ("Struct", "Union"):
                    wanted.append((child["Name"], child["Api"], td))
                    return f"ps:{child['Name']}"
            return self.resolve(t)
        if kind == "ApiRef" and t["TargetKind"] == "Default":
            td = nested.get(t["Name"])
            if td is not None:
                key = f"{scope}.{t['Name']}"
                target_api = api
            else:
                td = self.lookup(t["Api"], t["Name"])
                key = t["Name"]
                target_api = t["Api"]
            if td is not None and td["Kind"] in ("Struct", "Union"):
                size32, _ = self._layout_struct(td, target_api, 4, ())
                size64, _ = self._layout_struct(td, target_api, 8, ())
                wanted.append((key, target_api, td))
                if size32 != size64:
                    return f"st:{key}:{size32}/{size64}"
                return f"st:{key}:{size32}"
        return self.resolve(t)

    def struct_entry(self, key: str, api: str, td: dict, wanted: list) -> dict:
        """
        Build the struct table entry for ``td``: sizes for both pointer sizes
        and, when every field resolves, ``[name, code, offset32, offset64]``
        per field. Raises UnsupportedType when the struct cannot be laid out.
        """
        size32, _ = self._layout_struct(td, api, 4, ())
        size64, _ = self._layout_struct(td, api, 8, ())
        entry: dict = {"s": [size32, size64]}
        if td["Kind"] == "Union":
            entry["u"] = True
        nested = {t["Name"]: t for t in td.get("NestedTypes", [])}
        off32 = self.field_offsets(td, api, 4)
        off64 = self.field_offsets(td, api, 8)
        fields = []
        pending: list = []
        try:
            for field, o32, o64 in zip(td["Fields"], off32, off64):
                code = self.resolve_field(field["Type"], api, nested, key, pending)
                fields.append([field["Name"], code, o32, o64])
        except UnsupportedType:
            return entry
        entry["f"] = fields
        wanted.extend(pending)
        return entry

    def _enum_code(self, td: dict) -> str:
        base = td.get("IntegerBase") or "Int32"
        code, _ = NATIVE_TYPES[base]
        if not td["Values"]:
            return code
        self.used_enums.setdefault(td["Name"], td)
        return f"{code}:{td['Name']}"


def _align_up(value: int, align: int) -> int:
    if align <= 1:
        return value
    return (value + align - 1) // align * align


def _is_handle_typedef(td: dict) -> bool:
    """Heuristic: a pointer-sized typedef that behaves like a kernel/USER handle."""
    if td.get("FreeFunc") or td.get("InvalidHandleValue") is not None:
        return True
    name = td["Name"]
    return name.startswith("H") and name[1:2].isupper()


def normalize_dll(dll: str) -> str:
    dll = dll.lower()
    for ext in (".dll", ".drv", ".exe", ".cpl", ".sys"):
        if dll.endswith(ext):
            dll = dll[: -len(ext)]
            break
    return dll


def load_win32json(root: str) -> tuple[dict[str, dict[str, dict]], list[dict], dict[str, int]]:
    """Return (namespaces, functions, integer constants) from a win32json checkout."""
    api_dir = os.path.join(root, "api")
    files = sorted(glob.glob(os.path.join(api_dir, "*.json")))
    if not files:
        raise SystemExit(
            f"no win32json API files found under {api_dir!r}; run `git submodule update --init deps/win32json`"
        )
    namespaces: dict[str, dict[str, dict]] = {}
    functions: list[dict] = []
    constants: dict[str, int] = {}
    for path in files:
        ns = os.path.basename(path)[: -len(".json")]
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        namespaces[ns] = {t["Name"]: t for t in doc.get("Types", [])}
        for fn in doc.get("Functions", []):
            fn["_namespace"] = ns
            functions.append(fn)
        for const in doc.get("Constants", []):
            if isinstance(const.get("Value"), int) and not isinstance(const["Value"], bool):
                constants.setdefault(const["Name"], const["Value"])
    return namespaces, functions, constants


def load_overrides(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    for key in ("cdecl_dlls", "cdecl", "variadic", "skip"):
        doc[key] = set(doc.get(key, []))
    doc.setdefault("dll_aliases", {})
    doc.setdefault("name_prefixes", {})
    doc.setdefault("enum_extra", {})
    return doc


def _buffer_length(pm: dict, nparams: int) -> dict | None:
    """Describe how long the buffer a pointer parameter refers to is, if declared."""
    for attr in pm["Attrs"]:
        if isinstance(attr, dict) and attr.get("Kind") == "MemorySize":
            idx = attr.get("BytesParamIndex", -1)
            if 0 <= idx < nparams:
                return {"n": idx}
    t = pm["Type"]
    if t["Kind"] == "LPArray":
        idx = t.get("CountParamIndex", -1)
        if 0 <= idx < nparams:
            return {"c": idx}
        const = t.get("CountConst", -1)
        if const > 0:
            return {"k": const}
    return None


def build_entry(fn: dict, resolver: TypeResolver, overrides: dict) -> dict:
    dll = normalize_dll(fn["DllImport"])
    entry: dict = {"dll": dll}

    skip_reason = None
    try:
        entry["ret"] = resolver.resolve(fn["ReturnType"])
    except UnsupportedType as e:
        entry["ret"] = "p"
        skip_reason = f"return type: {e}"

    params = []
    for pm in fn["Params"]:
        flags = "".join(ATTR_FLAGS[a] for a in pm["Attrs"] if isinstance(a, str) and a in ATTR_FLAGS)
        try:
            code = resolver.resolve(pm["Type"])
        except UnsupportedType as e:
            code = "p"
            skip_reason = skip_reason or f"param {pm['Name']}: {e}"
        param = [pm["Name"], code, flags]
        length = _buffer_length(pm, len(fn["Params"]))
        if length:
            param.append(length)
        params.append(param)
    entry["params"] = params

    name = fn["Name"]
    if name in overrides["variadic"]:
        entry["variadic"] = True
        entry["conv"] = "cdecl"
    elif name in overrides["cdecl"] or dll in overrides["cdecl_dlls"]:
        entry["conv"] = "cdecl"

    if fn.get("Architectures"):
        entry["arch"] = sorted(ARCH_NAMES.get(a, a.lower()) for a in fn["Architectures"])
    if fn.get("SetLastError"):
        entry["sle"] = True
    if name in overrides["skip"]:
        skip_reason = "listed in overrides.skip"
    if skip_reason:
        entry["skip"] = skip_reason
    return entry


def build_enum_table(resolver: TypeResolver, constants: dict[str, int], overrides: dict) -> dict[str, dict]:
    """
    Flatten every enum some resolved type referenced. Values are masked to the
    enum's integer size so negative members compare equal to the unsigned
    argument slots the emulator reads. ``overrides["enum_extra"]`` appends
    named constants that win32metadata keeps outside the enum (e.g.
    ``GENERIC_READ`` for ``FILE_ACCESS_FLAGS``).
    """
    enums: dict[str, dict] = {}
    for name, td in sorted(resolver.used_enums.items()):
        _, size = NATIVE_TYPES[td.get("IntegerBase") or "Int32"]
        mask = (1 << (size * 8)) - 1
        values = [[v["Name"], v["Value"] & mask] for v in td["Values"]]
        seen = {v[0] for v in values}
        for extra in overrides["enum_extra"].get(name, ()):
            if extra in seen:
                continue
            if extra not in constants:
                raise SystemExit(f"enum_extra: constant {extra!r} for enum {name} not found in win32json")
            values.append([extra, constants[extra] & mask])
        entry: dict = {"v": values}
        if td.get("Flags"):
            entry["f"] = True
        enums[name] = entry
    return enums


def build_struct_table(resolver: TypeResolver, stats: collections.Counter) -> dict[str, dict]:
    """
    Layout of every struct some parameter points at, plus (transitively) every
    struct their fields embed or point at, for both pointer sizes.
    """
    structs: dict[str, dict] = {}
    worklist = [(name, api, td) for name, (api, td) in sorted(resolver.used_structs.items())]
    while worklist:
        key, api, td = worklist.pop()
        if key in structs:
            continue
        try:
            entry = resolver.struct_entry(key, api, td, worklist)
        except UnsupportedType as e:
            stats["structs:unsupported"] += 1
            logger_debug(f"struct {key}: {e}")
            continue
        structs[key] = entry
        if "f" not in entry:
            stats["structs:opaque"] += 1
    return dict(sorted(structs.items()))


def logger_debug(msg: str) -> None:
    if os.environ.get("GEN_WIN32_SIGNATURES_DEBUG"):
        print(msg, file=sys.stderr)


def generate(win32json_root: str, overrides_path: str) -> tuple[dict, collections.Counter]:
    namespaces, functions, constants = load_win32json(win32json_root)
    overrides = load_overrides(overrides_path)
    resolver = TypeResolver(namespaces)

    table: dict[str, list[dict]] = collections.defaultdict(list)
    stats: collections.Counter = collections.Counter()
    for fn in functions:
        entry = build_entry(fn, resolver, overrides)
        # Identical declarations can appear in more than one namespace.
        if any(e == entry for e in table[fn["Name"]]):
            stats["duplicates"] += 1
            continue
        table[fn["Name"]].append(entry)
        stats["functions"] += 1
        stats["skipped" if "skip" in entry else "supported"] += 1
        if entry.get("conv") == "cdecl":
            stats["cdecl"] += 1
        if entry.get("variadic"):
            stats["variadic"] += 1
        for param in entry["params"]:
            code = param[1]
            stats[f"param:{code.split(':', 1)[0]}"] += 1
            if code.split(":", 1)[0] in ("i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64") and ":" in code:
                stats["param:enum"] += 1
            if len(param) > 3:
                stats["param:sized-buffer"] += 1

    # structs first: resolving their fields can reference further enums
    structs = build_struct_table(resolver, stats)
    stats["structs"] = len(structs)
    enums = build_enum_table(resolver, constants, overrides)
    stats["enums"] = len(enums)

    version = "unknown"
    version_path = os.path.join(win32json_root, "version.txt")
    if os.path.exists(version_path):
        with open(version_path, encoding="utf-8") as f:
            version = f.read().strip()

    commit = None
    try:
        commit = subprocess.check_output(
            ["git", "-C", win32json_root, "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, text=True
        ).strip()
    except Exception:
        pass

    doc = {
        "format": FORMAT_VERSION,
        "source": "win32json",
        "version": version,
        "commit": commit,
        "generated_by": "scripts/gen_win32_signatures.py",
        "dll_aliases": {normalize_dll(k): normalize_dll(v) for k, v in overrides["dll_aliases"].items()},
        "name_prefixes": {normalize_dll(k): v for k, v in overrides["name_prefixes"].items()},
        "enums": enums,
        "structs": structs,
        "functions": dict(sorted(table.items())),
    }
    return doc, stats


def write_output(doc: dict, output: str) -> int:
    os.makedirs(os.path.dirname(output), exist_ok=True)
    raw = json.dumps(doc, separators=(",", ":"), sort_keys=False).encode("utf-8")
    # A fixed mtime and no embedded filename keep the archive byte-for-byte reproducible.
    with open(output, "wb") as f:
        with gzip.GzipFile(filename="", fileobj=f, mode="wb", mtime=0) as gz:
            gz.write(raw)
    return len(raw)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--win32json", default=DEFAULT_WIN32JSON, help="path to the win32json checkout")
    ap.add_argument("--overrides", default=DEFAULT_OVERRIDES, help="path to win32_overrides.json")
    ap.add_argument("--output", default=DEFAULT_OUTPUT, help="output .json.gz path")
    ap.add_argument("--stats", action="store_true", help="print generation statistics")
    args = ap.parse_args(argv)

    doc, stats = generate(args.win32json, args.overrides)
    raw_size = write_output(doc, args.output)
    print(
        f"wrote {args.output}: {stats['functions']} functions "
        f"({stats['supported']} supported, {stats['skipped']} skipped), "
        f"{stats['enums']} enums, {stats['structs']} structs, "
        f"{raw_size} bytes raw, {os.path.getsize(args.output)} bytes gzipped, "
        f"win32json {doc['version']}"
    )
    if args.stats:
        for key, value in sorted(stats.items()):
            print(f"  {key:24s} {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
