#!/usr/bin/env python3
"""
Generate speakeasy's native API signature database from phnt.

phnt (https://github.com/winsiderss/phnt, MIT) is the System Informer
collection of Windows native API headers: ``Nt*``/``Zw*`` system services,
``Rtl*``, ``Ldr*``, ``Csr*``, ``Dbg*`` and friends, most of which Microsoft's
win32metadata leaves undocumented. It is vendored as a git submodule at
``deps/phnt``. This script parses the prototypes in those headers into the
same compact table format that ``gen_win32_signatures.py`` produces from
win32json (see that script's docstring for the format and type codes), so
the emulator can load both through the same code path.

Only function prototypes and enums are extracted. Struct layouts are not:
the runtime resolves ``ps:NAME`` codes against every loaded signature source,
so structs that win32metadata also declares (UNICODE_STRING,
OBJECT_ATTRIBUTES, LARGE_INTEGER, ...) still render; phnt-only structs show
as plain pointers.

The output (``speakeasy/resources/win32/phnt_signatures.json.gz``) is a build
artifact: it is regenerated on every build and is not committed.

Usage::

    python scripts/gen_phnt_signatures.py [--phnt DIR] [--output FILE] [--stats]
"""

from __future__ import annotations

import argparse
import collections
import glob
import gzip
import json
import os
import re
import subprocess
import sys
from collections.abc import Iterator
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PHNT = os.path.join(REPO_ROOT, "deps", "phnt")
DEFAULT_OUTPUT = os.path.join(REPO_ROOT, "speakeasy", "resources", "win32", "phnt_signatures.json.gz")

FORMAT_VERSION = 2

# Headers that hold no exported prototypes worth emulating (inline helpers,
# the umbrella header) or describe kernel-mode-only interfaces.
SKIP_HEADERS = {"phnt.h", "ntintsafe.h", "ntstrsafe.h", "nttypesafe.h"}

# Everything in phnt is exported by ntdll.dll (the kernel-mode Zw*/Nt*
# services are also ntoskrnl exports; speakeasy matches those by name).
DLL = "ntdll"

# C / Windows SDK scalar types -> type code. Pointer-sized integers are "p".
BASE_TYPES: dict[str, str] = {
    "VOID": "v",
    "void": "v",
    "BOOLEAN": "B",
    "BOOL": "b",
    "LOGICAL": "u32",
    "CHAR": "i8",
    "CCHAR": "i8",
    "char": "i8",
    "UCHAR": "u8",
    "BYTE": "u8",
    "KIRQL": "u8",
    "KPROCESSOR_MODE": "u8",
    "SHORT": "i16",
    "CSHORT": "i16",
    "USHORT": "u16",
    "WORD": "u16",
    "WCHAR": "u16",
    "LANGID": "u16",
    "INT": "i32",
    "int": "i32",
    "LONG": "i32",
    "long": "i32",
    "NTSTATUS": "i32",
    "HRESULT": "i32",
    "KPRIORITY": "i32",
    "UINT": "u32",
    "ULONG": "u32",
    "DWORD": "u32",
    "ULONG32": "u32",
    "LONG32": "i32",
    "UINT32": "u32",
    "INT32": "i32",
    "ACCESS_MASK": "u32",
    "LCID": "u32",
    "LONGLONG": "i64",
    "LONG64": "i64",
    "INT64": "i64",
    "ULONGLONG": "u64",
    "ULONG64": "u64",
    "UINT64": "u64",
    "DWORD64": "u64",
    "DWORDLONG": "u64",
    "ULONG_PTR": "p",
    "LONG_PTR": "p",
    "DWORD_PTR": "p",
    "SIZE_T": "p",
    "SSIZE_T": "p",
    "UINT_PTR": "p",
    "INT_PTR": "p",
    "KAFFINITY": "p",
    "KSPIN_LOCK": "p",
    "size_t": "p",
    "HANDLE": "h",
    "HMODULE": "h",
    "HINSTANCE": "h",
    "HKEY": "h",
    "HWND": "h",
    "HDC": "h",
    "HANDLE_PTR": "p",
    "PVOID": "p",
    "LPVOID": "p",
    "PCVOID": "p",
    "LPCVOID": "p",
    "PVOID64": "p",
    "PSTR": "s",
    "LPSTR": "s",
    "PCSTR": "s",
    "LPCSTR": "s",
    "PCHAR": "s",
    "PCCH": "s",
    "PCH": "s",
    "PCSZ": "s",
    "PSZ": "s",
    "PWSTR": "S",
    "LPWSTR": "S",
    "PCWSTR": "S",
    "LPCWSTR": "S",
    "PWCHAR": "S",
    "PWCH": "S",
    "PCWCH": "S",
    "NWPSTR": "S",
    "PZZWSTR": "S",
    "PCZZWSTR": "S",
    "FLOAT": "f32",
    "float": "f32",
    "DOUBLE": "f64",
    "double": "f64",
    "GUID": "g",
    "LPGUID": "p:g",
    "PGUID": "p:g",
    "REFGUID": "p:g",
    "LPCGUID": "p:g",
    "PSID": "p",
    "PSECURITY_DESCRIPTOR": "p",
    "PGENERIC_MAPPING": "p",
    "PLUID": "ps:LUID",
    "PACL": "p",
    "PCONTEXT": "ps:CONTEXT",
    "LPPOINT": "ps:POINT",
    "PPOINT": "ps:POINT",
    "PRECT": "ps:RECT",
    "LPRECT": "ps:RECT",
    "HACCEL": "h",
    "PAPCFUNC": "p",
    "NOTIFICATIONCALLBACK": "p",
    "ENABLECALLBACK": "p",
    "USERTHREADINFOCLASS": "i32",
    "WNF_STATE_NAME": "st:WNF_STATE_NAME:8",
    "PS_PROTECTION": "u8",
    "SECURITY_DESCRIPTOR_CONTROL": "u16",
    "ACTIVATION_CONTEXT_INFO_CLASS": "i32",
    "DLL_DIRECTORY_COOKIE": "p",
    "BCD_OBJECT_DESCRIPTION": "st:BCD_OBJECT_DESCRIPTION:8",
    "TARGET_PLATFORM_CONTEXT_REFERENCE": "p",
    "PACKAGE_CONTEXT_REFERENCE": "p",
    "PACKAGE_RESOURCES_CONTEXT_REFERENCE": "p",
    "PIO_APC_ROUTINE": "p",
    "PTIMER_APC_ROUTINE": "p",
    "PKNORMAL_ROUTINE": "p",
    "PPS_APC_ROUTINE": "p",
    "PTP_CALLBACK_ENVIRON": "p",
    "PIMAGE_NT_HEADERS": "ps:IMAGE_NT_HEADERS32",
    "FARPROC": "p",
    "PROC": "p",
    "va_list": "p",
    "HKL": "h",
    "ATOM": "u16",
    "COLORREF": "u32",
    "LPARAM": "p",
    "WPARAM": "p",
    "LRESULT": "p",
    "HGDIOBJ": "h",
    "HBRUSH": "h",
    "HFONT": "h",
    "HBITMAP": "h",
    "HRGN": "h",
    "HICON": "h",
    "HCURSOR": "h",
    "HMENU": "h",
    "HDESK": "h",
    "HWINSTA": "h",
    "HHOOK": "h",
    "HRAWINPUT": "h",
    "HMONITOR": "h",
    "HPALETTE": "h",
    "HENHMETAFILE": "h",
    "HPOWERNOTIFY": "h",
    "HIMC": "h",
}

# Structs commonly passed by value; sizeof for x86 (and x64 when different).
BY_VALUE_STRUCTS: dict[str, str] = {
    "LARGE_INTEGER": "st:LARGE_INTEGER:8",
    "ULARGE_INTEGER": "st:ULARGE_INTEGER:8",
    "LUID": "st:LUID:8",
    "PROCESSOR_NUMBER": "st:PROCESSOR_NUMBER:4",
    "GROUP_AFFINITY": "st:GROUP_AFFINITY:12/16",
    "CLIENT_ID": "st:CLIENT_ID:8/16",
    "UNICODE_STRING": "st:UNICODE_STRING:8/16",
    "STRING": "st:STRING:8/16",
    "ANSI_STRING": "st:STRING:8/16",
    "GUID": "g",
    "FILETIME": "st:FILETIME:8",
    "SYSTEMTIME": "st:SYSTEMTIME:16",
    "POINT": "st:POINT:8",
    "RECT": "st:RECT:16",
    "SIZE": "st:SIZE:8",
    "OBJECT_ATTRIBUTES": "st:OBJECT_ATTRIBUTES:24/48",
}

# Windows SDK scalar typedefs and enums phnt uses but does not define.
SDK_SCALARS: dict[str, str] = {
    "SECURITY_INFORMATION": "u32",
    "SE_SIGNING_LEVEL": "u8",
    "EXECUTION_STATE": "u32",
    "AUDIT_EVENT_TYPE": "i32",
    "SECURITY_IMPERSONATION_LEVEL": "i32",
    "TOKEN_INFORMATION_CLASS": "i32",
    "TOKEN_TYPE": "i32",
    "NT_PRODUCT_TYPE": "i32",
    "EXCEPTION_DISPOSITION": "i32",
    "LATENCY_TIME": "i32",
    "POWER_ACTION": "i32",
    "SYSTEM_POWER_STATE": "i32",
    "DEVICE_POWER_STATE": "i32",
    "POWER_INFORMATION_LEVEL": "i32",
    "KTMOBJECT_TYPE": "i32",
    "TRANSACTION_OUTCOME": "i32",
    "TRANSACTION_STATE": "i32",
    "TRANSACTION_INFORMATION_CLASS": "i32",
    "TRANSACTIONMANAGER_INFORMATION_CLASS": "i32",
    "RESOURCEMANAGER_INFORMATION_CLASS": "i32",
    "ENLISTMENT_INFORMATION_CLASS": "i32",
    "NOTIFICATION_MASK": "u32",
    "DWORD32": "u32",
    "UINT8": "u8",
    "INT8": "i8",
    "UINT16": "u16",
    "INT16": "i16",
    "CHAR8": "u8",
    "BOOLEAN32": "u32",
    "TP_VERSION": "u32",
    "TP_WAIT_RESULT": "u32",
    "REGSAM": "u32",
    "PROCESSOR_MODE": "u8",
    "SECURITY_CONTEXT_TRACKING_MODE": "u8",
    "ACL_INFORMATION_CLASS": "i32",
    "SID_NAME_USE": "i32",
    "WELL_KNOWN_SID_TYPE": "i32",
    "WAIT_TYPE": "i32",
    "EVENT_TYPE": "i32",
    "TIMER_TYPE": "i32",
    "SECTION_INHERIT": "i32",
    "SE_SIGNING_LEVEL_TYPE": "u8",
    "TOKEN_ELEVATION_TYPE": "i32",
    "TOKEN_SECURITY_ATTRIBUTE_OPERATION": "i32",
    "SYSTEM_INFORMATION_CLASS_TYPE": "i32",
    "LOGICAL_PROCESSOR_RELATIONSHIP": "i32",
    "HEAP_INFORMATION_CLASS": "i32",
    "FIRMWARE_TYPE": "i32",
    "MEM_EXTENDED_PARAMETER_TYPE": "i32",
    "JOBOBJECTINFOCLASS": "i32",
    "RTL_PATH_TYPE": "i32",
    "ULONG_PTR64": "u64",
    "ULONG_PTR32": "u32",
    "PVOID32": "u32",
    "PVOID64": "u64",
    "ULONG_ALIGNED": "u32",
    "NTSTATUS_ALIGNED": "i32",
    "HKEY__": "h",
    "APPCONTAINER_SID_TYPE": "i32",
    "WNF_STATE_NAME_LIFETIME": "i32",
    "WNF_DATA_SCOPE": "i32",
    "WNF_STATE_NAME_INFORMATION": "i32",
}

API_MACROS = {"NTSYSCALLAPI", "NTSYSAPI", "PHNT_API", "EXTERN_C", "extern", "WINBASEAPI", "WINUSERAPI", "NTAPI_INLINE"}
CALL_CONVS = {
    "NTAPI": "stdcall",
    "WINAPI": "stdcall",
    "STDAPIVCALLTYPE": "cdecl",
    "__cdecl": "cdecl",
    "STDAPICALLTYPE": "stdcall",
}
IGNORED_PREFIX_TOKENS = {
    "__drv_aliasesMem",
    "DECLSPEC_NOALIAS",
    "DECLSPEC_NORETURN",
    "DECLSPEC_ALLOCATOR",
    "DECLSPEC_RESTRICT",
    "__inline",
    "__forceinline",
    "FORCEINLINE",
    "inline",
    "static",
    "PHNT_INLINE",
    "DECLSPEC_DEPRECATED",
    "CONST",
    "const",
}

ANNOTATION = re.compile(r"_[A-Z][A-Za-z0-9_]*_(?=\s|\(|$)")
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class UnsupportedType(Exception):
    pass


# -- header preprocessing ---------------------------------------------------


def strip_comments(text: str) -> str:
    text = text.replace("\r\n", "\n")
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    return text


def split_top_level(text: str, sep: str = ",") -> list[str]:
    """Split on ``sep`` outside parentheses/brackets/braces."""
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur))
    return parts


def match_brace(text: str, open_pos: int) -> int:
    """Index of the ``}`` matching the ``{`` at ``open_pos``."""
    depth = 0
    for i in range(open_pos, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    raise ValueError("unbalanced braces")


# -- type collection ----------------------------------------------------------


class TypeTable:
    """Struct names, enum definitions and typedef aliases gathered from the headers."""

    def __init__(self) -> None:
        self.structs: set[str] = set()
        self.enums: dict[str, list[tuple[str, int]]] = {}
        self.aliases: dict[str, str] = {}  # typedef name -> C type text it stands for
        self.function_pointers: set[str] = set()
        self.used_enums: set[str] = set()

    def collect(self, text: str) -> None:
        self._collect_aggregates(text)
        self._collect_simple_typedefs(text)

    def _collect_aggregates(self, text: str) -> None:
        for m in re.finditer(r"\btypedef\s+(struct|union|enum)\s+(_?[A-Za-z0-9_]+)?\s*\{", text):
            kind, tag = m.group(1), m.group(2)
            try:
                close = match_brace(text, m.end() - 1)
            except ValueError:
                continue
            semi = text.find(";", close)
            if semi == -1:
                continue
            names = [n.strip() for n in text[close + 1 : semi].split(",")]
            plain = [n for n in names if n and not n.startswith("*")]
            pointers = [n.lstrip("* ").strip() for n in names if n.startswith("*")]
            if not plain:
                continue
            name = plain[0]
            for alias in plain[1:]:
                self.aliases[alias] = name
            for ptr in pointers:
                self.aliases[ptr] = f"{name} *"
            if kind == "enum":
                values = parse_enum_body(text[m.end() : close])
                if values is not None:
                    self.enums[name] = values
            else:
                self.structs.add(name)
                if tag and tag != name:
                    self.aliases.setdefault(tag, name)

    def _collect_simple_typedefs(self, text: str) -> None:
        # typedef struct _FOO *PFOO;  typedef const UNICODE_STRING *PCUNICODE_STRING;
        # typedef ULONG_PTR KAFFINITY, *PKAFFINITY;
        for m in re.finditer(r"\btypedef\s+([^;{}()]+?)\s*;", text):
            decl = m.group(1)
            if "{" in decl or "(" in decl:
                continue
            parts = [p.strip() for p in decl.split(",")]
            head = parts[0].split()
            if len(head) < 2:
                continue
            first_name = head[-1].lstrip("*")
            stars = "*" * (head[-1].count("*") + "".join(head[:-1]).count("*"))
            base_tokens = [t.replace("*", "") for t in head[:-1] if t.replace("*", "")]
            aggregate = any(t in ("struct", "union") for t in base_tokens)
            base_tokens = [t for t in base_tokens if t not in ("struct", "union", "enum", "const", "CONST", "volatile")]
            if not base_tokens:
                continue
            base = " ".join(t.lstrip("_") if t.startswith("_") and t[1:2].isupper() else t for t in base_tokens)
            if aggregate and len(base_tokens) == 1:
                # typedef struct _TEB *PTEB; declares TEB as an (opaque) struct
                self.structs.add(base)
            if first_name and first_name != base:
                self.aliases.setdefault(first_name, f"{base} {stars}".strip())
            for extra in parts[1:]:
                extra = extra.strip()
                n = extra.lstrip("*").strip()
                s = "*" * extra.count("*")
                if n:
                    self.aliases.setdefault(n, f"{base} {s}".strip())
        # function pointer typedefs are just pointers
        for m in re.finditer(
            r"\btypedef\s+[^;{}]*?\(\s*(?:NTAPI|WINAPI|__cdecl|__stdcall|CALLBACK|STDAPIVCALLTYPE)?\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\(",
            text,
        ):
            self.function_pointers.add(m.group(1))

    # -- resolution --------------------------------------------------------

    def resolve(self, ctype: str, depth: int = 0) -> str:
        """Resolve C type text (``const UNICODE_STRING *``) to a type code."""
        if depth > 16:
            raise UnsupportedType(f"alias loop in {ctype}")
        tokens = ctype.replace("*", " * ").split()
        stars = tokens.count("*")
        words = [
            t
            for t in tokens
            if t != "*"
            and t not in ("const", "CONST", "volatile", "struct", "union", "enum", "__unaligned", "UNALIGNED")
        ]
        if not words:
            raise UnsupportedType(f"no type in {ctype!r}")
        if len(words) > 1:
            joined = " ".join(words)
            simple = {
                "unsigned long": "u32",
                "unsigned int": "u32",
                "unsigned short": "u16",
                "unsigned char": "u8",
                "long long": "i64",
                "unsigned long long": "u64",
                "signed char": "i8",
                "unsigned __int64": "u64",
                "__int64": "i64",
            }
            if joined in simple:
                base = simple[joined]
            else:
                raise UnsupportedType(f"multi-word type {ctype!r}")
        else:
            base = self._resolve_name(words[0], depth)
        for _ in range(stars):
            base = _pointer_to(base)
        return base

    def _resolve_name(self, name: str, depth: int) -> str:
        if name in BASE_TYPES:
            return BASE_TYPES[name]
        if name in self.function_pointers:
            return "p"
        if name in self.enums:
            self.used_enums.add(name)
            return f"i32:{name}"
        if name in self.structs:
            if name in BY_VALUE_STRUCTS:
                return BY_VALUE_STRUCTS[name]
            return f"st:{name}:?"
        if name in BY_VALUE_STRUCTS:
            return BY_VALUE_STRUCTS[name]
        if name in self.aliases:
            return self.resolve(self.aliases[name], depth + 1)
        # phnt sometimes uses P<TYPE> / PC<TYPE> without a typedef in view
        for prefix in ("PC", "P", "LPC", "LP"):
            if name.startswith(prefix) and len(name) > len(prefix) and name[len(prefix)].isupper():
                rest = name[len(prefix) :]
                if (
                    rest in BASE_TYPES
                    or rest in self.structs
                    or rest in self.enums
                    or rest in self.aliases
                    or rest in SDK_SCALARS
                ):
                    return _pointer_to(self._resolve_name(rest, depth + 1))
                if _looks_like_struct_name(rest):
                    # pointer to a Windows SDK struct phnt does not define itself
                    return f"ps:{rest}"
        if name in SDK_SCALARS:
            return SDK_SCALARS[name]
        if _looks_like_struct_name(name):
            # by-value SDK struct of unknown size: the caller decides whether to skip
            return f"st:{name}:?"
        raise UnsupportedType(f"unknown type {name}")


def _looks_like_struct_name(name: str) -> bool:
    """ALL_CAPS identifiers with an underscore are almost always SDK struct typedefs."""
    return name.isupper() and "_" in name and not name.startswith("P_")


def _pointer_to(code: str) -> str:
    kind = code.split(":", 1)[0]
    if kind == "st":
        return "ps:" + code.split(":", 2)[1]
    if code == "v":
        return "p"
    if code in ("u8", "i8"):
        return "s"
    if code == "u16":
        return "S"
    return f"p:{code}"


# -- enums --------------------------------------------------------------------


def parse_enum_body(body: str) -> list[tuple[str, int]] | None:
    values: list[tuple[str, int]] = []
    env: dict[str, int] = {}
    nxt = 0
    for item in split_top_level(body):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            name, expr = item.split("=", 1)
            name = name.strip()
            try:
                value = eval_const(expr.strip(), env)
            except ValueError:
                return None
        else:
            name, value = item, nxt
        if not IDENT.fullmatch(name):
            return None
        env[name] = value
        values.append((name, value))
        nxt = value + 1
    return values or None


_CONST_TOKEN = re.compile(r"\s*(0[xX][0-9a-fA-F]+[uUlL]*|\d+[uUlL]*|[A-Za-z_][A-Za-z0-9_]*|<<|>>|\|\||&&|[-+*/|&^~()])")


def eval_const(expr: str, env: dict[str, int]) -> int:
    """Evaluate a C integer constant expression made of literals, names and operators."""
    tokens = []
    pos = 0
    expr = expr.strip()
    while pos < len(expr):
        m = _CONST_TOKEN.match(expr, pos)
        if not m:
            raise ValueError(expr)
        tokens.append(m.group(1))
        pos = m.end()
    py = []
    for t in tokens:
        if re.fullmatch(r"0[xX][0-9a-fA-F]+[uUlL]*|\d+[uUlL]*", t):
            py.append(str(int(t.rstrip("uUlL"), 0)))
        elif IDENT.fullmatch(t):
            if t not in env:
                raise ValueError(t)
            py.append(str(env[t]))
        elif t in ("||", "&&"):
            raise ValueError(t)
        else:
            py.append(t)
    try:
        return int(eval("".join(py), {"__builtins__": {}}, {}))  # noqa: S307 - tokens are validated above
    except Exception as e:
        raise ValueError(expr) from e


def looks_like_flags(values: list[tuple[str, int]]) -> bool:
    nonzero = [v for _, v in values if v]
    return len(nonzero) >= 3 and all(v & (v - 1) == 0 for v in nonzero)


# -- prototypes ----------------------------------------------------------------

SAL_FLAGS = (("Inout", "io"), ("In", "i"), ("Out", "o"), ("opt", "?"), ("Reserved", "r"))


def parse_param(text: str, param_names: list[str]) -> tuple[str, str, str, dict | None]:
    """Return (name, ctype, flags, buffer_len) for one parameter declaration."""
    text = text.strip()
    flags = ""
    length = None
    while True:
        m = re.match(r"(_[A-Z][A-Za-z0-9_]*_)\s*(\(([^()]*(?:\([^()]*\)[^()]*)*)\))?\s*", text)
        if not m:
            break
        ann, args = m.group(1), m.group(3)
        for needle, flag in SAL_FLAGS:
            if needle in ann and flag not in flags:
                flags += flag
        if "Outptr" in ann and "o" not in flags:
            flags += "o"
        if args is not None and ("writes" in ann or "reads" in ann or "updates" in ann):
            first = split_top_level(args)[0].strip() if args.strip() else ""
            if IDENT.fullmatch(first) and first in param_names:
                length = {"n" if "bytes" in ann else "c": param_names.index(first)}
        text = text[m.end() :]
    flags = flags.replace("io", "io")
    if "io" in flags:
        flags = flags.replace("io", "")
        flags = "io" + flags
    text = re.sub(r"__drv_\w+(\([^)]*\))?|DECLSPEC_NOALIAS", " ", text)
    # array parameters decay to pointers
    text = re.sub(r"([A-Za-z_][A-Za-z0-9_]*)\s*(\[[^\]]*\]\s*)+", r"* \1", text)
    tokens = text.replace("*", " * ").split()
    if not tokens:
        raise UnsupportedType("empty parameter")
    if tokens[-1] == "*" or tokens[-1] in BASE_TYPES or len(tokens) == 1:
        # unnamed parameter (e.g. "VOID" or "PVOID *")
        name = ""
        ctype = " ".join(tokens)
    else:
        name = tokens[-1]
        ctype = " ".join(tokens[:-1])
    return name, ctype, flags, length


def _param_name(text: str) -> str:
    text = re.sub(r"_[A-Z][A-Za-z0-9_]*_\s*(\([^()]*(?:\([^()]*\)[^()]*)*\))?", " ", text)
    text = re.sub(r"__drv_\w+(\([^)]*\))?|DECLSPEC_NOALIAS", " ", text)
    text = re.sub(r"([A-Za-z_][A-Za-z0-9_]*)\s*(\[[^\]]*\]\s*)+", r"* \1", text)
    tokens = text.replace("*", " * ").split()
    if not tokens or tokens[-1] == "*" or tokens[-1] in BASE_TYPES or len(tokens) == 1:
        return ""
    return tokens[-1]


PROTOTYPE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\(\s*$", re.M)


def iter_prototypes(text: str) -> Iterator[tuple[list[str], str, str]]:
    """Yield (prefix_lines, name, params_text) for each ``Name(\\n...)`` block."""
    for m in PROTOTYPE.finditer(text):
        name = m.group(1)
        close = text.find(");", m.end())
        brace = text.find("{", m.end())
        if close == -1 or (brace != -1 and brace < close):
            continue  # inline function body or macro
        params = text[m.end() : close]
        if "{" in params or ";" in params:
            continue
        # walk back over the preceding non-blank lines
        prefix: list[str] = []
        pos = m.start()
        while pos > 0:
            prev_end = pos - 1
            prev_start = text.rfind("\n", 0, prev_end) + 1
            line = text[prev_start:prev_end].strip()
            if not line or line.startswith("#") or line.endswith(";") or line.endswith("}") or line.endswith("{"):
                break
            prefix.insert(0, line)
            pos = prev_start
            if len(prefix) > 8:
                break
        yield prefix, name, params


def parse_prototype(prefix: list[str], name: str, params_text: str, types: TypeTable) -> dict | None:
    tokens = " ".join(prefix).replace("*", " * ").split()
    if not any(t in API_MACROS for t in tokens):
        return None
    conv = None
    ret_tokens = []
    skip_paren = 0
    for t in tokens:
        if skip_paren:
            skip_paren += t.count("(") - t.count(")")
            continue
        if t in API_MACROS or t in IGNORED_PREFIX_TOKENS:
            continue
        if t in CALL_CONVS:
            conv = CALL_CONVS[t]
            continue
        if t.startswith("_") and "(" in t:
            skip_paren = t.count("(") - t.count(")")
            continue
        if ANNOTATION.match(t) or t.startswith("_") and t.endswith("_"):
            continue
        ret_tokens.append(t)
    if conv is None or not ret_tokens:
        return None
    ret_type = " ".join(ret_tokens)

    entry: dict = {"dll": DLL}
    skip = None
    try:
        entry["ret"] = types.resolve(ret_type)
    except UnsupportedType as e:
        entry["ret"] = "p"
        skip = f"return type: {e}"

    raw_params = [p for p in split_top_level(params_text) if p.strip()]
    variadic = any(p.strip() == "..." for p in raw_params)
    raw_params = [p for p in raw_params if p.strip() != "..."]
    names = [_param_name(p) for p in raw_params]
    params: list[list[Any]] = []
    for raw in raw_params:
        try:
            pname, ctype, flags, length = parse_param(raw, names)
        except UnsupportedType as e:
            skip = skip or f"param: {e}"
            continue
        if not pname and ctype in ("VOID", "void"):
            continue
        try:
            code = types.resolve(ctype)
        except UnsupportedType as e:
            code = "p"
            skip = skip or f"param {pname}: {e}"
        if code.startswith("st:") and code.endswith(":?"):
            skip = skip or f"param {pname}: by-value struct {ctype} of unknown size"
        param: list[Any] = [pname or f"param{len(params)}", code, flags]
        if length:
            param.append(length)
        params.append(param)
    entry["params"] = params
    if variadic:
        entry["variadic"] = True
        conv = "cdecl"
    if conv != "stdcall":
        entry["conv"] = conv
    if skip:
        entry["skip"] = skip
    return entry


# -- driver ---------------------------------------------------------------------


def load_headers(root: str) -> dict[str, str]:
    files = sorted(glob.glob(os.path.join(root, "*.h")))
    files = [f for f in files if os.path.basename(f) not in SKIP_HEADERS]
    if not files:
        raise SystemExit(f"no phnt headers found under {root!r}; run `git submodule update --init deps/phnt`")
    headers = {}
    for path in files:
        with open(path, encoding="utf-8", errors="replace") as f:
            headers[os.path.basename(path)] = strip_comments(f.read())
    return headers


def generate(phnt_root: str) -> tuple[dict, collections.Counter]:
    headers = load_headers(phnt_root)
    types = TypeTable()
    for text in headers.values():
        types.collect(text)

    table: dict[str, list[dict]] = collections.defaultdict(list)
    stats: collections.Counter = collections.Counter()
    reasons: collections.Counter = collections.Counter()
    for header, text in headers.items():
        for prefix, name, params in iter_prototypes(text):
            entry = parse_prototype(prefix, name, params, types)
            if entry is None:
                stats["ignored"] += 1
                continue
            if any(e == entry for e in table[name]):
                stats["duplicates"] += 1
                continue
            if table[name]:
                # keep the first declaration of a name (e.g. ntzwapi.h re-declares)
                stats["redeclared"] += 1
                continue
            table[name].append(entry)
            stats["functions"] += 1
            if "skip" in entry:
                stats["skipped"] += 1
                reasons[entry["skip"].split(":")[-1].strip()[:60]] += 1
            else:
                stats["supported"] += 1
            if entry.get("variadic"):
                stats["variadic"] += 1
            if entry.get("conv") == "cdecl":
                stats["cdecl"] += 1
    stats["skip_reasons"] = reasons  # type: ignore[assignment]

    enums = {}
    for name in sorted(types.used_enums):
        values = types.enums[name]
        entry = {"v": [[n, v & 0xFFFFFFFF] for n, v in values]}
        if looks_like_flags(values):
            entry["f"] = True
        enums[name] = entry
    stats["enums"] = len(enums)

    commit = None
    try:
        commit = subprocess.check_output(
            ["git", "-C", phnt_root, "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, text=True
        ).strip()
    except Exception:
        pass

    doc = {
        "format": FORMAT_VERSION,
        "source": "phnt",
        "version": commit[:12] if commit else "unknown",
        "commit": commit,
        "generated_by": "scripts/gen_phnt_signatures.py",
        "dll_aliases": {},
        "name_prefixes": {},
        "enums": enums,
        "structs": {},
        "functions": dict(sorted(table.items())),
    }
    return doc, stats


def write_output(doc: dict, output: str) -> int:
    os.makedirs(os.path.dirname(output), exist_ok=True)
    raw = json.dumps(doc, separators=(",", ":")).encode("utf-8")
    with open(output, "wb") as f:
        with gzip.GzipFile(filename="", fileobj=f, mode="wb", mtime=0) as gz:
            gz.write(raw)
    return len(raw)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--phnt", default=DEFAULT_PHNT, help="path to the phnt checkout")
    ap.add_argument("--output", default=DEFAULT_OUTPUT, help="output .json.gz path")
    ap.add_argument("--stats", action="store_true", help="print generation statistics")
    args = ap.parse_args(argv)

    doc, stats = generate(args.phnt)
    raw_size = write_output(doc, args.output)
    print(
        f"wrote {args.output}: {stats['functions']} functions "
        f"({stats['supported']} supported, {stats['skipped']} skipped), {stats['enums']} enums, "
        f"{raw_size} bytes raw, {os.path.getsize(args.output)} bytes gzipped, phnt {doc['version']}"
    )
    if args.stats:
        reasons = stats.pop("skip_reasons")
        for key, value in sorted(stats.items()):
            print(f"  {key:24s} {value}")
        for reason, count in reasons.most_common(25):  # type: ignore[attr-defined]
            print(f"    {count:5d} {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
