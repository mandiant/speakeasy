"""
The Win32 API signature database.

Speakeasy has handlers for a part of the Windows API (see ``speakeasy.winenv.api``).
For the other APIs, this module gives the declaration of an import: the number of
argument slots, the calling convention, the name and type of each parameter, and the
return type.

A ``SignatureSource`` gives the signatures. Two sources come with Speakeasy, and both
read the same compact JSON table format:

* ``Win32MetadataSource``: the documented Win32 API, from Microsoft win32metadata.
* ``PhntSource``: the ntdll exports that win32metadata does not document, such as
  the ``Nt`` and ``Rtl`` functions, from the phnt native API headers.

The build generates the signature files, so a source checkout can be without them.
A source without its file gives no signatures and logs one warning.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import threading
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from speakeasy.winenv.defs.lookup import get_value_names

logger = logging.getLogger(__name__)

SUPPORTED_FORMAT = 2

_RESOURCES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "resources", "win32"
)
DEFAULT_PATH = os.path.join(_RESOURCES, "win32json_signatures.json.gz")
DEFAULT_PHNT_PATH = os.path.join(_RESOURCES, "phnt_signatures.json.gz")

CONV_STDCALL = "stdcall"
CONV_CDECL = "cdecl"

ARCH_X86 = "x86"
ARCH_X64 = "x64"

# Byte size of each type code kind. None means pointer-sized. ParamSig.size gives the
# size of the ``st`` and ``arr`` kinds. A pointer kind can name its target type:
# ``p:u32`` (DWORD*), ``a:u16`` (WCHAR buffer), ``ps:NAME`` (struct pointer).
TYPE_SIZES: dict[str, int | None] = {
    "v": 0,
    "i8": 1,
    "u8": 1,
    "B": 1,
    "i16": 2,
    "u16": 2,
    "i32": 4,
    "u32": 4,
    "b": 4,
    "f32": 4,
    "i64": 8,
    "u64": 8,
    "f64": 8,
    "g": 16,
    "p": None,
    "ps": None,
    "a": None,
    "s": None,
    "S": None,
    "h": None,
}

STRING_KINDS = ("s", "S")
BOOL_KINDS = ("b", "B")
FLOAT_KINDS = ("f32", "f64")
AGGREGATE_KINDS = ("st", "g")
INT_KINDS = ("i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64")
EMULATION_SCALAR_KINDS = INT_KINDS + BOOL_KINDS + ("p", "ps", "a", "s", "S", "h")


def normalize_dll(name: str) -> str:
    """Lower-case a module name and strip its extension: ``KERNEL32.dll`` -> ``kernel32``."""
    name = name.lower()
    for ext in (".dll", ".drv", ".exe", ".cpl", ".sys"):
        if name.endswith(ext):
            return name[: -len(ext)]
    return name


@dataclass(frozen=True)
class EnumDef:
    """A named set of integer constants. With ``flags``, a value can combine more than one constant."""

    name: str
    values: tuple[tuple[str, int], ...]
    flags: bool = False

    def decode(self, value: int) -> str:
        """Render ``value`` with the rules of ``speakeasy.winenv.defs.lookup.get_value_names``."""
        return "|".join(get_value_names(self.values, value, self.flags))


@dataclass(frozen=True)
class FieldDef:
    """One field of a struct: name, type code and byte offset per pointer size."""

    name: str
    code: str
    offset32: int
    offset64: int

    def offset(self, ptr_size: int) -> int:
        return self.offset64 if ptr_size == 8 else self.offset32

    @property
    def kind(self) -> str:
        return self.code.split(":", 1)[0]

    def size(self, ptr_size: int) -> int:
        return ParamSig("", self.code).size(ptr_size)


@dataclass(frozen=True)
class StructDef:
    """
    Layout of a struct or union.

    ``fields`` is empty if the generator could not resolve all fields. The size is correct also then.
    """

    name: str
    size32: int
    size64: int
    fields: tuple[FieldDef, ...] = ()
    is_union: bool = False

    def size(self, ptr_size: int) -> int:
        return self.size64 if ptr_size == 8 else self.size32


@dataclass(frozen=True)
class ParamSig:
    """
    One parameter of an API signature.

    ``buffer_len`` gives the length of the buffer of a pointer parameter, if the
    declaration gives it. With ``("n", i)``, parameter ``i`` has the byte count. With
    ``("c", i)``, parameter ``i`` has the element count. With ``("k", n)``, the
    buffer has ``n`` elements.
    """

    name: str
    code: str
    flags: str = ""
    buffer_len: tuple[str, int] | None = None

    @property
    def kind(self) -> str:
        return self.code.split(":", 1)[0]

    @property
    def qualifier(self) -> str | None:
        parts = self.code.split(":", 1)
        return parts[1] if len(parts) > 1 else None

    @property
    def enum(self) -> str | None:
        """Name of the enum of an integer parameter, if any."""
        if self.kind in INT_KINDS:
            return self.qualifier
        return None

    @property
    def pointee(self) -> str | None:
        """Type code of the target of a pointer or buffer parameter, if known."""
        kind = self.kind
        if kind in ("p", "a"):
            return self.qualifier
        if kind == "s":
            return "u8"
        if kind == "S":
            return "u16"
        return None

    def elem_size(self, ptr_size: int) -> int | None:
        """Size in bytes of one target element, or None for an opaque pointer (void*)."""
        pointee = self.pointee
        if pointee is None:
            return None
        return ParamSig("", pointee).size(ptr_size)

    @property
    def is_in(self) -> bool:
        # A parameter without a direction is an input
        return "i" in self.flags or "o" not in self.flags

    @property
    def is_out(self) -> bool:
        return "o" in self.flags

    def size(self, ptr_size: int) -> int:
        """Size in bytes of the value of the parameter for ``ptr_size``."""
        kind = self.kind
        if kind == "st":
            # st:NAME:SIZE or st:NAME:SIZE32/SIZE64
            size_spec = (self.qualifier or "").rsplit(":", 1)[-1]
            if "/" in size_spec:
                s32, s64 = size_spec.split("/", 1)
                return int(s64 if ptr_size == 8 else s32)
            return int(size_spec or 0)
        if kind == "arr":
            # arr:COUNT:ELEMCODE (inline array in a struct)
            count, elem = (self.qualifier or "0:u8").split(":", 1)
            return int(count) * ParamSig("", elem).size(ptr_size)
        size = TYPE_SIZES.get(kind)
        if size is None:
            return ptr_size
        return size

    def slots(self, ptr_size: int) -> int:
        """Number of pointer-sized argument slots this parameter occupies."""
        if ptr_size == 8 and self.kind in AGGREGATE_KINDS:
            # Win64 passes an aggregate of 1, 2, 4 or 8 bytes in one slot, and other
            # aggregates by reference in one slot.
            return 1
        size = self.size(ptr_size)
        return max(1, -(-size // ptr_size))

    def value_mask(self, ptr_size: int) -> int | None:
        """Mask that gets a parameter narrower than a slot from the slot value, or None."""
        if self.kind in AGGREGATE_KINDS:
            return None
        size = self.size(ptr_size)
        if 0 < size < ptr_size:
            return (1 << (size * 8)) - 1
        return None


@dataclass(frozen=True)
class FuncSig:
    """Signature of an exported API function."""

    name: str
    dll: str
    ret: str
    params: tuple[ParamSig, ...]
    conv: str = CONV_STDCALL
    variadic: bool = False
    arch: tuple[str, ...] | None = None
    set_last_error: bool = False
    skip: str | None = None
    source: str = ""
    extra: dict = field(default_factory=dict, compare=False)

    @property
    def ret_kind(self) -> str:
        return self.ret.split(":", 1)[0]

    def supports_arch(self, arch: str) -> bool:
        return self.arch is None or arch in self.arch

    def supports_emulation(self, ptr_size: int) -> bool:
        """
        Return True if the emulator can call this function from the signature, without a handler.

        The emulator can call a cdecl or stdcall function whose arguments and return
        value are integers, pointers or structs passed by value. It cannot call a
        variadic function, a declaration with a skip marker, or a function with
        floating-point arguments, a struct return value or a return value wider than a
        pointer (EDX:EAX on x86). On x86, a 64-bit integer or a struct argument uses
        more than one stack slot. On x64, a struct argument uses one slot. The result
        does not change the exports of a module or the handlers and hooks that can run.
        """
        arch = ARCH_X86 if ptr_size == 4 else ARCH_X64
        if not self.supports_arch(arch) or self.skip is not None or self.variadic:
            return False
        if self.conv not in (CONV_CDECL, CONV_STDCALL):
            return False
        if self.ret_kind != "v":
            if self.ret_kind not in EMULATION_SCALAR_KINDS:
                return False
            if ParamSig("", self.ret).size(ptr_size) > ptr_size:
                return False
        return all(param.kind in EMULATION_SCALAR_KINDS + AGGREGATE_KINDS for param in self.params)

    def slot_layout(self, ptr_size: int) -> list[int]:
        return [p.slots(ptr_size) for p in self.params]

    def slot_count(self, ptr_size: int) -> int:
        """Total number of argument slots of a call. This is the ``argc`` of a handler."""
        return sum(self.slot_layout(ptr_size))

    def values_from_slots(self, slots: list[int], ptr_size: int) -> list[int]:
        """
        Join the raw argument slots into one integer for each parameter.

        A parameter with more than one slot, such as a 64-bit integer or a struct passed
        by value on x86, gets its slots in little-endian order. A parameter narrower than
        a slot gets only the bits of its size.
        """
        values = []
        pos = 0
        for param in self.params:
            n = param.slots(ptr_size)
            chunk = slots[pos : pos + n]
            pos += n
            value = 0
            for i, slot in enumerate(chunk):
                value |= (slot & ((1 << (ptr_size * 8)) - 1)) << (i * ptr_size * 8)
            mask = param.value_mask(ptr_size)
            if mask is not None:
                value &= mask
            values.append(value)
        return values


# ``read_uint(addr, size)`` reads a little-endian unsigned integer from emulated
# memory, or returns None if the address is unmapped.
ReadUInt = Callable[[int, int], "int | None"]
LookupStruct = Callable[[str], "StructDef | None"]


def buffer_count(sig: FuncSig, index: int, values: list[int], ptr_size: int, read_uint: ReadUInt) -> int | None:
    """
    Get the value of the count or size parameter ``index`` of a call with the argument ``values``.

    Read a count passed by pointer (``PDWORD pcbSize``) with ``read_uint``. Return None
    for a NULL or output pointer, an unmapped pointer or other parameter types.
    """
    param = sig.params[index]
    value = values[index]
    kind = param.kind
    if kind in INT_KINDS or (kind == "p" and param.qualifier is None):
        return value
    if kind == "p" and param.qualifier is not None:
        # Only an input pointer has a count before the call
        if not value or not param.is_in:
            return None
        size = param.elem_size(ptr_size) or ptr_size
        return read_uint(value, size)
    return None


def out_buffer_size(
    sig: FuncSig, index: int, values: list[int], ptr_size: int, lookup_struct: LookupStruct, read_uint: ReadUInt
) -> int | None:
    """
    Get the size in bytes of the buffer of an out pointer parameter, as the declaration gives it.

    Return None if the signature does not give the size, for example for a ``void*``
    without a size or an array without a count. A string without a declared size
    counts only its terminator.
    """
    param = sig.params[index]
    if param.buffer_len is not None:
        how, n = param.buffer_len
        count = n if how == "k" else buffer_count(sig, n, values, ptr_size, read_uint)
        if count is None:
            return None
        if how == "n":
            return count
        elem = param.elem_size(ptr_size)
        return None if elem is None else count * elem
    kind = param.kind
    if kind in STRING_KINDS:
        return 1 if kind == "s" else 2
    if kind == "ps":
        struct = lookup_struct(param.qualifier) if param.qualifier else None
        return struct.size(ptr_size) if struct is not None else None
    if kind == "p":
        return param.elem_size(ptr_size)
    return None


class SignatureSource(ABC):
    """A provider of API signatures."""

    name = ""

    @property
    @abstractmethod
    def available(self) -> bool:
        """True if this source has signatures."""

    @abstractmethod
    def lookup(self, dll: str, func: str, arch: str) -> FuncSig | None:
        """Return the signature for ``dll!func`` on ``arch`` ("x86" or "x64"), if known."""

    def iter_functions(self, dll: str, arch: str) -> Iterator[FuncSig]:
        """
        Yield the declarations of ``dll`` for ``arch``, also those that the emulator cannot call.

        The default yields nothing, so a source that has only ``lookup`` adds no exports.
        """
        return iter(())

    def lookup_enum(self, name: str) -> EnumDef | None:
        """Return the enum that a type code qualifier names, if this source has it."""
        return None

    def lookup_struct(self, name: str) -> StructDef | None:
        """Return the layout of struct ``name`` (the qualifier of a ``ps:`` code), if known."""
        return None


class Win32MetadataSource(SignatureSource):
    """
    Signatures generated from win32metadata via win32json.

    The index key is the function name. win32metadata records the DLL that implements
    a function (``KERNEL32.dll!K32EnumProcesses``), not the DLL that a sample imports it
    from (``psapi.dll!EnumProcesses``). So ``lookup`` uses the DLL only to select one of
    the declarations of a name and to add name prefixes.
    """

    name = "win32metadata"
    default_path = DEFAULT_PATH
    generator = "scripts/gen_win32_signatures.py"

    _missing_warned = False

    def __init__(self, path: str | None = None) -> None:
        self.path: str = path or self.default_path
        self._lock: threading.Lock = threading.Lock()
        self._loaded: bool = False
        self._functions: dict[str, list[dict]] = {}
        self._functions_by_dll: dict[str, dict[str, list[tuple[int, dict]]]] = {}
        self._enums: dict[str, dict] = {}
        self._structs: dict[str, dict] = {}
        self._dll_aliases: dict[str, str] = {}
        self._name_prefixes: dict[str, list[str]] = {}
        self._sig_cache: dict[tuple[str, int], FuncSig] = {}
        self._enum_cache: dict[str, EnumDef] = {}
        self._struct_cache: dict[str, StructDef] = {}
        self.version: str | None = None
        self.commit: str | None = None

    def _load(self) -> None:
        if self._loaded:
            return
        with self._lock:
            # Another thread can load the database while this thread waits for the lock.
            if self._loaded:
                return  # type: ignore[unreachable]
            self._loaded = True
            if not os.path.exists(self.path):
                cls = type(self)
                if not cls.__dict__.get("_missing_warned"):
                    cls._missing_warned = True
                    logger.warning(
                        "%s signature database not found at %s; unhooked imports it covers will not be "
                        "decoded (run %s or `just gen-signatures`)",
                        self.name,
                        self.path,
                        self.generator,
                    )
                return
            try:
                with gzip.open(self.path, "rb") as f:
                    doc = json.load(f)
            except Exception:
                logger.exception("Failed to load Win32 API signature database from %s", self.path)
                return
            if doc.get("format") != SUPPORTED_FORMAT:
                logger.warning(
                    "Win32 API signature database %s has format %r; expected %r. Regenerate it.",
                    self.path,
                    doc.get("format"),
                    SUPPORTED_FORMAT,
                )
                return
            self._functions = doc.get("functions", {})
            # Keep the raw declarations and their indices, so that iter_functions and lookup
            # share the FuncSig cache, and make a FuncSig only when a caller asks for it.
            for name, entries in self._functions.items():
                for idx, entry in enumerate(entries):
                    dll = normalize_dll(entry["dll"])
                    names = self._functions_by_dll.setdefault(dll, {})
                    names.setdefault(name, []).append((idx, entry))
            for dll, names in self._functions_by_dll.items():
                self._functions_by_dll[dll] = dict(sorted(names.items()))
            self._enums = doc.get("enums", {})
            self._structs = doc.get("structs", {})
            self._dll_aliases = doc.get("dll_aliases", {})
            self._name_prefixes = doc.get("name_prefixes", {})
            self.version = doc.get("version")
            self.commit = doc.get("commit")
            logger.debug(
                "Loaded %d API signatures (%s %s) from %s", len(self._functions), self.name, self.version, self.path
            )

    @property
    def available(self) -> bool:
        self._load()
        return bool(self._functions)

    def __len__(self) -> int:
        self._load()
        return len(self._functions)

    def canonical_dll(self, dll: str) -> str:
        dll = normalize_dll(dll)
        return self._dll_aliases.get(dll, dll)

    def iter_functions(self, dll: str, arch: str) -> Iterator[FuncSig]:
        """
        Yield the declarations of ``dll`` for ``arch``, in name order.

        Unlike ``lookup``, use only the declarations of this DLL, without DLL aliases or
        name prefixes. For each name, yield the first declaration for ``arch``, also if
        it has a skip marker.
        """
        self._load()
        dll = normalize_dll(dll)
        for name, entries in self._functions_by_dll.get(dll, {}).items():
            for idx, entry in entries:
                arches = entry.get("arch")
                if arches is not None and arch not in arches:
                    continue
                yield self._to_sig(name, idx, entry)
                break

    def lookup(self, dll: str, func: str, arch: str) -> FuncSig | None:
        self._load()
        if not self._functions:
            return None

        dll = self.canonical_dll(dll)
        names = [func] + [prefix + func for prefix in self._name_prefixes.get(dll, ())]

        candidates: list[tuple[str, int, dict]] = []
        for name in names:
            for idx, entry in enumerate(self._functions.get(name, ())):
                arches = entry.get("arch")
                if arches is not None and arch not in arches:
                    continue
                candidates.append((name, idx, entry))
        if not candidates:
            return None

        # Use the declaration of the DLL of the import. Else use the first declaration
        # of the name, because most names have only one.
        matching = [c for c in candidates if c[2]["dll"] == dll]
        name, idx, entry = (matching or candidates)[0]
        if not matching:
            logger.debug("signature for %s.%s taken from %s (name-only match)", dll, func, entry["dll"])
        return self._to_sig(name, idx, entry)

    def lookup_enum(self, name: str) -> EnumDef | None:
        self._load()
        enum = self._enum_cache.get(name)
        if enum is None:
            raw = self._enums.get(name)
            if raw is None:
                return None
            enum = EnumDef(name=name, values=tuple((v[0], v[1]) for v in raw.get("v", [])), flags=bool(raw.get("f")))
            self._enum_cache[name] = enum
        return enum

    def lookup_struct(self, name: str) -> StructDef | None:
        self._load()
        struct = self._struct_cache.get(name)
        if struct is None:
            raw = self._structs.get(name)
            if raw is None:
                return None
            sizes = raw.get("s") or [0, 0]
            struct = StructDef(
                name=name,
                size32=sizes[0],
                size64=sizes[-1],
                fields=tuple(FieldDef(f[0], f[1], f[2], f[3]) for f in raw.get("f", [])),
                is_union=bool(raw.get("u")),
            )
            self._struct_cache[name] = struct
        return struct

    def _to_sig(self, name: str, idx: int, entry: dict) -> FuncSig:
        key = (name, idx)
        sig = self._sig_cache.get(key)
        if sig is None:
            sig = FuncSig(
                name=name,
                dll=entry["dll"],
                ret=entry.get("ret", "p"),
                params=tuple(_to_param(p) for p in entry.get("params", [])),
                conv=entry.get("conv", CONV_STDCALL),
                variadic=bool(entry.get("variadic")),
                arch=tuple(entry["arch"]) if entry.get("arch") is not None else None,
                set_last_error=bool(entry.get("sle")),
                skip=entry.get("skip"),
                source=self.name,
            )
            self._sig_cache[key] = sig
        return sig


def _to_param(raw: list) -> ParamSig:
    buffer_len = None
    if len(raw) > 3 and isinstance(raw[3], dict) and raw[3]:
        how, n = next(iter(raw[3].items()))
        buffer_len = (how, int(n))
    return ParamSig(raw[0], raw[1], raw[2] if len(raw) > 2 else "", buffer_len)


class PhntSource(Win32MetadataSource):
    """
    Signatures generated from the phnt native API headers.

    It uses the table format of ``Win32MetadataSource``. ntdll exports all of its
    functions, and ntoskrnl also exports the ``Nt`` and ``Zw`` services. It has no
    struct layouts, so the other sources of the database give the structs of ``ps:``
    codes.
    """

    name = "phnt"
    default_path = DEFAULT_PHNT_PATH
    generator = "scripts/gen_phnt_signatures.py"

    _missing_warned = False


class SignatureDatabase:
    """An ordered list of signature sources. The first source with an answer wins."""

    def __init__(self, sources: list[SignatureSource] | None = None) -> None:
        if sources is None:
            sources = [Win32MetadataSource(), PhntSource()]
        self.sources: list[SignatureSource] = list(sources)
        self._functions: dict[tuple[str, str], dict[str, FuncSig]] = {}

    def add_source(self, source: SignatureSource, first: bool = False) -> None:
        self._functions.clear()
        if first:
            self.sources.insert(0, source)
        else:
            self.sources.append(source)

    @property
    def available(self) -> bool:
        return any(s.available for s in self.sources)

    def lookup(self, dll: str, func: str, arch: str) -> FuncSig | None:
        for source in self.sources:
            sig = source.lookup(dll, func, arch)
            if sig is not None:
                return sig
        return None

    def get_functions(self, dll: str, arch: str) -> dict[str, FuncSig]:
        """
        Get the declarations of one DLL, by name.

        The names come from ``iter_functions`` of each source, not from ``lookup`` or
        ``FuncSig.supports_emulation``. The first source that declares a name wins.
        """
        key = (normalize_dll(dll), arch)
        functions = self._functions.get(key)
        if functions is None:
            functions = {}
            for source in self.sources:
                for sig in source.iter_functions(dll, arch):
                    functions.setdefault(sig.name, sig)
            self._functions[key] = functions
        return functions

    def lookup_enum(self, name: str) -> EnumDef | None:
        for source in self.sources:
            enum = source.lookup_enum(name)
            if enum is not None:
                return enum
        return None

    def lookup_struct(self, name: str) -> StructDef | None:
        for source in self.sources:
            struct = source.lookup_struct(name)
            if struct is not None:
                return struct
        return None


_default_db: SignatureDatabase | None = None
_default_lock = threading.Lock()


def get_default_database() -> SignatureDatabase:
    """Get the shared database of the bundled win32metadata and phnt signatures."""
    global _default_db
    if _default_db is None:
        with _default_lock:
            if _default_db is None:
                _default_db = SignatureDatabase()
    return _default_db
