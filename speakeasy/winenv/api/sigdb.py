"""
Win32 API signature database.

Speakeasy implements a curated subset of the Windows API with hand-written
handlers (see ``speakeasy.winenv.api``). For everything else, this module
supplies just enough information about an import to keep emulation coherent:
how many argument slots the call consumed, which calling convention cleans
them up, the name and basic type of each parameter, and the return type.

Signatures come from pluggable :class:`SignatureSource` backends. The bundled
backend, :class:`Win32MetadataSource`, reads ``resources/win32/signatures.json.gz``
which is generated from Microsoft's win32metadata (via the ``deps/win32json``
submodule) by ``scripts/gen_win32_signatures.py``. That file is a build
artifact and may be absent from a source checkout; the database degrades to
"no signatures" and logs a single warning in that case.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

SUPPORTED_FORMAT = 2

DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "resources",
    "win32",
    "signatures.json.gz",
)

CONV_STDCALL = "stdcall"
CONV_CDECL = "cdecl"

ARCH_X86 = "x86"
ARCH_X64 = "x64"

# Byte size of each type code kind; None means pointer-sized. Kinds that carry
# a qualifier (``ps:NAME``, ``st:NAME:SIZE``) are handled in ParamSig.size().
# Pointer kinds may qualify their target: ``p:u32`` (DWORD*), ``a:u16``
# (WCHAR buffer), ``ps:NAME`` (struct pointer).
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


def normalize_dll(name: str) -> str:
    """Lower-case a module name and strip its extension: ``KERNEL32.dll`` -> ``kernel32``."""
    name = name.lower()
    for ext in (".dll", ".drv", ".exe", ".cpl", ".sys"):
        if name.endswith(ext):
            return name[: -len(ext)]
    return name


@dataclass(frozen=True)
class EnumDef:
    """A named set of integer constants, optionally combinable as flags."""

    name: str
    values: tuple[tuple[str, int], ...]
    flags: bool = False

    def decode(self, value: int) -> str:
        """
        Render ``value`` symbolically: the member name for an exact match, a
        ``|``-joined list of members for a flags enum, or hex when unknown.
        Any bits no member accounts for are appended as hex.
        """
        for name, member in self.values:
            if member == value:
                return name
        if not self.flags or value == 0:
            return hex(value)
        # Greedy decomposition, widest members first, so composite names
        # (FILE_GENERIC_READ) take precedence over their constituent bits.
        remaining = value
        parts = []
        for name, member in self._flags_by_width():
            if member and remaining & member == member:
                parts.append(name)
                remaining &= ~member
                if not remaining:
                    break
        if remaining or not parts:
            parts.append(hex(remaining))
        return "|".join(parts)

    def _flags_by_width(self) -> list[tuple[str, int]]:
        # High bits first among equally wide members; the stable sort keeps
        # declaration order for aliases of the same value, so the primary
        # name wins.
        return sorted(self.values, key=lambda nv: (-bin(nv[1]).count("1"), -nv[1]))


@dataclass(frozen=True)
class StructDef:
    """Layout summary of a struct or union."""

    name: str
    size32: int
    size64: int

    def size(self, ptr_size: int) -> int:
        return self.size64 if ptr_size == 8 else self.size32


@dataclass(frozen=True)
class ParamSig:
    """
    One parameter of an API signature.

    ``buffer_len`` describes how long the buffer a pointer parameter refers to
    is, when the declaration says: ``("n", i)`` parameter *i* holds the byte
    count, ``("c", i)`` parameter *i* holds the element count, ``("k", n)``
    a fixed count of *n* elements.
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
        """Name of the enum an integer parameter draws its value from, if any."""
        if self.kind in INT_KINDS:
            return self.qualifier
        return None

    @property
    def pointee(self) -> str | None:
        """Type code of what a pointer/buffer parameter points at, if known."""
        kind = self.kind
        if kind in ("p", "a"):
            return self.qualifier
        if kind == "s":
            return "u8"
        if kind == "S":
            return "u16"
        return None

    def elem_size(self, ptr_size: int) -> int | None:
        """Size in bytes of one pointed-at element, or None when opaque (void*)."""
        pointee = self.pointee
        if pointee is None:
            return None
        return ParamSig("", pointee).size(ptr_size)

    @property
    def is_in(self) -> bool:
        # Parameters without any direction annotation are treated as inputs.
        return "i" in self.flags or "o" not in self.flags

    @property
    def is_out(self) -> bool:
        return "o" in self.flags

    @property
    def is_optional(self) -> bool:
        return "?" in self.flags

    def size(self, ptr_size: int) -> int:
        """Size in bytes of the parameter's value for the given pointer size."""
        kind = self.kind
        if kind == "st":
            # st:NAME:SIZE or st:NAME:SIZE32/SIZE64
            size_spec = (self.qualifier or "").rsplit(":", 1)[-1]
            if "/" in size_spec:
                s32, s64 = size_spec.split("/", 1)
                return int(s64 if ptr_size == 8 else s32)
            return int(size_spec or 0)
        size = TYPE_SIZES.get(kind)
        if size is None:
            return ptr_size
        return size

    def slots(self, ptr_size: int) -> int:
        """Number of pointer-sized argument slots this parameter occupies."""
        if ptr_size == 8 and self.kind in AGGREGATE_KINDS:
            # Win64 passes aggregates that are not 1, 2, 4 or 8 bytes by
            # reference, so they always take exactly one slot.
            return 1
        size = self.size(ptr_size)
        return max(1, -(-size // ptr_size))

    def value_mask(self, ptr_size: int) -> int | None:
        """Mask to apply to a slot value to recover a narrower-than-slot parameter."""
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

    def slot_layout(self, ptr_size: int) -> list[int]:
        return [p.slots(ptr_size) for p in self.params]

    def slot_count(self, ptr_size: int) -> int:
        """Total argument slots consumed by a call (what speakeasy calls ``argc``)."""
        return sum(self.slot_layout(ptr_size))

    def values_from_slots(self, slots: list[int], ptr_size: int) -> list[int]:
        """
        Fold raw argument slots back into one integer per parameter. Multi-slot
        parameters (64-bit scalars and by-value structs on x86) are joined
        little-endian; narrower parameters are masked to their size.
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


def buffer_count(sig: FuncSig, index: int, values: list[int], ptr_size: int, read_uint) -> int | None:
    """
    Value of the count/size parameter ``index`` of a call with argument
    ``values``. Counts passed by pointer (``PDWORD pcbSize``) are read through
    ``read_uint(addr, size) -> int | None``; unknown shapes give None.
    """
    param = sig.params[index]
    value = values[index]
    kind = param.kind
    if kind in INT_KINDS or (kind == "p" and param.qualifier is None):
        return value
    if kind == "p" and param.qualifier is not None:
        # count lives behind a pointer; only meaningful if it is an input
        if not value or not param.is_in:
            return None
        size = param.elem_size(ptr_size) or ptr_size
        return read_uint(value, size)
    return None


def out_buffer_size(sig: FuncSig, index: int, values: list[int], ptr_size: int, lookup_struct, read_uint) -> int | None:
    """
    How many bytes an ``Out`` pointer parameter is declared to receive, or None
    when the signature does not say (``void*`` with no size, arrays with no
    count). Strings without a declared size count only their terminator.
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
        """True when this source has any signatures to offer."""

    @abstractmethod
    def lookup(self, dll: str, func: str, arch: str) -> FuncSig | None:
        """Return the signature for ``dll!func`` on ``arch`` ("x86" or "x64"), if known."""

    def lookup_enum(self, name: str) -> EnumDef | None:
        """Return the enum definition a type code qualifier refers to, if this source has it."""
        return None

    def lookup_struct(self, name: str) -> StructDef | None:
        """Return the layout of struct ``name`` (the qualifier of a ``ps:`` code), if known."""
        return None


class Win32MetadataSource(SignatureSource):
    """
    Signatures generated from win32metadata via win32json.

    Entries are indexed by function name first: win32metadata records the DLL
    that implements a function (``KERNEL32.dll!K32EnumProcesses``) rather than
    the forwarder a sample imports from (``psapi.dll!EnumProcesses``), so the
    DLL is used to disambiguate and to select name prefixes, not as a hard key.
    """

    name = "win32metadata"

    _missing_warned = False

    def __init__(self, path: str | None = None):
        self.path = path or DEFAULT_PATH
        self._lock = threading.Lock()
        self._loaded = False
        self._functions: dict[str, list[dict]] = {}
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
            if self._loaded:
                return
            self._loaded = True
            if not os.path.exists(self.path):
                if not Win32MetadataSource._missing_warned:
                    Win32MetadataSource._missing_warned = True
                    logger.warning(
                        "Win32 API signature database not found at %s; unhooked imports will not be "
                        "decoded (run scripts/gen_win32_signatures.py or `just gen-signatures`)",
                        self.path,
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
            self._enums = doc.get("enums", {})
            self._structs = doc.get("structs", {})
            self._dll_aliases = doc.get("dll_aliases", {})
            self._name_prefixes = doc.get("name_prefixes", {})
            self.version = doc.get("version")
            self.commit = doc.get("commit")
            logger.debug(
                "Loaded %d Win32 API signatures (win32metadata %s) from %s",
                len(self._functions),
                self.version,
                self.path,
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

    def lookup(self, dll: str, func: str, arch: str) -> FuncSig | None:
        self._load()
        if not self._functions:
            return None

        dll = self.canonical_dll(dll)
        names = [func] + [prefix + func for prefix in self._name_prefixes.get(dll, ())]

        candidates: list[tuple[str, int, dict]] = []
        for name in names:
            for idx, entry in enumerate(self._functions.get(name, ())):
                if entry.get("arch") and arch not in entry["arch"]:
                    continue
                candidates.append((name, idx, entry))
        if not candidates:
            return None

        # Prefer the declaration whose implementing DLL matches the import;
        # otherwise trust the (almost always unique) function name.
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
            struct = StructDef(name=name, size32=sizes[0], size64=sizes[-1])
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
                arch=tuple(entry["arch"]) if entry.get("arch") else None,
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


class SignatureDatabase:
    """Ordered collection of signature sources; the first source with an answer wins."""

    def __init__(self, sources: list[SignatureSource] | None = None):
        self.sources: list[SignatureSource] = list(sources) if sources is not None else [Win32MetadataSource()]

    def add_source(self, source: SignatureSource, first: bool = False) -> None:
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
    """Process-wide database backed by the bundled win32metadata signatures."""
    global _default_db
    if _default_db is None:
        with _default_lock:
            if _default_db is None:
                _default_db = SignatureDatabase()
    return _default_db
