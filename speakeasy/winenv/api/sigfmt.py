"""
Text of the arguments of API calls with a known signature.

``ArgFormatter`` changes raw argument values into the text of the API trace. It
uses the types of a ``SignatureDatabase``: it reads strings from memory, shows
BOOLs as ``TRUE`` or ``FALSE``, shows the names of enum and flag values, and
shows a pointer to a known struct as ``{field: value, ...}``. It follows nested
pointers to a fixed depth. Each top-level argument also gets a kind that tells a
consumer how to read its text. Strings inside a struct have quotes, top-level
strings do not.

``ArgFormatter`` reads memory through callbacks, so it does not need the
emulator, and a test can give it a ``bytes`` buffer.
"""

from __future__ import annotations

import struct as _struct
import uuid
from collections.abc import Callable
from typing import NamedTuple

from speakeasy.profiler_events import ApiArg, ApiArgType
from speakeasy.winenv.api import sigdb
from speakeasy.winenv.codepage import decode_ansi

ReadMem = Callable[[int, int], bytes]
ReadXmm = Callable[[int], int]

# Structs that show as one value, not as their fields
_COUNTED_STRING_STRUCTS = {"UNICODE_STRING": 2, "STRING": 1, "ANSI_STRING": 1, "CUNICODE_STRING": 2}
_INTEGER_STRUCTS = ("LARGE_INTEGER", "ULARGE_INTEGER")


class RenderedArg(NamedTuple):
    """Text of one top-level argument and its kind, as listed for ``ApiArg.type``."""

    text: str
    kind: ApiArgType


def quote_string(text: str) -> str:
    """Quote a decoded string the way the API trace shows it."""
    return '"{}"'.format(text.replace("\n", "\\n"))


class ArgFormatter:
    """Renders argument values for one emulator (fixed pointer size and memory)."""

    MAX_STRING_CHARS = 0x1000
    # how many pointer dereferences to follow inside a struct (0 = top-level struct only)
    MAX_POINTER_DEPTH = 1
    MAX_ARRAY_ITEMS = 8
    MAX_BLOB_BYTES = 16
    MAX_RENDER_CHARS = 1024

    def __init__(
        self, db: sigdb.SignatureDatabase, ptr_size: int, read_mem: ReadMem, read_xmm: ReadXmm | None = None
    ) -> None:
        self.db: sigdb.SignatureDatabase = db
        self.ptr_size: int = ptr_size
        self.read_mem: ReadMem = read_mem
        self.read_xmm: ReadXmm | None = read_xmm

    # -- parameters --------------------------------------------------------

    def render_param(self, param: sigdb.ParamSig, value: int, index: int) -> RenderedArg:
        """Render parameter ``index`` of a call. ``value`` is the parameter value, made from its argument slots."""
        kind = param.kind
        if kind in sigdb.FLOAT_KINDS:
            if self.ptr_size == 8 and index < 4 and self.read_xmm is not None:
                # Win64 passes the first four floating point arguments in XMM0-3
                try:
                    value = self.read_xmm(index)
                except Exception:
                    return RenderedArg(hex(value), ApiArgType.INT)
            return RenderedArg(self._format_float(kind, value), ApiArgType.FLOAT)
        if kind == "g" and self.ptr_size == 4:
            return RenderedArg(self._format_guid(value.to_bytes(16, "little")), ApiArgType.GUID)
        if kind == "st" and not (self.ptr_size == 8 and param.size(8) not in (1, 2, 4, 8)):
            # A struct passed by value is in the argument slots
            return self._render_struct_bytes(_struct_key(param), value.to_bytes(param.size(self.ptr_size), "little"))
        if kind in ("ps", "st", "g", *sigdb.STRING_KINDS) and (not param.is_in or not value):
            # Show NULL and out-only pointers as addresses. An out-only buffer has no data before the call.
            return RenderedArg(hex(value), ApiArgType.PTR)
        if kind == "g":
            # Win64 passes a GUID by value as a pointer to a copy
            try:
                return RenderedArg(self._format_guid(self.read_mem(value, 16)), ApiArgType.GUID)
            except Exception:
                return RenderedArg(hex(value), ApiArgType.PTR)
        if kind in ("ps", "st"):
            return self._render_struct_ptr(_struct_key(param), value)
        if kind in sigdb.STRING_KINDS:
            try:
                text = self._read_string(value, 1 if kind == "s" else 2, self.MAX_STRING_CHARS)
            except Exception:
                return RenderedArg(hex(value), ApiArgType.PTR)
            return RenderedArg(self._truncate(text), ApiArgType.STR)
        if kind in sigdb.BOOL_KINDS and value in (0, 1):
            return RenderedArg("TRUE" if value else "FALSE", ApiArgType.BOOL)
        if kind == "h":
            return RenderedArg(hex(value), ApiArgType.HANDLE)
        if kind in ("p", "a"):
            return RenderedArg(hex(value), ApiArgType.PTR)
        enum = self.db.lookup_enum(param.enum) if param.enum else None
        if enum is not None:
            text = enum.decode(value)
            if text != hex(value):
                return RenderedArg(self._truncate(text), ApiArgType.FLAGS if enum.flags else ApiArgType.ENUM)
        return RenderedArg(hex(value), ApiArgType.INT)

    # -- scalars -----------------------------------------------------------

    def _format_scalar(self, code: str, value: int, depth: int) -> str:
        kind = code.split(":", 1)[0]
        qualifier = code.split(":", 1)[1] if ":" in code else None
        if kind in sigdb.STRING_KINDS:
            if not value:
                return hex(value)
            return self._format_string_ptr(value, 1 if kind == "s" else 2)
        if kind in sigdb.BOOL_KINDS:
            if value == 0:
                return "FALSE"
            if value == 1:
                return "TRUE"
            return hex(value)
        if kind in sigdb.FLOAT_KINDS:
            return self._format_float(kind, value)
        if kind == "ps":
            if value and depth < self.MAX_POINTER_DEPTH:
                return self._format_struct_ptr(qualifier, value, depth + 1)
            return hex(value)
        if kind in sigdb.INT_KINDS and qualifier:
            enum = self.db.lookup_enum(qualifier)
            if enum is not None:
                return enum.decode(value)
        return hex(value)

    def _format_float(self, kind: str, value: int) -> str:
        try:
            if kind == "f32":
                return repr(_struct.unpack("<f", (value & 0xFFFFFFFF).to_bytes(4, "little"))[0])
            return repr(_struct.unpack("<d", (value & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little"))[0])
        except Exception:
            return hex(value)

    def _format_string_ptr(self, addr: int, width: int, max_chars: int | None = None) -> str:
        try:
            return quote_string(self._read_string(addr, width, max_chars or self.MAX_STRING_CHARS))
        except Exception:
            return hex(addr)

    def _read_string(self, addr: int, width: int, max_chars: int) -> str:
        """Read a NUL-terminated string, shrinking the read size near unmapped memory."""
        chunk = 0x100 * width
        data = bytearray()
        while len(data) < max_chars * width:
            try:
                part = self.read_mem(addr + len(data), chunk)
            except Exception:
                if chunk > width:
                    chunk //= 2
                    continue
                if not data:
                    raise
                break
            data += part
            if _find_terminator(data, width) != -1:
                break
        return _decode(bytes(data), width)

    @staticmethod
    def _format_guid(raw: bytes) -> str:
        try:
            return f"{{{uuid.UUID(bytes_le=raw[:16])}}}"
        except Exception:
            return "0x" + raw.hex()

    # -- structs -----------------------------------------------------------

    def _render_struct_ptr(self, name: str | None, addr: int) -> RenderedArg:
        struct = self.db.lookup_struct(name) if name else None
        if struct is None or not struct.fields or struct.size(self.ptr_size) == 0:
            return RenderedArg(hex(addr), ApiArgType.PTR)
        try:
            data = self.read_mem(addr, struct.size(self.ptr_size))
        except Exception:
            return RenderedArg(hex(addr), ApiArgType.PTR)
        return self._render_struct_bytes(name, data, struct)

    def _render_struct_bytes(self, name: str | None, data: bytes, struct: sigdb.StructDef | None = None) -> RenderedArg:
        if struct is None:
            struct = self.db.lookup_struct(name) if name else None
        if struct is None or not struct.fields:
            return RenderedArg(self._truncate("0x" + data.hex()), ApiArgType.BYTES)
        special = self._render_special_struct(struct, data)
        if special is not None:
            return RenderedArg(self._truncate(special.text), special.kind)
        return RenderedArg(self._truncate(self._format_struct_bytes(name, data, 0, struct)), ApiArgType.STRUCT)

    def _format_struct_ptr(self, name: str | None, addr: int, depth: int) -> str:
        if not addr:
            return hex(addr)
        struct = self.db.lookup_struct(name) if name else None
        if struct is None or not struct.fields or struct.size(self.ptr_size) == 0:
            return hex(addr)
        try:
            data = self.read_mem(addr, struct.size(self.ptr_size))
        except Exception:
            return hex(addr)
        return self._format_struct_bytes(name, data, depth, struct)

    def _format_struct_bytes(
        self, name: str | None, data: bytes, depth: int, struct: sigdb.StructDef | None = None
    ) -> str:
        if struct is None:
            struct = self.db.lookup_struct(name) if name else None
        if struct is None or not struct.fields:
            return "0x" + data.hex()
        special = self._render_special_struct(struct, data)
        if special is not None:
            return quote_string(special.text) if special.kind == ApiArgType.STR else special.text
        parts = []
        for field in struct.fields:
            size = field.size(self.ptr_size)
            off = field.offset(self.ptr_size)
            raw = data[off : off + size]
            if len(raw) < size:
                parts.append(f"{field.name}: ?")
                continue
            parts.append(f"{field.name}: {self._format_field(field.code, raw, depth)}")
        return "{" + ", ".join(parts) + "}"

    def _render_special_struct(self, struct: sigdb.StructDef, data: bytes) -> RenderedArg | None:
        """Render a counted string as its text without quotes, and a LARGE_INTEGER as one number, else None."""
        name = struct.name
        if name in _INTEGER_STRUCTS and len(data) >= 8:
            return RenderedArg(hex(int.from_bytes(data[:8], "little")), ApiArgType.INT)
        width = _COUNTED_STRING_STRUCTS.get(name)
        if width is not None:
            fields = {f.name: f for f in struct.fields}
            if "Length" in fields and "Buffer" in fields:
                length = self._field_int(fields["Length"], data)
                buffer = self._field_int(fields["Buffer"], data)
                if buffer and length is not None:
                    try:
                        raw = self.read_mem(buffer, min(length, self.MAX_STRING_CHARS * width))
                        return RenderedArg(_decode(raw, width), ApiArgType.STR)
                    except Exception:
                        return None
        return None

    def _field_int(self, field: sigdb.FieldDef, data: bytes) -> int | None:
        off = field.offset(self.ptr_size)
        size = field.size(self.ptr_size)
        raw = data[off : off + size]
        if len(raw) < size:
            return None
        return int.from_bytes(raw, "little")

    def _format_field(self, code: str, raw: bytes, depth: int) -> str:
        kind = code.split(":", 1)[0]
        if kind == "g":
            return self._format_guid(raw)
        if kind == "st":
            return self._format_struct_bytes(code.split(":", 1)[1].rsplit(":", 1)[0], raw, depth)
        if kind == "arr":
            return self._format_array(code, raw, depth)
        return self._format_scalar(code, int.from_bytes(raw, "little"), depth)

    def _format_array(self, code: str, raw: bytes, depth: int) -> str:
        count_text, elem = code.split(":", 2)[1:]
        count = int(count_text)
        elem_kind = elem.split(":", 1)[0]
        if elem_kind == "u16":
            # WCHAR name[N]: NUL-terminated text within the array
            return quote_string(_decode(raw, 2))
        if elem_kind in ("u8", "i8"):
            text = _decode(raw, 1)
            if (len(text) < count or count == 0) and _printable(text):
                return quote_string(text)
            shown = raw[: self.MAX_BLOB_BYTES]
            return "0x" + shown.hex() + ("..." if len(raw) > len(shown) else "")
        esize = sigdb.ParamSig("", elem).size(self.ptr_size)
        if esize == 0:
            return "[]"
        items = [
            self._format_field(elem, raw[i * esize : (i + 1) * esize], depth)
            for i in range(min(count, self.MAX_ARRAY_ITEMS))
        ]
        if count > self.MAX_ARRAY_ITEMS:
            items.append("...")
        return "[" + ", ".join(items) + "]"

    def _truncate(self, text: str) -> str:
        if len(text) > self.MAX_RENDER_CHARS:
            return text[: self.MAX_RENDER_CHARS] + "..."
        return text


def get_call_args(
    sig: sigdb.FuncSig,
    ptr_size: int,
    rendered: list[RenderedArg],
    slots: list[int],
) -> list[ApiArg]:
    """
    Make the named arguments of a call from its rendered parameters.

    ``slots`` has the raw argument slots of the call, and gives the value of each parameter.

    Raises:
        ValueError: if the slots or the rendered parameters do not match the signature.
    """
    if len(slots) != sig.slot_count(ptr_size) or len(rendered) != len(sig.params):
        raise ValueError(f"{sig.name}: argument slots do not match the signature")
    values = sig.values_from_slots(slots, ptr_size)
    return [
        ApiArg(name=param.name, type=arg.kind, value=value, display=arg.text)
        for param, arg, value in zip(sig.params, rendered, values)
    ]


def get_slot_args(slots: list[int]) -> list[ApiArg]:
    """Get the arguments of a call without a usable signature, one for each argument slot."""
    return [ApiArg(type=ApiArgType.INT, value=slot, display=hex(slot)) for slot in slots]


def _struct_key(param: sigdb.ParamSig) -> str | None:
    """Get the struct name of a ps:NAME or st:NAME:SIZE parameter, or None."""
    qualifier = param.qualifier or ""
    if param.kind == "st":
        return qualifier.rsplit(":", 1)[0] or None
    return qualifier or None


def _find_terminator(raw: bytes | bytearray, width: int) -> int:
    """Offset of the (aligned) NUL terminator in ``raw``, or -1."""
    if width == 2:
        end = raw.find(b"\x00\x00")
        while end != -1 and end % 2:
            end = raw.find(b"\x00\x00", end + 1)
        return end
    return raw.find(b"\x00")


def _decode(raw: bytes, width: int) -> str:
    """Decode a NUL-terminated narrow/wide string prefix of ``raw``."""
    end = _find_terminator(raw, width)
    if end != -1:
        raw = raw[:end]
    if width == 2:
        if len(raw) % 2:
            raw = raw[:-1]
        return raw.decode("utf-16le", errors="replace")
    return decode_ansi(raw)


def _printable(text: str) -> bool:
    return all(32 <= ord(c) < 127 or c in "\t\r\n" for c in text)
