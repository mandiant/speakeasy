"""Unit tests for speakeasy.winenv.api.sigfmt against a fake memory."""

import struct

import pytest

from speakeasy.profiler_events import ApiArg
from speakeasy.winenv.api import sigdb, sigfmt


class _Memory:
    """Sparse byte-addressable memory; reads touching unmapped bytes raise."""

    def __init__(self) -> None:
        self.bytes: dict[int, int] = {}

    def put(self, addr: int, data: bytes) -> int:
        for i, b in enumerate(data):
            self.bytes[addr + i] = b
        return addr

    def read(self, addr: int, size: int) -> bytes:
        out = bytearray()
        for i in range(size):
            if addr + i not in self.bytes:
                raise MemoryError(hex(addr + i))
            out.append(self.bytes[addr + i])
        return bytes(out)


class _Source(sigdb.SignatureSource):
    name = "test"

    def __init__(self, structs: dict[str, sigdb.StructDef], enums: dict[str, sigdb.EnumDef]) -> None:
        self.structs = structs
        self.enums = enums

    @property
    def available(self) -> bool:
        return True

    def lookup(self, dll: str, func: str, arch: str) -> sigdb.FuncSig | None:
        return None

    def lookup_struct(self, name: str) -> sigdb.StructDef | None:
        return self.structs.get(name)

    def lookup_enum(self, name: str) -> sigdb.EnumDef | None:
        return self.enums.get(name)


def _fields(*specs: tuple[str, str, int, int]) -> tuple[sigdb.FieldDef, ...]:
    return tuple(sigdb.FieldDef(name, code, off32, off64) for name, code, off32, off64 in specs)


STRUCTS = {
    "INFO": sigdb.StructDef(
        "INFO",
        20,
        40,
        _fields(
            ("cb", "u32", 0, 0),
            ("lpTitle", "S", 4, 8),
            ("dwFlags", "u32:INFO_FLAGS", 8, 16),
            ("ok", "b", 12, 24),
            ("pNext", "ps:INFO", 16, 32),
        ),
    ),
    "UNICODE_STRING": sigdb.StructDef(
        "UNICODE_STRING", 8, 16, _fields(("Length", "u16", 0, 0), ("MaximumLength", "u16", 2, 2), ("Buffer", "S", 4, 8))
    ),
    "OBJECT_ATTRIBUTES": sigdb.StructDef(
        "OBJECT_ATTRIBUTES", 8, 16, _fields(("Length", "u32", 0, 0), ("ObjectName", "ps:UNICODE_STRING", 4, 8))
    ),
    "LARGE_INTEGER": sigdb.StructDef("LARGE_INTEGER", 8, 8, _fields(("QuadPart", "i64", 0, 0)), is_union=True),
    "FILETIME": sigdb.StructDef(
        "FILETIME", 8, 8, _fields(("dwLowDateTime", "u32", 0, 0), ("dwHighDateTime", "u32", 4, 4))
    ),
    "ARRAYS": sigdb.StructDef(
        "ARRAYS",
        56,
        56,
        _fields(
            ("wide", "arr:8:u16", 0, 0),
            ("narrow", "arr:8:u8", 16, 16),
            ("blob", "arr:8:u8", 24, 24),
            ("ints", "arr:5:u32", 32, 32),
            ("ft", "st:FILETIME:8", 52, 52),  # deliberately short: the struct is 56 bytes
        ),
    ),
    "OPAQUE": sigdb.StructDef("OPAQUE", 8, 8),
    "GUIDS": sigdb.StructDef("GUIDS", 16, 16, _fields(("id", "g", 0, 0))),
}
ENUMS = {
    "INFO_FLAGS": sigdb.EnumDef("INFO_FLAGS", (("F_ONE", 1), ("F_TWO", 2)), flags=True),
    "MODE": sigdb.EnumDef("MODE", (("M_OPEN", 3),)),
}


@pytest.fixture
def mem() -> _Memory:
    return _Memory()


def _formatter(mem: _Memory, ptr_size: int = 4, read_xmm: sigfmt.ReadXmm | None = None) -> sigfmt.ArgFormatter:
    return sigfmt.ArgFormatter(sigdb.SignatureDatabase([_Source(STRUCTS, ENUMS)]), ptr_size, mem.read, read_xmm)


def _wstr(text: str) -> bytes:
    return text.encode("utf-16le") + b"\x00\x00"


def _param(code: str, flags: str = "i") -> sigdb.ParamSig:
    return sigdb.ParamSig("arg", code, flags)


def test_struct_pointer_x86(mem: _Memory) -> None:
    title = mem.put(0x2000, _wstr("hello"))
    mem.put(0x1000, struct.pack("<IIIII", 20, title, 3, 1, 0))
    assert _formatter(mem).render_param(_param("ps:INFO"), 0x1000, 0) == (
        '{cb: 0x14, lpTitle: "hello", dwFlags: F_TWO|F_ONE, ok: TRUE, pNext: 0x0}',
        "struct",
    )


def test_struct_pointer_x64_uses_64_bit_offsets(mem: _Memory) -> None:
    title = mem.put(0x2000, _wstr("x"))
    mem.put(0x1000, struct.pack("<I4xQI4xI4xQ", 40, title, 1, 0, 0))
    assert _formatter(mem, 8).render_param(_param("ps:INFO"), 0x1000, 0) == (
        '{cb: 0x28, lpTitle: "x", dwFlags: F_ONE, ok: FALSE, pNext: 0x0}',
        "struct",
    )


def test_nested_pointer_depth_is_bounded(mem: _Memory) -> None:
    # a -> b -> c: b is expanded (one dereference), c is left as a pointer
    mem.put(0x3000, struct.pack("<IIIII", 20, 0, 0, 0, 0))
    mem.put(0x2000, struct.pack("<IIIII", 20, 0, 0, 0, 0x3000))
    mem.put(0x1000, struct.pack("<IIIII", 20, 0, 0, 0, 0x2000))
    text = _formatter(mem).render_param(_param("ps:INFO"), 0x1000, 0).text
    assert text == (
        "{cb: 0x14, lpTitle: 0x0, dwFlags: 0x0, ok: FALSE, "
        "pNext: {cb: 0x14, lpTitle: 0x0, dwFlags: 0x0, ok: FALSE, pNext: 0x3000}}"
    )


def test_counted_string_and_integer_structs(mem: _Memory) -> None:
    buf = mem.put(0x3000, "\\??\\C:\\x".encode("utf-16le") + b"junk")
    us = mem.put(0x2000, struct.pack("<HHI", 16, 20, buf))
    mem.put(0x1000, struct.pack("<II", 8, us))
    f = _formatter(mem)
    # quoted inside a struct, bare at the top level
    assert f.render_param(_param("ps:OBJECT_ATTRIBUTES"), 0x1000, 0) == (
        '{Length: 0x8, ObjectName: "\\??\\C:\\x"}',
        "struct",
    )
    assert f.render_param(_param("ps:UNICODE_STRING"), us, 0) == ("\\??\\C:\\x", "str")
    li = mem.put(0x4000, struct.pack("<q", -1))
    assert f.render_param(_param("ps:LARGE_INTEGER"), li, 0) == ("0xffffffffffffffff", "int")


def test_arrays(mem: _Memory) -> None:
    data = (
        _wstr("abc").ljust(16, b"\x00")
        + b"name\x00\x00\x00\x00"
        + bytes(range(1, 9))
        + struct.pack("<5I", 1, 2, 3, 4, 5)
        + b"\x01\x00\x00\x00"
    )
    mem.put(0x1000, data)
    assert _formatter(mem).render_param(_param("ps:ARRAYS"), 0x1000, 0).text == (
        '{wide: "abc", narrow: "name", blob: 0x0102030405060708, ints: [0x1, 0x2, 0x3, 0x4, 0x5], ft: ?}'
    )


def test_long_arrays_and_blobs_are_truncated(mem: _Memory) -> None:
    f = _formatter(mem)
    assert f._format_field("arr:10:u32", struct.pack("<10I", *range(10)), 0) == (
        "[0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, ...]"
    )
    assert f._format_field("arr:20:u8", bytes(range(0x80, 0x94)), 0) == "0x808182838485868788898a8b8c8d8e8f..."
    assert f._format_field("arr:0:u32", b"", 0) == "[]"


def test_unmapped_null_and_out_pointers(mem: _Memory) -> None:
    f = _formatter(mem)
    assert f.render_param(_param("ps:INFO"), 0, 0) == ("0x0", "ptr")
    assert f.render_param(_param("ps:INFO"), 0xDEAD0000, 0) == ("0xdead0000", "ptr")
    mem.put(0x1000, struct.pack("<IIIII", 20, 0, 0, 0, 0))
    # Out-only struct pointers are not decoded (nothing meaningful is there yet)
    assert f.render_param(_param("ps:INFO", "o"), 0x1000, 0) == ("0x1000", "ptr")
    # structs the generator could not resolve show as a pointer
    mem.put(0x2000, b"\x00" * 8)
    assert f.render_param(_param("ps:OPAQUE"), 0x2000, 0) == ("0x2000", "ptr")
    assert f.render_param(_param("ps:UNKNOWN_STRUCT"), 0x2000, 0) == ("0x2000", "ptr")
    # strings at the very end of mapped memory still decode
    end = mem.put(0x3000, "tail".encode("utf-16le"))
    assert f.render_param(_param("S"), end, 0) == ("tail", "str")
    assert f.render_param(_param("S", "o"), end, 0) == (hex(end), "ptr")
    assert f.render_param(_param("s"), 0, 0) == ("0x0", "ptr")
    assert f.render_param(_param("s"), 0xDEAD0000, 0) == ("0xdead0000", "ptr")


def test_scalars_enums_bools_floats(mem: _Memory) -> None:
    f = _formatter(mem)
    assert f.render_param(_param("u32:INFO_FLAGS"), 3, 0) == ("F_TWO|F_ONE", "flags")
    assert f.render_param(_param("u32:INFO_FLAGS"), 0x10, 0) == ("0x10", "int")
    assert f.render_param(_param("u32:MODE"), 3, 0) == ("M_OPEN", "enum")
    assert f.render_param(_param("u32:NOPE"), 3, 0) == ("0x3", "int")
    assert f.render_param(_param("b"), 1, 0) == ("TRUE", "bool")
    assert f.render_param(_param("B"), 0, 0) == ("FALSE", "bool")
    assert f.render_param(_param("b"), 7, 0) == ("0x7", "int")
    assert f.render_param(_param("h"), 0x44, 0) == ("0x44", "handle")
    assert f.render_param(_param("p"), 0x1000, 0) == ("0x1000", "ptr")
    assert f.render_param(_param("f64"), struct.unpack("<Q", struct.pack("<d", 1.5))[0], 0) == ("1.5", "float")
    assert f.render_param(_param("f32"), struct.unpack("<I", struct.pack("<f", 2.0))[0], 0) == ("2.0", "float")


def test_x64_floats_come_from_xmm(mem: _Memory) -> None:
    xmm = {1: struct.unpack("<Q", struct.pack("<d", 0.25))[0]}
    f = _formatter(mem, 8, read_xmm=lambda i: xmm[i])
    assert f.render_param(_param("f64"), 0, 1) == ("0.25", "float")
    # the fifth and later floats are on the stack
    assert f.render_param(_param("f64"), struct.unpack("<Q", struct.pack("<d", 4.0))[0], 4) == ("4.0", "float")


def test_guids_and_by_value_structs(mem: _Memory) -> None:
    f32 = _formatter(mem)
    guid = b"\x10\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01"
    # x86: 16 bytes in four slots, folded little-endian
    text = "{0d0e0f10-0b0c-090a-0807-060504030201}"
    assert f32.render_param(_param("g"), int.from_bytes(guid, "little"), 0) == (text, "guid")
    # x64: passed by reference
    addr = mem.put(0x1000, guid)
    assert _formatter(mem, 8).render_param(_param("g"), addr, 0) == (text, "guid")
    assert _formatter(mem, 8).render_param(_param("g"), 0xDEAD0000, 0) == ("0xdead0000", "ptr")
    mem.put(0x2000, guid)
    assert f32.render_param(_param("ps:GUIDS"), 0x2000, 0) == (f"{{id: {text}}}", "struct")
    # by-value FILETIME: x86 in two slots, x64 in one register
    ft = int.from_bytes(struct.pack("<II", 0x11, 0x22), "little")
    expected = ("{dwLowDateTime: 0x11, dwHighDateTime: 0x22}", "struct")
    assert f32.render_param(_param("st:FILETIME:8"), ft, 0) == expected
    assert _formatter(mem, 8).render_param(_param("st:FILETIME:8"), ft, 0) == expected
    # a by-value struct without a known layout is a hex dump
    assert f32.render_param(_param("st:OPAQUE:8"), ft, 0) == ("0x1100000022000000", "bytes")
    # 20-byte struct by value on x64 is passed by reference
    mem.put(0x3000, struct.pack("<I4xQI4xI4xQ", 40, 0, 0, 0, 0))
    arg = _formatter(mem, 8).render_param(_param("st:INFO:20/40"), 0x3000, 0)
    assert arg.kind == "struct" and arg.text.startswith("{cb: 0x28")


def test_render_is_truncated(mem: _Memory) -> None:
    f = _formatter(mem)
    f.MAX_RENDER_CHARS = 30
    mem.put(0x1000, struct.pack("<IIIII", 20, 0, 0, 0, 0))
    text = f.render_param(_param("ps:INFO"), 0x1000, 0).text
    assert text.endswith("...") and len(text) == 33


def test_quote_string() -> None:
    assert sigfmt.quote_string("a\nb") == '"a\\nb"'


def _sig(*codes: str) -> sigdb.FuncSig:
    params = tuple(sigdb.ParamSig(f"p{i}", code, "i") for i, code in enumerate(codes))
    return sigdb.FuncSig("Func", "test", "u32", params)


def test_call_args_of_signature_call() -> None:
    sig = _sig("S", "u32", "h")
    rendered = [
        sigfmt.RenderedArg("C:\\x", "str"),
        sigfmt.RenderedArg("F_ONE", "flags"),
        sigfmt.RenderedArg("0x44", "handle"),
    ]
    assert sigfmt.get_call_args(sig, 4, rendered, [0x1000, 1, 0x44]) == [
        ApiArg(name="p0", type="str", value=0x1000, display="C:\\x"),
        ApiArg(name="p1", type="flags", value=1, display="F_ONE"),
        ApiArg(name="p2", type="handle", value=0x44, display="0x44"),
    ]


def test_handler_values_replace_rendered_params() -> None:
    sig = _sig("S", "u32", "u32", "u32", "h", "p")
    before = [0x1000, 0x80000000, 3, 7, 0x44, 0x2000]
    after = ["C:\\x", "GENERIC_READ", 4, "SYMBOLIC", 0x48, 0x3000]
    rendered = [
        sigfmt.RenderedArg("C:\\x", "str"),
        sigfmt.RenderedArg("GENERIC_READ", "flags"),
        sigfmt.RenderedArg("0x3", "int"),
        sigfmt.RenderedArg("0x7", "int"),
        sigfmt.RenderedArg("0x44", "handle"),
        sigfmt.RenderedArg("0x2000", "ptr"),
    ]
    args = sigfmt.get_call_args(sig, 4, rendered, before, after)
    assert [a.display for a in args] == ["C:\\x", "GENERIC_READ", "0x4", "SYMBOLIC", "0x48", "0x3000"]
    # the handler's name for a flags value gives way to the signature's decoding
    assert [a.type for a in args] == ["str", "flags", "int", "text", "handle", "ptr"]
    # values are what the caller passed, not what the handler wrote back
    assert [a.value for a in args] == before


def test_handler_value_for_multi_slot_param() -> None:
    sig = _sig("u64", "u32")
    rendered = [sigfmt.RenderedArg("0x200000001", "int"), sigfmt.RenderedArg("0x3", "int")]
    args = sigfmt.get_call_args(sig, 4, rendered, [1, 2, 3], [1, "COND", 3])
    assert args == [
        ApiArg(name="p0", type="text", value=0x200000001, display="COND"),
        ApiArg(name="p1", type="int", value=3, display="0x3"),
    ]


def test_slot_args_of_call_without_signature() -> None:
    args = sigfmt.get_slot_args([0x1000, 2], ["C:\\x", 2, "extra"])
    assert args == [
        ApiArg(type="text", value=0x1000, display="C:\\x"),
        ApiArg(type="int", value=2, display="0x2"),
        ApiArg(type="text", display="extra"),
    ]


def test_call_args_require_matching_slots() -> None:
    rendered = [sigfmt.RenderedArg("0x1", "int"), sigfmt.RenderedArg("0x2", "int")]
    with pytest.raises(ValueError):
        sigfmt.get_call_args(_sig("u32", "u32"), 4, rendered, [1, 2], [1, 2, 3])
    with pytest.raises(ValueError):
        sigfmt.get_call_args(_sig("u32", "u32"), 4, rendered[:1], [1, 2])
