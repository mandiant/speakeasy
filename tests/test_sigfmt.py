"""Unit tests for speakeasy.winenv.api.sigfmt against a fake memory."""

import struct

import pytest

from speakeasy.winenv.api import sigdb, sigfmt


class _Memory:
    """Sparse byte-addressable memory; reads touching unmapped bytes raise."""

    def __init__(self):
        self.bytes = {}

    def put(self, addr, data):
        for i, b in enumerate(data):
            self.bytes[addr + i] = b
        return addr

    def read(self, addr, size):
        out = bytearray()
        for i in range(size):
            if addr + i not in self.bytes:
                raise MemoryError(hex(addr + i))
            out.append(self.bytes[addr + i])
        return bytes(out)


class _Source(sigdb.SignatureSource):
    name = "test"

    def __init__(self, structs, enums):
        self.structs = structs
        self.enums = enums

    @property
    def available(self):
        return True

    def lookup(self, dll, func, arch):
        return None

    def lookup_struct(self, name):
        return self.structs.get(name)

    def lookup_enum(self, name):
        return self.enums.get(name)


def _fields(*specs):
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
ENUMS = {"INFO_FLAGS": sigdb.EnumDef("INFO_FLAGS", (("F_ONE", 1), ("F_TWO", 2)), flags=True)}


@pytest.fixture
def mem():
    return _Memory()


def _formatter(mem, ptr_size=4, read_xmm=None):
    return sigfmt.ArgFormatter(sigdb.SignatureDatabase([_Source(STRUCTS, ENUMS)]), ptr_size, mem.read, read_xmm)


def _wstr(text):
    return text.encode("utf-16le") + b"\x00\x00"


def _param(code, flags="i"):
    return sigdb.ParamSig("arg", code, flags)


def test_struct_pointer_x86(mem):
    title = mem.put(0x2000, _wstr("hello"))
    mem.put(0x1000, struct.pack("<IIIII", 20, title, 3, 1, 0))
    assert (
        _formatter(mem).format_param(_param("ps:INFO"), 0x1000, 0)
        == '{cb: 0x14, lpTitle: "hello", dwFlags: F_TWO|F_ONE, ok: TRUE, pNext: 0x0}'
    )


def test_struct_pointer_x64_uses_64_bit_offsets(mem):
    title = mem.put(0x2000, _wstr("x"))
    mem.put(0x1000, struct.pack("<I4xQI4xI4xQ", 40, title, 1, 0, 0))
    assert (
        _formatter(mem, 8).format_param(_param("ps:INFO"), 0x1000, 0)
        == '{cb: 0x28, lpTitle: "x", dwFlags: F_ONE, ok: FALSE, pNext: 0x0}'
    )


def test_nested_pointer_depth_is_bounded(mem):
    # a -> b -> c: b is expanded (one dereference), c is left as a pointer
    mem.put(0x3000, struct.pack("<IIIII", 20, 0, 0, 0, 0))
    mem.put(0x2000, struct.pack("<IIIII", 20, 0, 0, 0, 0x3000))
    mem.put(0x1000, struct.pack("<IIIII", 20, 0, 0, 0, 0x2000))
    text = _formatter(mem).format_param(_param("ps:INFO"), 0x1000, 0)
    assert text == (
        "{cb: 0x14, lpTitle: 0x0, dwFlags: 0x0, ok: FALSE, "
        "pNext: {cb: 0x14, lpTitle: 0x0, dwFlags: 0x0, ok: FALSE, pNext: 0x3000}}"
    )


def test_counted_string_and_integer_structs(mem):
    buf = mem.put(0x3000, "\\??\\C:\\x".encode("utf-16le") + b"junk")
    us = mem.put(0x2000, struct.pack("<HHI", 16, 20, buf))
    mem.put(0x1000, struct.pack("<II", 8, us))
    f = _formatter(mem)
    assert f.format_param(_param("ps:OBJECT_ATTRIBUTES"), 0x1000, 0) == '{Length: 0x8, ObjectName: "\\??\\C:\\x"}'
    assert f.format_param(_param("ps:UNICODE_STRING"), us, 0) == '"\\??\\C:\\x"'
    li = mem.put(0x4000, struct.pack("<q", -1))
    assert f.format_param(_param("ps:LARGE_INTEGER"), li, 0) == "0xffffffffffffffff"


def test_arrays(mem):
    data = (
        _wstr("abc").ljust(16, b"\x00")
        + b"name\x00\x00\x00\x00"
        + bytes(range(1, 9))
        + struct.pack("<5I", 1, 2, 3, 4, 5)
        + b"\x01\x00\x00\x00"
    )
    mem.put(0x1000, data)
    assert _formatter(mem).format_param(_param("ps:ARRAYS"), 0x1000, 0) == (
        '{wide: "abc", narrow: "name", blob: 0x0102030405060708, ints: [0x1, 0x2, 0x3, 0x4, 0x5], ft: ?}'
    )


def test_long_arrays_and_blobs_are_truncated(mem):
    f = _formatter(mem)
    assert f._format_field("arr:10:u32", struct.pack("<10I", *range(10)), 0) == (
        "[0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, ...]"
    )
    assert f._format_field("arr:20:u8", bytes(range(0x80, 0x94)), 0) == "0x808182838485868788898a8b8c8d8e8f..."
    assert f._format_field("arr:0:u32", b"", 0) == "[]"


def test_unmapped_null_and_out_pointers(mem):
    f = _formatter(mem)
    assert f.format_param(_param("ps:INFO"), 0, 0) == "0x0"
    assert f.format_param(_param("ps:INFO"), 0xDEAD0000, 0) == "0xdead0000"
    mem.put(0x1000, struct.pack("<IIIII", 20, 0, 0, 0, 0))
    # Out-only struct pointers are not decoded (nothing meaningful is there yet)
    assert f.format_param(_param("ps:INFO", "o"), 0x1000, 0) == "0x1000"
    # structs the generator could not resolve show as a pointer
    mem.put(0x2000, b"\x00" * 8)
    assert f.format_param(_param("ps:OPAQUE"), 0x2000, 0) == "0x2000"
    assert f.format_param(_param("ps:UNKNOWN_STRUCT"), 0x2000, 0) == "0x2000"
    # strings at the very end of mapped memory still decode
    end = mem.put(0x3000, "tail".encode("utf-16le"))
    assert f.format_param(_param("S"), end, 0) == '"tail"'
    assert f.format_param(_param("S", "o"), end, 0) == hex(end)


def test_scalars_enums_bools_floats(mem):
    f = _formatter(mem)
    assert f.format_param(_param("u32:INFO_FLAGS"), 3, 0) == "F_TWO|F_ONE"
    assert f.format_param(_param("u32:NOPE"), 3, 0) == "0x3"
    assert f.format_param(_param("b"), 1, 0) == "TRUE"
    assert f.format_param(_param("B"), 0, 0) == "FALSE"
    assert f.format_param(_param("b"), 7, 0) == "0x7"
    assert f.format_param(_param("h"), 0x44, 0) == "0x44"
    assert f.format_param(_param("f64"), struct.unpack("<Q", struct.pack("<d", 1.5))[0], 0) == "1.5"
    assert f.format_param(_param("f32"), struct.unpack("<I", struct.pack("<f", 2.0))[0], 0) == "2.0"


def test_x64_floats_come_from_xmm(mem):
    xmm = {1: struct.unpack("<Q", struct.pack("<d", 0.25))[0]}
    f = _formatter(mem, 8, read_xmm=lambda i: xmm[i])
    assert f.format_param(_param("f64"), 0, 1) == "0.25"
    # the fifth and later floats are on the stack
    assert f.format_param(_param("f64"), struct.unpack("<Q", struct.pack("<d", 4.0))[0], 4) == "4.0"


def test_guids_and_by_value_structs(mem):
    f32 = _formatter(mem)
    guid = b"\x10\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01"
    # x86: 16 bytes in four slots, folded little-endian
    assert f32.format_param(_param("g"), int.from_bytes(guid, "little"), 0) == "{0d0e0f10-0b0c-090a-0807-060504030201}"
    # x64: passed by reference
    addr = mem.put(0x1000, guid)
    assert _formatter(mem, 8).format_param(_param("g"), addr, 0) == "{0d0e0f10-0b0c-090a-0807-060504030201}"
    mem.put(0x2000, guid)
    assert f32.format_param(_param("ps:GUIDS"), 0x2000, 0) == "{id: {0d0e0f10-0b0c-090a-0807-060504030201}}"
    # by-value FILETIME: x86 in two slots, x64 in one register
    ft = struct.pack("<II", 0x11, 0x22)
    assert f32.format_param(_param("st:FILETIME:8"), int.from_bytes(ft, "little"), 0) == (
        "{dwLowDateTime: 0x11, dwHighDateTime: 0x22}"
    )
    assert _formatter(mem, 8).format_param(_param("st:FILETIME:8"), int.from_bytes(ft, "little"), 0) == (
        "{dwLowDateTime: 0x11, dwHighDateTime: 0x22}"
    )
    # 20-byte struct by value on x64 is passed by reference
    mem.put(0x3000, struct.pack("<I4xQI4xI4xQ", 40, 0, 0, 0, 0))
    assert _formatter(mem, 8).format_param(_param("st:INFO:20/40"), 0x3000, 0).startswith("{cb: 0x28")


def test_render_is_truncated(mem):
    f = _formatter(mem)
    f.MAX_RENDER_CHARS = 30
    mem.put(0x1000, struct.pack("<IIIII", 20, 0, 0, 0, 0))
    text = f.format_param(_param("ps:INFO"), 0x1000, 0)
    assert text.endswith("...") and len(text) == 33


def test_quote_string():
    assert sigfmt.quote_string("a\nb") == '"a\\nb"'
