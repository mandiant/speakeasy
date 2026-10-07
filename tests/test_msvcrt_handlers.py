import pytest

from speakeasy import Speakeasy
from tests.handler_harness import alloc, call


@pytest.mark.parametrize(
    "api, c, rv",
    [
        ("tolower", ord("A"), ord("a")),
        ("tolower", ord("Z"), ord("z")),
        ("tolower", ord("\\"), ord("\\")),
        ("tolower", ord("_"), ord("_")),
        ("tolower", ord("@"), ord("@")),
        ("tolower", 0xC9, 0xC9),
        ("toupper", ord("a"), ord("A")),
        ("toupper", ord("z"), ord("Z")),
        ("toupper", ord("`"), ord("`")),
        ("toupper", 0xE9, 0xE9),
    ],
)
def test_case_conversion_changes_only_ascii_letters(dll_emu: Speakeasy, api: str, c: int, rv: int) -> None:
    assert call(dll_emu, "msvcrt", api, [c])[0] == rv


@pytest.mark.parametrize("value, byte", [(0x41, b"A"), (0xFFFFFFFF, b"\xff"), (0x1E9, b"\xe9")])
def test_memset_fills_low_byte(dll_emu: Speakeasy, value: int, byte: bytes) -> None:
    buf = alloc(dll_emu, b"\xcc" * 5)
    assert call(dll_emu, "msvcrt", "memset", [buf, value, 4])[0] == buf
    assert dll_emu.mem_read(buf, 5) == byte * 4 + b"\xcc"


def test_time_writes_a_pointer_sized_time_t_on_x64(dll64_emu: Speakeasy) -> None:
    out = alloc(dll64_emu, b"\xcc" * 9)
    rv, _ = call(dll64_emu, "msvcrt", "time", [out])
    assert dll64_emu.mem_read(out, 9) == rv.to_bytes(8, "little") + b"\xcc"


@pytest.mark.parametrize("needle, offset", [("XYZ", 3), ("abc", 0), ("Q", None)])
def test_wcsstr_returns_pointer_to_match(dll_emu: Speakeasy, needle: str, offset: int | None) -> None:
    hay = alloc(dll_emu, "abcXYZ\0".encode("utf-16le"))
    rv, _ = call(dll_emu, "msvcrt", "wcsstr", [hay, alloc(dll_emu, f"{needle}\0".encode("utf-16le"))])
    assert rv == (0 if offset is None else hay + offset * 2)
