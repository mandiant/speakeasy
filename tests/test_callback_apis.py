"""
APIs that call a guest callback for each item, which malware uses to run shellcode without a direct call.

Each test runs x86 shellcode that calls the API with a recording callback. The callback stores its arguments and
the start of the memory at one pointer argument, and returns 1 or the value that the test gives for that call.
"""

import struct
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.api.usermode.user32 import WS_CHILD
from tests.handler_harness import get_win32_emu

CALLBACK = object()  # an API argument that is the address of the recording callback

CODE = 0x000
CALLBACK_CODE = 0x100
SLOT = 0x200
RESULT = 0x204
CURSOR = 0x208
COUNT = 0x20C
RETURNS = 0x300
DATA = 0x400
LOG = 0x800
SIZE = 0x2000
MAX_CALLS = 32


@dataclass(frozen=True)
class Call:
    args: tuple[int, ...]
    memory: bytes  # the start of the memory at the argument that the test selects


@dataclass(frozen=True)
class Result:
    value: int
    calls: list[Call]


def get_signed(value: int) -> int:
    return value - (1 << 32) if value & 0x80000000 else value


def get_string(data: bytes, width: int) -> str:
    text = data.decode("latin-1" if width == 1 else "utf-16le")
    return text.split("\0", 1)[0]


def get_callback_code(sc: int, argc: int, copy_arg: int | None, copy_dwords: int) -> bytes:
    """Build a stdcall callback of argc arguments that appends a record to the log and returns the next value."""
    record = 4 * (argc + copy_dwords)
    assert record < 0x80
    code = b"\x8b\x0d" + struct.pack("<I", sc + CURSOR)  # mov ecx, [cursor]
    for i in range(argc):
        code += b"\x8b\x44\x24" + bytes([4 + 4 * i])  # mov eax, [esp+4+4*i]
        code += b"\x89\x41" + bytes([4 * i])  # mov [ecx+4*i], eax
    if copy_arg is not None:
        code += b"\x8b\x54\x24" + bytes([4 + 4 * copy_arg])  # mov edx, [esp+4+4*copy_arg]
        for j in range(copy_dwords):
            code += b"\x8b\x42" + bytes([4 * j])  # mov eax, [edx+4*j]
            code += b"\x89\x41" + bytes([4 * (argc + j)])  # mov [ecx+4*(argc+j)], eax
    code += b"\x83\xc1" + bytes([record])  # add ecx, record
    code += b"\x89\x0d" + struct.pack("<I", sc + CURSOR)  # mov [cursor], ecx
    code += b"\xa1" + struct.pack("<I", sc + COUNT)  # mov eax, [count]
    code += b"\x8b\x04\x85" + struct.pack("<I", sc + RETURNS)  # mov eax, [returns+eax*4]
    code += b"\xff\x05" + struct.pack("<I", sc + COUNT)  # inc dword [count]
    code += b"\xc2" + struct.pack("<H", 4 * argc)  # ret 4*argc
    return code


@pytest.fixture
def shellcode_emu(base_config: dict[str, Any]) -> Iterator[Speakeasy]:
    se = Speakeasy(config=base_config)
    try:
        yield se
    finally:
        se.shutdown()


def load(se: Speakeasy) -> int:
    return se.load_shellcode(data=b"\xc3" * SIZE, arch="x86")


def run_api(
    se: Speakeasy,
    dll: str,
    name: str,
    args: Sequence[Any],
    argc: int,
    returns: dict[int, int] | None = None,
    copy_arg: int | None = None,
    copy_dwords: int = 0,
    sc: int | None = None,
) -> Result:
    """
    Call an API from x86 shellcode, with the recording callback of argc arguments in place of CALLBACK.

    A bytes argument goes in memory, and the API gets its address. ``returns`` gives the return value of a
    call by its index. ``sc`` is the shellcode of an earlier ``load``, else this function loads it.
    """
    if sc is None:
        sc = load(se)
    data = sc + DATA
    values = []
    for arg in args:
        if arg is CALLBACK:
            values.append(sc + CALLBACK_CODE)
        elif isinstance(arg, bytes):
            se.mem_write(data, arg)
            values.append(data)
            data += (len(arg) + 3) & ~3
        else:
            values.append(arg & 0xFFFFFFFF)
    code = b""
    for value in reversed(values):
        code += b"\x68" + struct.pack("<I", value)  # push value
    code += b"\xff\x15" + struct.pack("<I", sc + SLOT)  # call [slot]
    code += b"\xa3" + struct.pack("<I", sc + RESULT)  # mov [result], eax
    code += b"\xc3"
    assert data <= sc + LOG

    se.mem_write(sc + CODE, code)
    se.mem_write(sc + CALLBACK_CODE, get_callback_code(sc, argc, copy_arg, copy_dwords))
    se.mem_write(sc + SLOT, struct.pack("<I", se.emu.get_proc(dll, name)))
    se.mem_write(sc + RESULT, struct.pack("<I", 0xDEADBEEF))
    se.mem_write(sc + CURSOR, struct.pack("<II", sc + LOG, 0))
    table = [(returns or {}).get(i, 1) for i in range(MAX_CALLS)]
    se.mem_write(sc + RETURNS, struct.pack(f"<{MAX_CALLS}I", *table))
    se.run_shellcode(sc)

    (value,) = struct.unpack("<I", se.mem_read(sc + RESULT, 4))
    assert value != 0xDEADBEEF, "the shellcode did not return from the API"
    (count,) = struct.unpack("<I", se.mem_read(sc + COUNT, 4))
    record = 4 * (argc + copy_dwords)
    log = se.mem_read(sc + LOG, count * record)
    calls = []
    for i in range(count):
        entry = log[i * record : (i + 1) * record]
        calls.append(Call(struct.unpack(f"<{argc}I", entry[: 4 * argc]), entry[4 * argc :]))
    return Result(value, calls)


@pytest.mark.parametrize(
    "line, points",
    [
        # the call of the Mustang Panda loader that runs its shellcode
        ((10, 11, 12, 14), [(10, 11), (11, 12), (11, 13)]),
        ((3, 0, 0, 0), [(3, 0), (2, 0), (1, 0)]),
        ((-1, -1, -3, -2), [(-1, -1), (-2, -1)]),
        ((4, 4, 4, 4), []),
    ],
)
def test_line_dda_calls_the_procedure_for_each_point_except_the_end(
    shellcode_emu: Speakeasy, line: tuple[int, int, int, int], points: list[tuple[int, int]]
) -> None:
    result = run_api(shellcode_emu, "gdi32", "LineDDA", [*line, CALLBACK, 0x1234], argc=3)
    assert result.value == 1
    assert [(get_signed(x), get_signed(y)) for x, y, _ in (c.args for c in result.calls)] == points
    assert all(c.args[2] == 0x1234 for c in result.calls)


@pytest.mark.parametrize("name, width", [("EnumFontsA", 1), ("EnumFontsW", 2)])
def test_enum_fonts_calls_the_procedure_for_each_font(shellcode_emu: Speakeasy, name: str, width: int) -> None:
    face_offset = 28
    result = run_api(
        shellcode_emu, "gdi32", name, [0, 0, CALLBACK, 0x1234], argc=4, copy_arg=0, copy_dwords=(28 + 32 * width) // 4
    )
    assert result.value == 1
    assert [get_string(c.memory[face_offset:], width) for c in result.calls] == [
        "Arial",
        "Courier New",
        "Times New Roman",
    ]
    assert all(c.args[2:] == (4, 0x1234) for c in result.calls)  # TRUETYPE_FONTTYPE


def test_enum_fonts_selects_the_face_name_without_case(shellcode_emu: Speakeasy) -> None:
    result = run_api(
        shellcode_emu, "gdi32", "EnumFontsW", [0, "courier new\0".encode("utf-16le"), CALLBACK, 0], argc=4,
        copy_arg=0, copy_dwords=23,
    )  # fmt: skip
    assert [get_string(c.memory[28:], 2) for c in result.calls] == ["Courier New"]


def test_enum_fonts_without_a_font_of_the_face_name_returns_1(shellcode_emu: Speakeasy) -> None:
    result = run_api(shellcode_emu, "gdi32", "EnumFontFamiliesA", [0, b"Wingdings\0", CALLBACK, 0], argc=4)
    assert (result.value, result.calls) == (1, [])


def test_enum_fonts_returns_the_value_that_stops_it(shellcode_emu: Speakeasy) -> None:
    result = run_api(shellcode_emu, "gdi32", "EnumFontFamiliesW", [0, 0, CALLBACK, 0], argc=4, returns={1: 0})
    assert (result.value, len(result.calls)) == (0, 2)


@pytest.mark.parametrize("charset, count", [(1, 3), (0, 3), (128, 0)])  # DEFAULT, ANSI, SHIFTJIS
def test_enum_font_families_ex_selects_the_character_set(shellcode_emu: Speakeasy, charset: int, count: int) -> None:
    logfont = struct.pack("<5i8B", 0, 0, 0, 0, 0, 0, 0, 0, charset, 0, 0, 0, 0) + b"\0" * 64
    result = run_api(shellcode_emu, "gdi32", "EnumFontFamiliesExW", [0, logfont, CALLBACK, 0x1234, 0], argc=4)
    assert (result.value, len(result.calls)) == (1, count)


@pytest.mark.parametrize(
    "clip, rect",
    [
        (None, (0, 0, 1920, 1080)),
        ((100, 100, 5000, 200), (100, 100, 1920, 200)),
        ((2000, 0, 3000, 10), None),
    ],
)
def test_enum_display_monitors_calls_the_procedure_for_the_monitor_in_the_clip_rectangle(
    shellcode_emu: Speakeasy, clip: tuple[int, int, int, int] | None, rect: tuple[int, int, int, int] | None
) -> None:
    clip_arg = struct.pack("<4i", *clip) if clip else 0
    result = run_api(
        shellcode_emu, "user32", "EnumDisplayMonitors", [0, clip_arg, CALLBACK, 0x1234], argc=4, copy_arg=2,
        copy_dwords=4,
    )  # fmt: skip
    assert result.value == 1
    if rect is None:
        assert result.calls == []
        return
    (call,) = result.calls
    assert (call.args[0], call.args[1], call.args[3]) == (0x10001, 0, 0x1234)
    assert struct.unpack("<4i", call.memory) == rect


def test_enum_display_monitors_returns_false_when_the_procedure_does(shellcode_emu: Speakeasy) -> None:
    result = run_api(shellcode_emu, "user32", "EnumDisplayMonitors", [0, 0, CALLBACK, 0], argc=4, returns={0: 0})
    assert result.value == 0


def create_windows(se: Speakeasy) -> tuple[int, int, int, int]:
    """Create a top-level window with a child that has a child, and a second top-level window."""
    sessman = get_win32_emu(se).get_session_manager()
    top = sessman.create_window("top")
    child = sessman.create_window("child", style=WS_CHILD, parent=top)
    grandchild = sessman.create_window("grandchild", style=WS_CHILD, parent=child)
    other = sessman.create_window("other")
    return top, child, grandchild, other


def test_enum_child_windows_calls_the_procedure_for_each_descendant(shellcode_emu: Speakeasy) -> None:
    se = shellcode_emu
    sc = load(se)
    top, child, grandchild, _ = create_windows(se)
    result = run_api(se, "user32", "EnumChildWindows", [top, CALLBACK, 0x1234], argc=2, sc=sc)
    assert result.value == 1
    assert [c.args for c in result.calls] == [(child, 0x1234), (grandchild, 0x1234)]


def test_enum_child_windows_without_a_parent_calls_the_procedure_for_each_top_level_window(
    shellcode_emu: Speakeasy,
) -> None:
    se = shellcode_emu
    sc = load(se)
    top, child, grandchild, other = create_windows(se)
    handles = [c.args[0] for c in run_api(se, "user32", "EnumChildWindows", [0, CALLBACK, 0], argc=2, sc=sc).calls]
    assert top in handles and other in handles
    assert child not in handles and grandchild not in handles


def test_enum_child_windows_returns_false_without_a_child(shellcode_emu: Speakeasy) -> None:
    se = shellcode_emu
    sc = load(se)
    *_, other = create_windows(se)
    result = run_api(se, "user32", "EnumChildWindows", [other, CALLBACK, 0], argc=2, sc=sc)
    assert (result.value, result.calls) == (0, [])


def test_enum_child_windows_fails_for_an_unknown_window(shellcode_emu: Speakeasy) -> None:
    result = run_api(shellcode_emu, "user32", "EnumChildWindows", [0x1337, CALLBACK, 0], argc=2)
    assert (result.value, result.calls) == (0, [])
    assert shellcode_emu.emu.get_last_error() == 1400  # ERROR_INVALID_WINDOW_HANDLE


@pytest.mark.parametrize("name, width", [("EnumSystemLocalesA", 1), ("EnumSystemLocalesW", 2)])
@pytest.mark.parametrize("flags, locales", [(0, ["00000409"]), (2, ["00000409"]), (4, [])])
def test_enum_system_locales_gives_the_lcid_in_hex(
    shellcode_emu: Speakeasy, name: str, width: int, flags: int, locales: list[str]
) -> None:
    result = run_api(shellcode_emu, "kernel32", name, [CALLBACK, flags], argc=1, copy_arg=0, copy_dwords=5)
    assert result.value == 1
    assert [get_string(c.memory, width) for c in result.calls] == locales


def test_enum_system_locales_ex_gives_the_locale_name(shellcode_emu: Speakeasy) -> None:
    result = run_api(
        shellcode_emu, "kernel32", "EnumSystemLocalesEx", [CALLBACK, 0, 0x1234, 0], argc=3, copy_arg=0, copy_dwords=4
    )
    assert result.value == 1
    (call,) = result.calls
    assert get_string(call.memory, 2) == "en-US"
    assert call.args[1:] == (0x21, 0x1234)  # LOCALE_WINDOWS | LOCALE_SPECIFICDATA


def test_enum_system_locales_ex_fails_with_a_reserved_argument(shellcode_emu: Speakeasy) -> None:
    result = run_api(shellcode_emu, "kernel32", "EnumSystemLocalesEx", [CALLBACK, 0, 0, 1], argc=3)
    assert (result.value, result.calls) == (0, [])
    assert shellcode_emu.emu.get_last_error() == 87  # ERROR_INVALID_PARAMETER


def test_cert_enum_system_store_calls_the_procedure_for_each_store(shellcode_emu: Speakeasy) -> None:
    flags = 0x10000  # CERT_SYSTEM_STORE_CURRENT_USER
    result = run_api(
        shellcode_emu, "crypt32", "CertEnumSystemStore", [flags, 0, 0x1234, CALLBACK], argc=5, copy_arg=0,
        copy_dwords=4,
    )  # fmt: skip
    assert result.value == 1
    assert [get_string(c.memory, 2) for c in result.calls] == ["My", "Root", "Trust", "CA"]
    assert all((c.args[1], c.args[3], c.args[4]) == (flags, 0, 0x1234) for c in result.calls)


def test_cert_enum_system_store_returns_false_when_the_procedure_does(shellcode_emu: Speakeasy) -> None:
    result = run_api(shellcode_emu, "crypt32", "CertEnumSystemStore", [0x20000, 0, 0, CALLBACK], argc=5, returns={1: 0})
    assert (result.value, len(result.calls)) == (0, 2)


def test_cert_enum_system_store_fails_for_a_location_without_stores(shellcode_emu: Speakeasy) -> None:
    result = run_api(shellcode_emu, "crypt32", "CertEnumSystemStore", [0x60000, 0, 0, CALLBACK], argc=5)
    assert (result.value, result.calls) == (0, [])
