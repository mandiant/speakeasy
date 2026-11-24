"""
APIs that call a guest callback for each item, which malware uses to run shellcode without a direct call.

Each test calls the API as an x86 run, with a recording callback. The callback is a `ret` with a code hook that
records the arguments, reads data at one argument while it is valid, and sets the return value.
"""

import struct
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.api.usermode.user32 import WS_CHILD
from tests.handler_harness import get_win32_emu

CALLBACK = object()  # an API argument that is the address of the recording callback


@dataclass(frozen=True)
class Call:
    args: tuple[int, ...]
    data: Any  # the value that read returns at the call


@dataclass(frozen=True)
class Result:
    value: int
    calls: list[Call]


def get_signed(value: int) -> int:
    return value - (1 << 32) if value & 0x80000000 else value


@pytest.fixture
def shellcode_emu(config: dict[str, Any]) -> Iterator[Speakeasy]:
    se = Speakeasy(config=config)
    try:
        se.run_shellcode(se.load_shellcode(data=b"\xc3", arch="x86"))
        yield se
    finally:
        se.shutdown()


def run_api(
    se: Speakeasy,
    dll: str,
    name: str,
    args: Sequence[Any],
    argc: int,
    returns: dict[int, int] | None = None,
    read: Callable[[Speakeasy, tuple[int, ...]], Any] | None = None,
) -> Result:
    """
    Call an API with the recording callback of argc stdcall arguments in place of CALLBACK.

    run_api writes a bytes argument to memory and gives its address to the API. The callback returns
    ``returns[i]`` at call i, else 1. ``read`` gets the arguments of a call, and reads the data that is valid only
    during the call.
    """
    callback = se.mem_alloc(0x1000)
    se.mem_write(callback, b"\xc2" + struct.pack("<H", 4 * argc))  # ret 4*argc
    data = callback + 0x10
    values = []
    for arg in args:
        if arg is CALLBACK:
            values.append(callback)
        elif isinstance(arg, bytes):
            se.mem_write(data, arg)
            values.append(data)
            data += len(arg)
        else:
            values.append(arg & 0xFFFFFFFF)

    calls: list[Call] = []

    def record(emu: Any, address: int, size: int) -> None:
        argv = struct.unpack(f"<{argc}I", se.mem_read(se.get_stack_ptr() + 4, 4 * argc))
        se.reg_write("eax", (returns or {}).get(len(calls), 1))
        calls.append(Call(argv, read(se, argv) if read else None))

    se.add_code_hook(record, begin=callback, end=callback)
    se.call(se.emu.get_proc(dll, name), params=values)
    run = se.get_report().runs[-1]
    assert run.error is None
    return Result(run.return_value & 0xFFFFFFFF, calls)


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
def test_enum_fonts_selects_the_face_name_without_case(shellcode_emu: Speakeasy, name: str, width: int) -> None:
    face_name = "courier new\0".encode("utf-16le" if width == 2 else "ascii")
    result = run_api(
        shellcode_emu,
        "gdi32",
        name,
        [0, face_name, CALLBACK, 0x1234],
        argc=4,
        read=lambda se, args: se.read_mem_string(args[0] + 28, width),  # LOGFONT.lfFaceName
    )
    assert result.value == 1
    (call,) = result.calls
    assert call.data == "Courier New"
    assert call.args[2:] == (4, 0x1234)  # TRUETYPE_FONTTYPE


def test_enum_fonts_without_a_font_of_the_face_name_returns_1(shellcode_emu: Speakeasy) -> None:
    result = run_api(shellcode_emu, "gdi32", "EnumFontFamiliesA", [0, b"Wingdings\0", CALLBACK, 0], argc=4)
    assert (result.value, result.calls) == (1, [])


def test_enum_fonts_returns_the_value_that_stops_it(shellcode_emu: Speakeasy) -> None:
    result = run_api(shellcode_emu, "gdi32", "EnumFontFamiliesW", [0, 0, CALLBACK, 0], argc=4, returns={1: 0})
    assert (result.value, len(result.calls)) == (0, 2)


@pytest.mark.parametrize("charset, found", [(1, True), (0, True), (128, False)])  # DEFAULT, ANSI, SHIFTJIS
def test_enum_font_families_ex_selects_the_character_set(shellcode_emu: Speakeasy, charset: int, found: bool) -> None:
    logfont = struct.pack("<5i8B", 0, 0, 0, 0, 0, 0, 0, 0, charset, 0, 0, 0, 0) + b"\0" * 64
    result = run_api(shellcode_emu, "gdi32", "EnumFontFamiliesExW", [0, logfont, CALLBACK, 0x1234, 0], argc=4)
    assert result.value == 1
    assert bool(result.calls) == found


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
    result = run_api(
        shellcode_emu,
        "user32",
        "EnumDisplayMonitors",
        [0, struct.pack("<4i", *clip) if clip else 0, CALLBACK, 0x1234],
        argc=4,
        read=lambda se, args: struct.unpack("<4i", se.mem_read(args[2], 16)),
    )
    assert result.value == 1
    if rect is None:
        assert result.calls == []
        return
    (call,) = result.calls
    hmonitor, hdc, _, data = call.args
    assert hmonitor and (hdc, data) == (0, 0x1234)
    assert call.data == rect


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
    top, child, grandchild, _ = create_windows(shellcode_emu)
    result = run_api(shellcode_emu, "user32", "EnumChildWindows", [top, CALLBACK, 0x1234], argc=2)
    assert result.value == 1
    assert [c.args for c in result.calls] == [(child, 0x1234), (grandchild, 0x1234)]


def test_enum_child_windows_without_a_parent_calls_the_procedure_for_each_top_level_window(
    shellcode_emu: Speakeasy,
) -> None:
    top, child, grandchild, other = create_windows(shellcode_emu)
    result = run_api(shellcode_emu, "user32", "EnumChildWindows", [0, CALLBACK, 0], argc=2)
    handles = [c.args[0] for c in result.calls]
    assert top in handles and other in handles
    assert child not in handles and grandchild not in handles


def test_enum_child_windows_returns_false_without_a_child(shellcode_emu: Speakeasy) -> None:
    *_, other = create_windows(shellcode_emu)
    result = run_api(shellcode_emu, "user32", "EnumChildWindows", [other, CALLBACK, 0], argc=2)
    assert (result.value, result.calls) == (0, [])


def test_enum_child_windows_fails_for_an_unknown_window(shellcode_emu: Speakeasy) -> None:
    result = run_api(shellcode_emu, "user32", "EnumChildWindows", [0x1337, CALLBACK, 0], argc=2)
    assert (result.value, result.calls) == (0, [])
    assert shellcode_emu.emu.get_last_error() == 1400  # ERROR_INVALID_WINDOW_HANDLE


@pytest.mark.parametrize(
    "name, width, flags, locales",
    [
        ("EnumSystemLocalesA", 1, 2, ["00000409"]),  # LCID_SUPPORTED
        ("EnumSystemLocalesW", 2, 0, ["00000409"]),
        ("EnumSystemLocalesW", 2, 4, []),  # LCID_ALTERNATE_SORTS
    ],
)
def test_enum_system_locales_gives_the_lcid_in_hex(
    shellcode_emu: Speakeasy, name: str, width: int, flags: int, locales: list[str]
) -> None:
    result = run_api(
        shellcode_emu, "kernel32", name, [CALLBACK, flags], argc=1,
        read=lambda se, args: se.read_mem_string(args[0], width),
    )  # fmt: skip
    assert result.value == 1
    assert [c.data for c in result.calls] == locales


def test_enum_system_locales_ex_gives_the_locale_name(shellcode_emu: Speakeasy) -> None:
    result = run_api(
        shellcode_emu, "kernel32", "EnumSystemLocalesEx", [CALLBACK, 0, 0x1234, 0], argc=3,
        read=lambda se, args: se.read_mem_string(args[0], 2),
    )  # fmt: skip
    assert result.value == 1
    (call,) = result.calls
    assert call.data == "en-US"
    assert call.args[1:] == (0x21, 0x1234)  # LOCALE_WINDOWS | LOCALE_SPECIFICDATA


def test_enum_system_locales_ex_fails_with_a_reserved_argument(shellcode_emu: Speakeasy) -> None:
    result = run_api(shellcode_emu, "kernel32", "EnumSystemLocalesEx", [CALLBACK, 0, 0, 1], argc=3)
    assert (result.value, result.calls) == (0, [])
    assert shellcode_emu.emu.get_last_error() == 87  # ERROR_INVALID_PARAMETER


def test_cert_enum_system_store_calls_the_procedure_for_each_store(shellcode_emu: Speakeasy) -> None:
    flags = 0x10000  # CERT_SYSTEM_STORE_CURRENT_USER
    result = run_api(
        shellcode_emu, "crypt32", "CertEnumSystemStore", [flags, 0, 0x1234, CALLBACK], argc=5,
        read=lambda se, args: se.read_mem_string(args[0], 2),
    )  # fmt: skip
    assert result.value == 1
    assert {"My", "Root"} <= {c.data for c in result.calls}
    assert all((c.args[1], c.args[3], c.args[4]) == (flags, 0, 0x1234) for c in result.calls)


def test_cert_enum_system_store_returns_false_when_the_procedure_does(shellcode_emu: Speakeasy) -> None:
    result = run_api(shellcode_emu, "crypt32", "CertEnumSystemStore", [0x20000, 0, 0, CALLBACK], argc=5, returns={1: 0})
    assert (result.value, len(result.calls)) == (0, 2)


def test_cert_enum_system_store_fails_for_a_location_without_stores(shellcode_emu: Speakeasy) -> None:
    result = run_api(shellcode_emu, "crypt32", "CertEnumSystemStore", [0x60000, 0, 0, CALLBACK], argc=5)
    assert (result.value, result.calls) == (0, [])
    assert shellcode_emu.emu.get_last_error() == 2  # ERROR_FILE_NOT_FOUND
