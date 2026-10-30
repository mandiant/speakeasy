"""
User32 handlers return what Windows returns and write only what the caller owns.
"""

import struct
from typing import Any

import pefile
import pytest

from speakeasy import Speakeasy
from speakeasy.windows.win32 import Win32Emulator
from speakeasy.winenv import arch as e_arch
from speakeasy.winenv.defs.windows import user32 as u32defs
from tests.handler_harness import alloc, call, load_emu, start_process
from tests.pma_harness import PMA_DIR


@pytest.mark.parametrize("fixture, size", [("dll_emu", 28), ("dll64_emu", 48)])
def test_get_message_writes_one_msg(request: pytest.FixtureRequest, fixture: str, size: int) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    assert se.emu is not None
    start_process(se)
    call(se, "user32", "SetTimer", [0, 1, 10, 0])
    buf = alloc(se, b"\xcc" * 0x40)
    rv, _ = call(se, "user32", "GetMessageA", [buf, 0x1234, 0, 0])
    assert rv
    data = se.mem_read(buf, 0x40)
    assert data[size:] == b"\xcc" * (0x40 - size)
    assert int.from_bytes(data[se.emu.get_ptr_size() : se.emu.get_ptr_size() + 4], "little") == 0x113

    rv, _ = call(se, "user32", "DispatchMessageA", [buf])
    assert rv == 0


def get_timer_message(se: Speakeasy) -> tuple[int, int, int, int]:
    assert se.emu is not None
    ps = se.emu.get_ptr_size()
    buf = alloc(se, b"\x00" * 0x30)
    rv, _ = call(se, "user32", "GetMessageA", [buf, 0, 0, 0])
    assert rv
    hwnd, message, wparam, lparam = (int.from_bytes(se.mem_read(buf + i * ps, ps), "little") for i in range(4))
    assert message & 0xFFFFFFFF == 0x113
    call(se, "user32", "DispatchMessageA", [buf])
    return hwnd, wparam, lparam, se.emu.get_current_run().guest_callbacks[-1].function


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
def test_timer_messages_call_the_timer_proc(request: pytest.FixtureRequest, fixture: str) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    start_process(se)
    tid, _ = call(se, "user32", "SetTimer", [0, 0, 10, 0x401000])
    assert tid
    assert get_timer_message(se) == (0, tid, 0x401000, 0x401000)


def test_timer_messages_without_a_proc_go_to_the_window_proc(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    atom = register_class(dll_emu, b"mycls", 0x402000)
    hwnd = create_window_of_class(dll_emu, atom, 0x402000)
    assert call(dll_emu, "user32", "SetTimer", [hwnd, 7, 10, 0])[0] == 7
    assert get_timer_message(dll_emu) == (hwnd, 7, 0, 0x402000)


def test_timer_messages_rotate_and_stop_after_kill_timer(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    first, _ = call(dll_emu, "user32", "SetTimer", [0, 0, 10, 0x401000])
    second, _ = call(dll_emu, "user32", "SetTimer", [0, 0, 10, 0x401100])
    assert [get_timer_message(dll_emu)[1] for _ in range(3)] == [first, second, first]
    assert call(dll_emu, "user32", "KillTimer", [0, first])[0]
    assert [get_timer_message(dll_emu)[1] for _ in range(2)] == [second, second]
    call(dll_emu, "user32", "KillTimer", [0, second])
    assert not call(dll_emu, "user32", "GetMessageA", [alloc(dll_emu, b"\x00" * 0x30), 0, 0, 0])[0]


def register_class(se: Speakeasy, name: bytes | int, wndproc: int) -> int:
    wc = u32defs.WNDCLASSEX(se.get_ptr_size())
    wc.cbSize = wc.sizeof()
    wc.lpfnWndProc = wndproc
    wc.lpszClassName = name if isinstance(name, int) else alloc(se, name + b"\x00")
    atom, _ = call(se, "user32", "RegisterClassExA", [alloc(se, wc.get_bytes())])
    return atom


def test_dialog_box_param_takes_a_resource_id(dll_emu: Speakeasy) -> None:
    rv, _ = call(dll_emu, "user32", "DialogBoxParamA", [0, 101, 0, 0, 0])
    assert rv


# Bits of the return value of window_cases.c, one per case
DIALOG_CASES = {
    0x01: "DialogBoxParam sends WM_INITDIALOG with dwInitParam and returns the EndDialog result",
    0x02: "DialogBoxParam returns IDCANCEL when the procedure does not call EndDialog",
}

ENUM_WINDOWS_CASES = {
    0x04: "EnumWindows returns 0 after the first callback that returns FALSE",
    0x08: "EnumWindows calls the callback for the top-level window, but not for its child, and returns nonzero",
}

CREATE_WINDOW_CASES = {
    0x10: "CreateWindowEx sends WM_NCCREATE with a CREATESTRUCT of its arguments and fails when it returns FALSE",
    0x20: "CreateWindowEx sends WM_NCCREATE and WM_CREATE with a CREATESTRUCT and fails when WM_CREATE returns -1",
}


def get_failed_window_cases(config: dict, load_test_bin, run_test, cases: dict[int, str]) -> list[str]:
    ep = run_test(config, load_test_bin("window_cases_x86.exe.xz")).entry_points[0]
    assert ep.error is None
    return [case for bit, case in cases.items() if not ep.ret_val & bit]


def test_dialog_box_param_runs_the_dialog_procedure(config: dict, load_test_bin, run_test) -> None:
    assert not get_failed_window_cases(config, load_test_bin, run_test, DIALOG_CASES)


def test_register_class_takes_a_class_atom(dll_emu: Speakeasy) -> None:
    assert register_class(dll_emu, 0xC001, 0x401000)


def test_find_window_takes_a_class_atom(dll_emu: Speakeasy) -> None:
    rv, _ = call(dll_emu, "user32", "FindWindowA", [0xC001, 0])
    assert rv == 0


def create_window_of_class(se: Speakeasy, cls: int, wndproc: int) -> int:
    """Create a window of a class with a window procedure and return the HWND that its WM_NCCREATE gets."""
    assert se.emu is not None
    rv, _ = call(se, "user32", "CreateWindowExA", [0, cls, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    assert rv is None
    assert se.emu.get_current_run().guest_callbacks[-1].function == wndproc
    hwnd, message, _, _ = se.emu.get_func_argv(e_arch.CALL_CONV_STDCALL, 4)
    assert message == 0x81
    return hwnd


def test_update_window_with_an_unknown_class(dll_emu: Speakeasy) -> None:
    hwnd, _ = call(dll_emu, "user32", "CreateWindowExA", [0, alloc(dll_emu, b"EDIT\x00"), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    rv, _ = call(dll_emu, "user32", "UpdateWindow", [hwnd])
    assert rv


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
@pytest.mark.parametrize("name, cw", [("wvsprintfA", 1), ("wvsprintfW", 2)])
def test_wvsprintf_is_stdcall_and_writes_its_width(
    request: pytest.FixtureRequest, fixture: str, name: str, cw: int
) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    assert se.emu is not None and se.emu.api is not None
    _, (_, _, argc, conv, _) = se.emu.get_api_handler("user32", name)
    assert (argc, conv) == (3, e_arch.CALL_CONV_STDCALL)

    enc = "utf-8" if cw == 1 else "utf-16le"
    ps = se.emu.get_ptr_size()
    fmt = alloc(se, "x%dy\0".encode(enc))
    va = alloc(se, (7).to_bytes(ps, "little"))
    buf = alloc(se, b"\xcc" * 16)
    rv, _ = call(se, "user32", name, [buf, fmt, va])
    assert rv == 3
    assert se.mem_read(buf, 4 * cw) == "x7y\0".encode(enc)


@pytest.mark.parametrize(
    "name, fmt, arg, expected",
    [
        ("wsprintfW", "%s!", "abc", "abc!"),
        ("wsprintfW", "%ls!", "abc", "abc!"),
        ("wsprintfW", "%S!", b"abc", "abc!"),
        ("wsprintfW", "%hs!", b"abc", "abc!"),
        ("wsprintfA", "%s!", b"abc", "abc!"),
        ("wsprintfA", "%S!", "abc", "abc!"),
        ("wvsprintfW", "%s!", "abc", "abc!"),
        ("wvsprintfW", "%S!", b"abc", "abc!"),
    ],
)
def test_wsprintf_string_width(dll_emu: Speakeasy, name: str, fmt: str, arg: str | bytes, expected: str) -> None:
    enc = "utf-16le" if name.endswith("W") else "utf-8"
    sarg = alloc(dll_emu, arg + b"\x00" if isinstance(arg, bytes) else (arg + "\0").encode("utf-16le"))
    pfmt = alloc(dll_emu, (fmt + "\0").encode(enc))
    buf = alloc(dll_emu, b"\xcc" * 32)
    if name.startswith("wv"):
        argv = [buf, pfmt, alloc(dll_emu, sarg.to_bytes(4, "little"))]
    else:
        argv = [buf, pfmt, sarg]
    rv, _ = call(dll_emu, "user32", name, argv)
    assert rv == len(expected)
    data = (expected + "\0").encode(enc)
    assert dll_emu.mem_read(buf, len(data)) == data


@pytest.mark.parametrize("name, enc", [("wsprintfA", "utf-8"), ("wsprintfW", "utf-16le")])
def test_wsprintf_writes_one_percent_for_escape_without_arguments(dll_emu: Speakeasy, name: str, enc: str) -> None:
    buf = alloc(dll_emu, b"\xcc" * 16)
    fmt = alloc(dll_emu, "100%%\0".encode(enc))
    assert call(dll_emu, "user32", name, [buf, fmt])[0] == 4
    assert dll_emu.mem_read(buf, len("100%\0".encode(enc))) == "100%\0".encode(enc)


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
def test_create_dialog_indirect_param_passes_init_param_in_lparam(request: pytest.FixtureRequest, fixture: str) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    assert se.emu is not None
    parent = 0x1234
    rv, _ = call(se, "user32", "CreateDialogIndirectParamA", [0, alloc(se, b"\x00" * 32), parent, 0x401000, 0xBEEF])
    assert se.emu.get_pc() == 0x401000
    hdlg, msg, wparam, lparam = se.emu.get_func_argv(e_arch.CALL_CONV_STDCALL, 4)
    assert (hdlg, msg, wparam, lparam) == (rv, 0x110, 0, 0xBEEF)
    assert hdlg != parent


def test_oem_to_char_copies_the_string_and_its_nul(dll_emu: Speakeasy) -> None:
    src = alloc(dll_emu, b"hi\x80\x00")
    dst = alloc(dll_emu, b"\xcc" * 300)
    rv, _ = call(dll_emu, "user32", "OemToCharA", [src, dst])
    assert rv == 1
    assert dll_emu.mem_read(dst, 8) == b"hi\x80\x00" + b"\xcc" * 4


def test_oem_to_char_maps_a_page_for_an_unmapped_buffer(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    src = alloc(dll_emu, b"hi\x00")
    dst = 0x5FFF0010
    assert not dll_emu.emu.is_address_valid(dst)
    call(dll_emu, "user32", "OemToCharA", [src, dst])
    assert dll_emu.mem_read(dst, 3) == b"hi\x00"


def test_get_object_maps_a_page_for_an_unmapped_buffer(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    pv = 0x5FFF0010
    rv, _ = call(dll_emu, "gdi32", "GetObjectA", [0x1234, 24, pv])
    assert rv == 24
    assert dll_emu.mem_read(pv, 24) == b"\x00" * 24


@pytest.mark.parametrize(
    "name, cw, maxc, expected",
    [
        ("GetWindowTextA", 1, 5, "spea"),
        ("GetWindowTextW", 2, 5, "spea"),
        ("GetWindowTextA", 1, 64, "speakeasy window"),
        ("GetWindowTextA", 1, 1, ""),
    ],
)
def test_get_window_text_fits_the_buffer(dll_emu: Speakeasy, name: str, cw: int, maxc: int, expected: str) -> None:
    enc = "utf-8" if cw == 1 else "utf-16le"
    buf = alloc(dll_emu, b"\xcc" * 160)
    rv, _ = call(dll_emu, "user32", name, [0x1234, buf, maxc])
    assert rv == len(expected)
    data = (expected + "\0").encode(enc)
    assert dll_emu.mem_read(buf, len(data) + cw) == data + b"\xcc" * cw


def test_get_window_text_with_no_room(dll_emu: Speakeasy) -> None:
    buf = alloc(dll_emu, b"\xcc" * 4)
    rv, _ = call(dll_emu, "user32", "GetWindowTextA", [0x1234, buf, 0])
    assert rv == 0
    assert dll_emu.mem_read(buf, 4) == b"\xcc" * 4


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
def test_get_keyboard_layout_list_writes_one_hkl(request: pytest.FixtureRequest, fixture: str) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    assert se.emu is not None
    ps = se.emu.get_ptr_size()
    n, _ = call(se, "user32", "GetKeyboardLayoutList", [0, 0])
    assert n == 1
    buf = alloc(se, b"\xcc" * 16)
    rv, _ = call(se, "user32", "GetKeyboardLayoutList", [n, buf])
    assert rv == 1
    assert se.mem_read(buf, 16) == (0x04090409).to_bytes(ps, "little") + b"\xcc" * (16 - ps)


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
def test_get_raw_input_device_list(request: pytest.FixtureRequest, fixture: str) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    assert isinstance(se.emu, Win32Emulator)
    start_process(se)
    ps = se.emu.get_ptr_size()
    cb = 2 * ps
    pnum = alloc(se, b"\xcc" * 4)
    rv, _ = call(se, "user32", "GetRawInputDeviceList", [0, pnum, cb])
    assert rv == 0
    n = int.from_bytes(se.mem_read(pnum, 4), "little")
    assert n > 0

    se.mem_write(pnum, (n - 1).to_bytes(4, "little"))
    buf = alloc(se, b"\xcc" * (cb * (n + 1)))
    rv, _ = call(se, "user32", "GetRawInputDeviceList", [buf, pnum, cb])
    assert rv == 0xFFFFFFFF
    assert se.emu.get_last_error() == 122
    assert int.from_bytes(se.mem_read(pnum, 4), "little") == n
    assert se.mem_read(buf, cb) == b"\xcc" * cb

    rv, _ = call(se, "user32", "GetRawInputDeviceList", [buf, pnum, cb])
    assert rv == n
    data = se.mem_read(buf, cb * (n + 1))
    entries = [data[i * cb : (i + 1) * cb] for i in range(n)]
    handles = {int.from_bytes(e[:ps], "little") for e in entries}
    assert len(handles) == n and 0 not in handles
    assert all(int.from_bytes(e[ps : ps + 4], "little") in (0, 1, 2) for e in entries)
    assert data[cb * n :] == b"\xcc" * cb


@pytest.mark.parametrize(
    "name, data, cch, expected",
    [
        ("CharUpperBuffA", b"abcdef\x00", 3, b"ABCdef\x00"),
        ("CharUpperBuffA", b"a\xe4b\x00", 3, b"A\xe4B\x00"),
        ("CharUpperBuffA", b"abc\x00", 0, b"abc\x00"),
        ("CharLowerBuffA", b"ABC\x00DE\x00", 6, b"abc\x00de\x00"),
        ("CharUpperBuffW", "abßcd\0".encode("utf-16le"), 4, "ABßCd\0".encode("utf-16le")),
        ("CharLowerBuffW", "ABİCD\0".encode("utf-16le"), 4, "abİcD\0".encode("utf-16le")),
    ],
)
def test_char_case_buff_maps_exactly_cch_chars(
    dll_emu: Speakeasy, name: str, data: bytes, cch: int, expected: bytes
) -> None:
    buf = alloc(dll_emu, data + b"\xcc" * 4)
    rv, _ = call(dll_emu, "user32", name, [buf, cch])
    assert rv == cch
    assert dll_emu.mem_read(buf, len(data) + 4) == expected + b"\xcc" * 4


@pytest.mark.parametrize(
    "name, ch, expected",
    [
        ("CharUpperA", ord("a"), ord("A")),
        ("CharUpperA", 0xE4, 0xE4),
        ("CharLowerA", 0xC4, 0xC4),
        ("CharUpperW", 0xE4, 0xC4),
        ("CharUpperW", 0xDF, 0xDF),
        ("CharLowerW", 0x130, 0x130),
    ],
)
def test_char_case_of_a_single_char(dll_emu: Speakeasy, name: str, ch: int, expected: int) -> None:
    rv, _ = call(dll_emu, "user32", name, [ch])
    assert rv == expected


@pytest.mark.parametrize(
    "name, data, expected",
    [
        ("CharUpperA", b"a\xe4b\x00", b"A\xe4B\x00"),
        ("CharUpperW", "aßb\0".encode("utf-16le"), "AßB\0".encode("utf-16le")),
        ("CharLowerW", b"\x00\x00", b"\x00\x00"),
    ],
)
def test_char_case_of_a_string_keeps_its_length(dll_emu: Speakeasy, name: str, data: bytes, expected: bytes) -> None:
    buf = alloc(dll_emu, data + b"\xcc" * 4)
    rv, _ = call(dll_emu, "user32", name, [buf])
    assert rv == buf
    assert dll_emu.mem_read(buf, len(data) + 4) == expected + b"\xcc" * 4


@pytest.mark.parametrize("name, cw", [("CharNextA", 1), ("CharNextW", 2)])
def test_char_next_stops_at_the_nul(dll_emu: Speakeasy, name: str, cw: int) -> None:
    s = alloc(dll_emu, "a\0".encode("utf-8" if cw == 1 else "utf-16le"))
    rv, _ = call(dll_emu, "user32", name, [s])
    assert rv == s + cw
    rv, _ = call(dll_emu, "user32", name, [rv])
    assert rv == s + cw


def bitmap_info(width: int, height: int, bit_count: int) -> bytes:
    return struct.pack("<IiiHHIIiiII", 40, width, height, 1, bit_count, 0, 0, 0, 0, 0, 0)


@pytest.mark.parametrize(
    "width, height, bit_count, size",
    [(16, 16, 24, 48 * 16), (3, -2, 24, 12 * 2), (10, 1, 1, 4), (5, 4, 32, 80)],
)
def test_create_dib_section_returns_zeroed_bits(
    dll_emu: Speakeasy, width: int, height: int, bit_count: int, size: int
) -> None:
    bmi = alloc(dll_emu, bitmap_info(width, height, bit_count))
    ppv = alloc(dll_emu, b"\xcc" * 4)
    hbm, _ = call(dll_emu, "gdi32", "CreateDIBSection", [0, bmi, 0, ppv, 0, 0])
    assert hbm
    bits = struct.unpack("<I", dll_emu.mem_read(ppv, 4))[0]
    assert dll_emu.mem_read(bits, size) == b"\x00" * size


def test_create_compatible_dc_returns_a_new_memory_dc(dll_emu: Speakeasy) -> None:
    first, _ = call(dll_emu, "gdi32", "CreateCompatibleDC", [0])
    second, _ = call(dll_emu, "gdi32", "CreateCompatibleDC", [first])
    assert first
    assert second
    assert first != second


@pytest.mark.parametrize(
    "width, height, bit_count", [(0, 16, 24), (16, 0, 24), (16, 16, 7), (0x7FFFFFFF, 0x7FFFFFFF, 32)]
)
def test_create_dib_section_rejects_a_bad_header(dll_emu: Speakeasy, width: int, height: int, bit_count: int) -> None:
    bmi = alloc(dll_emu, bitmap_info(width, height, bit_count))
    ppv = alloc(dll_emu, b"\xcc" * 4)
    hbm, _ = call(dll_emu, "gdi32", "CreateDIBSection", [0, bmi, 0, ppv, 0, 0])
    assert hbm == 0
    assert dll_emu.mem_read(ppv, 4) == b"\x00" * 4


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
def test_window_from_point_returns_the_desktop_window(request: pytest.FixtureRequest, fixture: str) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    desktop, _ = call(se, "user32", "GetDesktopWindow", [])
    assert call(se, "user32", "WindowFromPoint", [10, 20])[0] == desktop


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
def test_register_class_without_ex_registers_the_window_procedure(request: pytest.FixtureRequest, fixture: str) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    assert se.emu is not None
    name = "Edp Notify".encode("utf-16le") + b"\x00\x00"
    wc = u32defs.WNDCLASS(se.get_ptr_size())
    wc.lpfnWndProc = 0x401000
    wc.lpszClassName = alloc(se, name)
    atom, _ = call(se, "user32", "RegisterClassW", [alloc(se, wc.get_bytes())])
    assert atom
    rv, _ = call(se, "user32", "CreateWindowExW", [0, alloc(se, name), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    assert rv is None
    assert [cb.function for cb in se.emu.get_current_run().guest_callbacks] == [0x401000]


WM_CREATE = 0x1
WM_NCCREATE = 0x81
WS_POPUP = 0x80000000
WS_CHILD = 0x40000000


def create_window(se: Speakeasy, style: int = 0, parent: int = 0) -> int:
    hwnd, _ = call(se, "user32", "CreateWindowExA", [0, 0, 0, style, 0, 0, 0, 0, parent, 0, 0, 0])
    return hwnd


@pytest.mark.parametrize("fixture, suffix", [("dll_emu", ""), ("dll64_emu", ""), ("dll64_emu", "Ptr")])
def test_set_window_long_returns_the_previous_value(request: pytest.FixtureRequest, fixture: str, suffix: str) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    start_process(se)
    hwnd = create_window(se, WS_POPUP)
    get, set_ = f"GetWindowLong{suffix}W", f"SetWindowLong{suffix}W"
    assert call(se, "user32", get, [hwnd, 0])[0] == 0
    assert call(se, "user32", set_, [hwnd, 0, 0x1234])[0] == 0
    assert call(se, "user32", set_, [hwnd, 0, 0x5678])[0] == 0x1234
    assert call(se, "user32", get, [hwnd, 0])[0] == 0x5678
    assert call(se, "user32", get, [hwnd, 0xFFFFFFF0])[0] == WS_POPUP


def test_set_window_long_wndproc_replaces_the_class_procedure(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    start_process(dll_emu)
    hwnd = create_window_of_class(dll_emu, register_class(dll_emu, b"mycls", 0x401000), 0x401000)
    assert call(dll_emu, "user32", "GetWindowLongA", [hwnd, 0xFFFFFFFC])[0] == 0x401000
    assert call(dll_emu, "user32", "SetWindowLongA", [hwnd, 0xFFFFFFFC, 0x402000])[0] == 0x401000
    assert call(dll_emu, "user32", "GetWindowLongA", [hwnd, 0xFFFFFFFC])[0] == 0x402000
    msg = u32defs.MSG(dll_emu.get_ptr_size())
    msg.hwnd = hwnd
    msg.message = 0x10
    call(dll_emu, "user32", "DispatchMessageA", [alloc(dll_emu, msg.get_bytes())])
    assert dll_emu.emu.get_current_run().guest_callbacks[-1].function == 0x402000


def test_get_parent_ends_at_a_top_level_window(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    start_process(dll_emu)
    desktop, _ = call(dll_emu, "user32", "GetDesktopWindow", [])
    top = create_window(dll_emu)
    child = create_window(dll_emu, WS_CHILD, top)
    owned = create_window(dll_emu, WS_POPUP, top)
    owned_overlapped = create_window(dll_emu, 0, top)
    assert call(dll_emu, "user32", "GetParent", [child])[0] == top
    assert call(dll_emu, "user32", "GetParent", [owned])[0] == top
    assert call(dll_emu, "user32", "GetParent", [owned_overlapped])[0] == 0
    assert call(dll_emu, "user32", "GetParent", [top])[0] == 0
    assert call(dll_emu, "user32", "GetParent", [desktop])[0] == 0
    assert call(dll_emu, "user32", "GetParent", [0x41420000])[0] == 0
    assert dll_emu.emu.get_last_error() == 1400


def test_window_properties_by_name(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    hwnd = create_window(dll_emu)
    name = alloc(dll_emu, b"SHE\x00")
    assert call(dll_emu, "user32", "GetPropA", [0x41420000, name])[0] == 0
    assert call(dll_emu, "user32", "GetPropA", [hwnd, name])[0] == 0
    assert call(dll_emu, "user32", "SetPropA", [hwnd, name, 0x1234])[0] == 1
    wide = alloc(dll_emu, "she".encode("utf-16le") + b"\x00\x00")
    assert call(dll_emu, "user32", "GetPropW", [hwnd, wide])[0] == 0x1234
    assert call(dll_emu, "user32", "GetPropA", [create_window(dll_emu), name])[0] == 0
    assert call(dll_emu, "user32", "RemovePropA", [hwnd, name])[0] == 0x1234
    assert call(dll_emu, "user32", "GetPropA", [hwnd, name])[0] == 0
    assert call(dll_emu, "user32", "RemovePropA", [hwnd, name])[0] == 0


def test_get_window_thread_process_id(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    start_process(dll_emu)
    hwnd = create_window(dll_emu)
    pid = alloc(dll_emu, b"\xcc" * 4)
    tid, _ = call(dll_emu, "user32", "GetWindowThreadProcessId", [hwnd, pid])
    assert tid == call(dll_emu, "kernel32", "GetCurrentThreadId", [])[0]
    assert dll_emu.mem_read(pid, 4) == struct.pack("<I", call(dll_emu, "kernel32", "GetCurrentProcessId", [])[0])
    assert call(dll_emu, "user32", "GetWindowThreadProcessId", [hwnd, 0])[0] == tid


def test_get_foreground_window_is_a_stable_explorer_window(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    start_process(dll_emu)
    hwnd, _ = call(dll_emu, "user32", "GetForegroundWindow", [])
    assert hwnd and call(dll_emu, "user32", "GetForegroundWindow", [])[0] == hwnd
    pid = alloc(dll_emu, b"\xcc" * 4)
    assert call(dll_emu, "user32", "GetWindowThreadProcessId", [hwnd, pid])[0] != 0
    explorer = next(p for p in dll_emu.emu.get_processes() if p.name == "explorer")
    assert dll_emu.mem_read(pid, 4) == struct.pack("<I", explorer.pid)


@pytest.mark.parametrize(
    "api, arg",
    [
        ("LoadCursorW", "lpCursorName"),
        ("LoadCursorA", "lpCursorName"),
        ("LoadIconW", "lpIconName"),
        ("LoadBitmapW", "lpBitmapName"),
        ("LoadAcceleratorsW", "lpTableName"),
    ],
)
def test_integer_resource_ids_display_as_integers(dll64_emu: Speakeasy, api: str, arg: str) -> None:
    dll64_emu.mem_write(dll64_emu.mem_alloc(0x1000, base=0x7000), b"A\x00" * 0x800)
    rv, displays = call(dll64_emu, "user32", api, [0, 0x7F00])
    assert rv
    assert displays[arg] == "0x7f00"


JUNGO = "0bfbb7da494de67f22f079f0f8f1f69d43f7b2fdeb58773acbc46f2a51a8e533.exe.xz"
DELPHI_RUNTIME_DEMO = "0faaab54ea0a43ee49d209046dde8ad55bbaee80810253ebe862ad8f64b60c5e.exe.xz"
STRING_TABLE_SAMPLE = PMA_DIR / "Practical Malware Analysis Lab 14-02.exe_"
STRING_1 = "http://127.0.0.1/tenfour.html"


def load_string_table_sample() -> bytes:
    """Return Lab 14-02, whose RT_STRING block 1 holds only string ID 1."""
    if not STRING_TABLE_SAMPLE.is_file():
        pytest.skip("capa-testfiles is not checked out")
    return STRING_TABLE_SAMPLE.read_bytes()


@pytest.mark.parametrize(
    "api, uid, rv, out",
    [
        ("LoadStringW", 1, 29, (STRING_1 + "\x00").encode("utf-16le")),
        ("LoadStringA", 1, 29, (STRING_1 + "\x00").encode()),
        ("LoadStringA", 0, 0, b"\xcc"),
        ("LoadStringA", 16, 0, b"\xcc"),
    ],
)
def test_load_string_reads_the_string_table(config: dict, api: str, uid: int, rv: int, out: bytes) -> None:
    for se in load_emu(config, load_string_table_sample()):
        assert se.emu is not None
        buf = alloc(se, b"\xcc" * 64)
        result, _ = call(se, "user32", api, [se.emu.modules[0].base, uid, buf, 32])
        assert (result, se.mem_read(buf, len(out))) == (rv, out)


def test_load_string_reads_the_string_table_in_memory(config: dict) -> None:
    data = load_string_table_sample()
    pe = pefile.PE(data=data)
    strings = next(e for e in pe.DIRECTORY_ENTRY_RESOURCE.entries if e.id == pefile.RESOURCE_TYPE["RT_STRING"])
    block = strings.directory.entries[0].directory.entries[0].data.struct
    for se in load_emu(config, data):
        assert se.emu is not None
        base = se.emu.modules[0].base
        se.mem_write(
            base + block.OffsetToData, b"\0\0" + struct.pack("<H", 3) + "abc".encode("utf-16le") + b"\0\0" * 14
        )
        buf = alloc(se, b"\xcc" * 32)
        result, _ = call(se, "user32", "LoadStringW", [base, 1, buf, 16])
        assert (result, se.mem_read(buf, 8)) == (3, "abc\x00".encode("utf-16le"))


def test_create_window_sends_nccreate_and_create_to_the_window_procedure(config: dict, load_test_bin) -> None:
    """
    0bfbb7da creates a hidden window of its class "Jungo". Its window procedure handles
    WM_CREATE: it creates a child button "Star" and posts BM_CLICK to it. The program
    does no more work unless CreateWindowExW sends WM_NCCREATE and WM_CREATE with a
    CREATESTRUCTW for the new window.
    """
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(JUNGO))
        messages = []

        def window_procedure(emu: Any, address: int, size: int) -> None:
            hwnd, msg, _, lparam = struct.unpack("<4I", se.mem_read(se.get_stack_ptr() + 4, 16))
            if msg in (WM_NCCREATE, WM_CREATE):
                cs = se.mem_cast(u32defs.CREATESTRUCT(se.get_ptr_size()), lparam)
                messages.append((hwnd, msg, se.read_mem_string(cs.lpszName, 2), se.read_mem_string(cs.lpszClass, 2)))

        se.add_code_hook(window_procedure, begin=module.base + 0x1306, end=module.base + 0x1306)
        se.run_module(module)
        events = api_events(se)

    created = [e for e in events if e.api_name == "user32.CreateWindowExW"]
    hwnd = int(created[0].ret_val, 16)
    assert hwnd
    assert messages == [(hwnd, WM_NCCREATE, "180000", "Jungo"), (hwnd, WM_CREATE, "180000", "Jungo")]
    assert [a.display for a in created[1].args[1:3]] == ["button", "Star"]
    assert created[1].args[8].value == hwnd
    assert int(created[1].ret_val, 16)


def test_create_window_fails_when_the_window_procedure_rejects_creation(config: dict, load_test_bin, run_test) -> None:
    assert not get_failed_window_cases(config, load_test_bin, run_test, CREATE_WINDOW_CASES)


def test_enum_windows_calls_the_callback_for_each_top_level_window(config: dict, load_test_bin, run_test) -> None:
    assert not get_failed_window_cases(config, load_test_bin, run_test, ENUM_WINDOWS_CASES)


def api_events(se: Speakeasy) -> list[Any]:
    return [e for ep in se.get_report().entry_points for e in ep.events or [] if e.event == "api"]


def test_call_window_proc_runs_the_previous_procedure(config: dict, load_test_bin) -> None:
    """
    0faaab54 is a UPX-packed Delphi program. CreateWindowExA of its form TForm1 sends
    WM_NCCREATE to the VCL InitWndProc, which subclasses the window and passes the message
    on with CallWindowProcA to 0x404ab8, a thunk that jumps to DefWindowProcA. The form
    is only made if CallWindowProcA calls that procedure and returns its TRUE.
    """
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(DELPHI_RUNTIME_DEMO))
        results = []

        def after_call_window_proc(emu: Any, address: int, size: int) -> None:
            results.append(se.reg_read("eax"))
            se.stop()

        se.add_code_hook(after_call_window_proc, begin=0x414D89, end=0x414D89)
        se.run_module(module)
        events = api_events(se)

    subclass = [e for e in events if e.api_name == "user32.SetWindowLongA"][-1]
    hwnd, index = subclass.args[0].value, subclass.args[1].value
    assert index is not None and index & 0xFFFFFFFF == 0xFFFFFFFC  # GWLP_WNDPROC
    call_window_proc, def_window_proc = events[-2:]
    assert call_window_proc.api_name == "user32.CallWindowProcA"
    assert [a.value for a in call_window_proc.args[:4]] == [0x404AB8, hwnd, WM_NCCREATE, 0]
    assert def_window_proc.api_name == "user32.DefWindowProcA"
    assert [a.value for a in def_window_proc.args] == [a.value for a in call_window_proc.args[1:]]
    assert results == [1]


def test_call_window_proc_without_a_previous_procedure_returns_zero(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    assert call(dll_emu, "user32", "CallWindowProcA", [0, 0x10000, 0x111, 0, 0])[0] == 0


LVM_GETCOLUMNA = 0x1019
LVM_INSERTCOLUMNA = 0x101B
LVM_DELETECOLUMN = 0x101C
LVM_GETCOLUMNWIDTH = 0x101D
LVM_SETCOLUMNWIDTH = 0x101E
LVM_GETCOLUMNW = 0x105F
LVCF_FMT = 1
LVCF_WIDTH = 2
LVCF_TEXT = 4
LVCF_SUBITEM = 8


def lvcolumn(se: Speakeasy, mask: int, fmt: int = 0, cx: int = 0, text: int = 0, cch: int = 0) -> int:
    col = u32defs.LVCOLUMN(se.get_ptr_size())
    col.mask = mask
    col.fmt = fmt
    col.cx = cx
    col.pszText = text
    col.cchTextMax = cch
    return alloc(se, col.get_bytes())


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
def test_list_view_columns_keep_their_widths(request: pytest.FixtureRequest, fixture: str) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    assert se.emu is not None
    hwnd, _ = call(se, "user32", "CreateWindowExA", [0, alloc(se, b"SysListView32\x00"), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    name = alloc(se, b"Name\x00")
    rv, _ = call(se, "user32", "SendMessageA", [hwnd, LVM_INSERTCOLUMNA, 0, lvcolumn(se, 7, 0, 150, name)])
    assert rv == 0
    rv, _ = call(se, "user32", "SendMessageA", [hwnd, LVM_INSERTCOLUMNA, 5, lvcolumn(se, 3, 1, 100)])
    assert rv == 1

    col = lvcolumn(se, LVCF_WIDTH | LVCF_FMT | LVCF_SUBITEM)
    rv, _ = call(se, "user32", "SendMessageA", [hwnd, LVM_GETCOLUMNA, 0, col])
    assert rv == 1
    got = se.mem_cast(u32defs.LVCOLUMN(se.get_ptr_size()), col)
    assert (got.mask, got.fmt, got.cx, got.iSubItem) == (LVCF_WIDTH | LVCF_FMT | LVCF_SUBITEM, 0, 150, 0)
    assert (got.pszText, got.cchTextMax) == (0, 0)

    buf = alloc(se, b"\xcc" * 16)
    col = lvcolumn(se, LVCF_TEXT, text=buf, cch=16)
    rv, _ = call(se, "user32", "SendMessageW", [hwnd, LVM_GETCOLUMNW, 0, col])
    assert rv == 1
    assert se.mem_read(buf, 10) == "Name\x00".encode("utf-16le")

    rv, _ = call(se, "user32", "SendMessageA", [hwnd, LVM_GETCOLUMNWIDTH, 1, 0])
    assert rv == 100
    rv, _ = call(se, "user32", "SendMessageA", [hwnd, LVM_SETCOLUMNWIDTH, 1, 80])
    assert rv == 1
    rv, _ = call(se, "user32", "SendMessageA", [hwnd, LVM_GETCOLUMNWIDTH, 1, 0])
    assert rv == 80

    rv, _ = call(se, "user32", "SendMessageA", [hwnd, LVM_DELETECOLUMN, 0, 0])
    assert rv == 1
    rv, _ = call(se, "user32", "SendMessageA", [hwnd, LVM_GETCOLUMNWIDTH, 0, 0])
    assert rv == 80
    rv, _ = call(se, "user32", "SendMessageA", [hwnd, LVM_GETCOLUMNA, 1, col])
    assert rv == 0
