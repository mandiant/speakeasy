"""
User32 handlers return what Windows returns and write only what the caller owns.
"""

import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.windows.win32 import Win32Emulator
from speakeasy.winenv import arch as e_arch
from tests.handler_harness import alloc, call, start_process


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


def register_class(se: Speakeasy, name: bytes | int, wndproc: int) -> int:
    assert se.emu is not None
    p = "I" if se.emu.get_ptr_size() == 4 else "Q"
    fmt = "<II" + p + "II" + p * 7
    size = struct.calcsize(fmt)
    lpsz = name if isinstance(name, int) else alloc(se, name + b"\x00")
    wc = struct.pack(fmt, size, 0, wndproc, 0, 0, *([0] * 5), lpsz, 0)
    atom, _ = call(se, "user32", "RegisterClassExA", [alloc(se, wc)])
    return atom


def test_dialog_box_param_takes_a_resource_id(dll_emu: Speakeasy) -> None:
    rv, _ = call(dll_emu, "user32", "DialogBoxParamA", [0, 101, 0, 0, 0])
    assert rv


def test_register_class_takes_a_class_atom(dll_emu: Speakeasy) -> None:
    assert register_class(dll_emu, 0xC001, 0x401000)


def test_find_window_takes_a_class_atom(dll_emu: Speakeasy) -> None:
    rv, _ = call(dll_emu, "user32", "FindWindowA", [0xC001, 0])
    assert rv == 0


def test_create_window_takes_a_class_atom(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    atom = register_class(dll_emu, b"mycls", 0x401000)
    hwnd, _ = call(dll_emu, "user32", "CreateWindowExA", [0, atom, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    assert hwnd
    rv, _ = call(dll_emu, "user32", "UpdateWindow", [hwnd])
    assert rv
    assert [cb[1] for cb in dll_emu.emu.get_current_run().api_callbacks] == [0x401000]


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
    _, (_, _, argc, conv, _) = se.emu.normalize_import_miss("user32", name)
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
