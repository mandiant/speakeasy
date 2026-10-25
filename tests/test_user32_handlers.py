"""
User32 handlers return what Windows returns and write only what the caller owns.
"""

import struct
from typing import Any

import pytest

from speakeasy import Speakeasy
from speakeasy.windows.win32 import Win32Emulator
from speakeasy.winenv import arch as e_arch
from tests.guest_harness import Deref, guest_call
from tests.handler_harness import alloc, call, load_emu, start_process
from tests.pe_builder import build_pe


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


def run_dialog_box(config: dict[str, Any], end_dialog: bool) -> tuple[int, int, int]:
    """
    Run DialogBoxParamA with a dialog procedure that records its message and lParam and,
    if end_dialog, calls EndDialog(hDlg, 0x1234). Return the result, the message and the lParam.
    """
    config["timeout"] = 2
    config["max_api_count"] = 200
    with Speakeasy(config=config) as se:
        se.run_shellcode(se.load_shellcode(data=b"\xc3", arch="x86"))
        assert se.emu is not None
        data = se.mem_alloc(0x1000)
        proc = se.mem_alloc(0x1000)
        code = b"\x8b\x44\x24\x08\xa3" + struct.pack("<I", data + 4)
        code += b"\x8b\x44\x24\x10\xa3" + struct.pack("<I", data + 8)
        if end_dialog:
            code += b"\x68" + struct.pack("<I", 0x1234) + b"\xff\x74\x24\x08"
            code += b"\xb8" + struct.pack("<I", se.emu.get_proc("user32", "EndDialog")) + b"\xff\xd0"
        code += b"\xb8" + struct.pack("<I", int(end_dialog)) + b"\xc2\x10\x00"
        se.mem_write(proc, code)
        caller = se.mem_alloc(0x1000)
        dialog_box = se.emu.get_proc("user32", "DialogBoxParamA")
        se.mem_write(caller, guest_call(4, dialog_box, 0, 1, 0, proc, 0x55, store=data) + b"\xc3")
        se.call(caller)
        assert se.get_report().entry_points[-1].error is None
        return struct.unpack("<III", se.mem_read(data, 12))


def test_dialog_box_param_returns_the_end_dialog_result(config: dict[str, Any]) -> None:
    assert run_dialog_box(config, end_dialog=True) == (0x1234, 0x110, 0x55)


def test_dialog_box_param_returns_idcancel_without_end_dialog(config: dict[str, Any]) -> None:
    assert run_dialog_box(config, end_dialog=False) == (2, 0x110, 0x55)


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


def test_create_window_takes_a_class_atom(dll_emu: Speakeasy) -> None:
    atom = register_class(dll_emu, b"mycls", 0x401000)
    hwnd = create_window_of_class(dll_emu, atom, 0x401000)
    assert hwnd
    rv, _ = call(dll_emu, "user32", "UpdateWindow", [hwnd])
    assert rv


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


STATUS_INVALID_PARAMETER = 0xC000000D


@pytest.mark.parametrize("fixture, ptr", [("dll_emu", 4), ("dll64_emu", 8)])
@pytest.mark.parametrize("has_buffer", [False, True])
def test_d3dkmt_enum_adapters2_reports_no_adapters(
    request: pytest.FixtureRequest, fixture: str, ptr: int, has_buffer: bool
) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    adapters = alloc(se, b"\xcc" * 0x40) if has_buffer else 0
    data = alloc(
        se, struct.pack("<I", 2 if has_buffer else 0xFFFFFFFF) + b"\x00" * (ptr - 4) + adapters.to_bytes(ptr, "little")
    )
    assert call(se, "gdi32", "D3DKMTEnumAdapters2", [data])[0] == 0
    assert se.mem_read(data, 4) == b"\x00" * 4
    assert int.from_bytes(se.mem_read(data + ptr, ptr), "little") == adapters
    if adapters:
        assert se.mem_read(adapters, 0x40) == b"\xcc" * 0x40


def test_d3dkmt_enum_adapters_reports_no_adapters(dll_emu: Speakeasy) -> None:
    data = alloc(dll_emu, b"\xcc" * 4)
    assert call(dll_emu, "gdi32", "D3DKMTEnumAdapters", [data])[0] == 0
    assert dll_emu.mem_read(data, 4) == b"\x00" * 4


def test_d3dkmt_adapter_calls_return_ntstatus(dll_emu: Speakeasy) -> None:
    data = alloc(dll_emu, b"\x00" * 0x20)
    assert call(dll_emu, "gdi32", "D3DKMTCloseAdapter", [data])[0] == 0
    assert call(dll_emu, "gdi32", "D3DKMTQueryAdapterInfo", [data])[0] == STATUS_INVALID_PARAMETER


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
    fmt = "<IIii6I" if se.emu.get_ptr_size() == 4 else "<I4xQii6Q"
    wc = struct.pack(fmt, 0, 0x401000, 0, 0, 0, 0, 0, 0, 0, alloc(se, name))
    atom, _ = call(se, "user32", "RegisterClassW", [alloc(se, wc)])
    assert atom
    rv, _ = call(se, "user32", "CreateWindowExW", [0, alloc(se, name), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    assert rv is None
    assert [cb.function for cb in se.emu.get_current_run().guest_callbacks] == [0x401000]


def test_clipboard_reports_no_text(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    cf_unicodetext = 13
    assert call(dll_emu, "user32", "IsClipboardFormatAvailable", [cf_unicodetext])[0] == 0
    assert call(dll_emu, "user32", "GetClipboardData", [cf_unicodetext])[0] == 0


WS_POPUP = 0x80000000
WS_CHILD = 0x40000000


def create_window(se: Speakeasy, style: int = 0, parent: int = 0) -> int:
    hwnd, _ = call(se, "user32", "CreateWindowExA", [0, 0, 0, style, 0, 0, 0, 0, parent, 0, 0, 0])
    return hwnd


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
@pytest.mark.parametrize("api", ["GetWindowLongW", "SetWindowLongW"])
def test_window_long_of_an_unknown_window_fails(request: pytest.FixtureRequest, fixture: str, api: str) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    assert se.emu is not None
    start_process(se)
    argv = [0x41420000, 0] + ([0x1234] if api.startswith("Set") else [])
    assert call(se, "user32", api, argv)[0] == 0
    assert se.emu.get_last_error() == 1400


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
    msg = alloc(dll_emu, struct.pack("<IIIIIII", hwnd, 0x10, 0, 0, 0, 0, 0))
    call(dll_emu, "user32", "DispatchMessageA", [msg])
    assert dll_emu.emu.get_current_run().guest_callbacks[-1].function == 0x402000


@pytest.mark.parametrize("api", ["GetDC", "GetWindowDC"])
def test_release_dc_releases_a_window_dc(dll_emu: Speakeasy, api: str) -> None:
    start_process(dll_emu)
    hwnd = create_window(dll_emu)
    dc = call(dll_emu, "user32", api, [hwnd])[0]
    assert dc
    assert call(dll_emu, "user32", "ReleaseDC", [hwnd, dc])[0] == 1


def test_release_dc_of_an_unknown_dc_fails(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    assert call(dll_emu, "user32", "ReleaseDC", [0, 0x1234])[0] == 0


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


def test_window_properties_by_atom(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    hwnd = create_window(dll_emu)
    assert call(dll_emu, "user32", "SetPropW", [hwnd, 0xC123, 0x5678])[0] == 1
    assert call(dll_emu, "user32", "GetPropW", [hwnd, 0xC123])[0] == 0x5678
    assert call(dll_emu, "user32", "GetPropW", [hwnd, 0xC124])[0] == 0
    assert call(dll_emu, "user32", "SetPropW", [0x41420000, 0xC123, 1])[0] == 0


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
def test_get_cursor_pos_writes_a_point_on_the_screen(request: pytest.FixtureRequest, fixture: str) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    pt = alloc(se, b"\xcc" * 12)
    assert call(se, "user32", "GetCursorPos", [pt])[0] == 1
    x, y, rest = struct.unpack("<iiI", se.mem_read(pt, 12))
    assert 0 <= x < 1920 and 0 <= y < 1080
    assert rest == 0xCCCCCCCC


def test_get_window_thread_process_id(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    start_process(dll_emu)
    hwnd = create_window(dll_emu)
    pid = alloc(dll_emu, b"\xcc" * 4)
    tid, _ = call(dll_emu, "user32", "GetWindowThreadProcessId", [hwnd, pid])
    assert tid == call(dll_emu, "kernel32", "GetCurrentThreadId", [])[0]
    assert dll_emu.mem_read(pid, 4) == struct.pack("<I", call(dll_emu, "kernel32", "GetCurrentProcessId", [])[0])
    assert call(dll_emu, "user32", "GetWindowThreadProcessId", [hwnd, 0])[0] == tid


def test_get_window_thread_process_id_of_the_desktop_is_csrss(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    start_process(dll_emu)
    desktop, _ = call(dll_emu, "user32", "GetDesktopWindow", [])
    pid = alloc(dll_emu, b"\xcc" * 4)
    tid, _ = call(dll_emu, "user32", "GetWindowThreadProcessId", [desktop, pid])
    csrss = next(p for p in dll_emu.emu.get_processes() if p.name == "csrss")
    assert tid and tid != call(dll_emu, "kernel32", "GetCurrentThreadId", [])[0]
    assert dll_emu.mem_read(pid, 4) == struct.pack("<I", csrss.pid)
    assert call(dll_emu, "user32", "GetWindowThreadProcessId", [desktop, 0])[0] == tid


def test_get_window_thread_process_id_of_an_invalid_window(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    start_process(dll_emu)
    pid = alloc(dll_emu, b"\xcc" * 4)
    assert call(dll_emu, "user32", "GetWindowThreadProcessId", [0x41420000, pid])[0] == 0
    assert dll_emu.mem_read(pid, 4) == b"\xcc" * 4
    assert dll_emu.emu.get_last_error() == 1400


@pytest.mark.parametrize(
    "index, expected",
    [(0, 1920), (1, 1080), (4, 23), (19, 1), (67, 0), (78, 1920), (79, 1080), (80, 1), (0x1000, 0), (0x7FFF, 0)],
)
def test_get_system_metrics(dll_emu: Speakeasy, index: int, expected: int) -> None:
    assert call(dll_emu, "user32", "GetSystemMetrics", [index])[0] == expected


@pytest.mark.parametrize("index, expected", [(5, 0xFFFFFF), (8, 0), (13, 0xD77800), (15, 0xF0F0F0), (200, 0)])
def test_get_sys_color(dll_emu: Speakeasy, index: int, expected: int) -> None:
    assert call(dll_emu, "user32", "GetSysColor", [index])[0] == expected


@pytest.mark.parametrize(
    "utype, rv",
    [
        (0x0, 1),  # MB_OK: IDOK
        (0x40, 1),  # MB_OK | MB_ICONINFORMATION: IDOK
        (0x1, 2),  # MB_OKCANCEL: IDCANCEL
        (0x2, 3),  # MB_ABORTRETRYIGNORE: IDABORT
        (0x3, 2),  # MB_YESNOCANCEL: IDCANCEL
        (0x4, 6),  # MB_YESNO: IDYES
        (0x5, 2),  # MB_RETRYCANCEL: IDCANCEL
        (0x6, 2),  # MB_CANCELTRYCONTINUE: IDCANCEL
    ],
)
def test_message_box_returns_a_button_of_its_type(dll_emu: Speakeasy, utype: int, rv: int) -> None:
    text = alloc(dll_emu, b"text\x00")
    assert call(dll_emu, "user32", "MessageBoxA", [0, text, text, utype])[0] == rv


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


def test_named_resources_display_their_names(dll64_emu: Speakeasy) -> None:
    name = alloc(dll64_emu, "MAINMENU\x00".encode("utf-16le"))
    assert call(dll64_emu, "user32", "LoadAcceleratorsW", [0, name])[1]["lpTableName"] == "MAINMENU"
    number = alloc(dll64_emu, "#101\x00".encode("utf-16le"))
    assert call(dll64_emu, "user32", "LoadAcceleratorsW", [0, number])[1]["lpTableName"] == "0x65"


def build_string_table_pe() -> bytes:
    """Return a PE whose RT_STRING block 2 holds ID 17 = "tenfour" and ID 18 = "x"."""
    rsrc = 0x2000
    block = b"\0\0" + struct.pack("<H", 7) + "tenfour".encode("utf-16le") + struct.pack("<H", 1) + b"x\0"
    block += b"\0\0" * 13
    data = struct.pack("<IIHHHHII", 0, 0, 0, 0, 0, 1, 6, 0x80000018)
    data += struct.pack("<IIHHHHII", 0, 0, 0, 0, 0, 1, 2, 0x80000030)
    data += struct.pack("<IIHHHHII", 0, 0, 0, 0, 0, 1, 0x409, 0x48)
    data += struct.pack("<IIII", rsrc + 0x60, len(block), 0, 0)
    data = data.ljust(0x60, b"\0") + block
    image, _ = build_pe(32, data=data, extra_dirs={2: (rsrc, 0x60)})
    return image


@pytest.mark.parametrize(
    "api, uid, rv, out",
    [
        ("LoadStringW", 17, 7, "tenfour\x00".encode("utf-16le")),
        ("LoadStringA", 18, 1, b"x\x00"),
        ("LoadStringA", 16, 0, b"\xcc"),
    ],
)
def test_load_string_reads_the_string_table(config: dict, api: str, uid: int, rv: int, out: bytes) -> None:
    for se in load_emu(config, build_string_table_pe()):
        assert se.emu is not None
        buf = alloc(se, b"\xcc" * 32)
        result, _ = call(se, "user32", api, [se.emu.modules[0].base, uid, buf, 16])
        assert (result, se.mem_read(buf, len(out))) == (rv, out)


def test_load_string_reads_the_string_table_in_memory(config: dict) -> None:
    for se in load_emu(config, build_string_table_pe()):
        assert se.emu is not None
        base = se.emu.modules[0].base
        se.mem_write(base + 0x2060, b"\0\0" + struct.pack("<H", 3) + "abc".encode("utf-16le") + b"\0\0" * 14)
        buf = alloc(se, b"\xcc" * 32)
        result, _ = call(se, "user32", "LoadStringW", [base, 17, buf, 16])
        assert (result, se.mem_read(buf, 8)) == (3, "abc\x00".encode("utf-16le"))


def test_register_window_message_gives_one_id_per_name(dll_emu: Speakeasy) -> None:
    def register(text: bytes) -> int:
        return call(dll_emu, "user32", "RegisterWindowMessageA", [alloc(dll_emu, text + b"\0")])[0]

    first = register(b"TaskbarCreated")
    second = register(b"MyPrivateMessage")

    assert 0xC000 <= first <= 0xFFFF
    assert second not in (first, 0)
    assert register(b"taskbarcreated") == first


def d32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def x86_call(function: int) -> bytes:
    return b"\xb8" + d32(function) + b"\xff\xd0"


def x86_logging_wndproc(data: int, nccreate_result: int, create_result: int) -> bytes:
    """
    A window procedure that appends each message to data + 0x10 and its lParam
    to data + 0x40, counting them at data + 4, and returns nccreate_result for
    WM_NCCREATE and create_result for all other messages.
    """
    code = b"\x8b\x44\x24\x08\x8b\x0d" + d32(data + 4)  # mov eax, [esp+8]; mov ecx, [data+4]
    code += b"\x89\x04\x8d" + d32(data + 0x10)  # mov [data+0x10+ecx*4], eax
    code += b"\x8b\x54\x24\x10\x89\x14\x8d" + d32(data + 0x40)  # mov edx, [esp+16]; mov [data+0x40+ecx*4], edx
    code += b"\xff\x05" + d32(data + 4)  # inc dword [data+4]
    code += b"\x3d\x81\x00\x00\x00\x75\x08"  # cmp eax, WM_NCCREATE; jne other
    code += b"\xb8" + d32(nccreate_result) + b"\xc2\x10\x00"
    return code + b"\xb8" + d32(create_result) + b"\xc2\x10\x00"


@pytest.mark.parametrize(
    "nccreate_result, create_result, messages, created",
    [(1, 0, [0x81, 0x1], True), (0, 0, [0x81], False), (1, -1, [0x81, 0x1], False)],
)
def test_create_window_sends_nccreate_and_create_to_the_window_procedure(
    config: dict, nccreate_result: int, create_result: int, messages: list[int], created: bool
) -> None:
    with Speakeasy(config=config) as se:
        base = se.load_shellcode(data=b"\xcc" * 0x1000, arch="x86")
        assert se.emu is not None
        data = se.mem_alloc(0x1000)
        wndproc, name, title, wc = base + 0x200, base + 0x300, base + 0x310, base + 0x320
        se.mem_write(wndproc, x86_logging_wndproc(data, nccreate_result, create_result))
        se.mem_write(name, b"mycls\x00")
        se.mem_write(title, b"mytitle\x00")
        se.mem_write(wc, struct.pack("<12I", 48, 0, wndproc, 0, 0, 0, 0, 0, 0, 0, name, 0))
        args = [0x400, name, title, WS_POPUP, 10, 20, 30, 40, 0, 0, 0x400000, 0x1234]
        main = b"\x68" + d32(wc) + x86_call(se.emu.get_proc("user32", "RegisterClassExA"))
        main += b"".join(b"\x68" + d32(arg) for arg in reversed(args))
        main += x86_call(se.emu.get_proc("user32", "CreateWindowExA")) + b"\xa3" + d32(data) + b"\xc3"
        se.mem_write(base, main)

        se.run_shellcode(base)

        assert se.get_report().entry_points[0].error is None
        u32 = struct.unpack("<1024I", se.mem_read(data, 0x1000))
        assert bool(u32[0]) == created
        assert list(u32[4 : 4 + u32[1]]) == messages
        lparams = u32[0x10 : 0x10 + u32[1]]
        assert len(set(lparams)) == 1
        cs = struct.unpack("<4I4i4I", se.mem_read(lparams[0], 48))
        assert cs == (0x1234, 0x400000, 0, 0, 40, 30, 20, 10, WS_POPUP, title, name, 0x400)


def test_def_window_proc_lets_nccreate_create_the_window(dll_emu: Speakeasy) -> None:
    assert call(dll_emu, "user32", "DefWindowProcA", [0x10000, 0x81, 0, 0])[0] == 1
    assert call(dll_emu, "user32", "DefWindowProcA", [0x10000, 0x1, 0, 0])[0] == 0


@pytest.mark.parametrize("callback_result, rv", [(0, 0), (1, 1)])
def test_enum_windows_calls_the_callback_for_each_top_level_window(config: dict, callback_result: int, rv: int) -> None:
    with Speakeasy(config=config) as se:
        base = se.load_shellcode(data=b"\xcc" * 0x1000, arch="x86")
        assert se.emu is not None
        data = se.mem_alloc(0x1000)
        callback, name = base + 0x200, base + 0x300
        code = b"\x8b\x44\x24\x04\xa3" + d32(data + 0x10)  # mov eax, [esp+4]; mov [data+0x10], eax
        code += b"\x8b\x44\x24\x08\xa3" + d32(data + 0x14)  # mov eax, [esp+8]; mov [data+0x14], eax
        code += b"\xff\x05" + d32(data + 8)  # inc dword [data+8]
        code += b"\xb8" + d32(callback_result) + b"\xc2\x08\x00"
        se.mem_write(callback, code)
        se.mem_write(name, b"mycls\x00")
        create = se.emu.get_proc("user32", "CreateWindowExA")
        main = guest_call(4, create, 0, name, 0, WS_POPUP, 0, 0, 0, 0, 0, 0, 0, 0, store=data)
        main += guest_call(4, create, 0, name, 0, WS_CHILD, 0, 0, 0, 0, Deref(data), 0, 0, 0)
        main += guest_call(4, se.emu.get_proc("user32", "EnumWindows"), callback, 0x55, store=data + 4)
        se.mem_write(base, main + b"\xc3")

        se.run_shellcode(base)

        assert se.get_report().entry_points[0].error is None
        hwnd, result, count, _, cb_hwnd, cb_lparam = struct.unpack("<6I", se.mem_read(data, 0x18))
        assert hwnd
        assert (result, count, cb_hwnd, cb_lparam) == (rv, 1, hwnd, 0x55)


def test_call_window_proc_runs_def_window_proc_for_a_subclassed_window(config: dict) -> None:
    with Speakeasy(config=config) as se:
        base = se.load_shellcode(data=b"\xcc" * 0x1000, arch="x86")
        assert se.emu is not None
        data = se.mem_alloc(0x1000)
        wndproc, name = base + 0x200, base + 0x300
        code = b"\xff\x74\x24\x10" * 4  # push lParam, wParam, Msg, hWnd
        code += b"\x68" + d32(se.emu.get_proc("user32", "DefWindowProcA"))
        code += x86_call(se.emu.get_proc("user32", "CallWindowProcA")) + b"\xc2\x10\x00"
        se.mem_write(wndproc, code)
        se.mem_write(name, b"mycls\x00")
        main = guest_call(
            4, se.emu.get_proc("user32", "RegisterClassA"), alloc(se, struct.pack("<10I", 0, wndproc, *[0] * 7, name))
        )
        main += guest_call(4, se.emu.get_proc("user32", "CreateWindowExA"), 0, name, 0, WS_POPUP, *[0] * 8, store=data)
        se.mem_write(base, main + b"\xc3")

        se.run_shellcode(base)

        assert se.get_report().entry_points[0].error is None
        assert struct.unpack("<I", se.mem_read(data, 4))[0]


def test_call_window_proc_returns_the_previous_procedure_result(config: dict) -> None:
    with Speakeasy(config=config) as se:
        base = se.load_shellcode(data=b"\xcc" * 0x1000, arch="x86")
        assert se.emu is not None
        data = se.mem_alloc(0x1000)
        prev = base + 0x200
        se.mem_write(data + 8, d32(0xFFFFFFFF))
        se.mem_write(prev, b"\x8b\x44\x24\x08\xa3" + d32(data + 4) + b"\xb8" + d32(0x1234) + b"\xc2\x10\x00")
        call_window_proc = se.emu.get_proc("user32", "CallWindowProcA")
        main = guest_call(4, call_window_proc, prev, 0x10000, 0x111, 0, 0, store=data)
        main += guest_call(4, call_window_proc, 0, 0x10000, 0x111, 0, 0, store=data + 8)
        se.mem_write(base, main + b"\xc3")

        se.run_shellcode(base)

        assert se.get_report().entry_points[0].error is None
        assert struct.unpack("<3I", se.mem_read(data, 12)) == (0x1234, 0x111, 0)
