"""
User32 handlers return what Windows returns and write only what the caller owns.
"""

import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv import arch as e_arch
from tests.handler_harness import alloc, call, start_process


@pytest.mark.parametrize("fixture, size", [("dll_emu", 28), ("dll64_emu", 48)])
def test_get_message_writes_one_msg(request: pytest.FixtureRequest, fixture: str, size: int) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
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
