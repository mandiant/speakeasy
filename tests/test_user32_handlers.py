"""
User32 handlers return what Windows returns and write only what the caller owns.
"""

import struct

import pytest

from speakeasy import Speakeasy
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
