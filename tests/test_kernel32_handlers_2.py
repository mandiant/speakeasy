"""
kernel32 handlers return what Windows returns and write what Windows writes.
"""

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.defs.windows import windows as windefs
from tests.handler_harness import alloc, call, start_process


@pytest.fixture
def emu(dll_emu: Speakeasy) -> Speakeasy:
    start_process(dll_emu)
    return dll_emu


def last_error(se: Speakeasy) -> int:
    assert se.emu is not None
    return se.emu.get_last_error()


def set_last_error(se: Speakeasy, code: int) -> None:
    assert se.emu is not None
    se.emu.set_last_error(code)


@pytest.mark.parametrize("name, width", [("GetEnvironmentVariableA", 1), ("GetEnvironmentVariableW", 2)])
def test_get_environment_variable_sizes(emu: Speakeasy, name: str, width: int) -> None:
    enc = "utf-8" if width == 1 else "utf-16le"
    var = alloc(emu, "windir\x00".encode(enc))
    assert call(emu, "kernel32", name, [var, 0, 0])[0] == len("C:\\Windows") + 1

    small = alloc(emu, b"\xcc" * 8 * width)
    assert call(emu, "kernel32", name, [var, small, 8])[0] == len("C:\\Windows") + 1
    assert emu.mem_read(small, 8 * width) == b"\xcc" * 8 * width

    buf = alloc(emu, b"\xcc" * 32 * width)
    assert call(emu, "kernel32", name, [var, buf, 32])[0] == len("C:\\Windows")
    assert emu.mem_read(buf, 11 * width) == "C:\\Windows\x00".encode(enc)


def test_get_environment_variable_missing(emu: Speakeasy) -> None:
    var = alloc(emu, b"nosuchvar\x00")
    buf = alloc(emu, b"\x00" * 32)
    assert call(emu, "kernel32", "GetEnvironmentVariableA", [var, buf, 32])[0] == 0
    assert last_error(emu) == windefs.ERROR_ENVVAR_NOT_FOUND
