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


GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
BYTE_FILL_PATH = "c:\\programdata\\mydir\\myfile.bin"


def open_file(se: Speakeasy, path: str, disposition: int = OPEN_EXISTING) -> int:
    name = alloc(se, path.encode() + b"\x00")
    hnd, _ = call(se, "kernel32", "CreateFileA", [name, GENERIC_READ, 0, 0, disposition, 0, 0])
    return hnd


def test_byte_fill_file_has_its_size(emu: Speakeasy) -> None:
    hnd = open_file(emu, BYTE_FILL_PATH)
    high = alloc(emu, b"\xcc" * 4)
    assert call(emu, "kernel32", "GetFileSize", [hnd, high])[0] == 512
    assert emu.mem_read(high, 4) == b"\x00" * 4

    buf = alloc(emu, b"\x00" * 16)
    read = alloc(emu, b"\x00" * 4)
    assert call(emu, "kernel32", "ReadFile", [hnd, buf, 16, read, 0])[0]
    assert emu.mem_read(buf, 16) == b"A" * 16
