"""
kernel32 handlers return what Windows returns and write what Windows writes.
"""

import datetime
import struct

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


def system_time(se: Speakeasy, when: datetime.datetime) -> int:
    fields = (when.year, when.month, 0, when.day, when.hour, when.minute, when.second, 0)
    return alloc(se, struct.pack("<8H", *fields))


@pytest.mark.parametrize("name, width", [("GetDateFormatA", 1), ("GetDateFormatW", 2)])
def test_get_date_format_counts_characters(emu: Speakeasy, name: str, width: int) -> None:
    enc = "utf-8" if width == 1 else "utf-16le"
    date = system_time(emu, datetime.datetime(2024, 3, 9))
    fmt = alloc(emu, "dd MMM yyyy\x00".encode(enc))
    assert call(emu, "kernel32", name, [0x400, 0, date, fmt, 0, 0])[0] == 12

    small = alloc(emu, b"\xcc" * 8 * width)
    assert call(emu, "kernel32", name, [0x400, 0, date, fmt, small, 8])[0] == 0
    assert emu.mem_read(small, 8 * width) == b"\xcc" * 8 * width

    buf = alloc(emu, b"\xcc" * 16 * width)
    assert call(emu, "kernel32", name, [0x400, 0, date, fmt, buf, 16])[0] == 12
    assert emu.mem_read(buf, 13 * width) == "09 Mar 2024\x00".encode(enc) + b"\xcc" * width


@pytest.mark.parametrize("name, width", [("GetTimeFormatA", 1), ("GetTimeFormatW", 2)])
def test_get_time_format_counts_characters(emu: Speakeasy, name: str, width: int) -> None:
    enc = "utf-8" if width == 1 else "utf-16le"
    when = system_time(emu, datetime.datetime(2024, 3, 9, 17, 4, 5))
    fmt = alloc(emu, "HH:mm:ss\x00".encode(enc))
    assert call(emu, "kernel32", name, [0x400, 0, when, fmt, 0, 0])[0] == 9

    small = alloc(emu, b"\xcc" * 4 * width)
    assert call(emu, "kernel32", name, [0x400, 0, when, fmt, small, 4])[0] == 0
    assert emu.mem_read(small, 4 * width) == b"\xcc" * 4 * width

    buf = alloc(emu, b"\xcc" * 16 * width)
    assert call(emu, "kernel32", name, [0x400, 0, when, fmt, buf, 16])[0] == 9
    assert emu.mem_read(buf, 10 * width) == "17:04:05\x00".encode(enc) + b"\xcc" * width


def test_get_date_and_time_format_use_now_for_null_time(emu: Speakeasy) -> None:
    buf = alloc(emu, b"\x00" * 64)
    fmt = alloc(emu, b"yyyy\x00")
    assert call(emu, "kernel32", "GetDateFormatA", [0x400, 0, 0, fmt, buf, 64])[0] == 5
    assert emu.mem_read(buf, 4).decode() == str(datetime.datetime.now().year)

    assert call(emu, "kernel32", "GetDateFormatA", [0x400, 0, 0, 0, buf, 64])[0] > 1
    assert call(emu, "kernel32", "GetTimeFormatA", [0x400, 0, 0, 0, buf, 64])[0] == 9


def test_open_thread(emu: Speakeasy) -> None:
    assert emu.emu is not None
    tid = emu.emu.curr_thread.tid
    assert call(emu, "kernel32", "OpenThread", [0x1F03FF, 0, tid])[0] != 0

    assert call(emu, "kernel32", "OpenThread", [0x1F03FF, 0, 0x7FFF0])[0] == 0
    assert last_error(emu) == windefs.ERROR_INVALID_PARAMETER


def test_get_module_file_name_ex(emu: Speakeasy) -> None:
    assert emu.emu is not None
    module = emu.emu.modules[0]
    path = module.emu_path
    buf = alloc(emu, b"\xcc" * 260)
    rv, displays = call(emu, "kernel32", "GetModuleFileNameExA", [0, module.base, buf, 260])
    assert rv == len(path)
    assert emu.mem_read(buf, len(path) + 1) == path.encode() + b"\x00"
    assert displays["lpFilename"] == path

    assert call(emu, "kernel32", "GetModuleFileNameExA", [0x7FF0, 0, buf, 260])[0] == 0
    assert last_error(emu) == windefs.ERROR_INVALID_HANDLE
