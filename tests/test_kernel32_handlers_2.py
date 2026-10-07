"""
kernel32 handlers return what Windows returns and write what Windows writes.
"""

import datetime
import struct
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.defs.windows import windows as windefs
from tests.handler_harness import alloc, call, load_emu, start_process


@pytest.fixture
def emu(dll_emu: Speakeasy) -> Speakeasy:
    start_process(dll_emu)
    return dll_emu


@pytest.fixture
def strict_fs_emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> Iterator[Speakeasy]:
    """An emulator where only the configured full paths exist."""
    files = config["filesystem"]["files"]
    config["filesystem"]["files"] = [f for f in files if f["mode"] == "full_path"]
    for se in load_emu(config, load_test_bin("dll_test_x86.dll.xz")):
        start_process(se)
        yield se


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


def test_lopen_and_lclose(strict_fs_emu: Speakeasy) -> None:
    se = strict_fs_emu
    hnd, _ = call(se, "kernel32", "_lopen", [alloc(se, BYTE_FILL_PATH.encode() + b"\x00"), 0])
    assert hnd not in (0, windefs.HFILE_ERROR)
    assert call(se, "kernel32", "_lclose", [hnd])[0] == 0
    assert call(se, "kernel32", "_lclose", [0x7FF0])[0] == windefs.HFILE_ERROR

    missing = alloc(se, b"c:\\no\\such\\file.bin\x00")
    assert call(se, "kernel32", "_lopen", [missing, 0])[0] == windefs.HFILE_ERROR


FILE_BEGIN, FILE_CURRENT, FILE_END = 0, 1, 2
CREATE_ALWAYS = 2


def test_set_file_pointer_on_first_open(strict_fs_emu: Speakeasy) -> None:
    hnd = open_file(strict_fs_emu, BYTE_FILL_PATH)
    assert call(strict_fs_emu, "kernel32", "SetFilePointer", [hnd, 0, 0, FILE_END])[0] == 512

    new = open_file(strict_fs_emu, "c:\\new.txt", CREATE_ALWAYS)
    assert call(strict_fs_emu, "kernel32", "SetFilePointer", [new, 0, 0, FILE_CURRENT])[0] == 0


def test_set_file_pointer_moves_back_from_the_end(emu: Speakeasy) -> None:
    hnd = open_file(emu, BYTE_FILL_PATH)
    assert call(emu, "kernel32", "SetFilePointer", [hnd, -4 & 0xFFFFFFFF, 0, FILE_END])[0] == 508

    buf = alloc(emu, b"\x00" * 16)
    read = alloc(emu, b"\xcc" * 4)
    assert call(emu, "kernel32", "ReadFile", [hnd, buf, 16, read, 0])[0]
    assert emu.mem_read(read, 4) == (4).to_bytes(4, "little")


def test_set_file_pointer_uses_the_high_part(emu: Speakeasy) -> None:
    hnd = open_file(emu, BYTE_FILL_PATH)
    high = alloc(emu, (-1 & 0xFFFFFFFF).to_bytes(4, "little"))
    assert call(emu, "kernel32", "SetFilePointer", [hnd, -8 & 0xFFFFFFFF, high, FILE_END])[0] == 504
    assert emu.mem_read(high, 4) == b"\x00" * 4


def test_set_file_pointer_fails_before_the_start(emu: Speakeasy) -> None:
    hnd = open_file(emu, BYTE_FILL_PATH)
    assert call(emu, "kernel32", "SetFilePointer", [hnd, -1 & 0xFFFFFFFF, 0, FILE_BEGIN])[0] == 0xFFFFFFFF
    assert last_error(emu) == windefs.ERROR_NEGATIVE_SEEK

    rv, _ = call(emu, "kernel32", "SetFilePointerEx", [hnd, 0xFFFFFFFF, 0xFFFFFFFF, 0, FILE_BEGIN])
    assert not rv
    assert last_error(emu) == windefs.ERROR_NEGATIVE_SEEK

    assert call(emu, "kernel32", "SetFilePointer", [0x7FF0, 0, 0, FILE_BEGIN])[0] == 0xFFFFFFFF
    assert last_error(emu) == windefs.ERROR_INVALID_HANDLE


def test_llseek(emu: Speakeasy) -> None:
    hnd = open_file(emu, BYTE_FILL_PATH)
    assert call(emu, "kernel32", "_llseek", [hnd, 0, FILE_END])[0] == 512
    assert call(emu, "kernel32", "_llseek", [hnd, 16, FILE_BEGIN])[0] == 16
    assert call(emu, "kernel32", "_llseek", [hnd, -4 & 0xFFFFFFFF, FILE_CURRENT])[0] == 12
    assert call(emu, "kernel32", "_llseek", [hnd, -1 & 0xFFFFFFFF, FILE_BEGIN])[0] == windefs.HFILE_ERROR
    assert call(emu, "kernel32", "_llseek", [0x7FF0, 0, FILE_BEGIN])[0] == windefs.HFILE_ERROR
