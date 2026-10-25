"""
kernel32 handlers return what Windows returns and write what Windows writes.
"""

import datetime
import struct
from collections.abc import Callable, Iterator
from typing import Any

import pytest
import unicorn

from speakeasy import Speakeasy
from speakeasy.config import get_default_config_dict
from speakeasy.winenv import arch as e_arch
from speakeasy.winenv.defs.windows import windows as windefs
from tests.guest_harness import get_api, guest_call
from tests.handler_harness import alloc, call, load_emu, start_process
from tests.pe_builder import build_pe


@pytest.fixture
def emu(dll_emu: Speakeasy) -> Speakeasy:
    start_process(dll_emu)
    return dll_emu


def load_strict_fs_emu(config: dict[str, Any], data: bytes) -> Iterator[Speakeasy]:
    """An emulator where only the configured full paths exist."""
    files = config["filesystem"]["files"]
    config["filesystem"]["files"] = [f for f in files if f["mode"] == "full_path"]
    for se in load_emu(config, data):
        start_process(se)
        yield se


@pytest.fixture
def strict_fs_emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> Iterator[Speakeasy]:
    yield from load_strict_fs_emu(config, load_test_bin("dll_test_x86.dll.xz"))


@pytest.fixture
def strict_fs_emu64(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> Iterator[Speakeasy]:
    yield from load_strict_fs_emu(config, load_test_bin("dll_test_x64.dll.xz"))


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


def test_default_temp_has_no_trailing_backslash_and_get_temp_path_adds_one(
    load_test_bin: Callable[[str], bytes],
) -> None:
    for se in load_emu(get_default_config_dict(), load_test_bin("dll_test_x86.dll.xz")):
        start_process(se)
        buf = alloc(se, b"\xcc" * 0x100)
        for name in ("TEMP", "TMP"):
            var = alloc(se, (name + "\x00").encode("utf-16le"))
            assert call(se, "kernel32", "GetEnvironmentVariableW", [var, buf, 0x40])[0] == 15
            assert se.mem_read(buf, 32) == "C:\\Windows\\temp\x00".encode("utf-16le")
        assert call(se, "kernel32", "GetTempPathW", [0x40, buf])[0] == 16
        assert se.mem_read(buf, 34) == "C:\\Windows\\temp\\\x00".encode("utf-16le")


@pytest.mark.parametrize("binary, arch", [("dll_test_x86.dll.xz", "x86"), ("dll_test_x64.dll.xz", "AMD64")])
def test_default_environment_has_path(load_test_bin: Callable[[str], bytes], binary: str, arch: str) -> None:
    for se in load_emu(get_default_config_dict(), load_test_bin(binary)):
        start_process(se)
        buf = alloc(se, b"\x00" * 0x1000)
        for name, value in [
            ("PATH", "C:\\Windows\\system32;C:\\Windows;"),
            ("PROCESSOR_ARCHITECTURE", arch),
            ("USERNAME", "speakeasy_user"),
            ("LOCALAPPDATA", "C:\\Users\\speakeasy_user\\AppData\\Local"),
        ]:
            var = alloc(se, (name + "\x00").encode("utf-16le"))
            rv, _ = call(se, "kernel32", "GetEnvironmentVariableW", [var, buf, 0x800])
            assert rv > 0
            assert se.mem_read(buf, rv * 2).decode("utf-16le").startswith(value)


GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
FILE_MAP_ALL_ACCESS = 0xF001F
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


LOCALE_SENGLISHCOUNTRYNAME = 0x1002


@pytest.mark.parametrize("name, width", [("GetLocaleInfoA", 1), ("GetLocaleInfoW", 2)])
def test_get_locale_info_counts_characters(emu: Speakeasy, name: str, width: int) -> None:
    enc = "utf-8" if width == 1 else "utf-16le"
    assert call(emu, "kernel32", name, [0x400, LOCALE_SENGLISHCOUNTRYNAME, 0, 0])[0] == 14

    small = alloc(emu, b"\xcc" * 4 * width)
    assert call(emu, "kernel32", name, [0x400, LOCALE_SENGLISHCOUNTRYNAME, small, 4])[0] == 0
    assert last_error(emu) == windefs.ERROR_INSUFFICIENT_BUFFER
    assert emu.mem_read(small, 4 * width) == b"\xcc" * 4 * width

    buf = alloc(emu, b"\xcc" * 32 * width)
    assert call(emu, "kernel32", name, [0x400, LOCALE_SENGLISHCOUNTRYNAME, buf, 32])[0] == 14
    assert emu.mem_read(buf, 14 * width) == "United States\x00".encode(enc)


@pytest.mark.parametrize("name", ["GetLongPathNameA", "GetLongPathNameW", "GetShortPathNameA", "GetShortPathNameW"])
def test_path_name_sizes(emu: Speakeasy, name: str) -> None:
    width = 1 if name.endswith("A") else 2
    enc = "utf-8" if width == 1 else "utf-16le"
    path = "C:\\WINDOWS\\A.TXT"
    src = alloc(emu, (path + "\x00").encode(enc))
    assert call(emu, "kernel32", name, [src, 0, 0])[0] == len(path) + 1

    small = alloc(emu, b"\xcc" * 4 * width)
    assert call(emu, "kernel32", name, [src, small, 4])[0] == len(path) + 1
    assert emu.mem_read(small, 4 * width) == b"\xcc" * 4 * width

    exact = alloc(emu, b"\xcc" * (len(path) + 1) * width)
    assert call(emu, "kernel32", name, [src, exact, len(path) + 1])[0] == len(path)
    assert emu.mem_read(exact, (len(path) + 1) * width) == (path + "\x00").encode(enc)


OPEN_ALWAYS = 4
TRUNCATE_EXISTING = 5


def test_create_file_open_always_reports_existing_files(strict_fs_emu: Speakeasy) -> None:
    se = strict_fs_emu
    set_last_error(se, windefs.ERROR_ALREADY_EXISTS)
    assert open_file(se, "c:\\marker.txt", OPEN_ALWAYS) != windefs.INVALID_HANDLE_VALUE
    assert last_error(se) == windefs.ERROR_SUCCESS

    assert open_file(se, "c:\\marker.txt", OPEN_ALWAYS) != windefs.INVALID_HANDLE_VALUE
    assert last_error(se) == windefs.ERROR_ALREADY_EXISTS


def test_create_file_truncate_existing(strict_fs_emu: Speakeasy) -> None:
    se = strict_fs_emu
    name = alloc(se, BYTE_FILL_PATH.encode() + b"\x00")
    hnd, displays = call(se, "kernel32", "CreateFileA", [name, GENERIC_READ, 0, 0, TRUNCATE_EXISTING, 0, 0])
    assert hnd != windefs.INVALID_HANDLE_VALUE
    assert displays["dwCreationDisposition"] == "TRUNCATE_EXISTING"

    assert open_file(se, "c:\\missing.txt", TRUNCATE_EXISTING) == windefs.INVALID_HANDLE_VALUE
    assert last_error(se) == windefs.ERROR_FILE_NOT_FOUND


MOVEFILE_REPLACE_EXISTING = 0x1
MOVEFILE_DELAY_UNTIL_REBOOT = 0x4


def move_file_ex(se: Speakeasy, src: str, dst: str | None, flags: int) -> int:
    src_name = alloc(se, src.encode() + b"\x00")
    dst_name = 0 if dst is None else alloc(se, dst.encode() + b"\x00")
    return call(se, "kernel32", "MoveFileExA", [src_name, dst_name, flags])[0]


def test_move_file_ex_moves_the_file(strict_fs_emu: Speakeasy) -> None:
    se = strict_fs_emu
    assert open_file(se, "c:\\src.txt", OPEN_ALWAYS) != windefs.INVALID_HANDLE_VALUE
    assert move_file_ex(se, "c:\\src.txt", "c:\\dst.txt", MOVEFILE_REPLACE_EXISTING) == 1
    assert open_file(se, "c:\\dst.txt") != windefs.INVALID_HANDLE_VALUE
    assert open_file(se, "c:\\src.txt") == windefs.INVALID_HANDLE_VALUE


def test_move_file_ex_replaces_only_with_the_flag(strict_fs_emu: Speakeasy) -> None:
    se = strict_fs_emu
    open_file(se, "c:\\src.txt", OPEN_ALWAYS)
    open_file(se, "c:\\dst.txt", OPEN_ALWAYS)
    assert move_file_ex(se, "c:\\src.txt", "c:\\dst.txt", 0) == 0
    assert last_error(se) == windefs.ERROR_ALREADY_EXISTS
    assert move_file_ex(se, "c:\\src.txt", "c:\\dst.txt", MOVEFILE_REPLACE_EXISTING) == 1


def test_move_file_ex_delete_on_reboot_keeps_the_file(strict_fs_emu: Speakeasy) -> None:
    se = strict_fs_emu
    open_file(se, "c:\\src.txt", OPEN_ALWAYS)
    assert move_file_ex(se, "c:\\src.txt", None, MOVEFILE_DELAY_UNTIL_REBOOT) == 1
    assert open_file(se, "c:\\src.txt") != windefs.INVALID_HANDLE_VALUE
    assert move_file_ex(se, "c:\\src.txt", None, 0) == 0
    assert last_error(se) == windefs.ERROR_INVALID_PARAMETER


def call_and_return(se: Speakeasy, dll: str, name: str, argv: list[int]) -> tuple[int, int]:
    """Call a handler, return to the caller, and give the result and the bytes popped from the stack."""
    emu = se.emu
    assert emu is not None and emu.api is not None
    _, func_attrs = emu.api.get_export_func_handler(dll, name)
    if not func_attrs:
        _, func_attrs = emu.normalize_import_miss(dll, name)
    _, _, argc, conv, _ = func_attrs
    esp = emu.reg_read(e_arch.X86_REG_ESP)
    rv, _ = call(se, dll, name, argv)
    emu.do_call_return(argc, 0x401000, rv, conv=conv)
    return rv, emu.reg_read(e_arch.X86_REG_ESP) - esp


def test_version_helpers_clean_the_stack(emu: Speakeasy) -> None:
    _, popped = call_and_return(emu, "kernel32", "VerSetConditionMask", [0, 0, 2, 3])
    assert popped == 4 + 16

    info = alloc(emu, b"\x00" * 284)
    rv, popped = call_and_return(emu, "kernel32", "VerifyVersionInfoW", [info, 2, 3 << 3, 0])
    assert rv
    assert popped == 4 + 16


def test_enum_processes_reports_bytes(emu: Speakeasy) -> None:
    assert emu.emu is not None
    count = len(emu.emu.get_processes())
    assert count > 1
    pids = alloc(emu, b"\x00" * 4 * 64)
    needed = alloc(emu, b"\xcc" * 4)
    assert call(emu, "kernel32", "EnumProcesses", [pids, 4 * 64, needed])[0]
    assert int.from_bytes(emu.mem_read(needed, 4), "little") == 4 * count

    assert call(emu, "kernel32", "EnumProcesses", [pids, 4 * 64, 0])[0]


def test_get_system_time_precise_as_file_time(emu: Speakeasy) -> None:
    ft = alloc(emu, b"\x00" * 8)
    call(emu, "kernel32", "GetSystemTimePreciseAsFileTime", [ft])
    ticks = int.from_bytes(emu.mem_read(ft, 8), "little")
    when = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ticks // 10)
    assert abs(when - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)) < datetime.timedelta(minutes=1)


def test_get_file_attributes_ex(strict_fs_emu: Speakeasy) -> None:
    se = strict_fs_emu
    name = alloc(se, BYTE_FILL_PATH.encode() + b"\x00")
    data = alloc(se, b"\xcc" * 36)
    assert call(se, "kernel32", "GetFileAttributesExA", [name, 0, data])[0]
    attrs, created, accessed, written, high, low = struct.unpack("<IQQQII", se.mem_read(data, 36))
    assert attrs == windefs.FILE_ATTRIBUTE_NORMAL
    assert (high, low) == (0, 512)
    assert created and accessed and written

    missing = alloc(se, b"c:\\missing.txt\x00")
    assert not call(se, "kernel32", "GetFileAttributesExA", [missing, 0, data])[0]
    assert last_error(se) == windefs.ERROR_FILE_NOT_FOUND


@pytest.mark.parametrize("api", ["GetFileAttributesA", "GetFileAttributesExA"])
def test_get_file_attributes_of_a_null_path_fails(emu: Speakeasy, api: str) -> None:
    argv = [0] if api == "GetFileAttributesA" else [0, 0, alloc(emu, b"\x00" * 36)]
    rv, _ = call(emu, "kernel32", api, argv)
    assert rv == (windefs.INVALID_FILE_ATTRIBUTES if api == "GetFileAttributesA" else 0)
    assert last_error(emu) == windefs.ERROR_PATH_NOT_FOUND


def test_remove_vectored_exception_handler(emu: Speakeasy) -> None:
    assert emu.emu is not None
    handle, _ = call(emu, "kernel32", "AddVectoredExceptionHandler", [1, 0x401000])
    assert 0x401000 in emu.emu.veh_handlers
    assert call(emu, "kernel32", "RemoveVectoredExceptionHandler", [handle])[0] != 0
    assert 0x401000 not in emu.emu.veh_handlers
    assert call(emu, "kernel32", "RemoveVectoredExceptionHandler", [handle])[0] == 0


ERROR_BAD_LENGTH = 24


@pytest.mark.parametrize(
    "fixture, info_class, size",
    [
        ("dll_emu", 1, 0x30),
        ("dll_emu", 2, 0x30),
        ("dll_emu", 9, 0x70),
        ("dll64_emu", 1, 0x30),
        ("dll64_emu", 2, 0x40),
        ("dll64_emu", 9, 0x90),
    ],
)
def test_query_information_job_object_reports_no_limits(
    request: pytest.FixtureRequest, fixture: str, info_class: int, size: int
) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    start_process(se)
    buf = alloc(se, b"\xcc" * (size + 8))
    length = alloc(se, b"\xcc" * 4)
    assert call(se, "kernel32", "QueryInformationJobObject", [0x1234, info_class, buf, size + 8, length])[0] == 1
    assert se.mem_read(buf, size + 8) == b"\x00" * size + b"\xcc" * 8
    assert struct.unpack("<I", se.mem_read(length, 4))[0] == size

    small = alloc(se, b"\xcc" * size)
    assert call(se, "kernel32", "QueryInformationJobObject", [0x1234, info_class, small, size - 1, 0])[0] == 0
    assert se.emu is not None
    assert se.emu.get_last_error() == ERROR_BAD_LENGTH
    assert se.mem_read(small, size) == b"\xcc" * size


@pytest.mark.parametrize(
    "name, width", [("GetTempPathA", 1), ("GetTempPathW", 2), ("GetTempPath2A", 1), ("GetTempPath2W", 2)]
)
def test_get_temp_path_sizes(emu: Speakeasy, name: str, width: int) -> None:
    enc = "utf-8" if width == 1 else "utf-16le"
    temp = "C:\\Windows\\temp\\"
    assert call(emu, "kernel32", name, [0, 0])[0] == len(temp) + 1

    small = alloc(emu, b"\xcc" * len(temp) * width)
    assert call(emu, "kernel32", name, [len(temp), small])[0] == len(temp) + 1
    assert emu.mem_read(small, len(temp) * width) == b"\xcc" * len(temp) * width

    buf = alloc(emu, b"\xcc" * (len(temp) + 1) * width)
    assert call(emu, "kernel32", name, [len(temp) + 1, buf])[0] == len(temp)
    assert emu.mem_read(buf, (len(temp) + 1) * width) == (temp + "\x00").encode(enc)


@pytest.mark.parametrize("fixture, size", [("dll_emu", 0x2CC), ("dll64_emu", 0x4D0)])
def test_rtl_capture_context_fills_one_context(request: pytest.FixtureRequest, fixture: str, size: int) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    assert se.emu is not None
    other = alloc(se, b"\xcc" * 0x600)
    se.emu.reg_write(e_arch.X86_REG_ECX if size == 0x2CC else e_arch.AMD64_REG_RCX, other)
    record = alloc(se, b"\xcc" * (size + 0x40))
    call(se, "kernel32", "RtlCaptureContext", [record])
    # ContextFlags is CONTEXT_FULL (with segments on x64), and the registers are the caller's
    if size == 0x2CC:
        assert int.from_bytes(se.mem_read(record, 4), "little") == 0x10007
        assert int.from_bytes(se.mem_read(record + 0xAC, 4), "little") == other
    else:
        assert int.from_bytes(se.mem_read(record + 0x30, 4), "little") == 0x10000F
        assert int.from_bytes(se.mem_read(record + 0x80, 8), "little") == other
    assert se.mem_read(record + size, 0x40) == b"\xcc" * 0x40
    assert se.mem_read(other, 0x600) == b"\xcc" * 0x600


def test_create_event_clears_a_stale_already_exists(emu: Speakeasy) -> None:
    name = alloc(emu, b"single-instance\x00")
    set_last_error(emu, windefs.ERROR_ALREADY_EXISTS)
    assert call(emu, "kernel32", "CreateEventA", [0, 1, 0, name])[0]
    assert last_error(emu) == windefs.ERROR_SUCCESS

    assert call(emu, "kernel32", "CreateEventA", [0, 1, 0, name])[0]
    assert last_error(emu) == windefs.ERROR_ALREADY_EXISTS


INFINITE = 0xFFFFFFFF


@pytest.fixture
def idle_emu(emu: Speakeasy) -> Speakeasy:
    """An emulator with no queued run, as when the last run executes."""
    emu.emu.run_queue.clear()
    return emu


def wait_one(se: Speakeasy, hnd: int, timeout: int = 500) -> int:
    return call(se, "kernel32", "WaitForSingleObject", [hnd, timeout])[0]


def wait_many(se: Speakeasy, handles: list[int], wait_all: int, timeout: int = 500) -> int:
    buf = alloc(se, struct.pack(f"<{len(handles)}I", *handles))
    return call(se, "kernel32", "WaitForMultipleObjects", [len(handles), buf, wait_all, timeout])[0]


def test_wait_times_out_on_an_unsignaled_event(idle_emu: Speakeasy) -> None:
    hnd, _ = call(idle_emu, "kernel32", "CreateEventA", [0, 0, 0, 0])
    before = call(idle_emu, "kernel32", "GetTickCount", [])[0]
    assert wait_many(idle_emu, [hnd], 0) == windefs.WAIT_TIMEOUT
    assert wait_one(idle_emu, hnd) == windefs.WAIT_TIMEOUT
    assert call(idle_emu, "kernel32", "GetTickCount", [])[0] - before >= 1000
    assert wait_one(idle_emu, hnd, INFINITE) == windefs.WAIT_OBJECT_0


def test_wait_resets_an_auto_reset_event(idle_emu: Speakeasy) -> None:
    hnd, _ = call(idle_emu, "kernel32", "CreateEventA", [0, 0, 0, 0])
    assert call(idle_emu, "kernel32", "SetEvent", [hnd])[0]
    assert wait_one(idle_emu, hnd) == windefs.WAIT_OBJECT_0
    assert wait_one(idle_emu, hnd) == windefs.WAIT_TIMEOUT

    hnd, _ = call(idle_emu, "kernel32", "CreateEventA", [0, 0, 1, 0])
    assert wait_many(idle_emu, [hnd], 0) == windefs.WAIT_OBJECT_0
    assert wait_many(idle_emu, [hnd], 0) == windefs.WAIT_TIMEOUT


def test_a_manual_reset_event_stays_signaled(idle_emu: Speakeasy) -> None:
    hnd, _ = call(idle_emu, "kernel32", "CreateEventA", [0, 1, 1, 0])
    assert wait_one(idle_emu, hnd) == windefs.WAIT_OBJECT_0
    assert wait_one(idle_emu, hnd) == windefs.WAIT_OBJECT_0
    assert call(idle_emu, "kernel32", "ResetEvent", [hnd])[0]
    assert wait_one(idle_emu, hnd) == windefs.WAIT_TIMEOUT
    assert call(idle_emu, "kernel32", "SetEvent", [hnd])[0]
    assert call(idle_emu, "kernel32", "PulseEvent", [hnd])[0]
    assert wait_one(idle_emu, hnd) == windefs.WAIT_TIMEOUT


@pytest.mark.parametrize("flags, results", [(0, [0x102]), (2, [0, 0x102]), (3, [0, 0])])
def test_create_event_ex_takes_the_state_from_the_flags(idle_emu: Speakeasy, flags: int, results: list[int]) -> None:
    hnd, _ = call(idle_emu, "kernel32", "CreateEventExA", [0, 0, flags, 0x1F0003])
    assert [wait_one(idle_emu, hnd) for _ in results] == results


def test_wait_for_multiple_objects_gives_the_first_signaled_event(idle_emu: Speakeasy) -> None:
    events = [call(idle_emu, "kernel32", "CreateEventA", [0, 0, 0, 0])[0] for _ in range(3)]
    call(idle_emu, "kernel32", "SetEvent", [events[1]])
    call(idle_emu, "kernel32", "SetEvent", [events[2]])
    assert wait_many(idle_emu, events, 1) == windefs.WAIT_TIMEOUT
    assert wait_many(idle_emu, events, 0) == windefs.WAIT_OBJECT_0 + 1
    assert wait_many(idle_emu, events, 0) == windefs.WAIT_OBJECT_0 + 2
    assert wait_many(idle_emu, events, 0) == windefs.WAIT_TIMEOUT

    for hnd in events:
        call(idle_emu, "kernel32", "SetEvent", [hnd])
    assert wait_many(idle_emu, events, 1) == windefs.WAIT_OBJECT_0
    assert wait_many(idle_emu, events, 0) == windefs.WAIT_TIMEOUT


def test_wait_returns_while_a_thread_is_queued(idle_emu: Speakeasy) -> None:
    hnd, _ = call(idle_emu, "kernel32", "CreateEventA", [0, 0, 0, 0])
    assert call(idle_emu, "kernel32", "CreateThread", [0, 0, 0x401000, 0, 0, 0])[0]
    assert wait_one(idle_emu, hnd) == windefs.WAIT_OBJECT_0
    assert wait_many(idle_emu, [hnd], 0) == windefs.WAIT_OBJECT_0


def test_wait_returns_for_a_thread(idle_emu: Speakeasy) -> None:
    thread, _ = call(idle_emu, "kernel32", "CreateThread", [0, 0, 0x401000, 0, windefs.CREATE_SUSPENDED, 0])
    assert wait_one(idle_emu, thread) == windefs.WAIT_OBJECT_0
    assert wait_many(idle_emu, [thread], 1) == windefs.WAIT_OBJECT_0


def test_find_files_set_the_last_error(strict_fs_emu: Speakeasy) -> None:
    se = strict_fs_emu
    data = alloc(se, b"\x00" * 0x200)
    pattern = alloc(se, b"c:\\programdata\\mydir\\*.bin\x00")
    hnd, _ = call(se, "kernel32", "FindFirstFileA", [pattern, data])
    assert hnd != windefs.INVALID_HANDLE_VALUE
    assert call(se, "kernel32", "FindNextFileA", [hnd, data])[0] == 0
    assert last_error(se) == windefs.ERROR_NO_MORE_FILES

    assert call(se, "kernel32", "FindNextFileA", [0x7FF0, data])[0] == 0
    assert last_error(se) == windefs.ERROR_INVALID_HANDLE

    nomatch = alloc(se, b"c:\\programdata\\mydir\\*.xyz\x00")
    assert call(se, "kernel32", "FindFirstFileA", [nomatch, data])[0] == windefs.INVALID_HANDLE_VALUE
    assert last_error(se) == windefs.ERROR_FILE_NOT_FOUND


@pytest.mark.parametrize("fixture, invalid", [("strict_fs_emu", 0xFFFFFFFF), ("strict_fs_emu64", 0xFFFFFFFFFFFFFFFF)])
def test_invalid_handle_value_is_pointer_sized(request: pytest.FixtureRequest, fixture: str, invalid: int) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    name = alloc(se, "c:\\missing.txt\x00".encode("utf-16le"))
    hnd, _ = call(se, "kernel32", "CreateFileW", [name, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0])
    assert hnd == invalid

    data = alloc(se, b"\x00" * 0x260)
    nomatch = alloc(se, "c:\\programdata\\mydir\\*.xyz\x00".encode("utf-16le"))
    assert call(se, "kernel32", "FindFirstFileW", [nomatch, data])[0] == invalid
    assert call(se, "kernel32", "FindFirstFileExW", [nomatch, 0, data, 0, 0, 0])[0] == invalid

    hmap, _ = call(se, "kernel32", "CreateFileMappingA", [invalid, 0, windefs.PAGE_READWRITE, 0, 0x1000, 0])
    view, _ = call(se, "kernel32", "MapViewOfFile", [hmap, FILE_MAP_ALL_ACCESS, 0, 0, 0])
    se.mem_write(view + 0xFF0, b"end")
    assert se.mem_read(view + 0xFF0, 3) == b"end"


def test_init_once_begin_initialize_sets_pending(emu: Speakeasy) -> None:
    init_once = alloc(emu, b"\x00" * 4)
    pending = alloc(emu, b"\xcc" * 4)
    assert call(emu, "kernel32", "InitOnceBeginInitialize", [init_once, 0, pending, 0])[0]
    assert emu.mem_read(pending, 4) == (1).to_bytes(4, "little")


def test_init_once_begin_initialize_check_only_does_not_start(emu: Speakeasy) -> None:
    init_once = alloc(emu, b"\x00" * 4)
    pending = alloc(emu, b"\xcc" * 4)
    assert call(emu, "kernel32", "InitOnceBeginInitialize", [init_once, 1, pending, 0])[0] == 0
    assert last_error(emu) == windefs.ERROR_GEN_FAILURE
    assert emu.mem_read(pending, 4) == b"\xcc" * 4


def test_init_once_complete_publishes_the_context(emu: Speakeasy) -> None:
    INIT_ONCE_CHECK_ONLY, INIT_ONCE_ASYNC = 1, 2
    init_once = alloc(emu, b"\x00" * 4)
    pending = alloc(emu, b"\xcc" * 4)
    context = alloc(emu, b"\xcc" * 4)
    assert call(emu, "kernel32", "InitOnceBeginInitialize", [init_once, INIT_ONCE_ASYNC, pending, 0])[0] == 1
    assert emu.mem_read(pending, 4) == struct.pack("<I", 1)
    assert call(emu, "kernel32", "InitOnceBeginInitialize", [init_once, INIT_ONCE_CHECK_ONLY, pending, context])[0] == 0
    assert last_error(emu) == windefs.ERROR_GEN_FAILURE

    assert call(emu, "kernel32", "InitOnceComplete", [init_once, INIT_ONCE_ASYNC, 0x6F05A000])[0] == 1
    assert call(emu, "kernel32", "InitOnceBeginInitialize", [init_once, INIT_ONCE_CHECK_ONLY, pending, context])[0] == 1
    assert emu.mem_read(pending, 4) == struct.pack("<I", 0)
    assert emu.mem_read(context, 4) == struct.pack("<I", 0x6F05A000)

    emu.mem_write(pending, b"\xcc" * 4)
    assert call(emu, "kernel32", "InitOnceBeginInitialize", [init_once, 0, pending, 0])[0] == 1
    assert emu.mem_read(pending, 4) == struct.pack("<I", 0)


def test_init_once_complete_with_init_failed_resets_the_state(emu: Speakeasy) -> None:
    INIT_ONCE_INIT_FAILED = 4
    init_once = alloc(emu, b"\x00" * 4)
    pending = alloc(emu, b"\xcc" * 4)
    assert call(emu, "kernel32", "InitOnceBeginInitialize", [init_once, 0, pending, 0])[0] == 1
    assert call(emu, "kernel32", "InitOnceComplete", [init_once, INIT_ONCE_INIT_FAILED, 0])[0] == 1
    assert emu.mem_read(init_once, 4) == b"\x00" * 4
    assert call(emu, "kernel32", "InitOnceBeginInitialize", [init_once, 0, pending, 0])[0] == 1
    assert emu.mem_read(pending, 4) == struct.pack("<I", 1)


def test_init_once_complete_rejects_a_context_with_low_bits(emu: Speakeasy) -> None:
    init_once = alloc(emu, b"\x00" * 4)
    pending = alloc(emu, b"\xcc" * 4)
    assert call(emu, "kernel32", "InitOnceBeginInitialize", [init_once, 0, pending, 0])[0] == 1
    assert call(emu, "kernel32", "InitOnceComplete", [init_once, 0, 0x6F05A001])[0] == 0
    assert last_error(emu) == windefs.ERROR_INVALID_PARAMETER


def test_queue_user_apc_returns_success(emu: Speakeasy) -> None:
    assert emu.emu is not None
    thread = emu.emu.get_object_handle(emu.emu.curr_thread)
    assert call(emu, "kernel32", "QueueUserAPC", [0x401000, thread, 0])[0]


@pytest.mark.parametrize("fixture, ptr", [("dll_emu", "I"), ("dll64_emu", "Q")])
@pytest.mark.parametrize("name", ["GetSystemInfo", "GetNativeSystemInfo"])
def test_get_system_info_fills_the_struct(request: pytest.FixtureRequest, fixture: str, ptr: str, name: str) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    layout = f"<HHI{ptr}{ptr}{ptr}IIIHH"
    info = alloc(se, b"\x00" * struct.calcsize(layout))
    call(se, "kernel32", name, [info])
    fields = struct.unpack(layout, se.mem_read(info, struct.calcsize(layout)))
    arch, _, page_size, min_addr, max_addr, mask, cpus, _, granularity, _, _ = fields
    assert arch == (0 if ptr == "I" else 9)
    assert page_size == 0x1000
    assert min_addr == 0x10000
    assert max_addr > 0x7FFE0000
    assert cpus >= 2
    assert mask == (1 << cpus) - 1
    assert granularity == 0x10000


@pytest.mark.parametrize("fixture, ptr", [("dll_emu", "I"), ("dll64_emu", "Q")])
def test_global_memory_status_fills_the_struct(request: pytest.FixtureRequest, fixture: str, ptr: str) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    layout = f"<II{ptr * 6}"
    status = alloc(se, b"\x00" * struct.calcsize(layout))
    call(se, "kernel32", "GlobalMemoryStatus", [status])
    length, load, total_phys, avail_phys, total_page, avail_page, total_virt, avail_virt = struct.unpack(
        layout, se.mem_read(status, struct.calcsize(layout))
    )
    assert length == struct.calcsize(layout)
    assert 0 < load <= 100
    assert 0 < avail_phys <= total_phys
    assert 0 < avail_page <= total_page
    assert 0 < avail_virt <= total_virt


@pytest.mark.parametrize("large_address_aware", [False, True])
def test_global_memory_status_clamps_for_a_32_bit_image(config: dict[str, Any], large_address_aware: bool) -> None:
    image = bytearray(build_pe(32)[0])
    if large_address_aware:
        image[0x96] |= 0x20
    for se in load_emu(config, bytes(image)):
        start_process(se)
        status = alloc(se, b"\x00" * 32)
        call(se, "kernel32", "GlobalMemoryStatus", [status])
        _, _, total_phys, avail_phys, total_page, _, total_virt, avail_virt = struct.unpack(
            "<8I", se.mem_read(status, 32)
        )
        limit = 0xFFFFFFFF if large_address_aware else 0x7FFFFFFF
        assert total_phys == limit
        assert avail_phys <= limit
        assert total_virt <= limit and avail_virt <= total_virt
        assert total_page == 0xFFFFFFFF


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
def test_global_memory_status_ex_returns_true(request: pytest.FixtureRequest, fixture: str) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    status = alloc(se, struct.pack("<I", 64) + b"\xcc" * 60)
    assert call(se, "kernel32", "GlobalMemoryStatusEx", [status])[0] == 1
    length, load, *sizes, extended = struct.unpack("<II7Q", se.mem_read(status, 64))
    total_phys, avail_phys, total_page, avail_page, total_virt, avail_virt = sizes
    assert length == 64
    assert 0 < load <= 100
    assert 0 < avail_phys <= total_phys
    assert 0 < avail_page <= total_page
    assert 0 < avail_virt <= total_virt
    assert extended == 0


def test_global_memory_status_ex_rejects_a_wrong_length(emu: Speakeasy) -> None:
    status = alloc(emu, struct.pack("<I", 32) + b"\xcc" * 60)
    assert call(emu, "kernel32", "GlobalMemoryStatusEx", [status])[0] == 0
    assert last_error(emu) == windefs.ERROR_INVALID_PARAMETER
    assert emu.mem_read(status + 4, 4) == b"\xcc" * 4


def test_get_disk_free_space_ex_writes_the_sizes(emu: Speakeasy) -> None:
    root = alloc(emu, b"C:\\\x00")
    caller, total, free = (alloc(emu, b"\x00" * 8) for _ in range(3))
    assert call(emu, "kernel32", "GetDiskFreeSpaceExA", [root, caller, total, free])[0]
    avail = int.from_bytes(emu.mem_read(caller, 8), "little")
    size = int.from_bytes(emu.mem_read(total, 8), "little")
    assert 0 < avail <= int.from_bytes(emu.mem_read(free, 8), "little") <= size

    assert call(emu, "kernel32", "GetDiskFreeSpaceExA", [root, 0, total, 0])[0]


@pytest.mark.parametrize("name, width", [("GetVolumeInformationA", 1), ("GetVolumeInformationW", 2)])
def test_get_volume_information_writes_the_out_params(emu: Speakeasy, name: str, width: int) -> None:
    enc = "utf-8" if width == 1 else "utf-16le"
    root = alloc(emu, "C:\\\x00".encode(enc))
    label = alloc(emu, b"\xcc" * 32 * width)
    serial, comp_len, flags = (alloc(emu, b"\x00" * 4) for _ in range(3))
    fs_name = alloc(emu, b"\xcc" * 32 * width)
    argv = [root, label, 32, serial, comp_len, flags, fs_name, 32]
    assert call(emu, "kernel32", name, argv)[0]
    assert emu.mem_read(label, width) == b"\x00" * width
    assert int.from_bytes(emu.mem_read(serial, 4), "little") != 0
    assert int.from_bytes(emu.mem_read(comp_len, 4), "little") == 255
    assert int.from_bytes(emu.mem_read(flags, 4), "little") != 0
    assert emu.mem_read(fs_name, 5 * width) == "NTFS\x00".encode(enc)

    assert call(emu, "kernel32", name, [root, 0, 0, serial, 0, 0, 0, 0])[0]


@pytest.mark.parametrize(
    "s1, n1, s2, n2, ignore_case, rv",
    [
        ("abc", -1, "abc", -1, 0, 2),
        ("abc", -1, "ABC", -1, 0, 3),
        ("abc", -1, "ABC", -1, 1, 2),
        ("ab", -1, "abc", -1, 0, 1),
        ("abcX", 3, "abcY", 3, 0, 2),
        ("a\0b", 3, "a\0c", 3, 0, 1),
        ("", 0, "", -1, 0, 2),
        ("é", -1, "É", -1, 1, 2),
    ],
)
def test_compare_string_ordinal_compares_code_units(
    dll_emu: Speakeasy, s1: str, n1: int, s2: str, n2: int, ignore_case: int, rv: int
) -> None:
    p1 = alloc(dll_emu, f"{s1}\0".encode("utf-16le"))
    p2 = alloc(dll_emu, f"{s2}\0".encode("utf-16le"))
    args = [p1, n1 & 0xFFFFFFFF, p2, n2 & 0xFFFFFFFF, ignore_case]
    assert call(dll_emu, "kernel32", "CompareStringOrdinal", args)[0] == rv


def test_compare_string_ordinal_rejects_a_negative_count(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    p = alloc(dll_emu, "a\0".encode("utf-16le"))
    assert call(dll_emu, "kernel32", "CompareStringOrdinal", [p, 0xFFFFFFFE, p, 1, 0])[0] == 0
    assert dll_emu.emu is not None
    assert dll_emu.emu.get_last_error() == windefs.ERROR_INVALID_PARAMETER


@pytest.mark.parametrize(
    "path, expected, rv",
    [
        ("C:\\a\\b.dll", "C:\\a", 0),
        ("C:\\Windows\\system32\\sample", "C:\\Windows\\system32", 0),
        ("C:\\b.dll", "C:\\", 0),
        ("C:\\", "C:\\", 1),
    ],
)
def test_path_cch_remove_file_spec_removes_the_last_element(emu: Speakeasy, path: str, expected: str, rv: int) -> None:
    buf = alloc(emu, f"{path}\0".encode("utf-16le") + b"\xcc" * 8)
    assert call(emu, "kernel32", "PathCchRemoveFileSpec", [buf, 260])[0] == rv
    assert emu.mem_read(buf, 2 * len(expected) + 2) == f"{expected}\0".encode("utf-16le")


def test_path_cch_remove_file_spec_rejects_a_null_path(emu: Speakeasy) -> None:
    assert call(emu, "kernel32", "PathCchRemoveFileSpec", [0, 260])[0] == windefs.E_INVALIDARG


APPMODEL_ERROR_NO_PACKAGE = 15700


@pytest.mark.parametrize(
    "name",
    ["GetCurrentPackageId", "GetCurrentPackageFamilyName", "GetCurrentPackageFullName", "GetCurrentPackagePath"],
)
def test_get_current_package_reports_an_unpackaged_process(emu: Speakeasy, name: str) -> None:
    length = alloc(emu, struct.pack("<I", 0x100))
    buf = alloc(emu, b"\xcc" * 0x200)
    assert call(emu, "kernel32", name, [length, buf])[0] == APPMODEL_ERROR_NO_PACKAGE
    assert emu.mem_read(length, 4) == b"\x00" * 4
    assert emu.mem_read(buf, 0x200) == b"\xcc" * 0x200


@pytest.mark.parametrize(
    "name, s1, n1, s2, n2, flags, rv",
    [
        ("CompareStringW", "username", -1, "USERNAME", -1, 1, 2),
        ("CompareStringA", "username", -1, "USERNAME", -1, 1, 2),
        ("CompareStringEx", "username", -1, "USERNAME", -1, 1, 2),
        ("CompareStringW", "a", -1, "b", -1, 0, 1),
        ("CompareStringA", "b", -1, "a", -1, 0, 3),
        ("CompareStringEx", "a", -1, "B", -1, 0, 1),
        ("CompareStringW", "abcX", 3, "ABCY", 3, 1, 2),
        ("CompareStringA", "ab", 2, "abc", -1, 0, 1),
    ],
)
def test_compare_string_compares_with_the_case_flag(
    dll_emu: Speakeasy, name: str, s1: str, n1: int, s2: str, n2: int, flags: int, rv: int
) -> None:
    enc = "latin-1" if name == "CompareStringA" else "utf-16le"
    p1 = alloc(dll_emu, f"{s1}\0".encode(enc))
    p2 = alloc(dll_emu, f"{s2}\0".encode(enc))
    args = [0, flags, p1, n1 & 0xFFFFFFFF, p2, n2 & 0xFFFFFFFF]
    if name == "CompareStringEx":
        args += [0, 0, 0]
    assert call(dll_emu, "kernel32", name, args)[0] == rv


def test_compare_string_rejects_a_null_string_with_a_count(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    p = alloc(dll_emu, "a\0".encode("utf-16le"))
    assert call(dll_emu, "kernel32", "CompareStringW", [0, 0, 0, 1, p, -1 & 0xFFFFFFFF])[0] == 0
    assert dll_emu.emu is not None
    assert dll_emu.emu.get_last_error() == windefs.ERROR_INVALID_PARAMETER


def test_init_once_execute_once_runs_the_init_function_once(base_config: dict[str, Any]) -> None:
    se = Speakeasy(config=base_config)
    try:
        sc = se.load_shellcode(data=b"\xc3" * 0x200, arch="x86")
        init_once, out, record, slot, fn = sc + 0x180, sc + 0x190, sc + 0x1A0, sc + 0x1B0, sc + 0x100

        def execute(result: int) -> bytes:
            return (
                b"\x6a\x00"  # push 0
                + b"\x68\x34\x12\x00\x00"  # push 0x1234
                + b"\x68"
                + struct.pack("<I", fn)
                + b"\x68"
                + struct.pack("<I", init_once)
                + b"\xff\x15"
                + struct.pack("<I", slot)  # call [slot]
                + b"\xa3"
                + struct.pack("<I", result)  # mov [result], eax
            )

        code = execute(out) + execute(out + 4) + b"\xc3"
        callback = (
            b"\xff\x05"
            + struct.pack("<I", record)  # inc dword [record]
            + b"\x8b\x44\x24\x08"  # mov eax, [esp+8]
            + b"\xa3"
            + struct.pack("<I", record + 4)  # mov [record+4], eax
            + b"\xb8\x01\x00\x00\x00"  # mov eax, 1
            + b"\xc2\x0c\x00"  # ret 0xc
        )
        se.mem_write(sc, code)
        se.mem_write(fn, callback)
        se.mem_write(init_once, b"\x00" * 0x30)
        se.mem_write(slot, struct.pack("<I", se.emu.get_proc("kernel32", "InitOnceExecuteOnce")))
        se.run_shellcode(sc)
        assert struct.unpack("<II", se.mem_read(record, 8)) == (1, 0x1234)
        assert struct.unpack("<II", se.mem_read(out, 8)) == (1, 1)
    finally:
        se.shutdown()


def test_virtual_alloc_commit_in_a_reservation_applies_the_protection(emu: Speakeasy) -> None:
    assert emu.emu is not None

    def permissions(address: int) -> int:
        return next(p for start, end, p in emu.emu.get_mem_regions() if start <= address <= end)

    base, _ = call(emu, "kernel32", "VirtualAlloc", [0, 0x100000, windefs.MEM_RESERVE, windefs.PAGE_NOACCESS])
    assert base
    assert permissions(base) == unicorn.UC_PROT_NONE
    committed, _ = call(
        emu, "kernel32", "VirtualAlloc", [base + 0x10, 0x4000, windefs.MEM_COMMIT, windefs.PAGE_READWRITE]
    )
    assert committed == base
    rw = unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE
    assert [permissions(base + offset) for offset in (0, 0x3FFC, 0x4010)] == [rw, rw, rw]
    assert permissions(base + 0x5000) == unicorn.UC_PROT_NONE


@pytest.mark.parametrize(
    "protect, expected",
    [
        (windefs.PAGE_WRITECOPY, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE),
        (windefs.PAGE_EXECUTE_WRITECOPY, unicorn.UC_PROT_ALL),
    ],
    ids=["PAGE_WRITECOPY", "PAGE_EXECUTE_WRITECOPY"],
)
def test_virtual_protect_write_copy_is_readable_and_writable(emu: Speakeasy, protect: int, expected: int) -> None:
    assert emu.emu is not None
    base, _ = call(emu, "kernel32", "VirtualAlloc", [0, 0x1000, windefs.MEM_COMMIT, windefs.PAGE_READONLY])
    old = alloc(emu, b"\x00" * 4)
    assert call(emu, "kernel32", "VirtualProtect", [base, 0x1000, protect, old])[0]
    assert next(p for start, end, p in emu.emu.get_mem_regions() if start <= base <= end) == expected


GENERIC_WRITE = 0x40000000


def test_writes_through_a_reopened_file_reach_the_file(strict_fs_emu: Speakeasy) -> None:
    se = strict_fs_emu
    name = alloc(se, b"c:\\drop.bin\x00")
    written = alloc(se, b"\x00" * 4)
    hnd, _ = call(se, "kernel32", "CreateFileA", [name, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0])
    call(se, "kernel32", "CloseHandle", [hnd])

    hnd, _ = call(se, "kernel32", "CreateFileA", [name, GENERIC_WRITE, 0, 0, OPEN_ALWAYS, 0, 0])
    assert call(se, "kernel32", "WriteFile", [hnd, alloc(se, b"MZ\x90\x00"), 4, written, 0])[0]
    call(se, "kernel32", "CloseHandle", [hnd])

    hnd = open_file(se, "c:\\drop.bin")
    buf = alloc(se, b"\x00" * 8)
    assert call(se, "kernel32", "ReadFile", [hnd, buf, 8, written, 0])[0]
    assert se.mem_read(buf, 4) == b"MZ\x90\x00"
    assert [f.get_contents() for f in se.get_dropped_files()] == [b"MZ\x90\x00"]


def test_write_file_writes_at_the_file_pointer(strict_fs_emu: Speakeasy) -> None:
    se = strict_fs_emu
    name = alloc(se, b"c:\\log.txt\x00")
    written = alloc(se, b"\x00" * 4)
    hnd, _ = call(se, "kernel32", "CreateFileA", [name, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0])
    assert call(se, "kernel32", "WriteFile", [hnd, alloc(se, b"AAAA"), 4, written, 0])[0]
    assert call(se, "kernel32", "SetFilePointer", [hnd, 1, 0, FILE_BEGIN])[0] == 1
    assert call(se, "kernel32", "WriteFile", [hnd, alloc(se, b"B"), 1, written, 0])[0]

    assert call(se, "kernel32", "SetFilePointer", [hnd, 0, 0, FILE_CURRENT])[0] == 2
    assert [f.get_contents() for f in se.get_dropped_files()] == [b"ABAA"]


def test_each_handle_to_a_file_has_its_own_position(strict_fs_emu: Speakeasy) -> None:
    se = strict_fs_emu
    first = open_file(se, BYTE_FILL_PATH)
    second = open_file(se, BYTE_FILL_PATH)
    assert call(se, "kernel32", "SetFilePointer", [first, 16, 0, FILE_BEGIN])[0] == 16
    assert call(se, "kernel32", "SetFilePointer", [second, 0, 0, FILE_CURRENT])[0] == 0


def test_get_file_type_tells_consoles_pipes_and_files_apart(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    for std in (0xFFFFFFF6, 0xFFFFFFF5, 0xFFFFFFF4):
        handle = call(dll_emu, "kernel32", "GetStdHandle", [std])[0]
        assert call(dll_emu, "kernel32", "GetFileType", [handle])[0] == 2

    pipes = alloc(dll_emu, b"\0" * 16)
    assert call(dll_emu, "kernel32", "CreatePipe", [pipes, pipes + 8, 0, 0])[0] == 1
    read_pipe = struct.unpack("<I", dll_emu.mem_read(pipes, 4))[0]
    assert call(dll_emu, "kernel32", "GetFileType", [read_pipe])[0] == 3

    path = alloc(dll_emu, b"C:\\Windows\\Temp\\type.txt\0")
    handle = call(dll_emu, "kernel32", "CreateFileA", [path, 0x40000000, 0, 0, 2, 0x80, 0])[0]
    assert call(dll_emu, "kernel32", "GetFileType", [handle])[0] == 1


@pytest.mark.parametrize(("api", "text"), [("WriteConsoleA", b"hi\n"), ("WriteConsoleW", "hi\n".encode("utf-16le"))])
def test_write_console_reports_the_characters_written(dll_emu: Speakeasy, api: str, text: bytes) -> None:
    start_process(dll_emu)
    out = call(dll_emu, "kernel32", "GetStdHandle", [0xFFFFFFF5])[0]
    written = alloc(dll_emu, b"\0" * 4)
    buf = alloc(dll_emu, text)

    rv, args = call(dll_emu, "kernel32", api, [out, buf, 3, written, 0])

    assert rv == 1
    assert struct.unpack("<I", dll_emu.mem_read(written, 4))[0] == 3
    assert "hi" in args["lpBuffer"]


def test_get_console_mode_writes_a_mode(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    out = call(dll_emu, "kernel32", "GetStdHandle", [0xFFFFFFF5])[0]
    mode = alloc(dll_emu, b"\xff" * 4)

    assert call(dll_emu, "kernel32", "GetConsoleMode", [out, mode])[0] == 1
    assert struct.unpack("<I", dll_emu.mem_read(mode, 4))[0] == 3
    assert call(dll_emu, "kernel32", "GetConsoleOutputCP", [])[0] == 437


def test_a_file_created_by_a_relative_path_is_found_again(strict_fs_emu: Speakeasy) -> None:
    se = strict_fs_emu
    name = alloc(se, b"out.txt\x00")
    written = alloc(se, b"\x00" * 4)
    for _ in range(2):
        hnd, _ = call(se, "kernel32", "CreateFileA", [name, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0])
        assert call(se, "kernel32", "WriteFile", [hnd, alloc(se, b"data"), 4, written, 0])[0]
        call(se, "kernel32", "CloseHandle", [hnd])
    assert [f.path for f in se.get_dropped_files()] == ["C:\\Windows\\system32\\out.txt"]

    for path in ("out.txt", "c:\\windows\\system32\\OUT.TXT"):
        hnd = open_file(se, path)
        buf = alloc(se, b"\x00" * 8)
        assert call(se, "kernel32", "ReadFile", [hnd, buf, 8, written, 0])[0]
        assert se.mem_read(buf, 4) == b"data"

    assert call(se, "kernel32", "DeleteFileA", [name])[0]
    assert open_file(se, "out.txt") == windefs.INVALID_HANDLE_VALUE


FILE_APPEND_DATA = 0x4


def test_writes_to_an_append_only_handle_go_to_the_end(strict_fs_emu: Speakeasy) -> None:
    se = strict_fs_emu
    name = alloc(se, b"c:\\log.txt\x00")
    written = alloc(se, b"\x00" * 4)
    hnd, _ = call(se, "kernel32", "CreateFileA", [name, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0])
    assert call(se, "kernel32", "WriteFile", [hnd, alloc(se, b"AAAA"), 4, written, 0])[0]
    call(se, "kernel32", "CloseHandle", [hnd])

    hnd, _ = call(se, "kernel32", "CreateFileA", [name, FILE_APPEND_DATA, 0, 0, OPEN_EXISTING, 0, 0])
    assert call(se, "kernel32", "WriteFile", [hnd, alloc(se, b"B"), 1, written, 0])[0]
    assert call(se, "kernel32", "SetFilePointer", [hnd, 0, 0, FILE_BEGIN])[0] == 0
    assert call(se, "kernel32", "WriteFile", [hnd, alloc(se, b"C"), 1, written, 0])[0]
    call(se, "kernel32", "CloseHandle", [hnd])

    hnd, _ = call(se, "kernel32", "CreateFileA", [name, GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0])
    assert call(se, "kernel32", "WriteFile", [hnd, alloc(se, b"D"), 1, written, 0])[0]
    assert [f.get_contents() for f in se.get_dropped_files()] == [b"DAAABC"]


def test_thread_ids_agree(emu: Speakeasy) -> None:
    assert emu.emu is not None
    tid = alloc(emu, b"\x00" * 4)
    hnd, _ = call(emu, "kernel32", "CreateThread", [0, 0, 0x401000, 0, 0, tid])
    run = emu.emu.run_queue[-1]
    assert run.thread.tid == int.from_bytes(emu.mem_read(tid, 4), "little")
    assert call(emu, "kernel32", "GetThreadId", [hnd])[0] == run.thread.tid

    cmd = alloc(emu, b"C:\\Windows\\system32\\notepad.exe\x00")
    si = alloc(emu, b"\x00" * 0x44)
    pi = alloc(emu, b"\x00" * 0x10)
    assert call(emu, "kernel32", "CreateProcessA", [0, cmd, 0, 0, 0, 0, 0, 0, si, pi])[0]
    _, hthread, _, dwThreadId = struct.unpack("<4I", emu.mem_read(pi, 16))
    assert call(emu, "kernel32", "GetThreadId", [hthread])[0] == dwThreadId


def get_system_time(se: Speakeasy, api: str) -> datetime.datetime:
    st = alloc(se, b"\x00" * 16)
    call(se, "kernel32", api, [st])
    year, month, day_of_week, day, hour, minute, second, ms = struct.unpack("<8H", se.mem_read(st, 16))
    when = datetime.datetime(year, month, day, hour, minute, second, ms * 1000)
    assert day_of_week == (when.weekday() + 1) % 7
    return when


def get_file_time(se: Speakeasy) -> int:
    ft = alloc(se, b"\x00" * 8)
    call(se, "kernel32", "GetSystemTimeAsFileTime", [ft])
    return int.from_bytes(se.mem_read(ft, 8), "little")


def test_system_time_follows_the_emulated_clock(emu: Speakeasy) -> None:
    times = [get_system_time(emu, "GetLocalTime") for _ in range(3)]
    assert times == sorted(set(times))

    utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    assert abs(get_system_time(emu, "GetSystemTime") - utc) < datetime.timedelta(minutes=1)

    ft = get_file_time(emu)
    from_ft = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)
    assert datetime.timedelta(0) < get_system_time(emu, "GetSystemTime") - from_ft < datetime.timedelta(seconds=1)
    assert get_file_time(emu) > ft


@pytest.mark.parametrize("api, argv", [("Sleep", [30000]), ("SleepEx", [30000, 0])])
def test_sleep_advances_the_clocks(emu: Speakeasy, api: str, argv: list[int]) -> None:
    counter = alloc(emu, b"\x00" * 8)

    def query_counter() -> int:
        call(emu, "kernel32", "QueryPerformanceCounter", [counter])
        return int.from_bytes(emu.mem_read(counter, 8), "little")

    ticks, perf, ft = call(emu, "kernel32", "GetTickCount", [])[0], query_counter(), get_file_time(emu)
    call(emu, "kernel32", api, argv)
    assert 30000 <= call(emu, "kernel32", "GetTickCount", [])[0] - ticks < 31000
    assert query_counter() - perf == 30000 * 10_000_000 // 1000
    assert 30000 * 10000 <= get_file_time(emu) - ft < 31000 * 10000


@pytest.mark.parametrize("arch", ["x86", "amd64"])
def test_sleep_advances_the_time_stamp_counter(config: dict[str, Any], arch: str) -> None:
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch=arch)
        data = se.mem_alloc(0x1000)
        if arch == "x86":
            ptr_size = 4

            def store_tsc(address: int) -> bytes:
                # rdtsc; mov [address], eax; mov [address + 4], edx
                return b"\x0f\x31\xa3" + struct.pack("<I", address) + b"\x89\x15" + struct.pack("<I", address + 4)
        else:
            ptr_size = 8

            def store_tsc(address: int) -> bytes:
                # rdtsc; shl rdx, 32; or rax, rdx; mov [address], rax
                return b"\x0f\x31\x48\xc1\xe2\x20\x48\x09\xd0\x48\xa3" + struct.pack("<Q", address)

        sleep = guest_call(ptr_size, get_api(se, "kernel32", "Sleep"), 50)
        se.mem_write(code, store_tsc(data) + sleep + store_tsc(data + 8) + b"\xc3")

        se.run_shellcode(code)

        assert se.get_report().entry_points[0].error is None
        before, after = struct.unpack("<QQ", se.mem_read(data, 16))
        assert after - before >= 50 * 1_000_000


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
def test_current_thread_pseudo_handle(request: pytest.FixtureRequest, fixture: str) -> None:
    se = request.getfixturevalue(fixture)
    start_process(se)
    assert se.emu is not None
    pseudo = (1 << (8 * se.emu.get_ptr_size())) - 2
    assert call(se, "kernel32", "GetCurrentThread", [])[0] == pseudo

    tid = call(se, "kernel32", "GetCurrentThreadId", [])[0]
    assert call(se, "kernel32", "GetThreadId", [pseudo])[0] == tid
    assert call(se, "kernel32", "SetThreadPriority", [pseudo, 2])[0]
    runs = len(se.emu.run_queue)
    assert call(se, "kernel32", "ResumeThread", [pseudo])[0] == 0
    assert call(se, "kernel32", "ResumeThread", [call(se, "kernel32", "OpenThread", [0x1F03FF, 0, tid])[0]])[0] == 0
    assert len(se.emu.run_queue) == runs

    token = alloc(se, b"\x00" * 8)
    assert call(se, "advapi32", "OpenThreadToken", [pseudo, 8, 0, token])[0]

    target = alloc(se, b"\x00" * 8)
    process = (1 << (8 * se.emu.get_ptr_size())) - 1
    assert call(se, "kernel32", "DuplicateHandle", [process, pseudo, process, target, 0, 0, 2])[0]
    duplicate = int.from_bytes(se.mem_read(target, se.emu.get_ptr_size()), "little")
    assert call(se, "kernel32", "GetThreadId", [duplicate])[0] == tid


def test_resume_thread_starts_a_suspended_thread_once(emu: Speakeasy) -> None:
    assert emu.emu is not None
    runs = len(emu.emu.run_queue)
    hnd, _ = call(emu, "kernel32", "CreateThread", [0, 0, 0x401000, 0, windefs.CREATE_SUSPENDED, 0])
    assert call(emu, "kernel32", "SuspendThread", [hnd])[0] == 1
    assert call(emu, "kernel32", "ResumeThread", [hnd])[0] == 2
    assert len(emu.emu.run_queue) == runs
    assert call(emu, "kernel32", "ResumeThread", [hnd])[0] == 1
    assert len(emu.emu.run_queue) == runs + 1
    assert call(emu, "kernel32", "ResumeThread", [hnd])[0] == 0
    assert len(emu.emu.run_queue) == runs + 1


@pytest.mark.parametrize(
    "path, attrs",
    [
        ("C:\\Windows", windefs.FILE_ATTRIBUTE_DIRECTORY),
        ("c:\\windows\\system32\\", windefs.FILE_ATTRIBUTE_DIRECTORY),
        ("C:\\", windefs.FILE_ATTRIBUTE_DIRECTORY),
        (".", windefs.FILE_ATTRIBUTE_DIRECTORY),
        ("..", windefs.FILE_ATTRIBUTE_DIRECTORY),
        ("C:\\ProgramData\\mydir", windefs.FILE_ATTRIBUTE_DIRECTORY),
        (BYTE_FILL_PATH, windefs.FILE_ATTRIBUTE_NORMAL),
        ("C:\\Windows\\system32\\cmd.exe", windefs.FILE_ATTRIBUTE_NORMAL),
        ("C:\\nodir\\", windefs.INVALID_FILE_ATTRIBUTES),
        ("C:\\ProgramData\\mydir\\myfile.bin\\sub", windefs.INVALID_FILE_ATTRIBUTES),
    ],
)
@pytest.mark.parametrize("cw", ["A", "W"])
def test_get_file_attributes_knows_directories(strict_fs_emu: Speakeasy, cw: str, path: str, attrs: int) -> None:
    se = strict_fs_emu
    name = alloc(se, (path + "\x00").encode("utf-16le" if cw == "W" else "latin-1"))
    assert call(se, "kernel32", f"GetFileAttributes{cw}", [name])[0] == attrs

    data = alloc(se, b"\xcc" * 36)
    ok, _ = call(se, "kernel32", f"GetFileAttributesEx{cw}", [name, 0, data])
    assert ok == (attrs != windefs.INVALID_FILE_ATTRIBUTES)
    if attrs == windefs.FILE_ATTRIBUTE_DIRECTORY:
        found, *_, high, low = struct.unpack("<IQQQII", se.mem_read(data, 36))
        assert (found, high, low) == (attrs, 0, 0)


def test_get_file_attributes_knows_the_environment_directories(
    config: dict[str, Any], load_test_bin: Callable[[str], bytes]
) -> None:
    config["env"]["temp"] = "C:\\Users\\user\\AppData\\Local\\Temp\\"
    config["env"]["path"] = "C:\\Tools\\bin;C:\\Python"
    for se in load_strict_fs_emu(config, load_test_bin("dll_test_x86.dll.xz")):
        for path in ("C:\\Users\\user\\AppData", "C:\\Tools\\bin\\", "C:\\Python"):
            name = alloc(se, path.encode() + b"\x00")
            assert call(se, "kernel32", "GetFileAttributesA", [name])[0] == windefs.FILE_ATTRIBUTE_DIRECTORY


PROGRAM_FILES_APP = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"


@pytest.mark.parametrize(
    "dll, api, app, cmdline, path",
    [
        ("kernel32", "CreateProcessA", PROGRAM_FILES_APP, None, PROGRAM_FILES_APP),
        ("kernel32", "CreateProcessA", PROGRAM_FILES_APP, "msedge.exe --x", PROGRAM_FILES_APP),
        ("kernel32", "CreateProcessA", f'"{PROGRAM_FILES_APP}"', None, PROGRAM_FILES_APP),
        ("kernel32", "CreateProcessA", None, f'"{PROGRAM_FILES_APP}" --x', PROGRAM_FILES_APP),
        ("advapi32", "CreateProcessAsUserA", PROGRAM_FILES_APP, None, PROGRAM_FILES_APP),
        ("advapi32", "CreateProcessAsUserA", None, f'"{PROGRAM_FILES_APP}" --x', PROGRAM_FILES_APP),
    ],
)
def test_create_process_uses_the_application_name_as_the_path(
    emu: Speakeasy, dll: str, api: str, app: str | None, cmdline: str | None, path: str
) -> None:
    assert emu.emu is not None
    si = alloc(emu, b"\x00" * 0x44)
    pi = alloc(emu, b"\x00" * 0x10)
    argv = [
        alloc(emu, app.encode() + b"\x00") if app else 0,
        alloc(emu, cmdline.encode() + b"\x00") if cmdline else 0,
        *[0] * 6,
        si,
        pi,
    ]
    if dll == "advapi32":
        argv.insert(0, 0)
    assert call(emu, dll, api, argv)[0]
    hproc = int.from_bytes(emu.mem_read(pi, 4), "little")
    proc = emu.emu.get_object_from_handle(hproc)
    assert proc.path == path
    assert proc.cmdline == (cmdline or "")


def test_shell_execute_uses_the_file_as_the_path(emu: Speakeasy) -> None:
    assert emu.emu is not None
    fn = alloc(emu, PROGRAM_FILES_APP.encode() + b"\x00")
    params = alloc(emu, b"--app=http://127.0.0.1:27870/\x00")
    assert call(emu, "shell32", "ShellExecuteA", [0, 0, fn, params, 0, 1])[0] == 33
    proc = emu.emu.processes[-1]
    assert (proc.path, proc.cmdline) == (PROGRAM_FILES_APP, "--app=http://127.0.0.1:27870/")


def test_win_exec_parses_the_command_line(emu: Speakeasy) -> None:
    assert emu.emu is not None
    cmd = alloc(emu, f'"{PROGRAM_FILES_APP}" --x\x00'.encode())
    assert call(emu, "kernel32", "WinExec", [cmd, 1])[0] == 32
    assert emu.emu.processes[-1].path == PROGRAM_FILES_APP


def get_open_file_size(se: Speakeasy, path: str) -> int:
    hnd = open_file(se, path)
    assert hnd
    return call(se, "kernel32", "GetFileSize", [hnd, 0])[0]


def test_the_host_exe_of_a_dll_run_is_not_the_sample(emu: Speakeasy, load_test_bin: Callable[[str], bytes]) -> None:
    buf = alloc(emu, b"\x00" * 260)
    size, _ = call(emu, "kernel32", "GetModuleFileNameA", [0, buf, 260])
    host = emu.mem_read(buf, size).decode()

    dll_size = len(load_test_bin("dll_test_x86.dll.xz"))
    assert get_open_file_size(emu, host) != dll_size
    assert get_open_file_size(emu, "svchost.exe") != dll_size
    assert get_open_file_size(emu, "C:\\Windows\\system32\\svchost.exe.log") != dll_size


def test_an_exe_finds_itself_by_its_command_line_name(
    config: dict[str, Any], load_test_bin: Callable[[str], bytes]
) -> None:
    data = load_test_bin("argv_test_x86.exe.xz")
    for se in load_emu(config, data):
        start_process(se)
        assert get_open_file_size(se, "svchost.exe") == len(data)
        assert get_open_file_size(se, "C:\\Windows\\system32\\svchost.exe") == len(data)
        assert get_open_file_size(se, "C:\\Windows\\system32\\svchost.exe.log") != len(data)


def wide(se: Speakeasy, text: str) -> int:
    return alloc(se, (text + "\x00").encode("utf-16le"))


def test_a_deleted_file_is_gone_until_it_is_created_again(emu: Speakeasy) -> None:
    assert emu.emu is not None
    sample = wide(emu, emu.emu.modules[0].emu_path)
    dst = wide(emu, "C:\\tmp\\x\\a.exe")

    assert call(emu, "kernel32", "DeleteFileW", [dst])[0] == 1
    assert call(emu, "kernel32", "GetFileAttributesW", [dst])[0] == windefs.INVALID_FILE_ATTRIBUTES
    assert last_error(emu) == windefs.ERROR_FILE_NOT_FOUND
    assert call(emu, "kernel32", "DeleteFileW", [dst])[0] == 0
    assert open_file(emu, "C:\\tmp\\x\\a.exe") == windefs.INVALID_HANDLE_VALUE

    assert call(emu, "kernel32", "CopyFileW", [sample, dst, 1])[0] == 1
    assert call(emu, "kernel32", "GetFileAttributesW", [dst])[0] == windefs.FILE_ATTRIBUTE_NORMAL
    assert call(emu, "kernel32", "CopyFileW", [sample, dst, 1])[0] == 0
    assert last_error(emu) == windefs.ERROR_FILE_EXISTS

    assert call(emu, "kernel32", "DeleteFileW", [dst])[0] == 1
    assert open_file(emu, "C:\\tmp\\x\\a.exe", windefs.CREATE_NEW) != windefs.INVALID_HANDLE_VALUE
    assert call(emu, "kernel32", "GetFileAttributesW", [dst])[0] == windefs.FILE_ATTRIBUTE_NORMAL


def test_fail_if_exists_ignores_the_extension_and_default_handlers(emu: Speakeasy) -> None:
    assert emu.emu is not None
    sample = wide(emu, emu.emu.modules[0].emu_path)

    assert call(emu, "kernel32", "CopyFileW", [sample, wide(emu, "C:\\tmp\\y\\b.exe"), 1])[0] == 1
    assert open_file(emu, "C:\\tmp\\y\\c.exe", windefs.CREATE_NEW) != windefs.INVALID_HANDLE_VALUE
    assert open_file(emu, "C:\\tmp\\y\\c.exe", windefs.CREATE_NEW) == windefs.INVALID_HANDLE_VALUE
    assert last_error(emu) == windefs.ERROR_FILE_EXISTS

    assert call(emu, "kernel32", "CopyFileW", [sample, wide(emu, "C:\\Windows\\system32\\cmd.exe"), 1])[0] == 0
    assert last_error(emu) == windefs.ERROR_FILE_EXISTS
    assert open_file(emu, BYTE_FILL_PATH, windefs.CREATE_NEW) == windefs.INVALID_HANDLE_VALUE
    assert last_error(emu) == windefs.ERROR_FILE_EXISTS


@pytest.mark.parametrize("name, width", [("GetLogicalDriveStringsA", 1), ("GetLogicalDriveStringsW", 2)])
def test_get_logical_drive_strings_lists_the_drive_roots(emu: Speakeasy, name: str, width: int) -> None:
    enc = "utf-8" if width == 1 else "utf-16le"
    mask, _ = call(emu, "kernel32", "GetLogicalDrives", [])
    roots = "".join(f"{chr(ord('A') + i)}:\\\0" for i in range(26) if mask & (1 << i))
    assert roots.startswith("C:\\\0")
    chars = len(roots)

    buf = alloc(emu, b"\xcc" * (chars + 1) * width)
    assert call(emu, "kernel32", name, [chars + 1, buf])[0] == chars
    assert emu.mem_read(buf, (chars + 1) * width) == (roots + "\0").encode(enc)

    small = alloc(emu, b"\xcc" * chars * width)
    assert call(emu, "kernel32", name, [chars, small])[0] == chars + 1
    assert emu.mem_read(small, chars * width) == b"\xcc" * chars * width
    assert call(emu, "kernel32", name, [0, 0])[0] == chars + 1


def test_get_process_times_gives_a_creation_time_before_now(emu: Speakeasy) -> None:
    times = alloc(emu, b"\xcc" * 32)
    rv, _ = call(emu, "kernel32", "GetProcessTimes", [0xFFFFFFFF, times, times + 8, times + 16, times + 24])
    assert rv == 1
    creation, exit_time, kernel, user = struct.unpack("<4Q", emu.mem_read(times, 32))
    now = alloc(emu, b"\x00" * 8)
    call(emu, "kernel32", "GetSystemTimeAsFileTime", [now])
    assert 0 < creation < struct.unpack("<Q", emu.mem_read(now, 8))[0]
    assert exit_time == 0
    assert kernel < 0xCCCCCCCCCCCCCCCC and user < 0xCCCCCCCCCCCCCCCC


def test_get_process_times_rejects_an_unknown_handle(emu: Speakeasy) -> None:
    times = alloc(emu, b"\xcc" * 32)
    assert call(emu, "kernel32", "GetProcessTimes", [0x1234, times, times + 8, times + 16, times + 24])[0] == 0
    assert last_error(emu) == windefs.ERROR_INVALID_HANDLE
