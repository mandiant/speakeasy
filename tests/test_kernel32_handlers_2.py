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
from speakeasy.winenv import arch as e_arch
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

    info = alloc(emu, b"\x00" * 0x9C)
    rv, popped = call_and_return(emu, "kernel32", "VerifyVersionInfoW", [info, 2, 0, 0])
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


@pytest.mark.parametrize("name, width", [("GetTempPathA", 1), ("GetTempPathW", 2)])
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
    if size == 0x2CC:
        assert se.mem_read(record, size) == b"\x00" * size
    else:
        # ContextFlags is CONTEXT_FULL | CONTEXT_SEGMENTS, and the registers are the caller's
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
