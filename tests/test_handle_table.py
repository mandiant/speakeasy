"""Handle values identify one object, and a bad handle fails the call like on Windows."""

import struct

import speakeasy.winenv.arch as _arch
from speakeasy import Speakeasy
from speakeasy.windows.handles import CURRENT_PROCESS_HANDLE, CURRENT_THREAD_HANDLE, InvalidHandle
from speakeasy.winenv.defs.enums import FILE_CREATION_DISPOSITION
from speakeasy.winenv.defs.nt import ddk
from speakeasy.winenv.defs.windows import windows as windefs
from tests.handler_harness import alloc, call, object_attributes, start_process

PAGE_READWRITE = 0x04
GENERIC_WRITE = 0x40000000
DUPLICATE_CLOSE_SOURCE = 0x1
DUPLICATE_SAME_ACCESS = 0x2
RET_ADDR = 0x41414141
BAD_HANDLE = 0x1234


def dispatch_x86(se: Speakeasy, dll: str, name: str, args: list[int]) -> int:
    """Call a stdcall API through import dispatch and return EAX."""
    emu = se.emu
    emu.set_func_args(emu.stack_base - 0x100, RET_ADDR, *args, conv=_arch.CALL_CONV_STDCALL)
    emu.reg_write(_arch.X86_REG_EIP, 0x1000)
    emu.dispatch_api_call(dll, name)
    assert emu.reg_read(_arch.X86_REG_EIP) == RET_ADDR
    return emu.reg_read(_arch.X86_REG_EAX)


def duplicate(se: Speakeasy, handle: int, options: int = DUPLICATE_SAME_ACCESS) -> int:
    out = alloc(se, b"\x00" * 4)
    rv, _ = call(
        se, "kernel32", "DuplicateHandle", [CURRENT_PROCESS_HANDLE, handle, CURRENT_PROCESS_HANDLE, out, 0, 0, options]
    )
    assert rv == 1
    return struct.unpack("<I", se.mem_read(out, 4))[0]


def test_handles_of_different_types_have_different_values(dll_emu: Speakeasy) -> None:
    # Each handle type had its own counter, and the kernel object counter reached the
    # first file mapping value after 24 handles.
    start_process(dll_emu)
    events = [call(dll_emu, "kernel32", "CreateEventA", [0, 1, 0, 0])[0] for _ in range(40)]
    hmap, _ = call(
        dll_emu, "kernel32", "CreateFileMappingA", [windefs.INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 0x1000, 0]
    )
    assert len(set(events + [hmap])) == 41


def test_close_of_a_bad_handle_sets_the_last_error(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    assert dispatch_x86(dll_emu, "kernel32", "CloseHandle", [BAD_HANDLE]) == 0
    assert dll_emu.emu.get_last_error() == windefs.ERROR_INVALID_HANDLE


def test_kernel_close_of_a_bad_handle_returns_the_status(driver_emu: Speakeasy) -> None:
    assert dispatch_x86(driver_emu, "ntoskrnl", "ZwClose", [BAD_HANDLE]) == ddk.STATUS_INVALID_HANDLE


def test_an_api_that_returns_its_error_returns_the_bad_handle_error(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    emu = dll_emu.emu
    module, _ = emu.get_api_handler("advapi32", "RegCloseKey")
    sig = emu.get_handler_signature("advapi32", "RegCloseKey", 1)
    emu.set_last_error(windefs.ERROR_SUCCESS)
    assert emu.fail_invalid_handle(module, None, sig, InvalidHandle(BAD_HANDLE)) == windefs.ERROR_INVALID_HANDLE
    assert emu.get_last_error() == windefs.ERROR_SUCCESS


def test_the_fail_value_of_the_apihook_is_the_return_value(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    emu = dll_emu.emu
    module, _ = emu.get_api_handler("kernel32", "CreateFileA")
    sig = emu.get_handler_signature("kernel32", "CreateFileA", 7)
    rv = emu.fail_invalid_handle(module, windefs.INVALID_HANDLE_VALUE, sig, InvalidHandle(BAD_HANDLE))
    assert rv == windefs.INVALID_HANDLE_VALUE
    assert emu.get_last_error() == windefs.ERROR_INVALID_HANDLE


def test_a_handle_is_closed_once(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    hnd, _ = call(dll_emu, "kernel32", "CreateEventA", [0, 1, 0, 0])
    assert call(dll_emu, "kernel32", "CloseHandle", [hnd])[0] == 1
    assert call(dll_emu, "kernel32", "SetEvent", [hnd])[0] == 0
    assert call(dll_emu, "kernel32", "CloseHandle", [hnd])[0] == 0
    assert dll_emu.emu.get_last_error() == windefs.ERROR_INVALID_HANDLE


def test_a_named_object_stays_open_while_a_handle_refers_to_it(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    name = alloc(dll_emu, b"evt\x00")
    first, _ = call(dll_emu, "kernel32", "CreateEventA", [0, 1, 0, name])
    second, _ = call(dll_emu, "kernel32", "CreateEventA", [0, 1, 0, name])
    assert dll_emu.emu.get_last_error() == windefs.ERROR_ALREADY_EXISTS
    assert first != second

    call(dll_emu, "kernel32", "CloseHandle", [first])
    assert call(dll_emu, "kernel32", "SetEvent", [second])[0] == 1
    third, _ = call(dll_emu, "kernel32", "OpenEventA", [0, 0, name])
    assert third != 0

    call(dll_emu, "kernel32", "CloseHandle", [second])
    call(dll_emu, "kernel32", "CloseHandle", [third])
    assert call(dll_emu, "kernel32", "OpenEventA", [0, 0, name])[0] == 0


def test_a_duplicate_refers_to_the_same_object(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    name = alloc(dll_emu, b"evt\x00")
    hnd, _ = call(dll_emu, "kernel32", "CreateEventA", [0, 1, 0, name])
    dup = duplicate(dll_emu, hnd)
    assert dup != hnd

    call(dll_emu, "kernel32", "CloseHandle", [hnd])
    assert call(dll_emu, "kernel32", "SetEvent", [dup])[0] == 1
    assert call(dll_emu, "kernel32", "OpenEventA", [0, 0, name])[0] != 0


def test_a_duplicate_can_close_the_source(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    hnd, _ = call(dll_emu, "kernel32", "CreateEventA", [0, 1, 0, 0])
    dup = duplicate(dll_emu, hnd, DUPLICATE_CLOSE_SOURCE)
    assert call(dll_emu, "kernel32", "CloseHandle", [hnd])[0] == 0
    assert call(dll_emu, "kernel32", "CloseHandle", [dup])[0] == 1


def test_a_duplicate_of_the_current_thread_is_a_real_handle(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    tid, _ = call(dll_emu, "kernel32", "GetCurrentThreadId", [])
    dup = duplicate(dll_emu, CURRENT_THREAD_HANDLE)
    assert dup != CURRENT_THREAD_HANDLE
    assert call(dll_emu, "kernel32", "GetThreadId", [dup])[0] == tid

    assert call(dll_emu, "kernel32", "CloseHandle", [dup])[0] == 1
    assert call(dll_emu, "kernel32", "GetThreadId", [duplicate(dll_emu, CURRENT_THREAD_HANDLE)])[0] == tid


def test_a_duplicate_of_a_bad_handle_fails(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    out = alloc(dll_emu, b"\x00" * 4)
    rv, _ = call(
        dll_emu,
        "kernel32",
        "DuplicateHandle",
        [CURRENT_PROCESS_HANDLE, BAD_HANDLE, CURRENT_PROCESS_HANDLE, out, 0, 0, DUPLICATE_SAME_ACCESS],
    )
    assert rv == 0
    assert dll_emu.emu.get_last_error() == windefs.ERROR_INVALID_HANDLE


def test_close_of_a_file_closes_the_file_handle(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    name = alloc(dll_emu, b"c:\\drop.bin\x00")
    written = alloc(dll_emu, b"\x00" * 4)
    hnd, _ = call(
        dll_emu, "kernel32", "CreateFileA", [name, GENERIC_WRITE, 0, 0, FILE_CREATION_DISPOSITION.CREATE_ALWAYS, 0, 0]
    )
    assert call(dll_emu, "kernel32", "WriteFile", [hnd, alloc(dll_emu, b"data"), 4, written, 0])[0] == 1

    assert call(dll_emu, "kernel32", "CloseHandle", [hnd])[0] == 1
    assert call(dll_emu, "kernel32", "CloseHandle", [hnd])[0] == 0
    assert dll_emu.emu.get_last_error() == windefs.ERROR_INVALID_HANDLE
    assert call(dll_emu, "kernel32", "GetFileSize", [hnd, 0])[0] == 0xFFFFFFFF


def test_kernel_close_of_a_registry_key_closes_the_key(driver_emu: Speakeasy) -> None:
    phnd = alloc(driver_emu, b"\x00" * 4)
    oa = object_attributes(driver_emu, "\\Registry\\Machine\\Software\\Contoso")
    assert call(driver_emu, "ntoskrnl", "ZwCreateKey", [phnd, 0xF003F, oa, 0, 0, 0, 0])[0] == ddk.STATUS_SUCCESS
    hkey = struct.unpack("<I", driver_emu.mem_read(phnd, 4))[0]

    assert call(driver_emu, "ntoskrnl", "ZwClose", [hkey])[0] == ddk.STATUS_SUCCESS
    assert call(driver_emu, "ntoskrnl", "ZwClose", [hkey])[0] == ddk.STATUS_INVALID_HANDLE


def test_close_of_a_wininet_connection_closes_its_requests(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    inet, _ = call(dll_emu, "wininet", "InternetOpenA", [0, 0, 0, 0, 0])
    server = alloc(dll_emu, b"example.com\x00")
    conn, _ = call(dll_emu, "wininet", "InternetConnectA", [inet, server, 80, 0, 0, 3, 0, 0])
    req, _ = call(dll_emu, "wininet", "HttpOpenRequestA", [conn, 0, alloc(dll_emu, b"/\x00"), 0, 0, 0, 0, 0])
    assert call(dll_emu, "wininet", "HttpSendRequestA", [req, 0, 0, 0, 0])[0] == 1

    assert call(dll_emu, "wininet", "InternetCloseHandle", [conn])[0] == 1
    assert call(dll_emu, "wininet", "HttpSendRequestA", [req, 0, 0, 0, 0])[0] == 0
    assert dll_emu.emu.get_last_error() == windefs.ERROR_INVALID_HANDLE
    assert call(dll_emu, "wininet", "InternetConnectA", [inet, server, 80, 0, 0, 3, 0, 0])[0]
