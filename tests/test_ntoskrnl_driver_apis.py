"""
Kernel APIs that corpus drivers import: registry keys, IRPs, I/O space,
feature staging, string helpers, and bug checks.
"""

import struct
from typing import Any

import pytest

import speakeasy.winenv.defs.nt.ddk as ddk
import speakeasy.winenv.defs.nt.ntoskrnl as ntdefs
import speakeasy.winenv.defs.registry.reg as regdefs
from speakeasy import Speakeasy
from speakeasy.profiler import Run
from speakeasy.profiler_events import RegCreateKeyEvent, RegWriteValueEvent
from tests.handler_harness import alloc, call
from tests.test_ntoskrnl_handlers import CDECL, STDCALL, call_x86

SOFTWARE_KEY = "\\Registry\\Machine\\Software\\Contoso"
IOCTL_BUFFERED = 0x222000
IOCTL_NEITHER = 0x222003


@pytest.fixture(params=["x86", "x64"])
def any_driver_emu(request: pytest.FixtureRequest) -> Speakeasy:
    se: Speakeasy = request.getfixturevalue("driver_emu" if request.param == "x86" else "driver64_emu")
    return se


def _ptr_size(se: Speakeasy) -> int:
    assert se.emu is not None
    size: int = se.emu.get_ptr_size()
    return size


def _ptr(se: Speakeasy, value: int) -> bytes:
    return value.to_bytes(_ptr_size(se), "little")


def _read_ptr(se: Speakeasy, addr: int) -> int:
    return int.from_bytes(se.mem_read(addr, _ptr_size(se)), "little")


def _unicode_string(se: Speakeasy, text: str, max_chars: int | None = None) -> int:
    data = text.encode("utf-16le")
    size = 2 * (len(text) + 1 if max_chars is None else max_chars)
    buf = alloc(se, data.ljust(size, b"\x00"))
    pad = b"\x00" * (_ptr_size(se) - 4)
    return alloc(se, struct.pack("<HH", len(data), size) + pad + _ptr(se, buf))


def _read_unicode_string(se: Speakeasy, addr: int) -> tuple[str, int, int]:
    length, max_length = struct.unpack("<HH", se.mem_read(addr, 4))
    buf = _read_ptr(se, addr + _ptr_size(se))
    return se.mem_read(buf, length).decode("utf-16le"), length, max_length


def _object_attributes(se: Speakeasy, name: str, root: int = 0) -> int:
    oa: Any = ntdefs.OBJECT_ATTRIBUTES(_ptr_size(se))
    oa.Length = oa.sizeof()
    oa.RootDirectory = root
    oa.ObjectName = _unicode_string(se, name)
    return alloc(se, oa.get_bytes())


def _current_run(se: Speakeasy) -> Run:
    assert se.emu is not None
    run = se.emu.curr_run
    assert run is not None
    return run


def _create_key(se: Speakeasy, name: str, root: int = 0) -> tuple[int, int, int]:
    """Create a key and return the status, the handle, and the disposition."""
    phnd = alloc(se, b"\x00" * _ptr_size(se))
    disposition = alloc(se, b"\xcc" * 4)
    oa = _object_attributes(se, name, root)
    rv, _ = call(se, "ntoskrnl", "ZwCreateKey", [phnd, 0xF003F, oa, 0, 0, 0, disposition])
    return rv, _read_ptr(se, phnd), struct.unpack("<I", se.mem_read(disposition, 4))[0]


def _query_value(se: Speakeasy, hnd: int, name: str) -> tuple[int, bytes]:
    """Read a value with ZwQueryValueKey and return its type and data."""
    out = alloc(se, b"\x00" * 0x100)
    ret_len = alloc(se, b"\x00" * 4)
    info_class = regdefs.KEY_VALUE_INFORMATION_CLASS.KeyValuePartialInformation
    rv, _ = call(se, "ntoskrnl", "ZwQueryValueKey", [hnd, _unicode_string(se, name), info_class, out, 0x100, ret_len])
    assert rv == ddk.STATUS_SUCCESS
    _, val_type, length = struct.unpack("<III", se.mem_read(out, 12))
    return val_type, se.mem_read(out + 12, length)


def test_zw_create_key_creates_a_key_once(any_driver_emu: Speakeasy) -> None:
    rv, hnd, disposition = _create_key(any_driver_emu, SOFTWARE_KEY)
    assert rv == ddk.STATUS_SUCCESS
    assert hnd
    assert disposition == regdefs.REG_CREATED_NEW_KEY

    rv, again, disposition = _create_key(any_driver_emu, SOFTWARE_KEY)
    assert rv == ddk.STATUS_SUCCESS
    assert again
    assert disposition == regdefs.REG_OPENED_EXISTING_KEY

    assert any_driver_emu.emu is not None
    key = any_driver_emu.emu.reg_get_key(hnd)
    assert key.get_path() == "HKEY_LOCAL_MACHINE\\Software\\Contoso"
    assert any_driver_emu.emu.reg_get_key(again) is key


def test_zw_create_key_opens_a_subkey_of_the_root_directory(driver_emu: Speakeasy) -> None:
    _, parent, _ = _create_key(driver_emu, SOFTWARE_KEY)
    rv, child, disposition = _create_key(driver_emu, "Parameters", root=parent)
    assert rv == ddk.STATUS_SUCCESS
    assert disposition == regdefs.REG_CREATED_NEW_KEY
    assert driver_emu.emu is not None
    assert driver_emu.emu.reg_get_key(child).get_path() == "HKEY_LOCAL_MACHINE\\Software\\Contoso\\Parameters"

    phnd = alloc(driver_emu, b"\x00" * 4)
    oa = _object_attributes(driver_emu, SOFTWARE_KEY + "\\Parameters")
    assert call(driver_emu, "ntoskrnl", "ZwOpenKey", [phnd, 0xF003F, oa])[0] == ddk.STATUS_SUCCESS


def test_zw_create_key_rejects_an_unknown_root_directory(driver_emu: Speakeasy) -> None:
    rv, hnd, disposition = _create_key(driver_emu, "Parameters", root=0x1234)
    assert rv == ddk.STATUS_INVALID_HANDLE
    assert hnd == 0
    assert disposition == 0xCCCCCCCC


def test_zw_create_key_records_a_create_event(driver_emu: Speakeasy) -> None:
    run = _current_run(driver_emu)
    _, hnd, _ = _create_key(driver_emu, SOFTWARE_KEY)
    events = [e for e in run.events if isinstance(e, RegCreateKeyEvent)]
    assert [(e.path, e.handle) for e in events] == [("HKEY_LOCAL_MACHINE\\Software\\Contoso", hex(hnd))]


@pytest.mark.parametrize(
    ("val_type", "data", "expected"),
    [
        (regdefs.REG_SZ, "C:\\evil.sys\x00".encode("utf-16le"), "C:\\evil.sys\x00".encode("utf-16le")),
        (regdefs.REG_DWORD, struct.pack("<I", 4), struct.pack("<I", 4)),
        (regdefs.REG_BINARY, b"\x01\x02\x03", b"\x01\x02\x03"),
    ],
    ids=["sz", "dword", "binary"],
)
def test_zw_set_value_key_writes_a_value_that_zw_query_value_key_reads(
    any_driver_emu: Speakeasy, val_type: int, data: bytes, expected: bytes
) -> None:
    _, hnd, _ = _create_key(any_driver_emu, SOFTWARE_KEY)
    rv, displays = call(
        any_driver_emu,
        "ntoskrnl",
        "ZwSetValueKey",
        [hnd, _unicode_string(any_driver_emu, "Start"), 0, val_type, alloc(any_driver_emu, data), len(data)],
    )
    assert rv == ddk.STATUS_SUCCESS
    assert displays["ValueName"] == "Start"
    assert _query_value(any_driver_emu, hnd, "Start") == (val_type, expected)


def test_zw_set_value_key_replaces_a_value(driver_emu: Speakeasy) -> None:
    _, hnd, _ = _create_key(driver_emu, SOFTWARE_KEY)
    for start in (2, 4):
        data = alloc(driver_emu, struct.pack("<I", start))
        name = _unicode_string(driver_emu, "Start")
        call(driver_emu, "ntoskrnl", "ZwSetValueKey", [hnd, name, 0, regdefs.REG_DWORD, data, 4])
    assert _query_value(driver_emu, hnd, "Start") == (regdefs.REG_DWORD, struct.pack("<I", 4))
    assert driver_emu.emu is not None
    assert len(driver_emu.emu.reg_get_key(hnd).get_values()) == 1


def test_zw_set_value_key_records_a_write_event(driver_emu: Speakeasy) -> None:
    run = _current_run(driver_emu)
    _, hnd, _ = _create_key(driver_emu, SOFTWARE_KEY)
    name = _unicode_string(driver_emu, "Start")
    data = alloc(driver_emu, struct.pack("<I", 2))
    call(driver_emu, "ntoskrnl", "ZwSetValueKey", [hnd, name, 0, regdefs.REG_DWORD, data, 4])
    events = [e for e in run.events if isinstance(e, RegWriteValueEvent)]
    assert [(e.path, e.value_name) for e in events] == [("HKEY_LOCAL_MACHINE\\Software\\Contoso", "Start")]


def test_zw_set_value_key_rejects_an_unknown_handle(driver_emu: Speakeasy) -> None:
    name = _unicode_string(driver_emu, "Start")
    rv, _ = call(driver_emu, "ntoskrnl", "ZwSetValueKey", [0x1234, name, 0, regdefs.REG_DWORD, 0, 0])
    assert rv == ddk.STATUS_INVALID_HANDLE


def test_ke_bug_check_ex_ends_the_run_with_the_bug_check_code(driver64_emu: Speakeasy) -> None:
    emu = driver64_emu.emu
    assert emu is not None
    run = _current_run(driver64_emu)
    call(driver64_emu, "ntoskrnl", "KeBugCheckEx", [0xE2, 1, 2, 3, 4])
    assert emu.is_run_complete
    assert run.error is not None
    assert run.error.type == "bug_check"
    assert run.error.api_name == "ntoskrnl.KeBugCheckEx"
    assert run.error.context_summary is not None
    assert "bug check 0xe2 (0x1, 0x2, 0x3, 0x4)" in run.error.context_summary


def _next_stack_location(se: Speakeasy, irp_addr: int) -> Any:
    irp = _read_irp(se, irp_addr)
    ios: Any = ntdefs.IO_STACK_LOCATION(_ptr_size(se))
    ios.cast(se.mem_read(irp.Tail.Overlay.CurrentStackLocation - ios.sizeof(), ios.sizeof()))
    return ios


def _read_irp(se: Speakeasy, irp_addr: int) -> Any:
    irp: Any = ntdefs.IRP(_ptr_size(se))
    irp.cast(se.mem_read(irp_addr, irp.sizeof()))
    return irp


@pytest.mark.parametrize(
    ("internal", "major"), [(0, ddk.IRP_MJ_DEVICE_CONTROL), (1, ddk.IRP_MJ_INTERNAL_DEVICE_CONTROL)]
)
def test_io_build_device_io_control_request_fills_the_next_stack_location(
    any_driver_emu: Speakeasy, internal: int, major: int
) -> None:
    se = any_driver_emu
    in_buf = alloc(se, b"input!")
    out_buf = alloc(se, b"\x00" * 0x20)
    event = alloc(se, b"\x00" * 0x20)
    iosb = alloc(se, b"\xcc" * 2 * _ptr_size(se))
    device = 0x7000
    irp_addr, _ = call(
        se,
        "ntoskrnl",
        "IoBuildDeviceIoControlRequest",
        [IOCTL_BUFFERED, device, in_buf, 6, out_buf, 0x20, internal, event, iosb],
    )
    assert irp_addr

    ios = _next_stack_location(se, irp_addr)
    assert ios.MajorFunction == major
    params = ios.Parameters.DeviceIoControl
    assert (params.IoControlCode, params.InputBufferLength, params.OutputBufferLength) == (IOCTL_BUFFERED, 6, 0x20)

    irp = _read_irp(se, irp_addr)
    assert irp.UserIosb == iosb
    assert irp.UserEvent == event
    assert irp.UserBuffer == out_buf
    assert irp.AssociatedIrp not in (0, in_buf)
    assert se.mem_read(irp.AssociatedIrp, 0x20) == b"input!" + b"\x00" * 0x1A


def test_io_build_device_io_control_request_passes_neither_buffers_through(driver64_emu: Speakeasy) -> None:
    se = driver64_emu
    in_buf = alloc(se, b"input!")
    out_buf = alloc(se, b"\x00" * 0x20)
    irp_addr, _ = call(
        se, "ntoskrnl", "IoBuildDeviceIoControlRequest", [IOCTL_NEITHER, 0x7000, in_buf, 6, out_buf, 0x20, 0, 0, 0]
    )
    assert _next_stack_location(se, irp_addr).Parameters.DeviceIoControl.Type3InputBuffer == in_buf
    irp = _read_irp(se, irp_addr)
    assert irp.UserBuffer == out_buf
    assert irp.AssociatedIrp == 0


def test_iof_call_driver_completes_the_caller_io_status_block(any_driver_emu: Speakeasy) -> None:
    se = any_driver_emu
    iosb = alloc(se, b"\xcc" * 2 * _ptr_size(se))
    irp_addr, _ = call(
        se, "ntoskrnl", "IoBuildDeviceIoControlRequest", [IOCTL_BUFFERED, 0x7000, 0, 0, 0, 0, 0, 0, iosb]
    )
    assert call(se, "ntoskrnl", "IofCallDriver", [0x7000, irp_addr])[0] == ddk.STATUS_SUCCESS
    assert se.mem_read(iosb, 2 * _ptr_size(se)) == b"\x00" * 2 * _ptr_size(se)


def test_x86_mm_map_io_space_reads_the_64_bit_physical_address(driver_emu: Speakeasy) -> None:
    va, left = call_x86(driver_emu, "MmMapIoSpace", [0xFEC00010, 0, 0x20, 0], STDCALL)
    assert left == 0
    assert va & 0xFFF == 0x10
    assert driver_emu.mem_read(va, 0x20) == b"\x00" * 0x20


def test_x64_mm_map_io_space_maps_writable_memory_until_unmapped(driver64_emu: Speakeasy) -> None:
    se = driver64_emu
    assert se.emu is not None
    va, _ = call(se, "ntoskrnl", "MmMapIoSpace", [0x1_0000_2000, 0x1800, 0, 0])
    assert va & 0xFFF == 0
    se.mem_write(va + 0x17FF, b"\x41")
    assert se.mem_read(va + 0x17FF, 1) == b"\x41"
    call(se, "ntoskrnl", "MmUnmapIoSpace", [va, 0x1800])
    assert se.emu.get_address_map(va) is None


@pytest.mark.parametrize(
    ("text", "count", "expected"),
    [("abcdef", 3, "xxxdef"), ("abc", 10, "xxx"), ("abc", 0, "abc")],
)
def test_x86_wcsnset_sets_at_most_count_characters(driver_emu: Speakeasy, text: str, count: int, expected: str) -> None:
    buf = alloc(driver_emu, (text + "\x00!").encode("utf-16le"))
    rv, left = call_x86(driver_emu, "_wcsnset", [buf, ord("x"), count], CDECL)
    assert rv == buf
    assert left == 12
    assert driver_emu.mem_read(buf, 2 * (len(text) + 2)).decode("utf-16le") == expected + "\x00!"


@pytest.mark.parametrize(
    ("source", "max_chars", "status", "expected"),
    [
        ("cd", 8, ddk.STATUS_SUCCESS, "abcd"),
        ("cd", 4, ddk.STATUS_SUCCESS, "abcd"),
        ("cde", 4, ddk.STATUS_BUFFER_TOO_SMALL, "ab"),
        (None, 4, ddk.STATUS_SUCCESS, "ab"),
    ],
)
def test_rtl_append_unicode_to_string_appends_within_the_maximum_length(
    any_driver_emu: Speakeasy, source: str | None, max_chars: int, status: int, expected: str
) -> None:
    se = any_driver_emu
    dest = _unicode_string(se, "ab", max_chars=max_chars)
    src = alloc(se, (source + "\x00").encode("utf-16le")) if source is not None else 0
    rv, _ = call(se, "ntoskrnl", "RtlAppendUnicodeToString", [dest, src])
    assert rv == status
    assert _read_unicode_string(se, dest) == (expected, 2 * len(expected), 2 * max_chars)


def test_rtl_append_unicode_to_string_ends_the_buffer_when_there_is_room(driver_emu: Speakeasy) -> None:
    dest = _unicode_string(driver_emu, "ab", max_chars=8)
    buf = _read_ptr(driver_emu, dest + 4)
    driver_emu.mem_write(buf + 4, "!!!!!!".encode("utf-16le"))
    call(driver_emu, "ntoskrnl", "RtlAppendUnicodeToString", [dest, alloc(driver_emu, "cd\x00".encode("utf-16le"))])
    assert driver_emu.mem_read(buf, 12).decode("utf-16le") == "abcd\x00!"


def test_rtl_append_unicode_string_to_string_appends_the_source(any_driver_emu: Speakeasy) -> None:
    se = any_driver_emu
    dest = _unicode_string(se, "ab", max_chars=4)
    rv, _ = call(se, "ntoskrnl", "RtlAppendUnicodeStringToString", [dest, _unicode_string(se, "cd")])
    assert rv == ddk.STATUS_SUCCESS
    assert _read_unicode_string(se, dest) == ("abcd", 8, 8)


@pytest.mark.parametrize(
    ("register", "argv", "unregister"),
    [
        (
            "RtlRegisterFeatureConfigurationChangeNotification",
            [0x401000, 0, 0, None],
            "RtlUnregisterFeatureConfigurationChangeNotification",
        ),
        ("RtlRegisterFeatureUsageProvider", [0x401000, 0x7000, None], "RtlUnregisterFeatureUsageProvider"),
    ],
)
def test_feature_registrations_return_a_handle(
    driver64_emu: Speakeasy, register: str, argv: list[int | None], unregister: str
) -> None:
    out = alloc(driver64_emu, b"\x00" * 8)
    rv, _ = call(driver64_emu, "ntoskrnl", register, [out if a is None else a for a in argv])
    assert rv == ddk.STATUS_SUCCESS
    hnd = _read_ptr(driver64_emu, out)
    assert hnd
    assert call(driver64_emu, "ntoskrnl", unregister, [hnd])[0] == ddk.STATUS_SUCCESS
