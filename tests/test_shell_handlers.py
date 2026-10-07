"""
Shell, COM, and ntdll handlers return what Windows returns and write what
Windows writes.
"""

import struct

from speakeasy import Speakeasy
from speakeasy.winenv.defs.nt import ddk
from tests.handler_harness import alloc, call


def test_sys_free_string_accepts_null(dll_emu: Speakeasy) -> None:
    rv, _ = call(dll_emu, "oleaut32", "SysFreeString", [0])
    assert rv is None


def test_ldr_access_resource_writes_address_and_ulong_size(dll64_emu: Speakeasy) -> None:
    base = 0x180000000
    entry = alloc(dll64_emu, struct.pack("<IIII", 0x1234, 0x56, 0, 0))
    resource = alloc(dll64_emu, b"\xcc" * 8)
    size = alloc(dll64_emu, b"\xcc" * 8)
    rv, _ = call(dll64_emu, "ntdll", "LdrAccessResource", [base, entry, resource, size])
    assert rv == ddk.STATUS_SUCCESS
    assert dll64_emu.mem_read(resource, 8) == struct.pack("<Q", base + 0x1234)
    assert dll64_emu.mem_read(size, 8) == struct.pack("<I", 0x56) + b"\xcc" * 4
