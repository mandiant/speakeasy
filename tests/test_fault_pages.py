"""Temporary pages mapped to recover from a fault leave no memory map behind."""

import copy
import struct

from speakeasy import Speakeasy

# fault: xor eax, eax; mov eax, [eax]; ret
# ok: nop; ret
_SC_FAULT_THEN_OK = b"\x31\xc0\x8b\x00\xc3" + b"\x90" * 3 + b"\x90\xc3"


def dword(value):
    return struct.pack("<I", value)


def test_fault_page_is_released_with_its_map(base_config) -> None:
    se = Speakeasy(config=copy.deepcopy(base_config))
    try:
        addr = se.load_shellcode(data=_SC_FAULT_THEN_OK, arch="x86")
        se.run_shellcode(addr)
        se.call(addr + 8)
        assert se.get_address_map(0) is None
        assert not se.is_address_valid(0)
        se.mem_free(0)
    finally:
        se.shutdown()


def test_handler_sees_a_fault_in_the_reserved_range_above_the_stack(config) -> None:
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="x86")
        data = se.mem_alloc(0x1000)
        saved = data
        done, handler = code + 0x80, code + 0x100

        main = b"\x89\x25" + dword(saved)  # mov [saved], esp
        main += b"\x68" + dword(handler)  # push handler
        main += b"\x64\xff\x35" + dword(0) + b"\x64\x89\x25" + dword(0)  # push fs:[0]; mov fs:[0], esp
        main += b"\x8b\x84\x24" + dword(0x1000)  # mov eax, [esp + 0x1000]
        finish = b"\x8b\x25" + dword(saved)  # mov esp, [saved]
        finish += b"\x64\x8b\x0d" + dword(0) + b"\x8b\x09" + b"\x64\x89\x0d" + dword(0)  # pop the registration
        finish += b"\xa1" + dword(data + 4) + b"\xc3"  # mov eax, [data + 4]; ret

        record = b"\x8b\x44\x24\x04"  # mov eax, [esp + 4]  (record)
        record += b"\x8b\x40\x18"  # mov eax, [eax + 0x18]  (ExceptionInformation[1])
        record += b"\xa3" + dword(data + 4)  # mov [data + 4], eax
        record += b"\x8b\x44\x24\x0c"  # mov eax, [esp + 0xc]  (context)
        record += b"\xc7\x80\xb8\x00\x00\x00" + dword(done)  # mov [eax + Eip], done
        record += b"\x31\xc0\xc3"  # return ExceptionContinueExecution

        se.mem_write(code, main)
        se.mem_write(done, finish)
        se.mem_write(handler, record)

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is None
        (esp,) = struct.unpack("<I", se.mem_read(saved, 4))
        assert run.ret_val == esp - 8 + 0x1000
        assert se.emu.get_reserve_map(run.ret_val) is not None
