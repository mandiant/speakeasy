"""x86 exception handlers that MSVC's language handlers do not cover."""

import struct

from speakeasy import Speakeasy
from tests.guest_harness import get_api


def dword(value):
    return struct.pack("<I", value)


def test_handler_that_unwinds_and_jumps_to_its_frame(config):
    """
    A handler compiled into the image, like _except_handler4 of a static CRT, calls
    RtlUnwind and jumps into its frame instead of returning. Five faults at one address.
    """
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="x86")
        data = se.mem_alloc(0x1000)
        saved, count = data, data + 4
        handler = code + 0x100

        again = b"\x68" + dword(handler)  # push handler
        again += b"\x64\xff\x35" + dword(0)  # push fs:[0]
        again += b"\x64\x89\x25" + dword(0)  # mov fs:[0], esp
        again += b"\x89\x25" + dword(saved)  # mov [saved], esp
        again += b"\xc7\x05" + dword(0) + dword(1)  # mov dword [0], 1
        recover = b"\x8b\x25" + dword(saved)  # mov esp, [saved]
        recover += b"\x64\x8f\x05" + dword(0)  # pop fs:[0]
        recover += b"\x83\xc4\x04"  # add esp, 4
        recover += b"\xff\x05" + dword(count)  # inc dword [count]
        recover += b"\x4b"  # dec ebx
        recover += b"\x75" + bytes([(-(len(again) + len(recover) + 2)) & 0xFF])  # jnz again
        main = b"\x53\xbb" + dword(5) + again + recover  # push ebx; mov ebx, 5
        main += b"\xa1" + dword(count) + b"\x5b\xc3"  # mov eax, [count]; pop ebx; ret
        recover_address = code + 6 + len(again)

        unwinding = b"\xb8" + dword(1) + b"\xc3"  # return ExceptionContinueSearch
        take = b"\x6a\x00\x50"  # push 0 (return value); push eax (record)
        take += b"\x68" + dword(recover_address)  # push recover
        take += b"\xff\x74\x24\x14"  # push the establisher frame
        take += b"\xb8" + dword(get_api(se, "kernel32", "RtlUnwind")) + b"\xff\xd0"  # call RtlUnwind
        take += b"\xb8" + dword(recover_address) + b"\xff\xe0"  # jmp recover
        handler_code = b"\x8b\x44\x24\x04"  # mov eax, [esp + 4]  (record)
        handler_code += b"\xf7\x40\x04" + dword(6)  # test dword [eax + 4], EXCEPTION_UNWINDING | EXIT_UNWIND
        handler_code += b"\x75" + bytes([len(take)]) + take + unwinding  # jnz unwinding

        se.mem_write(code, main)
        se.mem_write(handler, handler_code)

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is None
        assert run.ret_val == 5
