"""The x86 CRT _EH_prolog builds an SEH frame that guest code can use and unwind."""

import struct

from speakeasy import Speakeasy


def dword(value):
    return struct.pack("<I", value)


def read_dwords(se, address, count):
    return struct.unpack(f"<{count}I", se.mem_read(address, 4 * count))


def test_x86_eh_prolog_builds_frame_and_resumes_caller(config):
    saved_ebp = 0x13572468
    arguments = (0x11223344, 0x10203040)
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="x86")
        data = se.mem_alloc(0x1000)
        target = se.emu.get_proc("msvcrt", "_EH_prolog")
        function, handler = code + 0x100, code + 0x300
        previous = data + 0x100
        se.mem_write(previous, dword(0xFFFFFFFF) + dword(handler))
        se.mem_write(handler, b"\x31\xc0\xc3")

        # The caller installs an SEH chain and records its stack, EBP and FS:[0]
        # before the call and after the callee returns.
        caller = b"\xbd" + dword(saved_ebp)
        caller += b"\x64\xc7\x05" + dword(0) + dword(previous)
        caller += b"\x89\x25" + dword(data + 0x10)
        caller += b"\x68" + dword(arguments[1]) + b"\x68" + dword(arguments[0])
        call_site = code + len(caller)
        caller += b"\xe8" + dword((function - call_site - 5) & 0xFFFFFFFF)
        caller_resume = code + len(caller)
        caller += b"\x83\xc4\x08"
        caller += b"\x89\x25" + dword(data + 0x14) + b"\x89\x2d" + dword(data + 0x18)
        caller += b"\x64\x8b\x0d" + dword(0) + b"\x89\x0d" + dword(data + 0x1C)
        caller += b"\x40\xc3"
        se.mem_write(code, caller)

        # _EH_prolog takes the handler in EAX. The callee records the frame it
        # receives, uses its arguments through EBP, unlinks the frame and returns.
        callee = b"\xb8" + dword(handler)
        prolog_call = function + len(callee)
        callee += b"\xe8" + dword((target - prolog_call - 5) & 0xFFFFFFFF)
        callee += b"\x89\x25" + dword(data) + b"\x89\x2d" + dword(data + 4)
        callee += b"\x64\x8b\x0d" + dword(0) + b"\x89\x0d" + dword(data + 8)
        callee += b"\x89\xe6\xbf" + dword(data + 0x20) + b"\xb9" + dword(7) + b"\xf3\xa5"
        callee += b"\x8b\x45\x08\x03\x45\x0c"
        callee += b"\x8b\x4d\xf4\x64\x89\x0d" + dword(0)
        callee += b"\x89\xec\x5d\xc3"
        se.mem_write(function, callee)

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is None
        assert [event.api_name for event in run.events if event.event == "api"] == ["msvcrt._EH_prolog"]
        frame_sp, frame_ebp, frame_seh = read_dwords(se, data, 3)
        initial_sp, resumed_sp, resumed_ebp, resumed_seh = read_dwords(se, data + 0x10, 4)
        assert frame_sp == initial_sp - 28
        assert frame_ebp == initial_sp - 16
        assert frame_seh == frame_sp == frame_ebp - 12
        assert read_dwords(se, data + 0x20, 7) == (
            previous,
            handler,
            0xFFFFFFFF,
            saved_ebp,
            caller_resume,
            *arguments,
        )
        assert (resumed_sp, resumed_ebp, resumed_seh) == (initial_sp, saved_ebp, previous)
        assert run.ret_val == sum(arguments) + 1
