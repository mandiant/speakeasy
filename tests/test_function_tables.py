"""Unwind data registered at runtime for code outside loaded images."""

import struct

import pytest

from speakeasy import Speakeasy
from tests.guest_harness import get_api, guest_call

# A function with a __try around a write to null, and an __except that returns 42
FUNCTION = bytes.fromhex(
    "4883ec28"  # 0x00 sub rsp, 0x28
    "31c0"  # 0x04 xor eax, eax       __try
    "8900"  # 0x06 mov [rax], eax
    "90"  # 0x08 nop
    "4883c428c3"  # 0x09 add rsp, 0x28; ret
    "b82a000000"  # 0x0e mov eax, 42     __except
    "4883c428c3"  # 0x13 add rsp, 0x28; ret
)
UNWIND_INFO = 0x100
HANDLER_THUNK = 0x200
RUNTIME_FUNCTION = 0x300


def write_dynamic_function(se, base):
    """Write FUNCTION at base with its unwind data, which names __C_specific_handler."""
    se.mem_write(base, FUNCTION)
    unwind_info = bytes([1 | 3 << 3, 4, 1, 0])  # version 1, EHANDLER | UHANDLER, prolog 4, one code
    unwind_info += bytes([4, 4 << 4 | 2, 0, 0])  # at 4: UWOP_ALLOC_SMALL 0x28, then padding
    unwind_info += struct.pack("<I", HANDLER_THUNK)
    unwind_info += struct.pack("<IIIII", 1, 0x04, 0x09, 1, 0x0E)  # one scope: EXCEPTION_EXECUTE_HANDLER
    se.mem_write(base + UNWIND_INFO, unwind_info)
    handler = get_api(se, "ntdll", "__C_specific_handler")
    se.mem_write(base + HANDLER_THUNK, b"\xff\x25\x00\x00\x00\x00" + struct.pack("<Q", handler))
    se.mem_write(base + RUNTIME_FUNCTION, struct.pack("<III", 0, len(FUNCTION), UNWIND_INFO))


@pytest.mark.parametrize("register, delete", [(False, False), (True, False), (True, True)])
def test_function_table_lets_handlers_run(config, register, delete):
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="amd64")
        base = se.mem_alloc(0x1000)
        write_dynamic_function(se, base)
        call = b""
        if register:
            call += guest_call(8, get_api(se, "ntdll", "RtlAddFunctionTable"), base + RUNTIME_FUNCTION, 1, base)
        if delete:
            call += guest_call(8, get_api(se, "ntdll", "RtlDeleteFunctionTable"), base + RUNTIME_FUNCTION)
        call += guest_call(8, base)
        se.mem_write(code, call + b"\xc3")

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        if register and not delete:
            assert run.error is None
            assert run.ret_val == 42
        else:
            assert run.error is not None
            assert run.error.type == "invalid_write"


def test_lookup_finds_registered_function(config):
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="amd64")
        base = se.mem_alloc(0x1000)
        write_dynamic_function(se, base)
        image_base = base + 0x800
        call = guest_call(8, get_api(se, "ntdll", "RtlAddFunctionTable"), base + RUNTIME_FUNCTION, 1, base)
        call += guest_call(8, get_api(se, "ntdll", "RtlLookupFunctionEntry"), base + 6, image_base, 0)
        se.mem_write(code, call + b"\xc3")

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.ret_val == base + RUNTIME_FUNCTION
        assert struct.unpack("<Q", se.mem_read(image_base, 8))[0] == base


def test_table_with_a_wrong_count_faults_where_it_ends(config):
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="amd64")
        base = se.mem_alloc(0x1000)
        call = guest_call(8, get_api(se, "ntdll", "RtlAddFunctionTable"), base, 0xFFFFFFFF, base)
        se.mem_write(code, call + b"\xc3")

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is not None
        assert run.error.type == "invalid_read"


@pytest.mark.parametrize("dll", ["kernel32", "ntdll"])
def test_rtl_unwind_continues_in_the_target_frame(config, dll):
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="amd64")
        base = se.mem_alloc(0x1000)
        function = bytes.fromhex(
            "4883ec28"  # 0x00 sub rsp, 0x28
            "4889e1"  # 0x04 mov rcx, rsp            TargetFrame: this frame
            "488d1517000000"  # 0x07 lea rdx, [0x25]   TargetIp
            "4d31c0"  # 0x0e xor r8, r8
            "41b92a000000"  # 0x11 mov r9d, 42          ReturnValue
            "48b8"
            + struct.pack("<Q", get_api(se, dll, "RtlUnwind")).hex()  # 0x17 mov rax, RtlUnwind
            + "ffd0"  # 0x21 call rax
            "31c0"  # 0x23 xor eax, eax
            "4883c428c3"  # 0x25 add rsp, 0x28; ret
        )
        se.mem_write(base, function)
        se.mem_write(base + UNWIND_INFO, bytes([1, 4, 1, 0, 4, 4 << 4 | 2, 0, 0]))  # at 4: UWOP_ALLOC_SMALL 0x28
        se.mem_write(base + RUNTIME_FUNCTION, struct.pack("<III", 0, len(function), UNWIND_INFO))
        call = guest_call(8, get_api(se, "ntdll", "RtlAddFunctionTable"), base + RUNTIME_FUNCTION, 1, base)
        se.mem_write(code, call + guest_call(8, base) + b"\xc3")

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is None
        assert run.ret_val == 42
