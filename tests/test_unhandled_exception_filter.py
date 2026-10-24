"""The top-level exception filter of SetUnhandledExceptionFilter sees exceptions no frame handles."""

import struct

import pytest

from speakeasy import Speakeasy
from tests.guest_harness import get_api, guest_call

FAULT_ADDRESS = 0x10


@pytest.mark.parametrize("arch", ["x86", "amd64"])
def test_fault_delivered_to_unhandled_exception_filter_is_run_error(config, arch):
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch=arch)
        counter = se.mem_alloc(0x1000)
        ptr_size = se.get_ptr_size()
        filter_addr = code + 0x800
        # The filter counts itself and returns EXCEPTION_EXECUTE_HANDLER: the process ends.
        if ptr_size == 4:
            setup = b"\x64\xc7\x05" + struct.pack("<II", 0, 0)
            filter_code = b"\xff\x05" + struct.pack("<I", counter) + b"\xb8\x01\x00\x00\x00\xc2\x04\x00"
            probe = b"\xa1" + struct.pack("<I", FAULT_ADDRESS)
        else:
            setup = b""
            filter_code = b"\x48\xb8" + struct.pack("<Q", counter) + b"\xff\x00\xb8\x01\x00\x00\x00\xc3"
            probe = b"\x48\xa1" + struct.pack("<Q", FAULT_ADDRESS)
        setup += guest_call(ptr_size, get_api(se, "kernel32", "SetUnhandledExceptionFilter"), filter_addr)
        se.mem_write(code, setup + probe + b"\xc3")
        se.mem_write(filter_addr, filter_code)

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert int.from_bytes(se.mem_read(counter, 4), "little") == 1
        assert run.error is not None
        assert run.error.type == "invalid_read"
        assert run.error.pc == code + len(setup)
        assert run.error.address == FAULT_ADDRESS


def test_filter_continues_after_raise_exception(config):
    # SetUnhandledExceptionFilter(filter); RaiseException(0xC000008E); return 42
    # The filter counts itself and returns EXCEPTION_CONTINUE_EXECUTION, which continues after the call.
    # al-khaser's UnhandledExcepFilterTest checks the same on x86 (test_seh_samples.py).
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="amd64")
        counter = se.mem_alloc(0x1000)
        filter_addr = code + 0x800
        setup = guest_call(8, get_api(se, "kernel32", "SetUnhandledExceptionFilter"), filter_addr)
        setup += guest_call(8, get_api(se, "kernel32", "RaiseException"), 0xC000008E, 0, 0, 0)
        se.mem_write(code, setup + b"\xb8\x2a\x00\x00\x00\xc3")
        se.mem_write(filter_addr, b"\x48\xb8" + struct.pack("<Q", counter) + b"\xff\x00\xb8\xff\xff\xff\xff\xc3")

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is None
        assert run.ret_val == 42
        assert int.from_bytes(se.mem_read(counter, 4), "little") == 1
