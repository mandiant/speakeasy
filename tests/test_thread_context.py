"""x64 thread contexts: sections by ContextFlags, debug registers, capture and restore."""

import struct

from speakeasy import Speakeasy
from tests.guest_harness import get_api, guest_call

CONTEXT_SIZE = 0x4D0
CONTEXT_DEBUG_REGISTERS = 0x100010
CURRENT_THREAD = 0xFFFFFFFFFFFFFFFE
RETURN_42 = b"\xb8\x2a\x00\x00\x00\xc3"


def field(se, context, offset):
    return struct.unpack("<Q", se.mem_read(context + offset, 8))[0]


def run(config, build):
    """Run the code build(se, data, call) returns, where call(name, *args) calls a kernel32 API."""
    se = Speakeasy(config=config)
    code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="amd64")
    data = se.mem_alloc(0x2000)

    def call(name, *args, **kw):
        return guest_call(8, get_api(se, "kernel32", name), *args, **kw)

    se.mem_write(code, build(se, data, call) + RETURN_42)
    se.run_shellcode(code)
    return se, data, se.get_report().entry_points[0]


def test_get_thread_context_fills_only_requested_sections(config):
    def build(se, data, call):
        se.mem_write(data, b"\xaa" * CONTEXT_SIZE)
        se.mem_write(data + 0x30, struct.pack("<I", CONTEXT_DEBUG_REGISTERS))
        return call("GetThreadContext", CURRENT_THREAD, data)

    se, context, report = run(config, build)
    assert report.error is None
    assert [field(se, context, 0x48 + 8 * i) for i in range(6)] == [0] * 6  # Dr0-Dr3, Dr6, Dr7
    assert field(se, context, 0x78) == 0xAAAAAAAAAAAAAAAA  # Rax: not requested


def test_debug_registers_belong_to_the_thread(config):
    def build(se, data, call):
        source, target = data, data + 0x800
        se.mem_write(source + 0x30, struct.pack("<I", CONTEXT_DEBUG_REGISTERS))
        se.mem_write(source + 0x48, struct.pack("<Q", 0x12345678))  # Dr0
        se.mem_write(source + 0x70, struct.pack("<Q", 1))  # Dr7: L0
        se.mem_write(target + 0x30, struct.pack("<I", CONTEXT_DEBUG_REGISTERS))
        return call("SetThreadContext", CURRENT_THREAD, source) + call("GetThreadContext", CURRENT_THREAD, target)

    se, data, report = run(config, build)
    assert report.error is None
    assert field(se, data + 0x800, 0x48) == 0x12345678
    assert field(se, data + 0x800, 0x70) == 1


def test_restore_context_continues_at_capture(config):
    def build(se, data, call):
        context, counter = data, data + 0x800
        code = call("RtlCaptureContext", context)
        code += b"\x48\xff\x04\x25" + struct.pack("<I", counter)  # inc qword [counter]
        code += b"\x48\x83\x3c\x25" + struct.pack("<I", counter) + b"\x02"  # cmp qword [counter], 2
        restore = call("RtlRestoreContext", context, 0)
        code += b"\x74" + bytes([len(restore)]) + restore  # je past the restore
        code += b"\x48\x8b\x04\x25" + struct.pack("<I", counter) + b"\xc3"  # return the count
        return code

    se, data, report = run(config, build)
    assert report.error is None
    assert report.ret_val == 2
    assert field(se, data, 0x30) & 0xFFFFFFFF == 0x10000F  # CONTEXT_FULL | CONTEXT_SEGMENTS
