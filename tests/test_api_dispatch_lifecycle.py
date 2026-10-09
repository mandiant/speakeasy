"""Nested guest callbacks from API handlers return to the originating API frames."""

import struct

import pytest

from speakeasy import Speakeasy

OUTER_PARAM = 0x1111
LEAF_PARAM = 0x2222


def x86_program(base, data, api):
    """
    Return code that calls ``api`` (CreateDialogIndirectParamA) with an outer
    dialog procedure, which calls ``api`` again with a leaf procedure. Each
    procedure stores its HWND and lParam in ``data``; the caller stores its
    stack delta and the API result.
    """

    def d(value):
        return struct.pack("<I", value)

    def call_api(proc, param):
        return b"\x68" + d(param) + b"\x68" + d(proc) + b"\x6a\x00" * 3 + b"\xb8" + d(api) + b"\xff\xd0"

    def record_args(slot):
        code = b"\x8b\x44\x24\x10\xa3" + d(data + slot)
        return code + b"\x8b\x44\x24\x04\xa3" + d(data + slot + 8)

    outer, leaf = base + 0x100, base + 0x200
    main = b"\x89\xe6" + call_api(outer, OUTER_PARAM) + b"\x29\xe6\x89\x35" + d(data) + b"\xa3" + d(data + 8) + b"\xc3"
    finish = b"\xb8\x01\x00\x00\x00\xc2\x10\x00"
    outer_code = record_args(0x10) + call_api(leaf, LEAF_PARAM) + b"\xa3" + d(data + 0x40) + finish
    leaf_code = record_args(0x20) + finish
    return {base: main, outer: outer_code, leaf: leaf_code}


def x64_program(base, data, api):
    def q(value):
        return struct.pack("<Q", value)

    def call_api(proc, param):
        code = b"\x48\x83\xec\x38\x48\xc7\x44\x24\x20" + struct.pack("<I", param)
        code += b"\x31\xc9\x31\xd2\x45\x31\xc0\x49\xb9" + q(proc) + b"\x48\xb8" + q(api)
        return code + b"\xff\xd0\x48\x83\xc4\x38"

    def record_args(slot):
        return b"\x49\xba" + q(data) + b"\x4d\x89\x4a" + bytes([slot]) + b"\x49\x89\x4a" + bytes([slot + 8])

    outer, leaf = base + 0x100, base + 0x200
    main = b"\x48\x89\xe6" + call_api(outer, OUTER_PARAM) + b"\x48\x29\xe6"
    main += b"\x48\xbb" + q(data) + b"\x48\x89\x33\x48\x89\x43\x08\xc3"
    finish = b"\xb8\x01\x00\x00\x00\xc3"
    outer_code = record_args(0x10) + call_api(leaf, LEAF_PARAM)
    outer_code += b"\x49\xba" + q(data) + b"\x49\x89\x42\x40" + finish
    leaf_code = record_args(0x20) + finish
    return {base: main, outer: outer_code, leaf: leaf_code}


@pytest.mark.parametrize("architecture", ["x86", "amd64"])
def test_nested_dialog_callbacks_return_to_their_api_callers(config, architecture):
    with Speakeasy(config=config) as se:
        base = se.load_shellcode(data=b"\xcc" * 0x1000, arch=architecture)
        data = se.mem_alloc(0x1000)
        api = se.emu.get_proc("user32", "CreateDialogIndirectParamA")
        program = x86_program if architecture == "x86" else x64_program
        for address, code in program(base, data, api).items():
            se.mem_write(address, code)

        se.run_shellcode(base)

        run = se.get_report().entry_points[0]
        width = se.get_ptr_size()

        def slot(offset):
            return int.from_bytes(se.mem_read(data + offset, width), "little")

        assert run.error is None
        assert [event.api_name for event in run.events if event.event == "api"] == [
            "user32.CreateDialogIndirectParamA"
        ] * 2
        assert slot(0) == 0
        assert (slot(0x10), slot(0x20)) == (OUTER_PARAM, LEAF_PARAM)
        outer_hwnd, leaf_hwnd = slot(0x18), slot(0x28)
        assert outer_hwnd and leaf_hwnd and outer_hwnd != leaf_hwnd
        assert slot(0x40) == leaf_hwnd
        assert slot(8) == run.ret_val == outer_hwnd


@pytest.mark.parametrize("argc", [4, 5, 6])
def test_x64_api_callback_entry_stack_is_aligned(config, argc):
    with Speakeasy(config=config) as se:
        base = se.load_shellcode(data=b"\xcc" * 0x1000, arch="amd64")
        data = se.mem_alloc(0x1000)
        api = se.emu.get_proc("kernel32", "GetTickCount")
        callback = base + 0x100

        def handler(_se, _api, _original, args):
            se.emu.api.load_api_handler("user32").setup_callback(callback, list(range(argc)), caller_argv=args)
            return 0

        se.add_api_hook(handler, "kernel32", "GetTickCount", argc=0)
        main = b"\x48\x83\xec\x28\x48\xb8" + struct.pack("<Q", api) + b"\xff\xd0\x48\x83\xc4\x28\xc3"
        # mov r10, data; mov [r10], rsp; ret
        record_rsp = b"\x49\xba" + struct.pack("<Q", data) + b"\x49\x89\x22\xc3"
        se.mem_write(base, main)
        se.mem_write(callback, record_rsp)

        se.run_shellcode(base)

        assert se.get_report().entry_points[0].error is None
        rsp = int.from_bytes(se.mem_read(data, 8), "little")
        assert rsp and (rsp + 8) % 16 == 0
