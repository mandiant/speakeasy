# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import struct

import pytest

from speakeasy import Speakeasy


def get_api_calls(ep, api_name):
    events = ep.events or []
    return [evt for evt in events if evt.event == "api" and evt.api_name == api_name]


def test_get_proc_address_on_missing_function_returns_zero(config, load_test_bin, run_test):
    data = load_test_bin("GetProcAddress.exe.xz")
    report = run_test(config, data)
    eps = report.entry_points

    get_proc_addr = get_api_calls(eps[0], "kernel32.GetProcAddress")

    assert get_proc_addr[2].args[1].display == "AreFileApisANSI"
    assert get_proc_addr[2].ret_val != "0x0"

    assert get_proc_addr[3].args[1].display == "ThisFunctionIsNotExportedByKernel32"
    assert get_proc_addr[3].ret_val == "0x0"


def call_get_proc_address(config, architecture, module, name):
    """Run guest code that calls GetProcAddress, then GetLastError."""
    with Speakeasy(config=config) as se:
        code_base = se.load_shellcode(data=b"\xcc" * 0x100, arch=architecture)
        base = se.emu.load_module_by_name(module).base
        # GetProcAddress treats pointers below 64 KiB as ordinals.
        data = se.mem_alloc(0x1000, base=0x20000000)
        se.mem_write(data, b"\0" * 0x20 + name.encode() + b"\0")
        resolver = se.emu.get_proc("kernel32", "GetProcAddress")
        last_error = se.emu.get_proc("kernel32", "GetLastError")
        if architecture == "x86":

            def d(value):
                return struct.pack("<I", value)

            code = b"\x68" + d(data + 0x20) + b"\x68" + d(base) + b"\xb8" + d(resolver) + b"\xff\xd0\xa3" + d(data)
            code += b"\xb8" + d(last_error) + b"\xff\xd0\xa3" + d(data + 8) + b"\xc3"
        else:

            def q(value):
                return struct.pack("<Q", value)

            code = b"\x48\x83\xec\x28\x48\xb9" + q(base) + b"\x48\xba" + q(data + 0x20) + b"\x48\xb8" + q(resolver)
            code += b"\xff\xd0\x49\xba" + q(data) + b"\x49\x89\x02\x48\xb8" + q(last_error)
            code += b"\xff\xd0\x49\xba" + q(data) + b"\x49\x89\x42\x08\x48\x83\xc4\x28\xc3"
        se.mem_write(code_base, code)
        se.run_shellcode(code_base)
        assert se.get_report().entry_points[0].error is None
        width = se.get_ptr_size()
        result, error = (int.from_bytes(se.mem_read(data + offset, width), "little") for offset in (0, 8))
        expected = se.emu.get_proc(module, name) if result else 0
        return result, error & 0xFFFFFFFF, expected


@pytest.mark.parametrize("architecture", ["x86", "amd64"])
def test_get_proc_address_reports_unknown_names(config, architecture):
    config["modules"]["functions_always_exist"] = False
    assert call_get_proc_address(config, architecture, "kernel32", "SpeakeasyNoSuchExport")[:2] == (0, 127)
