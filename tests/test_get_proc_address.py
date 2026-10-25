# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import struct

from tests.handler_harness import alloc, call, load_emu, start_process
from tests.pe_builder import build_pe


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


def test_get_proc_address_on_the_host_image_of_a_dll_returns_zero(dll_emu):
    start_process(dll_emu)
    host = call(dll_emu, "kernel32", "GetModuleHandleA", [0])[0]
    assert host == dll_emu.emu.container_image.base
    name = alloc(dll_emu, b"ReShadeRegisterAddon\0")
    assert call(dll_emu, "kernel32", "GetProcAddress", [host, name])[0] == 0


def build_runtime_forwarder_exe():
    directory_rva, buffer_rva = 0x2000, 0x2100
    data = bytearray(0x200)
    struct.pack_into("<IIHHIIIIIII", data, 0, 0, 0, 0, 0, 0x2050, 1, 1, 1, 0x2028, 0x202C, 0x2030)
    struct.pack_into("<IIH", data, 0x28, buffer_rva, 0x2040, 0)
    data[0x40:0x44] = b"fwd\0"
    data[0x50:0x59] = b"test.exe\0"
    image, _ = build_pe(32, data=bytes(data), extra_dirs={0: (directory_rva, 0x80000000)})
    return image, buffer_rva


def test_get_proc_address_reads_a_forwarder_that_the_image_wrote_at_runtime(config):
    image, buffer_rva = build_runtime_forwarder_exe()
    for se in load_emu(config, image):
        start_process(se)
        host = call(se, "kernel32", "GetModuleHandleA", [0])[0]
        se.mem_write(host + buffer_rva, b"kernel32.Sleep\0")
        forwarded = call(se, "kernel32", "GetProcAddress", [host, alloc(se, b"fwd\0")])[0]
        kernel32 = call(se, "kernel32", "GetModuleHandleA", [alloc(se, b"kernel32\0")])[0]
        sleep = call(se, "kernel32", "GetProcAddress", [kernel32, alloc(se, b"Sleep\0")])[0]
        assert sleep != 0
        assert forwarded == sleep


def build_data_export_exe():
    directory_rva, buffer_rva = 0x2000, 0x2100
    data = bytearray(0x200)
    struct.pack_into("<IIHHIIIIIII", data, 0, 0, 0, 0, 0, 0x2050, 1, 1, 1, 0x2028, 0x202C, 0x2030)
    struct.pack_into("<IIH", data, 0x28, buffer_rva, 0x2040, 0)
    data[0x40:0x47] = b"szFile\0"
    data[0x50:0x59] = b"test.exe\0"
    image, _ = build_pe(32, data=bytes(data), extra_dirs={0: (directory_rva, 0x60)})
    return image, buffer_rva


def test_get_proc_address_follows_an_export_that_a_larger_export_directory_makes_a_forwarder(config):
    image, buffer_rva = build_data_export_exe()
    export_size = 0x80 + 0x18 + 96 + 4
    for se in load_emu(config, image):
        start_process(se)
        host = call(se, "kernel32", "GetModuleHandleA", [0])[0]
        name = alloc(se, b"szFile\0")
        assert call(se, "kernel32", "GetProcAddress", [host, name])[0] == host + buffer_rva

        se.mem_write(host + export_size, struct.pack("<I", 0x80000000))
        se.mem_write(host + buffer_rva, b"kernel32.GetTickCount\0")
        forwarded = call(se, "kernel32", "GetProcAddress", [host, name])[0]

        kernel32 = call(se, "kernel32", "GetModuleHandleA", [alloc(se, b"kernel32\0")])[0]
        get_tick_count = call(se, "kernel32", "GetProcAddress", [kernel32, alloc(se, b"GetTickCount\0")])[0]
        assert get_tick_count != 0
        assert forwarded == get_tick_count

        se.mem_write(host + export_size, struct.pack("<I", 0x60))
        assert call(se, "kernel32", "GetProcAddress", [host, name])[0] == host + buffer_rva
