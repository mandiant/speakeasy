# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from tests.handler_harness import alloc, call, start_process


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
