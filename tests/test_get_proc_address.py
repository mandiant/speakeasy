# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.


def get_api_calls(ep, api_name):
    events = ep.events or []
    return [evt for evt in events if evt.event == "api" and evt.api_name == api_name]


def test_get_proc_address_on_missing_function_returns_zero(config, load_test_bin, run_test):
    data = load_test_bin("GetProcAddress.exe.xz")
    report = run_test(config, data)
    eps = report.entry_points

    get_proc_addr = get_api_calls(eps[0], "KERNEL32.GetProcAddress")

    assert get_proc_addr[2].args[1] == "AreFileApisANSI"
    assert get_proc_addr[2].ret_val != "0x0"

    assert get_proc_addr[3].args[1] == "ThisFunctionIsNotExportedByKernel32"
    assert get_proc_addr[3].ret_val == "0x0"
