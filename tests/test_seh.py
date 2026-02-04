# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import copy

DISPATCH_SCRIPT = [
    "Hello emulator\n",
    "First access violation\r\n",
    "First nested access violation\r\n",
    "Second nested access violation\r\n",
    "After access violations\r\n",
    "In finally\r\n",
    "Returning...\n",
]


def test_seh_dispatch(config, load_test_bin, run_test):
    cfg = copy.deepcopy(config)
    cfg["exceptions"]["dispatch_handlers"] = True
    data = load_test_bin("seh_test_x86.exe.xz")
    report = run_test(cfg, data)

    ep = report["entry_points"]
    printfs = []
    for evt in ep[0].get("events", []):
        if evt.get("event") == "api" and "__stdio_common_vfprintf" in evt["api_name"]:
            printfs.append(evt)

    fmt_strings = [p["args"][2] for p in printfs]
    assert len(fmt_strings) == len(DISPATCH_SCRIPT)
    for i, s in enumerate(fmt_strings):
        assert s == DISPATCH_SCRIPT[i]


def test_seh_without_dispatch(config, load_test_bin, run_test):
    cfg = copy.deepcopy(config)
    cfg["exceptions"]["dispatch_handlers"] = False

    data = load_test_bin("seh_test_x86.exe.xz")
    report = run_test(cfg, data)

    ep = report["entry_points"]
    printfs = []
    for evt in ep[0].get("events", []):
        if evt.get("event") == "api" and "__stdio_common_vfprintf" in evt["api_name"]:
            printfs.append(evt)
            break

    assert len(printfs) == 1
    error = ep[0]["error"]

    assert error["type"] == "invalid_write"
    assert error["address"] == "0x0"
    assert error["instr"] == "mov dword ptr [0], 0x14"
