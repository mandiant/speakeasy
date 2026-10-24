# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import copy

import pytest

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

    ep = report.entry_points
    printfs = []
    for evt in ep[0].events or []:
        if evt.event == "api" and "__stdio_common_vfprintf" in evt.api_name:
            printfs.append(evt)

    fmt_strings = [p.args[2].display for p in printfs]
    assert len(fmt_strings) == len(DISPATCH_SCRIPT)
    for i, s in enumerate(fmt_strings):
        assert s == DISPATCH_SCRIPT[i]


def test_seh_without_dispatch(config, load_test_bin, run_test):
    cfg = copy.deepcopy(config)
    cfg["exceptions"]["dispatch_handlers"] = False

    data = load_test_bin("seh_test_x86.exe.xz")
    report = run_test(cfg, data)

    ep = report.entry_points
    printfs = []
    for evt in ep[0].events or []:
        if evt.event == "api" and "__stdio_common_vfprintf" in evt.api_name:
            printfs.append(evt)
            break

    assert len(printfs) == 1
    error = ep[0].error

    assert error.type == "invalid_write"
    assert error.instr == "mov dword ptr [0], 0x14"


# Bits of the return value of seh_cases.c, one per case
SEH_CASES = {
    0x01: "RaiseException caught by __except(1)",
    0x02: "filter function, then __finally during the unwind",
    0x04: "access violation in a leaf function",
    0x08: "filter returns EXCEPTION_CONTINUE_EXECUTION",
    0x10: "vectored handler steps over int3",
    0x20: "exception caught in the caller's frame",
    0x40: "bad pointer read by an API faults in its caller",
    0x80: "hardware breakpoint from SetThreadContext, resume flag, and disarming",
    0x100: "vectored handler catches a fault of its own in __try, then continues",
}


@pytest.mark.parametrize("arch", ["x64", "x86"])
def test_seh_cases(config, load_test_bin, run_test, arch):
    cfg = copy.deepcopy(config)
    cfg["exceptions"]["dispatch_handlers"] = True
    report = run_test(cfg, load_test_bin(f"seh_cases_{arch}.exe.xz"))

    ep = report.entry_points[0]
    assert ep.error is None
    failed = [case for bit, case in SEH_CASES.items() if not ep.ret_val & bit]
    assert not failed

    exceptions = [(e.exception_code, e.faulting_address) for e in ep.events or [] if e.event == "exception"]
    assert exceptions == [
        ("0xe0000001", None),
        ("0xe0000002", None),
        ("0xc0000005", "0x0"),
        ("0xe0000003", None),
        ("0x80000003", None),
        ("0xe0000005", None),
        ("0xc0000005", "0x10"),
        ("0x80000004", None),
        ("0x80000004", None),
        ("0xe0000009", None),
        ("0xc0000005", "0x0"),
    ]
