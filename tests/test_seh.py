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
    cfg["exceptions"]["dispatch"] = True
    data = load_test_bin("seh_test_x86.exe.xz")
    report = run_test(cfg, data)

    ep = report.runs
    printfs = []
    for evt in ep[0].events:
        if evt.event == "api" and "__stdio_common_vfprintf" in evt.api_name:
            printfs.append(evt)

    fmt_strings = [p.args[2].display for p in printfs]
    assert len(fmt_strings) == len(DISPATCH_SCRIPT)
    for i, s in enumerate(fmt_strings):
        assert s == DISPATCH_SCRIPT[i]


def test_seh_without_dispatch(config, load_test_bin, run_test):
    cfg = copy.deepcopy(config)
    cfg["exceptions"]["dispatch"] = False

    data = load_test_bin("seh_test_x86.exe.xz")
    report = run_test(cfg, data)

    ep = report.runs
    printfs = []
    for evt in ep[0].events:
        if evt.event == "api" and "__stdio_common_vfprintf" in evt.api_name:
            printfs.append(evt)
            break

    assert len(printfs) == 1
    error = ep[0].error

    assert error.type == "invalid_write"
    assert error.instruction == "mov dword ptr [0], 0x14"


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
    0x200: "read of the reserved range above the stack faults at that address",
    0x400: "C++ frame with no catch block passes a fault on to the outer frame",
}

SEH_CASES_X86 = {
    0x800: "fault context has the native x86 selectors",
    0x1000: "NtContinue resumes at a context from RtlCaptureContext",
}


@pytest.mark.parametrize("arch", ["x64", "x86"])
def test_seh_cases(config, load_test_bin, run_test, arch):
    cfg = copy.deepcopy(config)
    cfg["exceptions"]["dispatch"] = True
    report = run_test(cfg, load_test_bin(f"seh_cases_{arch}.exe.xz"))

    ep = report.runs[0]
    assert ep.error is None
    cases = SEH_CASES | SEH_CASES_X86 if arch == "x86" else SEH_CASES
    failed = [case for bit, case in cases.items() if not ep.return_value & bit]
    assert not failed

    exceptions = [(e.exception_code, e.address) for e in ep.events if e.event == "exception"]
    assert exceptions == [
        (0xE0000001, None),
        (0xE0000002, None),
        (0xC0000005, 0x0),
        (0xE0000003, None),
        (0x80000003, None),
        (0xE0000005, None),
        (0xC0000005, 0x10),
        (0x80000004, None),
        (0x80000004, None),
        (0xE0000009, None),
        (0xC0000005, 0x0),
        (0xC0000005, 0x1300000),
        (0xC0000005, 0x0),
    ] + ([(0xC0000005, 0x0)] if arch == "x86" else [])


@pytest.mark.parametrize("arch", ["x64", "x86"])
def test_an_exception_that_an_api_raises_has_the_pos_of_the_api_call(config, load_test_bin, run_test, arch):
    cfg = copy.deepcopy(config)
    cfg["limits"]["instructions"] = 10_000_000
    report = run_test(cfg, load_test_bin(f"seh_cases_{arch}.exe.xz"))

    events = report.runs[0].events
    raised = [
        (exception, call)
        for exception, call in zip(events, events[1:])
        if exception.event == "exception" and call.event == "api" and call.api_name == "kernel32.RaiseException"
    ]
    # The access violation of an API handler comes after the api event of its call.
    faulted = [
        (exception, call)
        for call, exception in zip(events, events[1:])
        if exception.event == "exception" and call.event == "api" and call.api_name == "kernel32.RtlMoveMemory"
    ]
    assert len(raised) == 5
    assert len(faulted) == 1
    for exception, call in raised + faulted:
        assert call.pos.tick is not None
        assert exception.pos == call.pos
        assert exception.instruction.startswith(("call", "jmp"))
