# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import struct
from typing import Any

from speakeasy import Speakeasy
from tests.handler_harness import alloc, call, start_process

FORWARDER_IN_FILE = "023f838239b6d3f9dbe5a1a0468dc99805bdced685616887d1b59afff4c3243d.exe.xz"
FORWARDER_AT_RUNTIME = "02c2d9f9893478f4af1395dcd57f1bf800f965d99d3f40e2100f3a1ff7aa5113.exe.xz"

RESOLVED_APIS = [
    "ntdll.ZwUnmapViewOfSection",
    "kernel32.CreateProcessA",
    "kernel32.GetThreadContext",
    "kernel32.ReadProcessMemory",
    "kernel32.VirtualQueryEx",
    "kernel32.VirtualProtectEx",
    "kernel32.WriteProcessMemory",
    "kernel32.SetThreadContext",
    "kernel32.ResumeThread",
]


def get_api_calls(ep, api_name):
    events = ep.events or []
    return [evt for evt in events if evt.event == "api" and evt.api_name == api_name]


def get_export_directory_size(se: Speakeasy, base: int) -> int:
    e_lfanew = struct.unpack("<I", se.mem_read(base + 0x3C, 4))[0]
    # PE32: optional header at +0x18, DataDirectory[0].Size at +0x60 + 4 within it
    return struct.unpack("<I", se.mem_read(base + e_lfanew + 0x7C, 4))[0]


def get_self_resolutions(config: dict[str, Any], data: bytes) -> tuple[list[tuple[str, int, int]], int, int]:
    """
    Run a sample that writes "dll.function" into its exported variable szFile and then
    calls GetProcAddress(itself, "szFile").

    Returns:
        (forwarder string, GetProcAddress result, address of the forwarded API) for each
        lookup, and the export directory Size of the image before and after the run.
    """
    with Speakeasy(config=config) as se:
        module = se.load_module(data=data)
        size_before = get_export_directory_size(se, module.base)
        se.run_module(module)
        size_after = get_export_directory_size(se, module.base)
        resolutions = []
        forwarder = ""
        for event in se.get_report().entry_points[0].events or []:
            if event.event != "api":
                continue
            if event.api_name == "kernel32.lstrcatA":
                forwarder = event.args[0].display + event.args[1].display
            elif event.api_name == "kernel32.GetProcAddress" and event.args[1].display == "szFile":
                assert int(event.args[0].display, 16) == module.base
                dll, name = forwarder.split(".")
                resolutions.append((forwarder, int(event.ret_val, 16), se.emu.get_proc(dll, name)))
    return resolutions, size_before, size_after


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


def test_get_proc_address_reads_a_forwarder_that_the_image_wrote_at_runtime(config, load_test_bin):
    """
    023f8382 declares an export directory of 0x80000000 bytes, larger than the image, so
    its exported variable szFile is a forwarder. Before each process hollowing API it
    needs, it writes "dll.function" into szFile and calls GetProcAddress on itself.
    """
    resolutions, size_before, size_after = get_self_resolutions(config, load_test_bin(FORWARDER_IN_FILE))

    assert size_before == size_after == 0x80000000
    assert [forwarder for forwarder, _, _ in resolutions] == RESOLVED_APIS
    for forwarder, resolved, expected in resolutions:
        assert resolved != 0, forwarder
        assert resolved == expected, forwarder


def test_get_proc_address_follows_an_export_that_a_larger_export_directory_makes_a_forwarder(config, load_test_bin):
    """
    02c2d9f9 is a variant of 023f8382 whose file declares an export directory of 0x45
    bytes, so szFile is a plain data export. At run time it makes its header writable with
    VirtualProtect and sets the directory Size to 0x80000000, which makes szFile a
    forwarder, then resolves its APIs as 023f8382 does.
    """
    resolutions, size_before, size_after = get_self_resolutions(config, load_test_bin(FORWARDER_AT_RUNTIME))

    assert size_before == 0x45
    assert size_after == 0x80000000
    assert [forwarder for forwarder, _, _ in resolutions] == RESOLVED_APIS
    for forwarder, resolved, expected in resolutions:
        assert resolved != 0, forwarder
        assert resolved == expected, forwarder
