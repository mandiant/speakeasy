"""
End-to-end tests for emulating imports that have no speakeasy handler using
the bundled Win32 API signature database.

Most tests load a small hand-assembled shellcode blob that calls one such API
followed by ``kernel32!ExitProcess`` (handled). The argument to ExitProcess is
pushed *before* the call so that, on x86, it is only seen correctly if the
fallback cleaned up exactly the right number of stack slots.
"""

import struct
from typing import Any

import pytest

from speakeasy import Speakeasy
from speakeasy.profiler_events import ApiArg, ApiEvent
from speakeasy.report import Report
from speakeasy.winenv.api import sigdb

LINK_NAME = "C:\\link"
TARGET_NAME = "C:\\target"
EXIT_CODE = 0x1234
SYMBOLIC_LINK_FLAG_DIRECTORY = 0x1

RESOURCE_UPDATER = "023f838239b6d3f9dbe5a1a0468dc99805bdced685616887d1b59afff4c3243d.exe.xz"


def _wstr(s: str) -> bytes:
    return s.encode("utf-16le") + b"\x00\x00"


def _build_x64() -> tuple[bytes, dict[str, tuple[int, int]]]:
    """
    call $+5 / pop rbx            ; rbx = blob + 5
    lea rcx, [rbx + link]
    lea rdx, [rbx + target]
    mov r8d, SYMBOLIC_LINK_FLAG_DIRECTORY
    sub rsp, 0x28
    mov rax, <CreateSymbolicLinkW> / call rax
    add rsp, 0x28
    mov ecx, EXIT_CODE
    sub rsp, 0x28
    mov rax, <ExitProcess> / call rax
    """
    code = bytearray()
    code += b"\xe8\x00\x00\x00\x00"  # call $+5
    code += b"\x5b"  # pop rbx
    lea_link_off = len(code)
    code += b"\x48\x8d\x8b" + b"\x00\x00\x00\x00"  # lea rcx, [rbx+disp]
    lea_target_off = len(code)
    code += b"\x48\x8d\x93" + b"\x00\x00\x00\x00"  # lea rdx, [rbx+disp]
    code += b"\x41\xb8" + struct.pack("<I", SYMBOLIC_LINK_FLAG_DIRECTORY)  # mov r8d, imm32
    code += b"\x48\x83\xec\x28"  # sub rsp, 0x28
    api_off = len(code) + 2
    code += b"\x48\xb8" + b"\x00" * 8  # mov rax, imm64
    code += b"\xff\xd0"  # call rax
    code += b"\x48\x83\xc4\x28"  # add rsp, 0x28
    code += b"\xb9" + struct.pack("<I", EXIT_CODE)  # mov ecx, imm32
    code += b"\x48\x83\xec\x28"  # sub rsp, 0x28
    exit_off = len(code) + 2
    code += b"\x48\xb8" + b"\x00" * 8  # mov rax, imm64
    code += b"\xff\xd0"  # call rax
    link_off = len(code)
    code += _wstr(LINK_NAME)
    target_off = len(code)
    code += _wstr(TARGET_NAME)
    code[lea_link_off + 3 : lea_link_off + 7] = struct.pack("<i", link_off - 5)
    code[lea_target_off + 3 : lea_target_off + 7] = struct.pack("<i", target_off - 5)
    return bytes(code), {"CreateSymbolicLinkW": (api_off, 8), "ExitProcess": (exit_off, 8)}


def _build_x86_call(api: str, args: list[int | bytes]) -> tuple[bytes, dict[str, tuple[int, int]], dict[int, int]]:
    """
    Generic x86 shellcode: ``api(*args)`` followed by ExitProcess(EXIT_CODE),
    whose argument is pushed *before* the call so it survives only if the
    callee cleaned up exactly the right number of slots. Each argument is an
    int (pushed as is) or bytes (placed in the blob and pushed by address).
    Returns (code, patches, {arg index: blob offset}).
    """
    code = bytearray()
    code += b"\xe8\x00\x00\x00\x00"  # call $+5
    code += b"\x5b"  # pop ebx ; ebx = blob + 5
    code += b"\x68" + struct.pack("<I", EXIT_CODE)  # push EXIT_CODE (for ExitProcess)
    fixups = []  # (offset of disp32, arg index)
    for index in reversed(range(len(args))):  # pushed right-to-left
        arg = args[index]
        if isinstance(arg, int):
            code += b"\x68" + struct.pack("<I", arg)  # push imm32
        else:
            fixups.append((len(code) + 2, index))
            code += b"\x8d\x83" + b"\x00\x00\x00\x00"  # lea eax, [ebx+disp]
            code += b"\x50"  # push eax
    api_off = len(code) + 1
    code += b"\xb8" + b"\x00\x00\x00\x00" + b"\xff\xd0"  # mov eax, imm32 ; call eax
    exit_off = len(code) + 1
    code += b"\xb8" + b"\x00\x00\x00\x00" + b"\xff\xd0"
    offsets = {}
    for index, arg in enumerate(args):
        if not isinstance(arg, int):
            code += b"\x00" * (-len(code) % 4)  # keep blobs 4-byte aligned
            offsets[index] = len(code)
            code += arg
    for off, index in fixups:
        code[off : off + 4] = struct.pack("<i", offsets[index] - 5)
    return bytes(code), {api: (api_off, 4), "ExitProcess": (exit_off, 4)}, offsets


def _run_x86_call(config: dict[str, Any], api: str, args: list[int | bytes]) -> tuple[Report, dict[int, bytes]]:
    """Run ``api(*args)`` on x86 and return (report, memory reader for blob arguments)."""
    if not sigdb.get_default_database().available:
        pytest.skip("bundled signature database not generated")
    code, patches, offsets = _build_x86_call(api, args)
    se = Speakeasy(config=config)
    try:
        sc_addr = se.load_shellcode(data=code, arch="x86")
        emu = se.emu
        for name, (offset, width) in patches.items():
            stub = emu.get_proc("kernel32", name)
            emu.mem_write(sc_addr + offset, stub.to_bytes(width, "little"))
        se.run_shellcode(sc_addr)
        report = se.get_report()
        blobs = {}
        for index, off in offsets.items():
            blob = args[index]
            assert isinstance(blob, bytes)
            blobs[index] = emu.mem_read(sc_addr + off, len(blob))
    finally:
        se.shutdown()
    return report, blobs


PROFILE_BUFFER_CHARS = 8


def _run_x64(config: dict[str, Any]) -> Report:
    if not sigdb.get_default_database().available:
        pytest.skip("bundled signature database not generated (run scripts/gen_win32_signatures.py)")
    code, patches = _build_x64()
    se = Speakeasy(config=config)
    try:
        sc_addr = se.load_shellcode(data=code, arch="amd64")
        emu = se.emu
        # Resolve import stubs the same way GetProcAddress would and patch the
        # absolute addresses into the blob.
        for name, (offset, width) in patches.items():
            stub = emu.get_proc("kernel32", name)
            emu.mem_write(sc_addr + offset, stub.to_bytes(width, "little"))
        se.run_shellcode(sc_addr)
        report: Report = se.get_report()
        return report
    finally:
        se.shutdown()


def _api_events(report: Report) -> list[ApiEvent]:
    return [e for e in (report.entry_points[0].events or []) if e.event == "api"]


def test_unhooked_import_is_emulated_from_signature(config: dict[str, Any], load_test_bin) -> None:
    """
    At the end of its run 023f8382 (x86) writes a resource into the copy of itself that
    it dropped, with BeginUpdateResourceA, UpdateResourceA and EndUpdateResourceA, which
    have no handler, then calls CloseHandle and ExitProcess. These calls are in start
    between RVA 0x1413 and 0x1449, where the stack pointer must be the same if each
    stdcall callee removed exactly its own arguments.
    """
    if not sigdb.get_default_database().available:
        pytest.skip("bundled signature database not generated (run scripts/gen_win32_signatures.py)")
    stack_pointers = {}
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(RESOURCE_UPDATER))
        for rva in (0x1413, 0x1449):

            def record(emu, address, size, rva=rva):
                stack_pointers[rva] = emu.get_stack_ptr()

            se.add_code_hook(record, begin=module.base + rva, end=module.base + rva)
        se.run_module(module)
        report = se.get_report()

    ep = report.entry_points[0]
    assert ep.error is None, ep.error
    events = _api_events(report)
    assert [e.api_name for e in events[-5:]] == [
        "kernel32.BeginUpdateResourceA",
        "kernel32.UpdateResourceA",
        "kernel32.EndUpdateResourceA",
        "kernel32.CloseHandle",
        "kernel32.ExitProcess",
    ]
    begin, update, end = events[-5:-2]
    assert [(a.name, a.type, a.display) for a in begin.args] == [
        ("pFileName", "str", "\\RemoteRegistry.exe"),
        ("bDeleteExistingResources", "bool", "FALSE"),
    ]
    handle = begin.ret_val
    assert handle != "0x0"
    assert [(a.name, a.type, a.display) for a in update.args] == [
        ("hUpdate", "handle", handle),
        ("lpType", "str", "RT_RCDATA"),
        ("lpName", "ptr", "0x66"),
        ("wLanguage", "int", "0x409"),
        ("lpData", "ptr", "0x4050b4"),
        ("cb", "int", "0x3000"),
    ]
    assert update.ret_val == "0x1"
    assert [(a.name, a.type, a.display) for a in end.args] == [
        ("hUpdate", "handle", handle),
        ("fDiscard", "bool", "FALSE"),
    ]
    assert end.ret_val == "0x1"
    assert stack_pointers[0x1413] == stack_pointers[0x1449]


def test_unhooked_import_is_emulated_from_signature_on_x64(config: dict[str, Any]) -> None:
    report = _run_x64(config)
    ep = report.entry_points[0]
    assert ep.error is None, ep.error

    events = _api_events(report)
    names = [e.api_name for e in events]
    assert names == ["kernel32.CreateSymbolicLinkW", "kernel32.ExitProcess"]

    created = events[0]
    assert [(a.name, a.type, a.display) for a in created.args] == [
        ("lpSymlinkFileName", "str", LINK_NAME),
        ("lpTargetFileName", "str", TARGET_NAME),
        ("dwFlags", "flags", "SYMBOLIC_LINK_FLAG_DIRECTORY"),
    ]
    assert created.args[2].value == SYMBOLIC_LINK_FLAG_DIRECTORY
    # BOOLEAN return: fake success
    assert created.ret_val == "0x1"

    # the registers were left exactly as the caller expects
    assert [a.display for a in events[1].args] == [f"{EXIT_CODE:#x}"]


def test_out_buffer_is_zero_filled(config: dict[str, Any]) -> None:
    """An Out buffer sized by a sibling parameter is zeroed; memory past it is untouched."""
    buffer = b"\xcc" * (PROFILE_BUFFER_CHARS * 2 + 4)  # buffer plus a sentinel that must survive
    args: list[int | bytes] = [
        _wstr("app"),
        _wstr("key"),
        _wstr("def"),
        buffer,
        PROFILE_BUFFER_CHARS,
        _wstr("C:\\x.ini"),
    ]
    report, blobs = _run_x86_call(config, "GetPrivateProfileStringW", args)

    ep = report.entry_points[0]
    assert ep.error is None, ep.error
    events = _api_events(report)
    assert [e.api_name for e in events] == ["kernel32.GetPrivateProfileStringW", "kernel32.ExitProcess"]
    call = events[0]
    assert [a.name for a in call.args] == [
        "lpAppName",
        "lpKeyName",
        "lpDefault",
        "lpReturnedString",
        "nSize",
        "lpFileName",
    ]
    displays = [a.display for a in call.args]
    assert displays[:3] == ["app", "key", "def"]
    assert displays[3].startswith("0x")
    assert displays[4:] == [f"{PROFILE_BUFFER_CHARS:#x}", "C:\\x.ini"]
    # the Out buffer is a pointer, not a string, before the call fills it
    assert [a.type for a in call.args] == ["str", "str", "str", "ptr", "int", "str"]
    # "0 characters copied" and an empty string in the buffer agree with each other
    assert call.ret_val == "0x0"
    assert blobs[3] == b"\x00" * (PROFILE_BUFFER_CHARS * 2) + b"\xcc" * 4
    assert [a.display for a in events[1].args] == [f"{EXIT_CODE:#x}"]


def test_in_struct_pointer_is_decoded(config: dict[str, Any]) -> None:
    """A pointer to a known struct renders as {field: value, ...} with typed fields."""
    security_attributes = struct.pack("<III", 12, 0, 1)  # nLength, lpSecurityDescriptor, bInheritHandle
    args: list[int | bytes] = [_wstr("C:\\tmpl"), _wstr("C:\\new"), security_attributes]
    report, _ = _run_x86_call(config, "CreateDirectoryExW", args)

    ep = report.entry_points[0]
    assert ep.error is None, ep.error
    events = _api_events(report)
    assert [e.api_name for e in events] == ["kernel32.CreateDirectoryExW", "kernel32.ExitProcess"]
    assert [(a.name, a.type, a.display) for a in events[0].args] == [
        ("lpTemplateDirectory", "str", "C:\\tmpl"),
        ("lpNewDirectory", "str", "C:\\new"),
        ("lpSecurityAttributes", "struct", "{nLength: 0xc, lpSecurityDescriptor: 0x0, bInheritHandle: TRUE}"),
    ]
    assert events[0].ret_val == "0x1"
    assert [a.display for a in events[1].args] == [f"{EXIT_CODE:#x}"]


GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x1
OPEN_EXISTING = 0x3
FILE_ATTRIBUTE_NORMAL = 0x80


def test_handled_api_args_are_named(config: dict[str, Any]) -> None:
    """A call served by a Python handler is recorded with the parameter names of its signature."""
    args: list[int | bytes] = [
        _wstr("C:\\missing.txt"),
        GENERIC_READ,
        FILE_SHARE_READ,
        0,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        0,
    ]
    report, _ = _run_x86_call(config, "CreateFileW", args)

    ep = report.entry_points[0]
    assert ep.error is None, ep.error
    events = _api_events(report)
    assert [e.api_name for e in events] == ["kernel32.CreateFileW", "kernel32.ExitProcess"]
    call = events[0]
    # the handler's own decoding of lpFileName is kept; the rest come from the signature
    assert [(a.name, a.type, a.display) for a in call.args] == [
        ("lpFileName", "str", "C:\\missing.txt"),
        ("dwDesiredAccess", "flags", "GENERIC_READ"),
        ("dwShareMode", "flags", "FILE_SHARE_READ"),
        ("lpSecurityAttributes", "ptr", "0x0"),
        ("dwCreationDisposition", "enum", "OPEN_EXISTING"),
        ("dwFlagsAndAttributes", "flags", "FILE_ATTRIBUTE_NORMAL"),
        ("hTemplateFile", "handle", "0x0"),
    ]
    values = [a.value for a in call.args[1:]]
    assert values == [GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0]
    assert events[1].args == [ApiArg(name="uExitCode", type="int", value=EXIT_CODE, display=f"{EXIT_CODE:#x}")]


def test_handler_signature_requires_matching_argc(config: dict[str, Any]) -> None:
    """A handler is only named from a signature that consumes the same argument slots."""
    if not sigdb.get_default_database().available:
        pytest.skip("bundled signature database not generated")
    se = Speakeasy(config=config)
    try:
        se.load_shellcode(data=b"\xc3", arch="x86")
        emu = se.emu
        sig = emu.get_handler_signature("kernel32", "CreateFileW", 7)
        assert sig is not None and sig.name == "CreateFileW"
        assert emu.get_handler_signature("kernel32", "CreateFileW", 6) is None
        assert emu.get_handler_signature("kernel32", "wsprintfW", 3) is None
        assert emu.get_handler_signature("msvcrt", "ThisApiDoesNotExistAnywhere", 1) is None
    finally:
        se.shutdown()


def test_functions_always_exist_still_applies_to_unknown_names(config: dict[str, Any]) -> None:
    # An import that is in neither the handlers nor the metadata stays fatal
    # unless functions_always_exist is set, exactly as before.
    if not sigdb.get_default_database().available:
        pytest.skip("bundled signature database not generated")
    se = Speakeasy(config=config)
    try:
        code = b"\xb8\x00\x00\x00\x00\xff\xd0"  # mov eax, imm32 ; call eax
        sc_addr = se.load_shellcode(data=code, arch="x86")
        emu = se.emu
        stub = emu.get_proc("kernel32", "ThisApiDoesNotExistAnywhere")
        emu.mem_write(sc_addr + 1, stub.to_bytes(4, "little"))
        se.run_shellcode(sc_addr)
        report = se.get_report()
    finally:
        se.shutdown()
    ep = report.entry_points[0]
    assert ep.error is not None and ep.error.type == "unsupported_api"


def test_get_proc_address_resolves_signature_only_exports(config: dict[str, Any]) -> None:
    """GetProcAddress succeeds for functions known only through their signature."""
    if not sigdb.get_default_database().available:
        pytest.skip("bundled signature database not generated")
    se = Speakeasy(config=config)
    try:
        sc_addr = se.load_shellcode(data=b"\x90\xc3", arch="x86")
        se.run_shellcode(sc_addr)
        emu = se.emu
        assert emu.has_api_signature("kernel32", "CreateSymbolicLinkW")
        assert not emu.has_api_signature("kernel32", "ThisApiDoesNotExistAnywhere")
    finally:
        se.shutdown()


def test_api_set_declarations_belong_to_the_host_module(config: dict[str, Any]) -> None:
    """Functions win32metadata declares only under an API set are declared by its host module."""
    if not sigdb.get_default_database().available:
        pytest.skip("bundled signature database not generated")
    se = Speakeasy(config=config)
    try:
        sc_addr = se.load_shellcode(data=b"\x90\xc3", arch="x86")
        se.run_shellcode(sc_addr)
        emu = se.emu
        assert emu.has_api_signature("combase", "RoInitialize")
        assert emu.has_api_signature("combase", "WindowsCreateString")
        assert emu.has_api_signature("kernel32", "PathCchCombine")
        assert not emu.has_api_signature("kernel32", "RoInitialize")
        assert not emu.has_api_signature("combase", "PathCchCombine")
    finally:
        se.shutdown()


def test_struct_argument_passed_by_value_is_emulated(config: dict[str, Any]) -> None:
    """A COORD passed by value takes one stack slot and renders as a struct."""
    report, _ = _run_x86_call(config, "SetConsoleScreenBufferSize", [0x7, 0x00190050])

    ep = report.entry_points[0]
    assert ep.error is None, ep.error
    events = _api_events(report)
    assert [e.api_name for e in events] == ["kernel32.SetConsoleScreenBufferSize", "kernel32.ExitProcess"]
    assert [(a.name, a.type, a.display) for a in events[0].args] == [
        ("hConsoleOutput", "handle", "0x7"),
        ("dwSize", "struct", "{X: 0x50, Y: 0x19}"),
    ]
    assert events[0].ret_val == "0x1"
    assert [a.display for a in events[1].args] == [f"{EXIT_CODE:#x}"]
