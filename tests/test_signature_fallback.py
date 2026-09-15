"""
End-to-end tests for emulating imports that have no speakeasy handler using
the bundled Win32 API signature database.

Each test loads a small hand-assembled shellcode blob that calls
``kernel32!MoveFileExW`` (no handler in speakeasy) followed by
``kernel32!ExitProcess`` (handled). The argument to ExitProcess is pushed
*before* the MoveFileExW call so that, on x86, it is only seen correctly if
the fallback cleaned up exactly the right number of stack slots.
"""

import struct
from typing import Any

import pytest

from speakeasy import Speakeasy
from speakeasy.profiler_events import ApiEvent
from speakeasy.report import Report
from speakeasy.winenv.api import sigdb

OLD_NAME = "C:\\old.txt"
NEW_NAME = "C:\\new.txt"
EXIT_CODE = 0x1234
MOVEFILE_REPLACE_EXISTING = 0x1


def _wstr(s: str) -> bytes:
    return s.encode("utf-16le") + b"\x00\x00"


def _build_x86() -> tuple[bytes, dict[str, tuple[int, int]]]:
    """
    call $+5 / pop ebx            ; ebx = blob + 5
    push EXIT_CODE                ; argument for ExitProcess, must survive the stdcall cleanup
    push MOVEFILE_REPLACE_EXISTING
    lea eax, [ebx + new] / push eax
    lea eax, [ebx + old] / push eax
    mov eax, <MoveFileExW>        ; patched
    call eax
    mov eax, <ExitProcess>        ; patched
    call eax
    """
    code = bytearray()
    code += b"\xe8\x00\x00\x00\x00"  # call $+5
    code += b"\x5b"  # pop ebx
    code += b"\x68" + struct.pack("<I", EXIT_CODE)  # push EXIT_CODE
    code += b"\x68" + struct.pack("<I", MOVEFILE_REPLACE_EXISTING)  # push dwFlags
    lea_new_off = len(code)
    code += b"\x8d\x83" + b"\x00\x00\x00\x00"  # lea eax, [ebx+disp]
    code += b"\x50"  # push eax
    lea_old_off = len(code)
    code += b"\x8d\x83" + b"\x00\x00\x00\x00"  # lea eax, [ebx+disp]
    code += b"\x50"  # push eax
    move_off = len(code) + 1
    code += b"\xb8" + b"\x00\x00\x00\x00"  # mov eax, imm32
    code += b"\xff\xd0"  # call eax
    exit_off = len(code) + 1
    code += b"\xb8" + b"\x00\x00\x00\x00"  # mov eax, imm32
    code += b"\xff\xd0"  # call eax
    old_off = len(code)
    code += _wstr(OLD_NAME)
    new_off = len(code)
    code += _wstr(NEW_NAME)
    # ebx holds the address of the byte after the initial call (offset 5)
    code[lea_new_off + 2 : lea_new_off + 6] = struct.pack("<i", new_off - 5)
    code[lea_old_off + 2 : lea_old_off + 6] = struct.pack("<i", old_off - 5)
    return bytes(code), {"MoveFileExW": (move_off, 4), "ExitProcess": (exit_off, 4)}


def _build_x64() -> tuple[bytes, dict[str, tuple[int, int]]]:
    """
    call $+5 / pop rbx            ; rbx = blob + 5
    lea rcx, [rbx + old]
    lea rdx, [rbx + new]
    mov r8d, MOVEFILE_REPLACE_EXISTING
    sub rsp, 0x28
    mov rax, <MoveFileExW> / call rax
    add rsp, 0x28
    mov ecx, EXIT_CODE
    sub rsp, 0x28
    mov rax, <ExitProcess> / call rax
    """
    code = bytearray()
    code += b"\xe8\x00\x00\x00\x00"  # call $+5
    code += b"\x5b"  # pop rbx
    lea_old_off = len(code)
    code += b"\x48\x8d\x8b" + b"\x00\x00\x00\x00"  # lea rcx, [rbx+disp]
    lea_new_off = len(code)
    code += b"\x48\x8d\x93" + b"\x00\x00\x00\x00"  # lea rdx, [rbx+disp]
    code += b"\x41\xb8" + struct.pack("<I", MOVEFILE_REPLACE_EXISTING)  # mov r8d, imm32
    code += b"\x48\x83\xec\x28"  # sub rsp, 0x28
    move_off = len(code) + 2
    code += b"\x48\xb8" + b"\x00" * 8  # mov rax, imm64
    code += b"\xff\xd0"  # call rax
    code += b"\x48\x83\xc4\x28"  # add rsp, 0x28
    code += b"\xb9" + struct.pack("<I", EXIT_CODE)  # mov ecx, imm32
    code += b"\x48\x83\xec\x28"  # sub rsp, 0x28
    exit_off = len(code) + 2
    code += b"\x48\xb8" + b"\x00" * 8  # mov rax, imm64
    code += b"\xff\xd0"  # call rax
    old_off = len(code)
    code += _wstr(OLD_NAME)
    new_off = len(code)
    code += _wstr(NEW_NAME)
    code[lea_old_off + 3 : lea_old_off + 7] = struct.pack("<i", old_off - 5)
    code[lea_new_off + 3 : lea_new_off + 7] = struct.pack("<i", new_off - 5)
    return bytes(code), {"MoveFileExW": (move_off, 8), "ExitProcess": (exit_off, 8)}


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
        assert emu is not None
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

BUILDERS = {"x86": _build_x86, "amd64": _build_x64}


def _run(config: dict[str, Any], arch: str) -> Report:
    if not sigdb.get_default_database().available:
        pytest.skip("bundled signature database not generated (run scripts/gen_win32_signatures.py)")
    code, patches = BUILDERS[arch]()
    se = Speakeasy(config=config)
    try:
        sc_addr = se.load_shellcode(data=code, arch=arch)
        emu = se.emu
        assert emu is not None
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


@pytest.mark.parametrize("arch", ["x86", "amd64"])
def test_unhooked_import_is_emulated_from_signature(config: dict[str, Any], arch: str) -> None:
    report = _run(config, arch)
    ep = report.entry_points[0]
    assert ep.error is None, ep.error

    events = _api_events(report)
    names = [e.api_name for e in events]
    assert names == ["kernel32.MoveFileExW", "kernel32.ExitProcess"]

    move = events[0]
    assert move.args == [
        f'lpExistingFileName: "{OLD_NAME}"',
        f'lpNewFileName: "{NEW_NAME}"',
        "dwFlags: MOVEFILE_REPLACE_EXISTING",
    ]
    # BOOL return: fake success
    assert move.ret_val == "0x1"

    # The stack (x86) / registers (x64) were left exactly as the caller expects
    assert events[1].args == [f"{EXIT_CODE:#x}"]


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
    assert call.args[:3] == ['lpAppName: "app"', 'lpKeyName: "key"', 'lpDefault: "def"']
    assert call.args[3].startswith("lpReturnedString: 0x")
    assert call.args[4:] == [f"nSize: {PROFILE_BUFFER_CHARS:#x}", 'lpFileName: "C:\\x.ini"']
    # "0 characters copied" and an empty string in the buffer agree with each other
    assert call.ret_val == "0x0"
    assert blobs[3] == b"\x00" * (PROFILE_BUFFER_CHARS * 2) + b"\xcc" * 4
    assert events[1].args == [f"{EXIT_CODE:#x}"]


def test_in_struct_pointer_is_decoded(config: dict[str, Any]) -> None:
    """A pointer to a known struct renders as {field: value, ...} with typed fields."""
    security_attributes = struct.pack("<III", 12, 0, 1)  # nLength, lpSecurityDescriptor, bInheritHandle
    args: list[int | bytes] = [_wstr("C:\\tmpl"), _wstr("C:\\new"), security_attributes]
    report, _ = _run_x86_call(config, "CreateDirectoryExW", args)

    ep = report.entry_points[0]
    assert ep.error is None, ep.error
    events = _api_events(report)
    assert [e.api_name for e in events] == ["kernel32.CreateDirectoryExW", "kernel32.ExitProcess"]
    assert events[0].args == [
        'lpTemplateDirectory: "C:\\tmpl"',
        'lpNewDirectory: "C:\\new"',
        "lpSecurityAttributes: {nLength: 0xc, lpSecurityDescriptor: 0x0, bInheritHandle: TRUE}",
    ]
    assert events[0].ret_val == "0x1"
    assert events[1].args == [f"{EXIT_CODE:#x}"]


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
        assert emu is not None
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
        assert emu is not None
        assert emu.has_api_signature("kernel32", "MoveFileExW")
        assert not emu.has_api_signature("kernel32", "ThisApiDoesNotExistAnywhere")
        # skip-marked declarations are not offered
        sig = sigdb.get_default_database().lookup("oleaut32", "VarCyAdd", "x86")
        if sig is not None and sig.skip:
            assert not emu.has_api_signature("oleaut32", "VarCyAdd")
    finally:
        se.shutdown()
