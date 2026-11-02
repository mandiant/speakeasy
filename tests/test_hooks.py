"""Every hook callback gets the emulator first, and ``remove_hook`` or ``disable`` stops the calls."""

import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.windows.win32 import Win32Emulator


def _call(se, api):
    return b"\xb8" + struct.pack("<I", se.emu.get_proc("kernel32", api)) + b"\xff\xd0"


def _get_virtual_alloc_code(se):
    # VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE),
    # then write ret into the buffer and call it.
    push_args = b"\x6a\x40\x68\x00\x30\x00\x00\x68\x00\x10\x00\x00\x6a\x00"
    return push_args + _call(se, "VirtualAlloc") + b"\xc6\x00\xc3\xff\xd0\xc3"


CASES = {
    "api": (
        lambda se, cb: se.add_api_hook(cb, "kernel32", "GetTickCount"),
        lambda se: _call(se, "GetTickCount") + b"\xc3",
    ),
    "code": (lambda se, cb: se.add_code_hook(cb), lambda se: b"\xc3"),
    "mem_read": (lambda se, cb: se.add_mem_read_hook(cb), lambda se: b"\xc3"),
    "mem_write": (lambda se, cb: se.add_mem_write_hook(cb), lambda se: b"\x50\x58\xc3"),
    "mem_invalid": (lambda se, cb: se.add_mem_invalid_hook(cb), lambda se: b"\xa1\x00\x00\x00\x00\xc3"),
    "mem_map": (lambda se, cb: se.add_mem_map_hook(cb), _get_virtual_alloc_code),
    "interrupt": (lambda se, cb: se.add_interrupt_hook(cb), lambda se: b"\xcc\xc3"),
    "invalid_instruction": (lambda se, cb: se.add_invalid_instruction_hook(cb), lambda se: b"\x0f\x0b\xc3"),
    "dyn_code": (lambda se, cb: se.add_dyn_code_hook(cb), _get_virtual_alloc_code),
}


@pytest.mark.parametrize("when", ["before_load", "after_load"])
@pytest.mark.parametrize("kind", CASES)
def test_hook_gets_emulator_and_stops_after_remove_or_disable(config, kind, when):
    add_hook, get_code = CASES[kind]
    kept: list = []
    removed: list = []
    disabled: list = []

    def add_hooks(se):
        # An API hook's return value is the API's return value, so return 0.
        hooks = [
            add_hook(se, lambda emu, *args, calls=calls: calls.append(emu) or 0) for calls in (kept, removed, disabled)
        ]
        se.remove_hook(hooks[1])
        hooks[2].disable()

    with Speakeasy(config=config) as se:
        if when == "before_load":
            add_hooks(se)
        base = se.load_shellcode(data=bytes(0x1000), arch="x86")
        if when == "after_load":
            add_hooks(se)
        se.mem_write(base, get_code(se))
        se.run_shellcode(base)

    assert kept
    assert all(isinstance(emu, Win32Emulator) for emu in kept)
    assert removed == []
    assert disabled == []
