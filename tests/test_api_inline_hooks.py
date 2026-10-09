"""Guest five-byte inline hooks can call an untouched original API trampoline."""

import struct

import pytest

from speakeasy.profiler import Run


@pytest.mark.parametrize("dynamic", [False, True])
@pytest.mark.parametrize("tracing", [False, True])
def test_x86_guest_five_byte_hook_calls_original_trampoline(dll_emu, dynamic, tracing):
    se = dll_emu
    emu = se.emu
    emu.curr_run = Run()
    emu.profiler.add_run(emu.curr_run)
    emu.set_hooks()
    if tracing:
        emu.add_code_hook(emu._hook_code_tracing)
    dll = "inline_hook_target" if dynamic else "kernel32"
    function = "Tick" if dynamic else "GetTickCount"
    if dynamic:
        module = emu.load_module_by_name(dll)
        address = emu.api_registry.dynamic(module, function).address
    else:
        address = emu.get_proc(dll, function)
    entry = emu.api_registry.entries[address]
    trap = entry.trap
    original = emu.mem_read(address, 16)
    caller = emu.mem_map(0x1000, tag="inline_hook.guest")
    trampoline, hook = caller + 0x100, caller + 0x200
    # The guest hook CALLs its saved trampoline, then adjusts the original result.
    hook_code = b"\xe8" + struct.pack("<I", (trampoline - hook - 5) & 0xFFFFFFFF)
    emu.mem_write(hook, hook_code + b"\x83\xc0\x01\xc3")
    # Like a real inline-hook installer, guest instructions copy exactly five
    # bytes, append JMP original+5, and patch the original with JMP guest_hook.
    code = b"\xbe" + struct.pack("<I", address) + b"\xbf" + struct.pack("<I", trampoline)
    code += b"\xa5\xa4"  # MOVSD; MOVSB
    code += b"\xc6\x05" + struct.pack("<I", trampoline + 5) + b"\xe9"
    code += b"\xc7\x05" + struct.pack("<II", trampoline + 6, (address + 5 - trampoline - 10) & 0xFFFFFFFF)
    code += b"\xc6\x05" + struct.pack("<I", address) + b"\xe9"
    code += b"\xc7\x05" + struct.pack("<II", address + 1, (hook - address - 5) & 0xFFFFFFFF)
    code += b"\xb8" + struct.pack("<I", address) + b"\xff\xd0"
    stop_address = caller + len(code)
    emu.mem_write(caller, code + b"\x90")
    # Hook installers make the target page writable before patching it.
    emu.mem_protect(address & ~0xFFF, 0x1000, 7)
    hits = []
    se.add_api_hook(lambda e, api, original, args: hits.append(api) or 77, dll, function, argc=0)
    stack = emu.get_stack_ptr()
    stop = emu.add_code_hook(lambda e, a, n: e.emu_eng.stop(), begin=stop_address, end=stop_address)
    try:
        emu._run_api_engine(caller, timeout=3, count=100)
    finally:
        stop.disable()
    assert emu.get_pc() == stop_address
    assert emu.get_stack_ptr() == stack
    assert emu.get_return_val() == 78
    assert hits == [f"{dll}.{function}"]
    assert emu.curr_run.error is None
    assert emu.mem_read(trampoline, 5) == original[:5]
    assert emu.mem_read(address + 5, 11) == original[5:]
    assert emu.api_registry.entries[address] is entry
    assert emu.api_registry.traps[trap] is entry
    assert [event.api_name for event in emu.curr_run.events if event.event == "api"] == [f"{dll}.{function}"]
