"""Guest five-byte inline hooks on an API entry can call the original through a trampoline."""

import struct

import pytest

from speakeasy import Speakeasy, common


@pytest.mark.parametrize("memory_tracing", [False, True], ids=["plain", "traced"])
def test_x86_guest_five_byte_hook_calls_original_trampoline(config, memory_tracing):
    config["analysis"]["memory_tracing"] = memory_tracing
    with Speakeasy(config=config) as se:
        caller = se.load_shellcode(data=b"\xcc" * 0x1000, arch="x86")
        address = se.emu.get_proc("kernel32", "GetTickCount")
        trampoline, hook = caller + 0x100, caller + 0x200
        # The guest hook CALLs its saved trampoline, then adds one to the result.
        hook_code = b"\xe8" + struct.pack("<I", (trampoline - hook - 5) & 0xFFFFFFFF)
        se.mem_write(hook, hook_code + b"\x83\xc0\x01\xc3")
        # Like an inline-hook installer, the guest copies exactly five bytes,
        # appends JMP original+5, patches the original with JMP hook, then calls it.
        code = b"\xbe" + struct.pack("<I", address) + b"\xbf" + struct.pack("<I", trampoline)
        code += b"\xa5\xa4"
        code += b"\xc6\x05" + struct.pack("<I", trampoline + 5) + b"\xe9"
        code += b"\xc7\x05" + struct.pack("<II", trampoline + 6, (address + 5 - trampoline - 10) & 0xFFFFFFFF)
        code += b"\xc6\x05" + struct.pack("<I", address) + b"\xe9"
        code += b"\xc7\x05" + struct.pack("<II", address + 1, (hook - address - 5) & 0xFFFFFFFF)
        code += b"\xb8" + struct.pack("<I", address) + b"\xff\xd0\xc3"
        se.mem_write(caller, code)
        se.emu.mem_protect(address & ~0xFFF, 0x1000, common.PERM_MEM_RWX)
        hits = []
        se.add_api_hook(lambda e, api, original, args: hits.append(api) or 77, "kernel32", "GetTickCount", argc=0)

        se.run_shellcode(caller)

        run = se.get_report().entry_points[0]
        assert run.error is None
        assert run.ret_val == 78
        assert hits == ["kernel32.GetTickCount"]
        assert [event.api_name for event in run.events if event.event == "api"] == ["kernel32.GetTickCount"]
