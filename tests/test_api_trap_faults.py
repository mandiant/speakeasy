"""Guest probes of an API entry's private jump target fault like unmapped memory."""

import struct

import pytest

from speakeasy import Speakeasy


def dword(value):
    return struct.pack("<I", value)


def api_events(entry):
    return [event.api_name for event in entry.events or [] if event.event == "api"]


@pytest.mark.parametrize(("access", "handled"), [("read", True), ("write", False)], ids=["read-seh", "write-unhandled"])
def test_x86_probe_of_jump_target_reaches_guest_seh(config, access, handled):
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="x86")
        data = se.mem_alloc(0x1000)
        entry = se.emu.get_proc("kernel32", "GetTickCount")
        raw = se.mem_read(entry, 16)
        jump = raw.index(b"\xe9")
        target = entry + jump + 5 + struct.unpack_from("<i", raw, jump + 1)[0]
        handler = code + 0x200
        registration = data + 0x100
        se.mem_write(registration, dword(0xFFFFFFFF) + dword(handler))
        # A hook detector decodes the entry's JMP rel32 and dereferences its target.
        setup = b"\x64\xc7\x05" + dword(0) + dword(registration if handled else 0)
        setup += b"\xb8" + dword(entry) + b"\x8b\x88" + dword(jump + 1)
        setup += b"\x8d\x80" + dword(jump + 5) + b"\x01\xc8"
        probe = b"\x8b\x00" if access == "read" else b"\x89\x10"
        fault_pc = code + len(setup)
        finish = fault_pc + len(probe)
        tail = b"\x64\xc7\x05" + dword(0) + dword(0) + b"\xb8" + dword(42) + b"\xc3"
        se.mem_write(code, setup + probe + tail)
        # The handler counts itself and sets CONTEXT.Eip past the probe.
        handler_code = b"\xff\x05" + dword(data)
        handler_code += b"\x8b\x4c\x24\x0c\xc7\x81" + dword(0xB8) + dword(finish)
        handler_code += b"\x31\xc0\xc3"
        se.mem_write(handler, handler_code)
        mapped_in_handler = []
        se.add_code_hook(
            lambda s, a, n: mapped_in_handler.append(s.get_address_map(target)), begin=handler, end=handler
        )

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert api_events(run) == []
        assert se.get_address_map(target) is None
        if handled:
            assert run.error is None
            assert run.ret_val == 42
            assert int.from_bytes(se.mem_read(data, 4), "little") == 1
            assert mapped_in_handler == [None]
        else:
            assert run.error.type == f"invalid_{access}"
            assert run.error.pc == fault_pc
            assert mapped_in_handler == []


def test_x64_probe_of_embedded_jump_target_is_typed_fault(config):
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="amd64")
        entry = se.emu.get_proc("kernel32", "GetTickCount")
        target = struct.unpack_from("<Q", se.mem_read(entry, 16), 8)[0]
        # Follow the FF 25 embedded pointer, then read through it.
        setup = b"\x48\xb8" + struct.pack("<Q", entry) + b"\x48\x8b\x40\x08"
        se.mem_write(code, setup + b"\x48\x8b\x00\xc3")

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error.type == "invalid_read"
        assert run.error.pc == code + len(setup)
        assert api_events(run) == []
        assert se.get_address_map(target) is None
