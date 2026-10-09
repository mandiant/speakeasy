"""Private API targets fault like memory, without materializing trap pages."""

import struct

import pytest

from speakeasy.profiler import Run


def _dword(value):
    return struct.pack("<I", value)


@pytest.mark.parametrize(
    ("access", "handled"),
    [(access, handled) for access in ("read", "write", "fetch") for handled in (False, True)]
    + [("read", "repeat"), ("write", "repeat")],
)
def test_private_trap_fault_is_seh_visible_and_stays_unmapped(dll_emu, access, handled):
    emu = dll_emu.emu
    emu.prepare_module_for_emulation(emu.modules[0], all_entrypoints=False)
    emu.run_queue.clear()
    entry = emu.get_proc("kernel32", "GetTickCount")
    raw = emu.mem_read(entry, 16)
    jump = raw.index(b"\xe9")
    target = entry + jump + 5 + struct.unpack_from("<i", raw, jump + 1)[0]
    assert target in emu.api_registry.traps
    # A detector follows the public entry's relative jump, then probes the
    # target. Fetch uses an unallocated token, so it must not dispatch an API.
    expected_address = target if access != "fetch" else emu.api_registry.trap_base + emu.api_registry.TRAP_SIZE - 1
    code = emu.mem_map(0x1000, tag="trap_fault.code")
    data = emu.mem_map(0x1000, tag="trap_fault.data")
    handler = code + 0x200
    registration = data + 0x100
    emu.mem_write(registration, _dword(0xFFFFFFFF) + _dword(handler))
    setup = b"\xc7\x05" + _dword(emu.fs_addr) + _dword(registration if handled else 0)
    if access == "fetch":
        setup += b"\xb8" + _dword(expected_address)
        probe = b"\xff\xe0"
    else:
        setup += b"\xb8" + _dword(entry)
        setup += b"\x8b\x88" + _dword(jump + 1)
        setup += b"\x8d\x80" + _dword(jump + 5) + b"\x01\xc8"
        probe = b"\x8b\x00" if access == "read" else b"\x89\x10"
    fault_pc = code + len(setup)
    finish = fault_pc + len(probe)
    tail = b"\xc7\x05" + _dword(emu.fs_addr) + _dword(0) + b"\xb8" + _dword(42) + b"\xc3"
    emu.mem_write(code, setup + probe + tail)
    # CONTEXT.Eip is the third SEH argument. Skip the probe and continue guest
    # execution; the reservation remains absent throughout handler execution.
    handler_code = b"\xff\x05" + _dword(data)
    handler_code += b"\x8b\x4c\x24\x0c\xc7\x81" + _dword(0xB8) + _dword(fault_pc if handled == "repeat" else finish)
    handler_code += b"\x31\xc0\xc3"
    emu.mem_write(handler, handler_code)
    run = Run()
    run.start_addr, run.type, run.args, run.thread = code, "trap_fault", [], emu.curr_thread
    emu.add_run(run)
    observed = []

    def verify_unmapped(_emu, _pc, _size):
        assert emu.get_address_map(expected_address) is None
        assert not any(start <= expected_address <= end for start, end, _ in emu.get_mem_regions())
        observed.append(True)

    emu.add_code_hook(verify_unmapped)
    emu.start()
    assert observed
    assert not any(event.event == "api" for event in run.events)
    if handled is True:
        assert run.error is None
        assert run.ret_val == 42
        assert int.from_bytes(emu.mem_read(data, 4), "little") == 1
    else:
        assert run.error.type == f"invalid_{access}"
        # Fetch errors identify the destination; data errors identify the
        # faulting instruction and expose the accessed target separately.
        assert run.error.pc == (expected_address if access == "fetch" else fault_pc)
        assert int.from_bytes(emu.mem_read(data, 4), "little") == (3 if handled == "repeat" else 0)
    assert emu.get_address_map(expected_address) is None
    assert emu._pending_trap_fault is None


@pytest.mark.parametrize("access", ["read", "write"])
def test_win64_probe_of_embedded_trap_address_is_typed(dll64_emu, access):
    emu = dll64_emu.emu
    emu.prepare_module_for_emulation(emu.modules[0], all_entrypoints=False)
    emu.run_queue.clear()
    entry = emu.get_proc("kernel32", "GetTickCount")
    target = struct.unpack_from("<Q", emu.mem_read(entry, 16), 8)[0]
    assert target in emu.api_registry.traps
    code = emu.mem_map(0x1000, tag="trap_fault.x64_code")
    # Follow FF 25's embedded pointer in guest code, as a hook detector does.
    setup = b"\x48\xb8" + struct.pack("<Q", entry) + b"\x48\x8b\x40\x08"
    probe = b"\x48\x8b\x00" if access == "read" else b"\x48\x89\x10"
    emu.mem_write(code, setup + probe + b"\xc3")
    run = Run()
    run.start_addr, run.type, run.args, run.thread = code, "trap_fault.x64", [], emu.curr_thread
    emu.add_run(run)
    emu.start()
    assert run.error.type == f"invalid_{access}"
    assert run.error.pc == code + len(setup)
    assert emu.get_address_map(target) is None
    assert not any(start <= target <= end for start, end, _ in emu.get_mem_regions())
    assert not any(event.event == "api" for event in run.events)
