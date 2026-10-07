import struct
from typing import Any

from speakeasy import Speakeasy
from speakeasy.profiler_events import ApiEvent

EXIT_CODE = 0x1234


def _run_realloc(config: dict[str, Any], psz: bytes | None, length: int) -> tuple[list[ApiEvent], int, bytes]:
    """
    Run SysReAllocStringLen(&slot, psz, length) then ExitProcess(EXIT_CODE) on x86.

    Returns the API events, the BSTR stored in the slot, and the memory from
    the BSTR length prefix through the terminator.
    """
    code = bytearray()
    code += b"\xe8\x00\x00\x00\x00"  # call $+5
    code += b"\x5b"  # pop ebx ; ebx = blob + 5
    code += b"\x68" + struct.pack("<I", EXIT_CODE)  # push EXIT_CODE (for ExitProcess)
    code += b"\x68" + struct.pack("<I", length)  # push len
    psz_fixup = None
    if psz is None:
        code += b"\x6a\x00"  # push 0
    else:
        psz_fixup = len(code) + 2
        code += b"\x8d\x83" + b"\x00" * 4 + b"\x50"  # lea eax, [ebx+disp] ; push eax
    slot_fixup = len(code) + 2
    code += b"\x8d\x83" + b"\x00" * 4 + b"\x50"  # lea eax, [ebx+disp] ; push eax
    api_off = len(code) + 1
    code += b"\xb8" + b"\x00" * 4 + b"\xff\xd0"  # mov eax, imm32 ; call eax
    exit_off = len(code) + 1
    code += b"\xb8" + b"\x00" * 4 + b"\xff\xd0"
    code += b"\x00" * (-len(code) % 4)
    slot_off = len(code)
    code += b"\x00" * 4
    code[slot_fixup : slot_fixup + 4] = struct.pack("<i", slot_off - 5)
    if psz is not None and psz_fixup is not None:
        psz_off = len(code)
        code += psz
        code[psz_fixup : psz_fixup + 4] = struct.pack("<i", psz_off - 5)

    se = Speakeasy(config=config)
    try:
        sc_addr = se.load_shellcode(data=bytes(code), arch="x86")
        emu = se.emu
        assert emu is not None
        for module, name, offset in (
            ("oleaut32", "SysReAllocStringLen", api_off),
            ("kernel32", "ExitProcess", exit_off),
        ):
            emu.mem_write(sc_addr + offset, emu.get_proc(module, name).to_bytes(4, "little"))
        se.run_shellcode(sc_addr)
        bstr = int.from_bytes(emu.mem_read(sc_addr + slot_off, 4), "little")
        data = emu.mem_read(bstr - 4, 4 + length * 2 + 2) if bstr else b""
        report = se.get_report()
    finally:
        se.shutdown()

    ep = report.entry_points[0]
    assert ep.error is None, ep.error
    events = [e for e in (ep.events or []) if e.event == "api"]
    return events, bstr, data


def test_realloc_copies_exactly_len_characters(config: dict[str, Any]) -> None:
    events, bstr, data = _run_realloc(config, "ab\x00cdef".encode("utf-16le"), 5)

    assert [e.api_name for e in events] == ["oleaut32.SysReAllocStringLen", "kernel32.ExitProcess"]
    assert events[0].ret_val == "0x1"
    assert bstr != 0
    assert data == struct.pack("<I", 10) + "ab\x00cd".encode("utf-16le") + b"\x00\x00"
    assert events[1].args == [f"{EXIT_CODE:#x}"]


def test_realloc_with_null_source_allocates_len_characters(config: dict[str, Any]) -> None:
    events, bstr, data = _run_realloc(config, None, 3)

    assert events[0].ret_val == "0x1"
    assert bstr != 0
    assert data[:4] == struct.pack("<I", 6)
    assert data[-2:] == b"\x00\x00"
    assert events[1].args == [f"{EXIT_CODE:#x}"]
