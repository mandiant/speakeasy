import struct
import zlib
from base64 import b64decode
from collections.abc import Callable
from functools import partial
from pathlib import Path

import pytest

from speakeasy import Speakeasy
from speakeasy.profiler_events import ApiEvent
from speakeasy.report import Report


def _call(se: Speakeasy, api: str) -> bytes:
    return b"\xb8" + struct.pack("<I", se.emu.get_proc("kernel32", api)) + b"\xff\xd0"


def _get_virtual_alloc_call(se: Speakeasy) -> bytes:
    # VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    push_args = b"\x6a\x40\x68\x00\x30\x00\x00\x68\x00\x10\x00\x00\x6a\x00"
    return push_args + _call(se, "VirtualAlloc")


def _get_overwrite_after_run_code(se: Speakeasy) -> bytes:
    # mov byte [eax], 0xc3 ; push eax ; call eax ; pop eax ; mov byte [eax], 0xcc ; ret
    return _get_virtual_alloc_call(se) + b"\xc6\x00\xc3\x50\xff\xd0\x58\xc6\x00\xcc\xc3"


def _get_api_return_code(se: Speakeasy) -> bytes:
    # The stub at offset 0x20 is after the code hook on the start of the region,
    # so the emulator finds the code only when GetTickCount returns into the stub.
    stub = _call(se, "GetTickCount") + b"\xc3"
    # mov dword [eax+0x20], stub[:4] ; mov dword [eax+0x24], stub[4:] ; add eax, 0x20 ; call eax ; ret
    write_stub = b"\xc7\x40\x20" + stub[:4] + b"\xc7\x40\x24" + stub[4:]
    return _get_virtual_alloc_call(se) + write_stub + b"\x83\xc0\x20\xff\xd0\xc3"


def _run(
    config: dict, snapshot: bool, get_code: Callable[[Speakeasy], bytes] = _get_overwrite_after_run_code
) -> tuple[Report, bytes]:
    config["memory"]["dynamic_code_contents"]["enabled"] = snapshot
    with Speakeasy(config=config) as se:
        base = se.load_shellcode(data=bytes(0x1000), arch="x86")
        se.mem_write(base, get_code(se))
        se.run_shellcode(base)
        report = se.get_report()
        segment = report.entry_points[0].dynamic_code_segments[-1]
        end_of_run = bytes(se.mem_read(segment.base, segment.size))
    return report, end_of_run


def test_dynamic_code_segment_has_position_of_first_run(config):
    # Without snapshots, the run counts ticks only with an instruction budget or memory tracing.
    config["limits"]["instructions"] = 1000
    report, _ = _run(config, snapshot=False)

    entry = report.entry_points[0]
    [segment] = entry.dynamic_code_segments
    [virtual_alloc] = [e for e in entry.events if isinstance(e, ApiEvent) and e.api_name == "kernel32.VirtualAlloc"]
    assert segment.pos.pc == segment.base
    assert segment.pos.tick > virtual_alloc.pos.tick
    assert (segment.pos.pid, segment.pos.tid) == (virtual_alloc.pos.pid, virtual_alloc.pos.tid)
    assert segment.data_ref is None
    assert segment.snapshot_limit_reached is None


def test_snapshot_keeps_the_region_bytes_at_first_run(config):
    report, end_of_run = _run(config, snapshot=True)

    [segment] = report.entry_points[0].dynamic_code_segments
    assert segment.data_ref is not None
    artifact = report.data[segment.data_ref]
    first_run = zlib.decompress(b64decode(artifact.data))
    assert first_run == b"\xc3" + bytes(segment.size - 1)
    assert end_of_run[0] == 0xCC


def test_position_of_api_return_into_region_is_in_the_region(config):
    report, _ = _run(config, snapshot=False, get_code=_get_api_return_code)

    [segment] = report.entry_points[0].dynamic_code_segments
    assert segment.pos.pc == segment.base + 0x27


def _get_region_writes(code: bytes) -> bytes:
    # mov dword [eax+i], code[i:i+4] for each 4 bytes of code
    padded = code.ljust(-(-len(code) // 4) * 4, b"\x90")
    return b"".join(b"\xc7\x40" + bytes([i]) + padded[i : i + 4] for i in range(0, len(padded), 4))


def _get_stage_loop_code(se: Speakeasy, passes: int) -> bytes:
    # The loop writes the region before each call, so the write instructions run from a translation
    # that the emulator made before it watched the region.
    # mov esi, eax ; mov ecx, passes
    # loop: mov byte [esi], 0xc3 ; mov byte [esi+1], cl ; call esi ; dec ecx ; jnz loop ; ret
    loop = b"\xc6\x06\xc3\x88\x4e\x01\xff\xd6\x49"
    jnz = b"\x75" + bytes([(-(len(loop) + 2)) & 0xFF])
    return _get_virtual_alloc_call(se) + b"\x89\xc6\xb9" + struct.pack("<I", passes) + loop + jnz + b"\xc3"


def _get_decoder_loop_code(se: Speakeasy) -> bytes:
    # The region changes its own byte at offset 0x40 on each pass, and the caller calls it two times.
    # mov ecx, 50 ; loop: inc byte [esi+0x40] ; dec ecx ; jnz loop ; ret
    region = b"\xb9\x32\x00\x00\x00\xfe\x46\x40\x49\x75\xfa\xc3"
    # mov esi, eax ; call esi ; call esi ; ret
    return _get_virtual_alloc_call(se) + _get_region_writes(region) + b"\x89\xc6\xff\xd6\xff\xd6\xc3"


def _get_api_call_after_change_code(se: Speakeasy) -> bytes:
    # The region changes its byte at offset 0x40, then calls GetTickCount, which returns into the region.
    # inc byte [esi+0x40] ; <call GetTickCount> ; ret
    region = b"\xfe\x46\x40" + _call(se, "GetTickCount") + b"\xc3"
    # mov esi, eax ; call esi ; ret
    return _get_virtual_alloc_call(se) + _get_region_writes(region) + b"\x89\xc6\xff\xd6\xc3"


def _get_write_process_memory_code(se: Speakeasy) -> bytes:
    # mov esi, eax ; mov byte [esi], 0xc3 ; call esi
    first = b"\x89\xc6\xc6\x06\xc3\xff\xd6"
    # push 0xc3909090 ; mov ebx, esp
    # WriteProcessMemory(GetCurrentProcess(), esi, ebx, 4, NULL) ; call esi ; pop eax ; ret
    write = b"\x68\x90\x90\x90\xc3\x89\xe3\x6a\x00\x6a\x04\x53\x56\x6a\xff" + _call(se, "WriteProcessMemory")
    return _get_virtual_alloc_call(se) + first + write + b"\xff\xd6\x58\xc3"


def _get_snapshots(report: Report) -> list[bytes]:
    segments = report.entry_points[0].dynamic_code_segments
    assert len({segment.base for segment in segments}) == 1
    return [zlib.decompress(b64decode(report.data[segment.data_ref].data)) for segment in segments if segment.data_ref]


def test_region_that_changes_between_calls_has_a_snapshot_of_each_stage(config):
    report, _ = _run(config, snapshot=True, get_code=lambda se: _get_stage_loop_code(se, passes=2))

    first, later = report.entry_points[0].dynamic_code_segments
    assert _get_snapshots(report) == [b"\xc3\x02" + bytes(0xFFE), b"\xc3\x01" + bytes(0xFFE)]
    assert (later.tag, later.base, later.size) == (first.tag, first.base, first.size)
    assert later.pos.pc == first.base
    assert later.pos.tick > first.pos.tick
    assert (first.snapshot_limit_reached, later.snapshot_limit_reached) == (None, None)


def test_snapshot_positions_have_the_ticks_of_a_run_with_an_instruction_limit(config):
    def get_positions(report: Report) -> list:
        entry = report.entry_points[0]
        return [segment.pos for segment in entry.dynamic_code_segments] + [event.pos for event in entry.events]

    get_code = partial(_get_stage_loop_code, passes=3)
    counted, _ = _run(config | {"limits": {"instructions": 1_000_000}}, snapshot=True, get_code=get_code)
    report, _ = _run(config, snapshot=True, get_code=get_code)

    assert get_positions(report) == get_positions(counted)
    assert report.entry_points[0].dynamic_code_segments[-1].pos.tick > 0


def test_decoder_loop_in_the_region_gives_one_snapshot_for_each_call(config):
    report, _ = _run(config, snapshot=True, get_code=_get_decoder_loop_code)

    first, later = _get_snapshots(report)
    assert (first[0x40], later[0x40]) == (0, 50)


def test_api_return_into_a_changed_region_gives_a_snapshot(config):
    report, _ = _run(config, snapshot=True, get_code=_get_api_call_after_change_code)

    segments = report.entry_points[0].dynamic_code_segments
    first, later = _get_snapshots(report)
    assert (first[0x40], later[0x40]) == (0, 1)
    assert segments[1].pos.pc == segments[0].base + 10


def test_write_by_an_api_handler_changes_the_region(config):
    report, _ = _run(config, snapshot=True, get_code=_get_write_process_memory_code)

    first, later = _get_snapshots(report)
    assert (first[:4], later[:4]) == (b"\xc3\x00\x00\x00", b"\x90\x90\x90\xc3")


def test_snapshot_limit_shows_on_the_last_entry_of_the_region(config):
    config["memory"]["dynamic_code_contents"]["limit"] = 2
    report, _ = _run(config, snapshot=True, get_code=lambda se: _get_stage_loop_code(se, passes=4))

    segments = report.entry_points[0].dynamic_code_segments
    assert len(_get_snapshots(report)) == 2
    assert [segment.snapshot_limit_reached for segment in segments] == [None, True]


def test_delphi_object_instance_page_has_a_snapshot_of_each_new_thunk(config):
    # A Delphi program that keeps window procedure thunks (MakeObjectInstance) in one
    # VirtualAlloc page. Each thunk is "call base+4" and then the method that it calls.
    path = Path(__file__).resolve().parent / "capa-testfiles" / "5dd0b130d5c3d40c69e3972f39fd7d62.exe_"
    if not path.exists():
        pytest.skip(f"missing sample: {path}")
    config["memory"]["dynamic_code_contents"]["enabled"] = True
    with Speakeasy(config=config) as se:
        module = se.load_module(str(path))
        se.run_module(module)
        report = se.get_report()

    segment, later, *_ = report.entry_points[0].dynamic_code_segments
    first, bound, *_ = _get_snapshots(report)
    thunk = later.pos.pc - segment.base
    call = b"\xe8" + struct.pack("<i", 4 - (thunk + 5))
    [old_link] = struct.unpack_from("<I", first, thunk + 5)
    [method] = struct.unpack_from("<I", bound, thunk + 5)
    assert first[thunk : thunk + 5] == bound[thunk : thunk + 5] == call
    assert segment.base <= old_link < segment.base + segment.size
    assert module.base <= method < module.base + module.image_size
