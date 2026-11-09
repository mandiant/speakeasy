import struct
import zlib
from base64 import b64decode

from speakeasy import Speakeasy
from speakeasy.profiler_events import ApiEvent
from speakeasy.report import Report


def _call(se: Speakeasy, api: str) -> bytes:
    return b"\xb8" + struct.pack("<I", se.emu.get_proc("kernel32", api)) + b"\xff\xd0"


def _get_overwrite_after_run_code(se: Speakeasy) -> bytes:
    # VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    push_args = b"\x6a\x40\x68\x00\x30\x00\x00\x68\x00\x10\x00\x00\x6a\x00"
    # mov byte [eax], 0xc3 ; push eax ; call eax ; pop eax ; mov byte [eax], 0xcc ; ret
    run_then_overwrite = b"\xc6\x00\xc3\x50\xff\xd0\x58\xc6\x00\xcc\xc3"
    return push_args + _call(se, "VirtualAlloc") + run_then_overwrite


def _run(config: dict, snapshot: bool) -> tuple[Report, bytes]:
    config["analysis"] = {**config.get("analysis", {}), "dynamic_code_snapshots": snapshot}
    # The run counts ticks only with an instruction budget or memory tracing.
    config["max_instructions"] = 1000
    with Speakeasy(config=config) as se:
        base = se.load_shellcode(data=bytes(0x1000), arch="x86")
        se.mem_write(base, _get_overwrite_after_run_code(se))
        se.run_shellcode(base)
        report = se.get_report()
        [segment] = report.entry_points[0].dynamic_code_segments
        end_of_run = bytes(se.mem_read(segment.base, segment.size))
    return report, end_of_run


def test_dynamic_code_segment_has_position_of_first_run(config):
    report, _ = _run(config, snapshot=False)

    entry = report.entry_points[0]
    [segment] = entry.dynamic_code_segments
    [virtual_alloc] = [e for e in entry.events if isinstance(e, ApiEvent) and e.api_name == "kernel32.VirtualAlloc"]
    assert segment.pos.pc == segment.base
    assert segment.pos.tick > virtual_alloc.pos.tick
    assert (segment.pos.pid, segment.pos.tid) == (virtual_alloc.pos.pid, virtual_alloc.pos.tid)
    assert segment.data_ref is None


def test_snapshot_keeps_the_region_bytes_at_first_run(config):
    report, end_of_run = _run(config, snapshot=True)

    [segment] = report.entry_points[0].dynamic_code_segments
    assert segment.data_ref is not None
    artifact = report.data[segment.data_ref]
    first_run = zlib.decompress(b64decode(artifact.data))
    assert first_run == b"\xc3" + bytes(segment.size - 1)
    assert end_of_run[0] == 0xCC
