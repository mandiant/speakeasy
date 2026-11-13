import hashlib
import io
import json
from dataclasses import dataclass
from typing import Any

import pytest

from speakeasy.profiler import Profiler, Run
from speakeasy.profiler_events import (
    ApiArg,
    ApiEvent,
    EventType,
    FileWriteEvent,
    MemAllocEvent,
    RegWriteValueEvent,
    ThreadCreateEvent,
    ThreadInjectEvent,
    TracePosition,
)
from speakeasy.report import EntryPointType
from speakeasy.windows.fileman import File


@dataclass(frozen=True)
class TargetProcess:
    """The process attributes ``record_process_event`` reads off its target."""

    id: int
    path: str
    cmdline: str = ""


def build_report(profiler: Profiler, run: Run):
    run.args = []
    run.start_addr = 0x401000
    run.type = EntryPointType.MODULE_ENTRY
    profiler.add_run(run)
    profiler.stop_run_clock()
    return profiler.get_report()


def test_dropped_file_embeds_data_ref_when_within_limit():
    profiler = Profiler()
    run = Run()
    file_obj = File("C:\\temp\\drop.bin", data=b"payload")

    profiler.record_dropped_files_event(run, [file_obj])
    report = build_report(profiler, run)

    dropped = report.entry_points[0].dropped_files[0]
    assert dropped.size == 7
    assert dropped.data_ref == dropped.sha256
    assert dropped.data_ref in report.data


def test_dropped_file_holds_the_whole_contents_whatever_the_file_pointer():
    profiler = Profiler()
    run = Run()
    file_obj = File("C:\\temp\\drop.bin", data=b"payload")
    file_obj.seek(0, io.SEEK_END)

    profiler.record_dropped_files_event(run, [file_obj])
    report = build_report(profiler, run)

    dropped = report.entry_points[0].dropped_files[0]
    assert dropped.size == 7
    assert dropped.sha256 == hashlib.sha256(b"payload").hexdigest()


def test_dropped_file_skips_large_embedded_payload():
    profiler = Profiler()
    run = Run()
    payload = b"A" * ((10 * 1024 * 1024) + 1)
    file_obj = File("C:\\temp\\large.bin", data=payload)

    profiler.record_dropped_files_event(run, [file_obj])
    report = build_report(profiler, run)

    dropped = report.entry_points[0].dropped_files[0]
    assert dropped.size == len(payload)
    assert dropped.data_ref is None
    assert dropped.sha256 not in (report.data or {})


def test_empty_dropped_file_has_no_payload():
    profiler = Profiler()
    run = Run()

    profiler.record_dropped_files_event(run, [File("C:\\temp\\empty.bin", data=b"")])
    report = build_report(profiler, run)

    dropped = report.entry_points[0].dropped_files[0]
    assert dropped.size == 0
    assert dropped.sha256 == hashlib.sha256(b"").hexdigest()
    assert dropped.data_ref is None
    assert not report.data


def get_dumped_data_refs(value: Any) -> set[str]:
    if isinstance(value, dict):
        refs = {value["data_ref"]} if value.get("data_ref") else set()
        for item in value.values():
            refs |= get_dumped_data_refs(item)
        return refs
    if isinstance(value, list):
        return set().union(*(get_dumped_data_refs(item) for item in value))
    return set()


def test_report_data_holds_only_referenced_payloads():
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)
    process = TargetProcess(id=3, path="C:\\sample.exe")

    for chunk in (b"one", b"two", b"three"):
        profiler.record_file_access_event(
            run, pos, "C:\\temp\\x.bin", EventType.FILE_WRITE, data=chunk, size=len(chunk)
        )
    for offset, chunk in enumerate((b"aaaa", b"bbbb", b"cccc")):
        profiler.record_process_event(
            run, pos, process, EventType.MEM_WRITE, {"base": 0x1000 + 4 * offset, "size": 4, "data": chunk}
        )
    profiler.record_http_event(run, pos, "example.com", 80, headers="GET / HTTP/1.1", body=b"first")
    profiler.record_http_event(run, pos, "example.com", 80, headers="GET / HTTP/1.1", body=b"second")
    report = build_report(profiler, run)

    refs = get_dumped_data_refs(report.model_dump(mode="json"))
    assert len(refs) == 3
    assert set(report.data) == refs


def test_file_write_merge_preserves_raw_bytes():
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)

    profiler.record_file_access_event(run, pos, "C:\\temp\\x.bin", EventType.FILE_WRITE, data=b"\x00\xff", size=2)
    profiler.record_file_access_event(run, pos, "C:\\temp\\x.bin", EventType.FILE_WRITE, data=b"\x01\x02", size=2)
    report = build_report(profiler, run)

    event = next(evt for evt in report.entry_points[0].events if isinstance(evt, FileWriteEvent))
    assert event.size == 4
    assert event.data_ref is not None and event.data_ref in report.data
    artifact = profiler.artifact_store.get_bytes(event.data_ref)
    assert artifact == b"\x00\xff\x01\x02"


def test_registry_write_event_is_reported_with_data_ref():
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)

    profiler.record_registry_access_event(
        run,
        pos,
        "HKEY_LOCAL_MACHINE\\Software\\Example",
        EventType.REG_WRITE_VALUE,
        value_name="ValueName",
        data=b"abc",
        size=3,
    )
    report = build_report(profiler, run)

    event = next(evt for evt in report.entry_points[0].events if isinstance(evt, RegWriteValueEvent))
    assert event.value_name == "ValueName"
    assert event.data_ref is not None and event.data_ref in report.data
    assert profiler.artifact_store.get_bytes(event.data_ref) == b"abc"


def test_local_memory_event_omits_target_pid():
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)
    actor = TargetProcess(id=3, path="C:\\sample.exe")

    profiler.record_process_event(run, pos, actor, EventType.MEM_ALLOC, {"base": 0x500000, "size": 0x1000})
    report = build_report(profiler, run)

    event = next(evt for evt in report.entry_points[0].events if isinstance(evt, MemAllocEvent))
    assert event.pid is None
    assert event.pos.pid == 3


def test_remote_memory_event_carries_target_pid():
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)
    target = TargetProcess(id=9, path="C:\\victim.exe")

    profiler.record_process_event(run, pos, target, EventType.MEM_ALLOC, {"base": 0x500000, "size": 0x1000})
    report = build_report(profiler, run)

    event = next(evt for evt in report.entry_points[0].events if isinstance(evt, MemAllocEvent))
    assert event.pid == 9


def test_local_thread_create_keeps_target_tid():
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)
    actor = TargetProcess(id=3, path="C:\\sample.exe")

    profiler.record_process_event(
        run, pos, actor, EventType.THREAD_CREATE, {"start_address": 0x401500, "param": 0, "tid": 44}
    )
    report = build_report(profiler, run)

    event = next(evt for evt in report.entry_points[0].events if isinstance(evt, ThreadCreateEvent))
    assert event.pid is None
    assert event.tid == 44


def test_remote_thread_inject_carries_target_pid_and_tid():
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)
    target = TargetProcess(id=9, path="C:\\victim.exe")

    profiler.record_process_event(
        run, pos, target, EventType.THREAD_INJECT, {"start_address": 0x401500, "param": 0, "tid": 44}
    )
    report = build_report(profiler, run)

    event = next(evt for evt in report.entry_points[0].events if isinstance(evt, ThreadInjectEvent))
    assert event.pid == 9
    assert event.tid == 44


def test_repeated_api_call_with_same_rendering_is_recorded_once():
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=0, tid=1, pid=1, pc=0x401000)

    def lib_name(buffer: int) -> list[ApiArg]:
        return [ApiArg(name="lpLibFileName", type="str", value=buffer, display="psapi.dll")]

    profiler.record_api_event(run, pos, "kernel32.LoadLibraryA", 0x71000000, lib_name(0x2000))
    # same string from another buffer: one event, holding the first call's values
    profiler.record_api_event(run, pos, "kernel32.LoadLibraryA", 0x71000000, lib_name(0x3000))
    unnamed = [ApiArg(type="int", value=1, display="0x1")]
    profiler.record_api_event(run, pos, "kernel32.LoadLibraryA", 0x71000000, unnamed)

    assert all(isinstance(e, ApiEvent) for e in run.events)
    assert [e.args for e in run.events if isinstance(e, ApiEvent)] == [lib_name(0x2000), unnamed]


def test_repeated_api_call_from_another_caller_is_recorded():
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=0, tid=1, pid=1, pc=0x401000)

    for return_address in (0x402005, 0x403005, 0x403005):
        profiler.record_api_event(run, pos, "kernel32.GetCurrentProcessId", 4, [], return_address=return_address)

    assert len(run.events) == 2


@pytest.mark.parametrize("event_type", [EventType.MEM_WRITE, EventType.MEM_READ])
def test_memory_event_does_not_merge_into_another_run_or_process(event_type: EventType) -> None:
    profiler = Profiler()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)
    explorer = TargetProcess(id=9, path="C:\\Windows\\explorer.exe")
    svchost = TargetProcess(id=10, path="C:\\Windows\\system32\\svchost.exe")

    run1 = Run()
    profiler.record_process_event(run1, pos, explorer, event_type, {"base": 0x1000, "size": 4, "data": b"aaaa"})
    run2 = Run()
    profiler.record_process_event(run2, pos, svchost, event_type, {"base": 0x1004, "size": 4, "data": b"bbbb"})
    profiler.record_process_event(run2, pos, explorer, event_type, {"base": 0x1008, "size": 4, "data": b"cccc"})
    # The same run and target process, and the range starts at the end of the last range: one event.
    profiler.record_process_event(run2, pos, explorer, event_type, {"base": 0x100C, "size": 4, "data": b"dddd"})

    assert [(e.pid, e.base, e.size) for e in run1.events] == [(9, 0x1000, 4)]
    assert [(e.pid, e.base, e.size) for e in run2.events] == [(10, 0x1004, 4), (9, 0x1008, 8)]


def test_json_report_is_compact():
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)
    profiler.record_file_access_event(run, pos, "C:\\temp\\x.bin", EventType.FILE_WRITE, data=b"a\nb", size=3)
    report = build_report(profiler, run)

    text = profiler.get_json_report()

    assert "\n" not in text
    assert ": " not in text
    assert json.loads(text) == json.loads(report.model_dump_json(exclude_none=True))
