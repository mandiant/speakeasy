from dataclasses import dataclass

from speakeasy.profiler import Profiler, Run
from speakeasy.profiler_events import (
    FILE_WRITE,
    MEM_ALLOC,
    REG_WRITE,
    THREAD_CREATE,
    THREAD_INJECT,
    FileWriteEvent,
    MemAllocEvent,
    RegWriteValueEvent,
    ThreadCreateEvent,
    ThreadInjectEvent,
    TracePosition,
)
from speakeasy.windows.fileman import File
from speakeasy.windows.objman import HandleAllocator


@dataclass(frozen=True)
class TargetProcess:
    """The process attributes ``record_process_event`` reads off its target."""

    id: int
    path: str
    cmdline: str = ""


def build_report(profiler: Profiler, run: Run):
    run.args = []
    run.start_addr = 0x401000
    run.type = "entry_point"
    profiler.add_run(run)
    profiler.stop_run_clock()
    return profiler.get_report()


def test_dropped_file_embeds_data_ref_when_within_limit():
    profiler = Profiler()
    run = Run()
    file_obj = File(HandleAllocator(), "C:\\temp\\drop.bin", data=b"payload")

    profiler.record_dropped_files_event(run, [file_obj])
    report = build_report(profiler, run)

    dropped = report.entry_points[0].dropped_files[0]
    assert dropped.size == 7
    assert dropped.data_ref == dropped.sha256
    assert dropped.data_ref in report.data


def test_dropped_file_skips_large_embedded_payload():
    profiler = Profiler()
    run = Run()
    payload = b"A" * ((10 * 1024 * 1024) + 1)
    file_obj = File(HandleAllocator(), "C:\\temp\\large.bin", data=payload)

    profiler.record_dropped_files_event(run, [file_obj])
    report = build_report(profiler, run)

    dropped = report.entry_points[0].dropped_files[0]
    assert dropped.size == len(payload)
    assert dropped.data_ref is None
    assert dropped.sha256 not in (report.data or {})


def test_file_write_merge_preserves_raw_bytes():
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)

    profiler.record_file_access_event(run, pos, "C:\\temp\\x.bin", FILE_WRITE, data=b"\x00\xff", size=2)
    profiler.record_file_access_event(run, pos, "C:\\temp\\x.bin", FILE_WRITE, data=b"\x01\x02", size=2)
    report = build_report(profiler, run)

    event = next(evt for evt in report.entry_points[0].events if isinstance(evt, FileWriteEvent))
    assert event.size == 4
    assert event.data_ref in report.data
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
        REG_WRITE,
        value_name="ValueName",
        data=b"abc",
        size=3,
    )
    report = build_report(profiler, run)

    event = next(evt for evt in report.entry_points[0].events if isinstance(evt, RegWriteValueEvent))
    assert event.value_name == "ValueName"
    assert event.data_ref in report.data
    assert profiler.artifact_store.get_bytes(event.data_ref) == b"abc"


def test_local_memory_event_omits_target_pid():
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)
    actor = TargetProcess(id=3, path="C:\\sample.exe")

    profiler.record_process_event(run, pos, actor, MEM_ALLOC, {"base": 0x500000, "size": 0x1000})
    report = build_report(profiler, run)

    event = next(evt for evt in report.entry_points[0].events if isinstance(evt, MemAllocEvent))
    assert event.pid is None
    assert event.pos.pid == 3


def test_remote_memory_event_carries_target_pid():
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)
    target = TargetProcess(id=9, path="C:\\victim.exe")

    profiler.record_process_event(run, pos, target, MEM_ALLOC, {"base": 0x500000, "size": 0x1000})
    report = build_report(profiler, run)

    event = next(evt for evt in report.entry_points[0].events if isinstance(evt, MemAllocEvent))
    assert event.pid == 9


def test_local_thread_create_keeps_target_tid():
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)
    actor = TargetProcess(id=3, path="C:\\sample.exe")

    profiler.record_process_event(run, pos, actor, THREAD_CREATE, {"start_addr": 0x401500, "param": 0, "tid": 44})
    report = build_report(profiler, run)

    event = next(evt for evt in report.entry_points[0].events if isinstance(evt, ThreadCreateEvent))
    assert event.pid is None
    assert event.tid == 44


def test_remote_thread_inject_carries_target_pid_and_tid():
    profiler = Profiler()
    run = Run()
    pos = TracePosition(tick=1, tid=2, pid=3, pc=0x401000)
    target = TargetProcess(id=9, path="C:\\victim.exe")

    profiler.record_process_event(run, pos, target, THREAD_INJECT, {"start_addr": 0x401500, "param": 0, "tid": 44})
    report = build_report(profiler, run)

    event = next(evt for evt in report.entry_points[0].events if isinstance(evt, ThreadInjectEvent))
    assert event.pid == 9
    assert event.tid == 44
