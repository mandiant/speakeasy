# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import hashlib
import time
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, TypedDict

from speakeasy.artifacts import MAX_EMBEDDED_FILE_SIZE, ArtifactStore
from speakeasy.config import CodeConfig, MemoryConfig
from speakeasy.errors import SpeakeasyError
from speakeasy.profiler_events import (
    AnyEvent,
    ApiArg,
    ApiEvent,
    DirectoryCreateEvent,
    DirectoryDeleteEvent,
    EventType,
    ExceptionEvent,
    FileCreateEvent,
    FileDeleteEvent,
    FileOpenEvent,
    FileReadEvent,
    FileWriteEvent,
    MemAllocEvent,
    MemFreeEvent,
    MemProtectEvent,
    MemReadEvent,
    MemWriteEvent,
    ModuleLoadEvent,
    NetDnsEvent,
    NetHttpEvent,
    NetHttpProtocol,
    NetTrafficEvent,
    NetTrafficProtocol,
    NetTrafficType,
    ProcessCreateEvent,
    RegCreateKeyEvent,
    RegDeleteKeyEvent,
    RegDeleteValueEvent,
    RegListSubkeysEvent,
    RegOpenKeyEvent,
    RegReadValueEvent,
    RegWriteValueEvent,
    ThreadCreateEvent,
    ThreadInjectEvent,
    TracePosition,
)
from speakeasy.report import (
    ApiLoop,
    ApiLoopSite,
    DroppedFile,
    DynamicCodeSegment,
    ErrorInfo,
    LoadedModule,
    MemoryAccesses,
    MemoryLayout,
    MemoryRegion,
    RegionAccesses,
    Report,
    RunReport,
    RunType,
    StringCollection,
    StringsReport,
    SymbolAccesses,
)
from speakeasy.windows.loaders import InitRoutine

if TYPE_CHECKING:
    from speakeasy.windows.objman import Process, Thread


class MemAccess:
    """Read, write and execute counts of one memory range or symbol."""

    def __init__(self, base=None, sym=None, size=0):
        self.base: int | None = base
        self.size: int = size
        self.sym: str | None = sym
        self.reads: int = 0
        self.writes: int = 0
        self.execs: int = 0


@dataclass
class GuestCallbackFrame:
    """State of a guest callback sequence, and of the API call that started it, if any."""

    stack_pointer: int
    return_address: int
    # The address of the API call, or None if the frame has no API call or the emulator does not know it.
    call_pc: int | None = None
    argc: int = 0
    convention: int | None = None
    function: int = 0
    pending: list[tuple[int, tuple[int, ...]]] = field(default_factory=list)
    result: int | None = None
    initializers: dict[int, InitRoutine] = field(default_factory=dict)
    failure_result: int = 0
    failure_writes: list[tuple[int, bytes]] = field(default_factory=list)
    event: ApiEvent | None = None
    created_modules: list[Any] = field(default_factory=list)
    peb_module_snapshot: list[tuple[Any, dict[int, Any]]] = field(default_factory=list)
    # The generator handler (speakeasy.windows.guest_callbacks) that runs on this frame, if any.
    handler: Any = None
    # (register, value) pairs of the nonvolatile registers before the first guest call.
    saved_registers: tuple[tuple[int, int], ...] | None = None


ApiCallSite = tuple[str, int | None]
"""An API name and the return address of a call."""

MAX_API_LOOP_SITES = 16


@dataclass
class ApiLoopTracker:
    """
    Count the API calls of a run since its last call from a new call site.

    A call site is an API and a return address. A call from a site that the run did not call before
    is progress, and it sets the count to 0.
    """

    sites: set[ApiCallSite] = field(default_factory=set)
    calls: int = 0
    start: TracePosition | None = None
    site_calls: dict[ApiCallSite, int] = field(default_factory=dict)

    def record(self, site: ApiCallSite, pos: TracePosition) -> None:
        """Count one API call from ``site`` at ``pos``."""
        if site not in self.sites:
            self.sites.add(site)
            self.calls = 0
            self.start = None
            self.site_calls.clear()
            return
        if self.start is None:
            self.start = pos
        self.calls += 1
        self.site_calls[site] = self.site_calls.get(site, 0) + 1

    def get_loop(self) -> ApiLoop | None:
        """Get the calls since the last new call site, with the sites that have the most calls first."""
        if self.start is None:
            return None
        ranked = sorted(self.site_calls.items(), key=lambda item: item[1], reverse=True)
        sites = [
            ApiLoopSite(api_name=name, return_address=return_address, calls=calls)
            for (name, return_address), calls in ranked[:MAX_API_LOOP_SITES]
        ]
        return ApiLoop(start=self.start, calls=self.calls, sites=sites)


class DynCodeMapping(TypedDict):
    tag: str
    base: int
    size: int
    pos: TracePosition
    data_ref: str | None
    snapshot_limit_reached: bool


class DynCode(TypedDict):
    mmap: list[DynCodeMapping]
    base_addrs: set[int]


class Run:
    """
    One unit of execution in the run queue, and the report data that the run collects.

    A run starts at one address: an entry point, an export, a TLS callback, a thread or a child process.
    """

    def __init__(self):
        self.instr_cnt: int = 0
        self.execution_elapsed: float = 0.0
        self.budget_instructions: int = 0
        self.guest_initialization: InitRoutine | None = None
        self.return_value: int | None = None
        self.events: list[AnyEvent] = []
        self.sym_access: dict[int, MemAccess] = {}
        # The files that the guest dropped, up to the end of the run. None in kernel mode.
        self.dropped_files: list[dict[str, Any]] | None = None
        # The access counts of each region, by the base of the region in the report.
        self.region_access: dict[int, MemAccess] = {}
        self.dyn_code: DynCode = {"mmap": [], "base_addrs": set()}
        self.process_context: Process | None = None
        self.thread: Thread | None = None
        self.unique_apis: list[str] = []
        self.api_hash: hashlib._Hash = hashlib.sha256()
        self.stack: MemAccess | None = None
        self.guest_callbacks: list[GuestCallbackFrame] = []
        # The address range [start, end) and the access counts of the regions of the last accesses.
        self.exec_cache: deque[tuple[int, int, MemAccess]] = deque(maxlen=4)
        self.read_cache: deque[tuple[int, int, MemAccess]] = deque(maxlen=4)
        self.write_cache: deque[tuple[int, int, MemAccess]] = deque(maxlen=4)

        self.args: list[Any] | tuple[Any, ...] | None = None
        self.registers: dict[int, int] = {}
        self.start_addr: int | None = None
        self.type: RunType | None = None
        self.name: str | None = None
        self.error: ErrorInfo | None = None
        self.num_apis: int = 0
        self.api_loop: ApiLoopTracker = ApiLoopTracker()
        self.coverage: set[int] = set()
        self.memory_regions: list[dict[str, Any]] = []
        self.loaded_modules: list[dict[str, Any]] = []

    def get_api_count(self):
        """Get the number of APIs that the run called."""
        return self.num_apis

    def get_label(self) -> str:
        """Get the type and the name of the run for log messages, for example ``export DllRegisterServer``."""
        kind = self.type.value if self.type is not None else "unknown"
        return f"{kind} {self.name}" if self.name else kind


def get_data_refs(runs: list[RunReport]) -> set[str]:
    """Get the payload keys that the runs refer to."""
    refs: set[str] = set()
    for run in runs:
        holders: list[Any] = [*run.events, *run.dynamic_code_segments, *(run.dropped_files or [])]
        if run.memory:
            holders.extend(run.memory.layout)
        refs.update(ref for holder in holders if (ref := getattr(holder, "data_ref", None)))
    return refs


class Profiler:
    """Collect the events of all runs and build the report."""

    def __init__(self, memory: MemoryConfig | None = None, code: CodeConfig | None = None):
        super().__init__()

        self.memory_config: MemoryConfig = memory or MemoryConfig()
        self.code_config: CodeConfig = code or CodeConfig()
        self.start_time: float = time.time()
        self.strings: dict[str, list[str]] = {"ansi": [], "unicode": []}
        self.decoded_strings: dict[str, list[str]] = {"ansi": [], "unicode": []}
        self.last_data: list[int] = [0, 0]
        self.last_event: AnyEvent | dict[str, Any] = {}
        self.last_event_run: Run | None = None
        self.clock_started: bool = False
        self.runtime: float = 0
        self.meta: dict[str, Any] = {}
        self.runs: list[Run] = []
        self.artifact_store: ArtifactStore = ArtifactStore()

    def add_input_metadata(self, meta):
        """Set the metadata of the input, such as the path and the SHA-256, for the report."""
        self.meta = meta

    def start_clock(self):
        """
        Start the report clock, if it is not started.

        The emulator calls this on each start of the run queue, so the clock starts at the first start.
        """
        if not self.clock_started:
            self.start_time = time.time()
            self.clock_started = True

    def get_run_time(self):
        """Get the number of seconds since the start of the report clock."""
        return time.time() - self.start_time

    def stop_run_clock(self):
        """Save the time since the start of the report clock as the runtime of the report."""
        self.runtime = self.get_run_time()

    def add_run(self, run: Run) -> None:
        """Add a run to the report."""
        self.runs.append(run)

    def put_binary_data(self, data: bytes, limit: int | None = None) -> str | None:
        """Store the data, cut to ``limit`` bytes, and return its artifact reference."""
        if not data:
            return None
        payload = data[:limit] if limit else data
        return self.artifact_store.put_bytes(payload)

    def merge_binary_data(self, artifact_ref: str | None, data: bytes, limit: int | None = None) -> str | None:
        """Append the data to an artifact, cut the result to ``limit`` bytes, and return the new reference."""
        if not data and artifact_ref:
            return artifact_ref
        if not artifact_ref:
            return self.put_binary_data(data, limit=limit)
        merged = self.artifact_store.get_bytes(artifact_ref) + data
        if limit:
            merged = merged[:limit]
        return self.artifact_store.put_bytes(merged)

    def record_error_event(self, error: ErrorInfo) -> None:
        """Add an error to the top-level ``errors`` list of the report."""
        if not self.meta.get("errors"):
            self.meta["errors"] = []
        self.meta["errors"].append(error)

    def record_dropped_files_event(self, run, files):
        run.dropped_files = []
        for f in files:
            data = f.get_contents()
            _hash = f.get_hash()
            data_ref = None
            if len(data) <= MAX_EMBEDDED_FILE_SIZE:
                data_ref = self.put_binary_data(data)
            entry = {"path": f.path, "size": len(data), "sha256": _hash, "data_ref": data_ref}
            run.dropped_files.append(entry)

    def record_api_event(
        self,
        run: Run,
        pos: TracePosition,
        name: str,
        ret: int | None,
        args: list[ApiArg],
        *,
        deduplicate: bool = True,
        return_address: int | None = None,
    ) -> ApiEvent:
        """
        Record a call to an API, with the arguments and the return value.

        If ``deduplicate`` is true, the profiler does not add a call that has the same API, pc,
        return address, shown arguments and return value as one of the last 3 events of the run.
        Calls through one thunk have the same pc, and the return address keeps the calls of
        different callers apart. The shown
        argument values are compared, not the raw values, so a loop that passes the same string
        from a different buffer gives one event.
        """
        run.num_apis += 1
        run.api_loop.record((name, return_address), pos)

        if name not in run.unique_apis:
            run.api_hash.update(name.lower().encode("utf-8"))
            run.unique_apis.append(name)

        event = ApiEvent(pos=pos, api_name=name, args=args, return_value=ret, return_address=return_address)

        shown = [(a.name, a.type, a.display) for a in args]
        recent_events = [e for e in run.events[-3:] if isinstance(e, ApiEvent)]
        if not deduplicate or not any(
            e.pos.pc == event.pos.pc
            and e.return_address == event.return_address
            and e.api_name == event.api_name
            and [(a.name, a.type, a.display) for a in e.args] == shown
            and e.return_value == event.return_value
            for e in recent_events
        ):
            run.events.append(event)
        return event

    def record_file_access_event(
        self,
        run,
        pos: TracePosition,
        path,
        event_type: EventType,
        data=None,
        handle=0,
        disposition=None,
        access=None,
        buffer=0,
        size=None,
    ):
        """
        Record a file event: create, open, read, write or delete of a file, or create or delete of a directory.

        A read or a write merges with the last event of the same type and path in the run. The
        data preview keeps the first 1024 bytes.

        Raises:
            ValueError: if ``event_type`` is not a file event type.
        """
        for et in (EventType.FILE_WRITE, EventType.FILE_READ):
            if event_type == et:
                for evt in reversed(run.events):
                    if isinstance(evt, (FileWriteEvent, FileReadEvent)) and evt.path == path and evt.event == et:
                        if size:
                            evt.size = (evt.size or 0) + size
                        if data:
                            evt.data_ref = self.merge_binary_data(evt.data_ref, data, limit=1024)
                        return

        data_ref = self.put_binary_data(data or b"", limit=1024)

        open_flags = None
        if disposition:
            open_flags = disposition if isinstance(disposition, list) else [disposition]
        access_flags = None
        if access:
            access_flags = access if isinstance(access, list) else [access]

        event: AnyEvent
        if event_type == EventType.FILE_CREATE:
            event = FileCreateEvent(
                pos=pos,
                path=path,
                handle=handle or None,
                open_flags=open_flags,
                access_flags=access_flags,
            )
        elif event_type == EventType.FILE_OPEN:
            event = FileOpenEvent(
                pos=pos,
                path=path,
                handle=handle or None,
                open_flags=open_flags,
                access_flags=access_flags,
            )
        elif event_type == EventType.FILE_READ:
            event = FileReadEvent(
                pos=pos,
                path=path,
                handle=handle or None,
                size=size,
                data_ref=data_ref,
                buffer=buffer or None,
            )
        elif event_type == EventType.FILE_WRITE:
            event = FileWriteEvent(
                pos=pos,
                path=path,
                handle=handle or None,
                size=size,
                data_ref=data_ref,
                buffer=buffer or None,
            )
        elif event_type == EventType.FILE_DELETE:
            event = FileDeleteEvent(pos=pos, path=path)
        elif event_type == EventType.DIRECTORY_CREATE:
            event = DirectoryCreateEvent(pos=pos, path=path)
        elif event_type == EventType.DIRECTORY_DELETE:
            event = DirectoryDeleteEvent(pos=pos, path=path)
        else:
            raise ValueError(f"not a file event type: {event_type}")

        run.events.append(event)

    def record_registry_access_event(
        self,
        run,
        pos: TracePosition,
        path,
        event_type: EventType,
        value_name=None,
        data=None,
        handle=0,
        disposition=None,
        access=None,
        buffer=0,
        size=None,
    ):
        """
        Record a registry event: open, create, list or delete of a key, or read, write or delete of a value.

        Raises:
            ValueError: if ``event_type`` is not a registry event type.
        """
        data_ref = self.put_binary_data(data or b"", limit=1024)

        open_flags = None
        if disposition:
            open_flags = disposition if isinstance(disposition, list) else [disposition]
        access_flags_list = None
        if access:
            access_flags_list = access if isinstance(access, list) else [access]

        event: AnyEvent
        if event_type == EventType.REG_OPEN_KEY:
            event = RegOpenKeyEvent(
                pos=pos,
                path=path,
                handle=handle or None,
                access_flags=access_flags_list,
            )
        elif event_type == EventType.REG_CREATE_KEY:
            event = RegCreateKeyEvent(
                pos=pos,
                path=path,
                handle=handle or None,
                open_flags=open_flags,
                access_flags=access_flags_list,
            )
        elif event_type == EventType.REG_READ_VALUE:
            event = RegReadValueEvent(
                pos=pos,
                path=path,
                handle=handle or None,
                value_name=value_name,
                size=size,
                data_ref=data_ref,
                buffer=buffer or None,
            )
        elif event_type == EventType.REG_WRITE_VALUE:
            event = RegWriteValueEvent(
                pos=pos,
                path=path,
                handle=handle or None,
                value_name=value_name,
                size=size,
                data_ref=data_ref,
                buffer=buffer or None,
            )
        elif event_type == EventType.REG_LIST_SUBKEYS:
            event = RegListSubkeysEvent(
                pos=pos,
                path=path,
                handle=handle or None,
            )
        elif event_type == EventType.REG_DELETE_KEY:
            event = RegDeleteKeyEvent(
                pos=pos,
                path=path,
                handle=handle or None,
            )
        elif event_type == EventType.REG_DELETE_VALUE:
            event = RegDeleteValueEvent(
                pos=pos,
                path=path,
                handle=handle or None,
                value_name=value_name,
            )
        else:
            raise ValueError(f"not a registry event type: {event_type}")

        run.events.append(event)

    def record_process_event(self, run, pos: TracePosition, proc, event_type: EventType, kwargs):
        """
        Record a process, memory or thread event.

        ``pos`` gives the process and the thread that do the operation, and ``proc`` is the target
        process. The ``pid`` of the event is the target process ID, or ``None`` when the target is
        the process of the actor.

        A memory read or write merges with the last process event when that event is of the same
        type, is in the same run, has the same target process, and its range ends at the start of the
        new range.

        Raises:
            ValueError: if ``event_type`` is not a process, memory or thread event type.
        """
        pid = None if proc.id == pos.pid else proc.id
        path = proc.path

        event: AnyEvent
        if event_type == EventType.PROCESS_CREATE:
            event = ProcessCreateEvent(
                pos=pos,
                path=path,
                command_line=proc.cmdline,
                pid=pid,
            )

        elif event_type == EventType.MEM_ALLOC:
            event = MemAllocEvent(
                pos=pos,
                path=path,
                base=kwargs.get("base", 0),
                size=kwargs.get("size", 0),
                protect=kwargs.get("protect"),
                pid=pid,
            )

        elif event_type == EventType.MEM_PROTECT:
            event = MemProtectEvent(
                pos=pos,
                path=path,
                base=kwargs.get("base", 0),
                size=kwargs.get("size", 0),
                protect=kwargs.get("protect"),
                pid=pid,
            )

        elif event_type == EventType.MEM_FREE:
            event = MemFreeEvent(
                pos=pos,
                path=path,
                base=kwargs.get("base", 0),
                size=kwargs.get("size", 0),
                pid=pid,
            )

        elif event_type in (EventType.MEM_WRITE, EventType.MEM_READ):
            event_cls = MemWriteEvent if event_type == EventType.MEM_WRITE else MemReadEvent
            base = kwargs["base"]
            size = kwargs["size"]
            data = kwargs["data"]
            last_base, last_size = self.last_data
            last_evt = self.last_event
            self.last_data = [base, size]
            if (
                isinstance(last_evt, event_cls)
                and self.last_event_run is run
                and last_evt.path == path
                and last_evt.pid == pid
                and (last_base + last_size) == base
            ):
                last_evt.data_ref = self.merge_binary_data(last_evt.data_ref, data, limit=1024)
                last_evt.size += len(data)
                return
            event = event_cls(
                pos=pos,
                path=path,
                base=base,
                size=size,
                data_ref=self.put_binary_data(data, limit=1024),
                pid=pid,
            )

        elif event_type == EventType.THREAD_INJECT:
            event = ThreadInjectEvent(
                pos=pos,
                path=path,
                start_address=kwargs["start_address"],
                param=kwargs["param"],
                pid=pid,
                tid=kwargs.get("tid"),
            )

        elif event_type == EventType.THREAD_CREATE:
            event = ThreadCreateEvent(
                pos=pos,
                path=path,
                start_address=kwargs["start_address"],
                param=kwargs["param"],
                pid=pid,
                tid=kwargs.get("tid"),
            )

        else:
            raise ValueError(f"not a process event type: {event_type}")

        run.events.append(event)
        self.last_event = event
        self.last_event_run = run

    def record_dns_event(self, run, pos: TracePosition, domain, ip=""):
        """Record a DNS lookup. The profiler adds one event for each query and response in a run."""
        for evt in run.events:
            if isinstance(evt, NetDnsEvent) and evt.query == domain and evt.response == ip:
                return

        event = NetDnsEvent(
            pos=pos,
            query=domain,
            response=ip if ip else None,
        )
        run.events.append(event)

    def record_http_event(self, run, pos: TracePosition, server, port, headers="", body=b"", secure=False):
        """Record an HTTP request. The profiler adds one event for each server, port, protocol and headers in a run."""
        proto = NetHttpProtocol.HTTPS if secure else NetHttpProtocol.HTTP
        headers = headers if headers else None
        for evt in run.events:
            if (
                isinstance(evt, NetHttpEvent)
                and evt.server == server
                and evt.port == port
                and evt.proto == proto
                and evt.headers == headers
            ):
                return

        event = NetHttpEvent(
            pos=pos,
            server=server,
            port=port,
            proto=proto,
            headers=headers,
            data_ref=self.put_binary_data(body or b"", limit=0x3000),
        )
        run.events.append(event)

    def record_module_load_event(self, run, pos: TracePosition, name, path, base, size):
        """Record a module that the guest loads at run time."""
        run.events.append(ModuleLoadEvent(pos=pos, name=name, path=path, base=base, size=size))

    def record_dyn_code_event(self, run, pos: TracePosition, tag, base, size, data: bytes | None):
        """Record a dynamic code region that the guest runs. The profiler adds each base address once per run."""
        if base not in run.dyn_code["base_addrs"]:
            data_ref = self.artifact_store.put_bytes(data) if data is not None else None
            entry: DynCodeMapping = {
                "tag": tag,
                "base": base,
                "size": size,
                "pos": pos,
                "data_ref": data_ref,
                "snapshot_limit_reached": False,
            }
            run.dyn_code["mmap"].append(entry)
            run.dyn_code["base_addrs"].add(base)

    def record_dyn_code_snapshot(self, run, pos: TracePosition, base, data: bytes) -> bool:
        """
        Record one more snapshot of the dynamic code region at ``base``, as a new entry of the region.

        Return ``False``, and record nothing, if the data is the same as the last snapshot of the region.
        """
        last = self._get_last_dyn_code_entry(run, base)
        data_ref = self.artifact_store.put_bytes(data)
        if data_ref == last["data_ref"]:
            return False
        entry: DynCodeMapping = {**last, "pos": pos, "data_ref": data_ref}
        run.dyn_code["mmap"].append(entry)
        return True

    def record_dyn_code_limit(self, run, base):
        """Record that the dynamic code region at ``base`` changed again after its last allowed snapshot."""
        self._get_last_dyn_code_entry(run, base)["snapshot_limit_reached"] = True

    def _get_last_dyn_code_entry(self, run: Run, base: int) -> DynCodeMapping:
        """Get the last entry of the dynamic code region at ``base`` in the run."""
        return next(seg for seg in reversed(run.dyn_code["mmap"]) if seg["base"] == base)

    def record_network_event(
        self,
        run,
        pos: TracePosition,
        server,
        port,
        typ: NetTrafficType | None = None,
        proto: NetTrafficProtocol = NetTrafficProtocol.UNKNOWN,
        data=b"",
        method="",
    ):
        """Record socket traffic."""
        data_ref = self.put_binary_data(data or b"", limit=0x3000)

        event = NetTrafficEvent(
            pos=pos,
            server=server,
            port=port,
            proto=proto,
            type=typ,
            data_ref=data_ref,
            method=method if method else None,
        )
        run.events.append(event)

    def record_exception_event(
        self,
        run,
        pos: TracePosition,
        instruction,
        exception_code,
        handler_address,
        registers,
        address=None,
        pc_module=None,
        pc_offset=None,
        stack=None,
    ):
        """Record an exception that the emulator sends to a guest handler."""
        event = ExceptionEvent(
            pos=pos,
            instruction=instruction,
            exception_code=exception_code,
            handler_address=handler_address,
            registers=registers,
            address=address,
            pc_module=pc_module,
            pc_offset=pc_offset,
            stack=stack,
        )
        run.events.append(event)

    def get_json_report(self) -> str:
        """Get the report as compact JSON, with no indentation. Fields with a ``None`` value are left out."""
        report = self.get_report()
        return report.model_dump_json(exclude_none=True)

    def get_report(self) -> Report:
        """Build the report from the runs, the strings and the artifacts."""
        run_reports = []

        for r in self.runs:
            error_info = r.error

            accesses = None
            if self.memory_config.accesses:
                accesses = MemoryAccesses(
                    regions=[
                        RegionAccesses(region=base, reads=access.reads, writes=access.writes, execs=access.execs)
                        for base, access in sorted(r.region_access.items())
                    ],
                    symbols=[
                        SymbolAccesses(symbol=access.sym, reads=access.reads, writes=access.writes, execs=access.execs)
                        for _, access in sorted(r.sym_access.items())
                        if access.sym is not None
                    ],
                )

            dyn_code_segments = [
                DynamicCodeSegment(
                    tag=seg["tag"],
                    base=seg["base"],
                    size=seg["size"],
                    pos=seg["pos"],
                    data_ref=seg["data_ref"],
                    snapshot_limit_reached=seg["snapshot_limit_reached"] or None,
                )
                for seg in r.dyn_code["mmap"]
            ]

            dropped_files = None
            if r.dropped_files is not None:
                dropped_files = [
                    DroppedFile(path=f["path"], size=f["size"], sha256=f["sha256"], data_ref=f.get("data_ref"))
                    for f in r.dropped_files
                ]

            memory_layout = None
            if r.memory_regions or r.loaded_modules:
                regions = []
                for reg in r.memory_regions:
                    regions.append(
                        MemoryRegion(
                            base=reg["base"],
                            size=reg["size"],
                            perms=reg["perms"],
                            tag=reg.get("tag"),
                            module=reg.get("module"),
                            section=reg.get("section"),
                            freed=reg.get("freed"),
                            data_ref=reg.get("data_ref"),
                        )
                    )
                modules = [
                    LoadedModule(name=mod["name"], path=mod["path"], base=mod["base"], size=mod["size"])
                    for mod in r.loaded_modules
                ]
                memory_layout = MemoryLayout(layout=regions, modules=modules)

            ep_tid = r.thread.tid if r.thread else None
            ep_pid = None
            if r.process_context:
                ep_pid = r.process_context.id
            elif r.thread and r.thread.process:
                ep_pid = r.thread.process.id

            if r.start_addr is None:
                raise SpeakeasyError("run has no start address")
            if r.type is None:
                raise SpeakeasyError("run has no type")
            run_report = RunReport(
                type=r.type,
                name=r.name,
                start_address=r.start_addr,
                args=list(r.args or []),
                pid=ep_pid,
                tid=ep_tid,
                instruction_count=r.instr_cnt,
                api_call_count=r.num_apis,
                api_hash=r.api_hash.hexdigest(),
                return_value=r.return_value,
                error=error_info,
                events=list(r.events),
                accesses=accesses,
                dynamic_code_segments=dyn_code_segments,
                coverage=sorted(r.coverage) if self.code_config.coverage else None,
                dropped_files=dropped_files,
                memory=memory_layout,
            )
            run_reports.append(run_report)

        strings_report = None
        if self.memory_config.strings:
            strings_report = StringsReport(
                static=StringCollection(
                    ansi=self.strings["ansi"],
                    unicode=self.strings["unicode"],
                ),
                in_memory=StringCollection(
                    ansi=self.decoded_strings["ansi"],
                    unicode=self.decoded_strings["unicode"],
                ),
            )

        errors: list[ErrorInfo] = self.meta.get("errors", [])

        return Report(
            emulation_total_runtime=round(self.runtime, 3),
            timestamp=int(self.start_time),
            arch=self.meta.get("arch"),
            path=self.meta.get("path"),
            sha256=self.meta.get("sha256"),
            size=self.meta.get("size"),
            file_type=self.meta.get("file_type"),
            image_base=self.meta.get("image_base"),
            errors=errors,
            strings=strings_report,
            data=self.artifact_store.to_report_data(get_data_refs(run_reports)),
            runs=run_reports,
        )
