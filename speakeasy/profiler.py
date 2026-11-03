# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import hashlib
import time
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, TypedDict

from speakeasy.artifacts import MAX_EMBEDDED_FILE_SIZE, ArtifactStore
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
    DroppedFile,
    DynamicCodeSegment,
    EntryPoint,
    EntryPointType,
    ErrorInfo,
    LoadedModule,
    MemoryAccesses,
    MemoryLayout,
    MemoryRegion,
    ModuleSegment,
    Report,
    StringCollection,
    StringsReport,
    SymAccessReport,
)
from speakeasy.windows.loaders import InitRoutine

if TYPE_CHECKING:
    from speakeasy.memmgr import MemMap
    from speakeasy.windows.objman import Process, Thread


class MemAccess:
    """Represent a symbolicated chunk of memory that can be tracked."""

    def __init__(self, base=None, sym=None, size=0):
        self.base: int | None = base
        self.size: int = size
        self.sym: str | None = sym
        self.reads: int = 0
        self.writes: int = 0
        self.execs: int = 0


@dataclass
class GuestCallbackFrame:
    """State retained while guest callbacks run: the API call that started them, if any."""

    stack_pointer: int
    return_address: int
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
    # Set while a generator handler (speakeasy.windows.guest_callbacks) runs on this frame
    handler: Any = None
    # (register, value) pairs of the nonvolatile registers when the first guest call starts
    saved_registers: tuple[tuple[int, int], ...] | None = None


class DynCodeMapping(TypedDict):
    tag: str
    base: int
    size: int


class DynCode(TypedDict):
    mmap: list[DynCodeMapping]
    base_addrs: set[int]


class Run:
    """
    Basic execution primitive for the emulation engine.

    A run can represent any form of execution: a thread, a callback, an exported function,
    or even a child process.
    """

    def __init__(self):
        self.instr_cnt: int = 0
        self.execution_elapsed: float = 0.0
        self.budget_instructions: int = 0
        self.guest_initialization: InitRoutine | None = None
        self.return_value: int | None = None
        self.events: list[AnyEvent] = []
        self.sym_access: dict[int, MemAccess] = {}
        self.dropped_files: list[dict[str, Any]] = []
        self.mem_access: dict[MemMap, MemAccess] = {}
        self.section_access: dict[tuple[int, int], MemAccess] = {}
        self.dyn_code: DynCode = {"mmap": [], "base_addrs": set()}
        self.process_context: Process | None = None
        self.thread: Thread | None = None
        self.unique_apis: list[str] = []
        self.api_hash: hashlib._Hash = hashlib.sha256()
        self.stack: MemAccess | None = None
        self.guest_callbacks: list[GuestCallbackFrame] = []
        self.exec_cache: deque[MemAccess] = deque(maxlen=4)
        self.read_cache: deque[MemAccess] = deque(maxlen=4)
        self.write_cache: deque[MemAccess] = deque(maxlen=4)

        self.args: list[Any] | tuple[Any, ...] | None = None
        self.registers: dict[int, int] = {}
        self.start_addr: int | None = None
        self.type: EntryPointType | None = None
        self.name: str | None = None
        self.error: ErrorInfo | None = None
        self.num_apis: int = 0
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


class Profiler:
    """Generate an execution report for all runs that occur within a binary emulation."""

    def __init__(self):
        super().__init__()

        self.start_time: float = 0
        self.strings: dict[str, list[str]] = {"ansi": [], "unicode": []}
        self.decoded_strings: dict[str, list[str]] = {"ansi": [], "unicode": []}
        self.last_data: list[int] = [0, 0]
        self.last_event: AnyEvent | dict[str, Any] = {}
        self.set_start_time()
        self.runtime: float = 0
        self.meta: dict[str, Any] = {}
        self.runs: list[Run] = []
        self.artifact_store: ArtifactStore = ArtifactStore()

    def add_input_metadata(self, meta):
        """Add top-level profiler fields with metadata for the module to emulate."""
        self.meta = meta

    def set_start_time(self):
        """Record the start time of a sample to time the execution length."""
        self.start_time = time.time()

    def get_run_time(self):
        """Get the time spent emulating a specific run."""
        return time.time() - self.start_time

    def stop_run_clock(self):
        """Stop the runtime clock to include in the report."""
        self.runtime = self.get_run_time()

    def add_run(self, run: Run) -> None:
        """Add a new run to the captured run list."""
        self.runs.append(run)

    def put_binary_data(self, data: bytes, limit: int | None = None) -> str | None:
        """Store binary data and return its artifact reference."""
        if not data:
            return None
        payload = data[:limit] if limit else data
        return self.artifact_store.put_bytes(payload)

    def merge_binary_data(self, artifact_ref: str | None, data: bytes, limit: int | None = None) -> str | None:
        """Append raw bytes to an existing artifact payload and store the merged result."""
        if not data and artifact_ref:
            return artifact_ref
        if not artifact_ref:
            return self.put_binary_data(data, limit=limit)
        merged = self.artifact_store.get_bytes(artifact_ref) + data
        if limit:
            merged = merged[:limit]
        return self.artifact_store.put_bytes(merged)

    def record_error_event(self, error: ErrorInfo) -> None:
        """Log a top level emulator error for the emulation report."""
        if not self.meta.get("errors"):
            self.meta["errors"] = []
        self.meta["errors"].append(error)

    def record_dropped_files_event(self, run, files):
        for f in files:
            data = f.get_contents()
            _hash = f.get_hash()
            data_ref = None
            if len(data) <= MAX_EMBEDDED_FILE_SIZE:
                data_ref = self.artifact_store.put_bytes(data)
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
    ) -> ApiEvent:
        """
        Log a call to an OS API. This includes arguments, return address, and return value.

        A call is recorded once when it repeats the API, address, arguments and
        return value of one of the last few events. Raw argument values do not
        count, so a loop that passes the same string from another buffer stays
        one event.
        """
        run.num_apis += 1

        if name not in run.unique_apis:
            run.api_hash.update(name.lower().encode("utf-8"))
            run.unique_apis.append(name)

        event = ApiEvent(pos=pos, api_name=name, args=args, return_value=ret)

        shown = [(a.name, a.type, a.display) for a in args]
        recent_events = [e for e in run.events[-3:] if isinstance(e, ApiEvent)]
        if not deduplicate or not any(
            e.pos.pc == event.pos.pc
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
        Log file access events.

        This includes handles being opened, data reads, and data writes.

        Raises:
            ValueError: if ``event_type`` is not a file event type.
        """
        data_ref = self.put_binary_data(data or b"", limit=1024)

        for et in (EventType.FILE_WRITE, EventType.FILE_READ):
            if event_type == et:
                for evt in reversed(run.events):
                    if isinstance(evt, (FileWriteEvent, FileReadEvent)) and evt.path == path and evt.event == et:
                        if size:
                            evt.size = (evt.size or 0) + size
                        if data:
                            evt.data_ref = self.merge_binary_data(evt.data_ref, data, limit=1024)
                        return

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
        Log registry access events.

        This includes values and keys being accessed, read, and written.

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
                open_flags=open_flags,
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
        Log events related to a process accessing another process.

        This includes creating a child process, reading or writing to a process, and creating
        a thread within another process.

        ``pos`` is the actor's execution position (the process/thread that performed
        the operation); ``proc`` is the target. The target process id is carried as
        event payload (``pid``) so the event stays in the actor's timeline. When the
        target is the actor's own process, the payload ``pid`` is left NULL, so a
        populated ``pid`` always means the operation crossed a process boundary.

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

        elif event_type == EventType.MEM_WRITE:
            base = kwargs["base"]
            size = kwargs["size"]
            data = kwargs["data"]
            last_base, last_size = self.last_data
            last_evt = self.last_event
            if isinstance(last_evt, MemWriteEvent) and (last_base + last_size) == base:
                last_evt.data_ref = self.merge_binary_data(last_evt.data_ref, data, limit=1024)
                last_evt.size += len(data)
                self.last_data = [base, size]
                return
            event = MemWriteEvent(
                pos=pos,
                path=path,
                base=base,
                size=size,
                data_ref=self.put_binary_data(data, limit=1024),
                pid=pid,
            )
            self.last_data = [base, size]

        elif event_type == EventType.MEM_READ:
            base = kwargs["base"]
            size = kwargs["size"]
            data = kwargs["data"]
            last_base, last_size = self.last_data
            last_evt = self.last_event
            if isinstance(last_evt, MemReadEvent) and (last_base + last_size) == base:
                last_evt.data_ref = self.merge_binary_data(last_evt.data_ref, data, limit=1024)
                last_evt.size += len(data)
                self.last_data = [base, size]
                return
            event = MemReadEvent(
                pos=pos,
                path=path,
                base=base,
                size=size,
                data_ref=self.put_binary_data(data, limit=1024),
                pid=pid,
            )
            self.last_data = [base, size]

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

    def record_dns_event(self, run, pos: TracePosition, domain, ip=""):
        """Log DNS name lookups for the emulation report."""
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
        """Log HTTP traffic that occurs during emulation."""
        event = NetHttpEvent(
            pos=pos,
            server=server,
            port=port,
            proto=NetHttpProtocol.HTTPS if secure else NetHttpProtocol.HTTP,
            headers=headers if headers else None,
            data_ref=self.put_binary_data(body or b"", limit=0x3000),
        )

        for evt in run.events:
            if (
                isinstance(evt, NetHttpEvent)
                and evt.server == event.server
                and evt.port == event.port
                and evt.proto == event.proto
                and evt.headers == event.headers
            ):
                return

        run.events.append(event)

    def record_dyn_code_event(self, run, tag, base, size):
        """Log code that the emulated program generates at runtime and then executes."""
        if base not in run.dyn_code["base_addrs"]:
            entry: DynCodeMapping = {"tag": tag, "base": base, "size": size}
            run.dyn_code["mmap"].append(entry)
            run.dyn_code["base_addrs"].add(base)

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
        """Log network activity for an emulation run."""
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
        """Log a handled exception event."""
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
        """Get the execution profile of the emulator as a JSON string."""
        report = self.get_report()
        return report.model_dump_json(indent=4, exclude_none=True)

    def get_report(self) -> Report:
        """Get the execution profile of the emulator."""
        entry_points = []

        for r in self.runs:
            error_info = r.error

            events = None
            if r.events:
                events = list(r.events)

            symbol_accesses: list[SymAccessReport] | None = None
            if r.sym_access:
                symbol_accesses = []
                for maccess in r.sym_access.values():
                    if maccess.sym is None:
                        continue
                    symbol_accesses.append(
                        SymAccessReport(
                            symbol=maccess.sym,
                            reads=maccess.reads,
                            writes=maccess.writes,
                            execs=maccess.execs,
                        )
                    )
                if not symbol_accesses:
                    symbol_accesses = None

            dyn_code_segments = None
            if r.dyn_code and r.dyn_code.get("mmap"):
                dyn_code_segments = [
                    DynamicCodeSegment(tag=seg["tag"], base=seg["base"], size=seg["size"]) for seg in r.dyn_code["mmap"]
                ]

            dropped_files = None
            if r.dropped_files:
                dropped_files = [
                    DroppedFile(path=f["path"], size=f["size"], sha256=f["sha256"], data_ref=f.get("data_ref"))
                    for f in r.dropped_files
                ]

            memory_layout = None
            if r.memory_regions or r.loaded_modules:
                regions = []
                for reg in r.memory_regions:
                    accesses = None
                    if reg.get("accesses"):
                        accesses = MemoryAccesses(
                            reads=reg["accesses"]["reads"],
                            writes=reg["accesses"]["writes"],
                            execs=reg["accesses"]["execs"],
                        )
                    regions.append(
                        MemoryRegion(
                            tag=reg["tag"],
                            base=reg["base"],
                            size=reg["size"],
                            perms=reg["perms"],
                            is_free=reg.get("is_free", False),
                            accesses=accesses,
                            data_ref=reg.get("data_ref"),
                        )
                    )
                modules = []
                for mod in r.loaded_modules:
                    segs = [
                        ModuleSegment(
                            name=seg["name"],
                            base=seg["base"],
                            size=seg["size"],
                            perms=seg["perms"],
                        )
                        for seg in mod.get("segments", [])
                    ]
                    modules.append(
                        LoadedModule(
                            name=mod["name"],
                            path=mod["path"],
                            base=mod["base"],
                            size=mod["size"],
                            segments=segs,
                        )
                    )
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
            ep = EntryPoint(
                type=r.type,
                name=r.name,
                start_address=r.start_addr,
                args=list(r.args or []),
                pid=ep_pid,
                tid=ep_tid,
                instruction_count=r.instr_cnt if r.instr_cnt else None,
                api_hash=r.api_hash.hexdigest(),
                return_value=r.return_value,
                error=error_info,
                events=events,
                symbol_accesses=symbol_accesses,
                dynamic_code_segments=dyn_code_segments,
                coverage=sorted(r.coverage) if r.coverage else None,
                dropped_files=dropped_files,
                memory=memory_layout,
            )
            entry_points.append(ep)

        strings_report = None
        if (
            self.strings["ansi"]
            or self.strings["unicode"]
            or self.decoded_strings["ansi"]
            or self.decoded_strings["unicode"]
        ):
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

        errors: list[ErrorInfo] | None = self.meta.get("errors") or None

        report_data = self.artifact_store.to_report_data()
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
            data=report_data or None,
            entry_points=entry_points,
        )
