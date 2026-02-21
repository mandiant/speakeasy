# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

# Data format versioning
__report_version__ = "2.0.0"

import hashlib
import time
from base64 import b64encode
from collections import deque

from speakeasy.const import (
    FILE_CREATE,
    FILE_OPEN,
    FILE_READ,
    FILE_WRITE,
    MEM_ALLOC,
    MEM_FREE,
    MEM_PROTECT,
    MEM_READ,
    MEM_WRITE,
    PROC_CREATE,
    REG_CREATE,
    REG_LIST,
    REG_OPEN,
    REG_READ,
    THREAD_CREATE,
    THREAD_INJECT,
)
from speakeasy.profiler_events import (
    AnyEvent,
    ApiEvent,
    ExceptionEvent,
    FileCreateEvent,
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
    NetTrafficEvent,
    ProcessCreateEvent,
    RegCreateKeyEvent,
    RegListSubkeysEvent,
    RegOpenKeyEvent,
    RegReadValueEvent,
    ThreadCreateEvent,
    ThreadInjectEvent,
    TracePosition,
)
from speakeasy.report import (
    DroppedFile,
    DynamicCodeSegment,
    EntryPoint,
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


class ProfileError(Exception):
    pass


class MemAccess:
    """
    Represents a symbolicated chunk of memory that can be tracked
    """

    def __init__(self, base=None, sym=None, size=0):
        self.base = base
        self.size = size
        self.sym = sym
        self.reads = 0
        self.writes = 0
        self.execs = 0


class Run:
    """
    This class represents the basic execution primative for the emulation engine
    A "run" can represent any form of execution: a thread, a callback, an exported function,
    or even a child process.
    """

    def __init__(self):
        self.instr_cnt = 0
        self.ret_val = None
        self.events: list[AnyEvent] = []
        self.sym_access = {}
        self.dropped_files = []
        self.mem_access = {}
        self.dyn_code: dict[str, list | set] = {"mmap": [], "base_addrs": set()}
        self.process_context = None
        self.thread = None
        self.unique_apis = []
        self.api_hash = hashlib.sha256()
        self.stack = None
        self.api_callbacks = []
        self.exec_cache: deque = deque(maxlen=4)
        self.read_cache: deque = deque(maxlen=4)
        self.write_cache: deque = deque(maxlen=4)

        self.args = None
        self.start_addr = None
        self.type = None
        self.error = {}
        self.num_apis = 0
        self.coverage = []
        self.memory_regions: list[dict] = []
        self.loaded_modules: list[dict] = []

    def get_api_count(self):
        """
        Get the number of APIs that were called during the run
        """
        return self.num_apis


class Profiler:
    """
    The profiler class exists to generate an execution report
    for all runs that occur within a binary emulation.
    """

    def __init__(self):
        super().__init__()

        self.start_time: float = 0
        self.strings: dict[str, list] = {"ansi": [], "unicode": []}
        self.decoded_strings: dict[str, list] = {"ansi": [], "unicode": []}
        self.last_data = [0, 0]
        self.last_event: AnyEvent | dict = {}
        self.set_start_time()
        self.runtime = 0
        self.meta = {}
        self.runs = []

    def add_input_metadata(self, meta):
        """
        Add top level profiler fields containing metadata for the
        module that will be emulated
        """
        self.meta = meta

    def set_start_time(self):
        """
        Get the start time for a sample so we can time the execution length
        """
        self.start_time = time.time()

    def get_run_time(self):
        """
        Get the time spent emulating a specific "run"
        """
        return time.time() - self.start_time

    def stop_run_clock(self):
        """
        Stop the runtime clock to include in the report
        """
        self.runtime = self.get_run_time()

    def get_epoch_time(self):
        """
        Get the current time in epoch format
        """
        return int(time.time())

    def add_run(self, run):
        """
        Add a new run to the captured run list
        """
        self.runs.append(run)

    def handle_binary_data(self, data):
        """
        Compress and encode binary data to be included in a report
        """
        return b64encode(data).decode("utf-8")

    def record_error_event(self, error):
        """
        Log a top level emulator error for the emulation report
        """
        if not self.meta.get("errors"):
            self.meta["errors"] = []
        self.meta["errors"].append(error)

    def record_dropped_files_event(self, run, files):
        for f in files:
            data = f.get_data()
            if data is None:
                continue

            _hash = f.get_hash()
            entry = {"path": f.get_path(), "size": len(data), "sha256": _hash}
            run.dropped_files.append(entry)

    def record_api_event(self, run, pos: TracePosition, name, ret, argv, ctx=[]):
        """
        Log a call to an OS API. This includes arguments, return address, and return value
        """
        run.num_apis += 1

        if name not in run.unique_apis:
            run.api_hash.update(name.lower().encode("utf-8"))
            run.unique_apis.append(name)

        ret_str = hex(ret) if ret is not None else None

        args = argv.copy()
        for i, arg in enumerate(args):
            if isinstance(arg, int):
                args[i] = hex(arg)

        event = ApiEvent(
            pos=pos,
            api_name=name,
            args=args,
            ret_val=ret_str,
        )

        recent_events = [e for e in run.events[-3:] if isinstance(e, ApiEvent)]
        if not any(
            e.pos.pc == event.pos.pc
            and e.api_name == event.api_name
            and e.args == event.args
            and e.ret_val == event.ret_val
            for e in recent_events
        ):
            run.events.append(event)

    def record_file_access_event(
        self,
        run,
        pos: TracePosition,
        path,
        event_type,
        data=None,
        handle=0,
        disposition=[],
        access=[],
        buffer=0,
        size=None,
    ):
        """
        Log file access events. This will include things like handles being opened,
        data reads, and data writes.
        """
        enc = None
        if data:
            enc = self.handle_binary_data(data[:1024])

        for et in (FILE_WRITE, FILE_READ):
            if event_type == et:
                for evt in reversed(run.events):
                    if isinstance(evt, (FileWriteEvent, FileReadEvent)) and evt.path == path and evt.event == et:
                        if size:
                            evt.size = (evt.size or 0) + size
                        if enc:
                            evt.data = (evt.data or "") + enc
                        return

        handle_str = hex(handle) if handle else None
        buffer_str = hex(buffer) if buffer else None

        open_flags = None
        if disposition:
            open_flags = disposition if isinstance(disposition, list) else [disposition]
        access_flags = None
        if access:
            access_flags = access if isinstance(access, list) else [access]

        event: AnyEvent
        if event_type == FILE_CREATE:
            event = FileCreateEvent(
                pos=pos,
                path=path,
                handle=handle_str,
                open_flags=open_flags,
                access_flags=access_flags,
            )
        elif event_type == FILE_OPEN:
            event = FileOpenEvent(
                pos=pos,
                path=path,
                handle=handle_str,
                open_flags=open_flags,
                access_flags=access_flags,
            )
        elif event_type == FILE_READ:
            event = FileReadEvent(
                pos=pos,
                path=path,
                handle=handle_str,
                size=size,
                data=enc,
                buffer=buffer_str,
            )
        elif event_type == FILE_WRITE:
            event = FileWriteEvent(
                pos=pos,
                path=path,
                handle=handle_str,
                size=size,
                data=enc,
                buffer=buffer_str,
            )
        else:
            return

        run.events.append(event)

    def record_registry_access_event(
        self,
        run,
        pos: TracePosition,
        path,
        event_type,
        value_name=None,
        data=None,
        handle=0,
        disposition=[],
        access=[],
        buffer=0,
        size=None,
    ):
        """
        Log registry access events. This includes values and keys being accessed and
        being read/written
        """
        enc = None
        if data:
            enc = self.handle_binary_data(data[:1024])

        handle_str = hex(handle) if handle else None
        buffer_str = hex(buffer) if buffer else None

        open_flags = None
        if disposition:
            open_flags = disposition if isinstance(disposition, list) else [disposition]
        access_flags_list = None
        if access:
            access_flags_list = access if isinstance(access, list) else [access]

        event: AnyEvent
        if event_type == REG_OPEN:
            event = RegOpenKeyEvent(
                pos=pos,
                path=path,
                handle=handle_str,
                open_flags=open_flags,
                access_flags=access_flags_list,
            )
        elif event_type == REG_CREATE:
            event = RegCreateKeyEvent(
                pos=pos,
                path=path,
                handle=handle_str,
                open_flags=open_flags,
                access_flags=access_flags_list,
            )
        elif event_type == REG_READ:
            event = RegReadValueEvent(
                pos=pos,
                path=path,
                handle=handle_str,
                value_name=value_name,
                size=size,
                data=enc,
                buffer=buffer_str,
            )
        elif event_type == REG_LIST:
            event = RegListSubkeysEvent(
                pos=pos,
                path=path,
                handle=handle_str,
            )
        else:
            return

        run.events.append(event)

    def record_process_event(self, run, pos: TracePosition, proc, event_type, kwargs):
        """
        Log events related to a process accessing another process. This includes:
        creating a child process, reading/writing to a process, or creating a thread
        within another process.
        """
        pid = proc.get_id()
        path = proc.get_process_path()
        proc_pos = TracePosition(tick=pos.tick, tid=pos.tid, pid=pid, pc=pos.pc)

        event: AnyEvent
        if event_type == PROC_CREATE:
            event = ProcessCreateEvent(
                pos=proc_pos,
                path=path,
                cmdline=proc.get_command_line(),
            )

        elif event_type == MEM_ALLOC:
            event = MemAllocEvent(
                pos=proc_pos,
                path=path,
                base=hex(kwargs.get("base", 0)),
                size=hex(kwargs.get("size", 0)),
                protect=kwargs.get("protect"),
            )

        elif event_type == MEM_PROTECT:
            event = MemProtectEvent(
                pos=proc_pos,
                path=path,
                base=hex(kwargs.get("base", 0)),
                size=hex(kwargs.get("size", 0)),
                protect=kwargs.get("protect"),
            )

        elif event_type == MEM_FREE:
            event = MemFreeEvent(
                pos=proc_pos,
                path=path,
                base=hex(kwargs.get("base", 0)),
                size=hex(kwargs.get("size", 0)),
            )

        elif event_type == MEM_WRITE:
            base = kwargs["base"]
            size = kwargs["size"]
            data = kwargs["data"]
            last_base, last_size = self.last_data
            last_evt = self.last_event
            if isinstance(last_evt, MemWriteEvent) and (last_base + last_size) == base:
                last_evt.data += data
                last_evt.size += len(data)
                self.last_data = [base, size]
                return
            event = MemWriteEvent(
                pos=proc_pos,
                path=path,
                base=hex(base),
                size=size,
                data=data,
            )
            self.last_data = [base, size]

        elif event_type == MEM_READ:
            base = kwargs["base"]
            size = kwargs["size"]
            data = kwargs["data"]
            last_base, last_size = self.last_data
            last_evt = self.last_event
            if isinstance(last_evt, MemReadEvent) and (last_base + last_size) == base:
                last_evt.data += data
                last_evt.size += len(data)
                self.last_data = [base, size]
                return
            event = MemReadEvent(
                pos=proc_pos,
                path=path,
                base=hex(base),
                size=size,
                data=data,
            )
            self.last_data = [base, size]

        elif event_type == THREAD_INJECT:
            event = ThreadInjectEvent(
                pos=proc_pos,
                path=path,
                start_addr=hex(kwargs["start_addr"]),
                param=hex(kwargs["param"]),
            )

        elif event_type == THREAD_CREATE:
            event = ThreadCreateEvent(
                pos=proc_pos,
                path=path,
                start_addr=hex(kwargs["start_addr"]),
                param=hex(kwargs["param"]),
            )

        else:
            return

        run.events.append(event)
        self.last_event = event

    def record_dns_event(self, run, pos: TracePosition, domain, ip=""):
        """
        Log DNS name lookups for the emulation report
        """
        for evt in run.events:
            if isinstance(evt, NetDnsEvent) and evt.query == domain and evt.response == ip:
                return

        event = NetDnsEvent(
            pos=pos,
            query=domain,
            response=ip if ip else None,
        )
        run.events.append(event)

    def record_http_event(
        self, run, pos: TracePosition, server, port, proto="http", headers="", body=b"", secure=False
    ):
        """
        Log HTTP traffic that occur during emulation
        """
        proto_str = "https" if secure else "http"
        body_enc = None
        if body:
            body_enc = self.handle_binary_data(body[:0x3000])

        event = NetHttpEvent(
            pos=pos,
            server=server,
            port=port,
            proto=f"tcp.{proto_str}",
            headers=headers if headers else None,
            body=body_enc,
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
        """
        Log code that is generated at runtime and then executed
        """
        if base not in run.dyn_code["base_addrs"]:
            entry = {"tag": tag, "base": hex(base), "size": hex(size)}
            run.dyn_code["mmap"].append(entry)
            run.dyn_code["base_addrs"].add(base)

    def record_network_event(
        self, run, pos: TracePosition, server, port, typ="unknown", proto="unknown", data=b"", method=""
    ):
        """
        Log network activity for an emulation run
        """
        data_enc = None
        if data:
            data_enc = self.handle_binary_data(data[:0x3000])

        event = NetTrafficEvent(
            pos=pos,
            server=server,
            port=port,
            proto=proto,
            type=typ if typ != "unknown" else None,
            data=data_enc,
            method=method if method else None,
        )
        run.events.append(event)

    def record_exception_event(self, run, pos: TracePosition, instr, exception_code, handler_address, registers):
        """
        Log a handled exception event
        """
        event = ExceptionEvent(
            pos=pos,
            instr=instr,
            exception_code=hex(exception_code),
            handler_address=hex(handler_address),
            registers=registers,
        )
        run.events.append(event)

    def record_module_load_event(self, run, pos: TracePosition, name, path, base, size):
        """
        Log module (PE/DLL) load events
        """
        event = ModuleLoadEvent(
            pos=pos,
            name=name,
            path=path,
            base=hex(base),
            size=hex(size),
        )
        run.events.append(event)

    def get_json_report(self) -> str:
        """
        Retrieve the execution profile for the emulator as a json string
        """
        report = self.get_report()
        return report.model_dump_json(indent=4, exclude_none=True)

    def get_report(self) -> Report:
        """
        Retrieve the execution profile for the emulator
        """
        entry_points = []

        for r in self.runs:
            args = []
            for a in r.args:
                if isinstance(a, int):
                    args.append(hex(a))
                else:
                    args.append(a)

            error_info = None
            if r.error:
                pc_str = r.error.get("pc")
                pc_int = int(pc_str, 16) if pc_str else None
                error_info = ErrorInfo(
                    type=r.error.get("type", ""),
                    pc=pc_int,
                    instr=r.error.get("instr"),
                )

            events = None
            if r.events:
                events = []
                for evt in r.events:
                    if isinstance(evt, (MemWriteEvent, MemReadEvent)):
                        evt.data = evt.data[:1024]
                    events.append(evt)

            sym_accesses: list[SymAccessReport] | None = None
            if r.sym_access:
                sym_accesses = []
                for address, maccess in r.sym_access.items():
                    sym_accesses.append(
                        SymAccessReport(
                            symbol=maccess.sym,
                            reads=maccess.reads,
                            writes=maccess.writes,
                            execs=maccess.execs,
                        )
                    )
                if not sym_accesses:
                    sym_accesses = None

            dyn_code_segments = None
            if r.dyn_code and r.dyn_code.get("mmap"):
                dyn_code_segments = [
                    DynamicCodeSegment(tag=seg["tag"], base=seg["base"], size=seg["size"]) for seg in r.dyn_code["mmap"]
                ]

            dropped_files = None
            if r.dropped_files:
                dropped_files = [
                    DroppedFile(path=f["path"], data=f.get("data"), sha256=f["sha256"]) for f in r.dropped_files
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
                            address=reg["address"],
                            size=reg["size"],
                            prot=reg["prot"],
                            is_free=reg.get("is_free", False),
                            accesses=accesses,
                        )
                    )
                modules = []
                for mod in r.loaded_modules:
                    segs = [
                        ModuleSegment(
                            name=seg["name"],
                            address=seg["address"],
                            size=seg["size"],
                            prot=seg["prot"],
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

            ep = EntryPoint(
                ep_type=r.type,
                start_addr=r.start_addr,
                ep_args=args,
                instr_count=r.instr_cnt if r.instr_cnt else None,
                apihash=r.api_hash.hexdigest(),
                ret_val=r.ret_val,
                error=error_info,
                events=events,
                sym_accesses=sym_accesses,
                dynamic_code_segments=dyn_code_segments,
                coverage=r.coverage if r.coverage else None,
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

        errors = None
        meta_errors = self.meta.get("errors", [])
        if meta_errors:

            def parse_error(e):
                pc_str = e.get("pc")
                pc_int = int(pc_str, 16) if pc_str else None
                return ErrorInfo(type=e.get("type", ""), pc=pc_int, instr=e.get("instr"))

            errors = [parse_error(e) for e in meta_errors]

        report = Report(
            report_version=__report_version__,
            emulation_total_runtime=round(self.runtime, 3),
            timestamp=int(self.start_time),
            arch=self.meta.get("arch"),
            filepath=self.meta.get("filepath"),
            sha256=self.meta.get("sha256"),
            size=self.meta.get("size"),
            filetype=self.meta.get("filetype"),
            errors=errors,
            strings=strings_report,
            entry_points=entry_points,
        )
        return report
