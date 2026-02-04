# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

# Data format versioning
__report_version__ = "2.0.0"

import hashlib
import json
import time
from base64 import b64encode
from collections import deque

from speakeasy.const import (
    FILE_CREATE,
    FILE_OPEN,
    FILE_READ,
    FILE_WRITE,
    MEM_ALLOC,
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
    MemProtectEvent,
    MemReadEvent,
    MemWriteEvent,
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
        self.dyn_code = {"mmap": [], "base_addrs": set()}
        self.process_context = None
        self.thread = None
        self.unique_apis = []
        self.api_hash = hashlib.sha256()
        self.stack = None
        self.api_callbacks = []
        self.exec_cache = deque(maxlen=4)
        self.read_cache = deque(maxlen=4)
        self.write_cache = deque(maxlen=4)

        self.args = None
        self.start_addr = None
        self.type = None
        self.error = {}
        self.num_apis = 0
        self.coverage = []

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

        self.start_time = 0
        self.strings = {"ansi": [], "unicode": []}
        self.decoded_strings = {"ansi": [], "unicode": []}
        self.last_data = [0, 0]
        self.last_event = {}
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

    def log_error(self, error):
        """
        Log a top level emulator error for the emulation report
        """
        if not self.meta.get("errors"):
            self.meta["errors"] = []
        self.meta["errors"].append(error)

    def log_dropped_files(self, run, files):
        for f in files:
            data = f.get_data()
            if data is None:
                continue

            _hash = f.get_hash()
            entry = {"path": f.get_path(), "size": len(data), "sha256": _hash}
            run.dropped_files.append(entry)

    def log_api(self, run, tick, tid, pc, name, ret, argv, ctx=[]):
        """
        Log a call to an OS API. This includes arguments, return address, and return value
        """
        run.num_apis += 1

        if name not in run.unique_apis:
            run.api_hash.update(name.lower().encode("utf-8"))
            run.unique_apis.append(name)

        pc_str = hex(pc)
        ret_str = hex(ret) if ret is not None else None

        args = argv.copy()
        for i, arg in enumerate(args):
            if isinstance(arg, int):
                args[i] = hex(arg)

        event = ApiEvent(
            tick=tick,
            tid=tid,
            pc=pc_str,
            api_name=name,
            args=args,
            ret_val=ret_str,
        )

        recent_events = [e for e in run.events[-3:] if isinstance(e, ApiEvent)]
        if not any(
            e.pc == event.pc and e.api_name == event.api_name and e.args == event.args and e.ret_val == event.ret_val
            for e in recent_events
        ):
            run.events.append(event)

    def log_file_access(
        self, run, tick, tid, path, event_type, data=None, handle=0, disposition=[], access=[], buffer=0, size=None
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

        if event_type == FILE_CREATE:
            event = FileCreateEvent(
                tick=tick,
                tid=tid,
                path=path,
                handle=handle_str,
                open_flags=open_flags,
                access_flags=access_flags,
            )
        elif event_type == FILE_OPEN:
            event = FileOpenEvent(
                tick=tick,
                tid=tid,
                path=path,
                handle=handle_str,
                open_flags=open_flags,
                access_flags=access_flags,
            )
        elif event_type == FILE_READ:
            event = FileReadEvent(
                tick=tick,
                tid=tid,
                path=path,
                handle=handle_str,
                size=size,
                data=enc,
                buffer=buffer_str,
            )
        elif event_type == FILE_WRITE:
            event = FileWriteEvent(
                tick=tick,
                tid=tid,
                path=path,
                handle=handle_str,
                size=size,
                data=enc,
                buffer=buffer_str,
            )
        else:
            return

        run.events.append(event)

    def log_registry_access(
        self,
        run,
        tick,
        tid,
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

        if event_type == REG_OPEN:
            event = RegOpenKeyEvent(
                tick=tick,
                tid=tid,
                path=path,
                handle=handle_str,
                open_flags=open_flags,
                access_flags=access_flags_list,
            )
        elif event_type == REG_CREATE:
            event = RegCreateKeyEvent(
                tick=tick,
                tid=tid,
                path=path,
                handle=handle_str,
                open_flags=open_flags,
                access_flags=access_flags_list,
            )
        elif event_type == REG_READ:
            event = RegReadValueEvent(
                tick=tick,
                tid=tid,
                path=path,
                handle=handle_str,
                value_name=value_name,
                size=size,
                data=enc,
                buffer=buffer_str,
            )
        elif event_type == REG_LIST:
            event = RegListSubkeysEvent(
                tick=tick,
                tid=tid,
                path=path,
                handle=handle_str,
            )
        else:
            return

        run.events.append(event)

    def log_process_event(self, run, tick, tid, proc, event_type, kwargs):
        """
        Log events related to a process accessing another process. This includes:
        creating a child process, reading/writing to a process, or creating a thread
        within another process.
        """
        pid = proc.get_id()
        path = proc.get_process_path()

        if event_type == PROC_CREATE:
            event = ProcessCreateEvent(
                tick=tick,
                tid=tid,
                pid=pid,
                path=path,
                cmdline=proc.get_command_line(),
            )

        elif event_type == MEM_ALLOC:
            event = MemAllocEvent(
                tick=tick,
                tid=tid,
                pid=pid,
                path=path,
                base=hex(kwargs.get("base", 0)),
                size=hex(kwargs.get("size", 0)),
                protect=kwargs.get("protect"),
            )

        elif event_type == MEM_PROTECT:
            event = MemProtectEvent(
                tick=tick,
                tid=tid,
                pid=pid,
                path=path,
                base=hex(kwargs.get("base", 0)),
                size=hex(kwargs.get("size", 0)),
                protect=kwargs.get("protect"),
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
                tick=tick,
                tid=tid,
                pid=pid,
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
                tick=tick,
                tid=tid,
                pid=pid,
                path=path,
                base=hex(base),
                size=size,
                data=data,
            )
            self.last_data = [base, size]

        elif event_type == THREAD_INJECT:
            event = ThreadInjectEvent(
                tick=tick,
                tid=tid,
                pid=pid,
                path=path,
                start_addr=hex(kwargs["start_addr"]),
                param=hex(kwargs["param"]),
            )

        elif event_type == THREAD_CREATE:
            event = ThreadCreateEvent(
                tick=tick,
                tid=tid,
                pid=pid,
                path=path,
                start_addr=hex(kwargs["start_addr"]),
                param=hex(kwargs["param"]),
            )

        else:
            return

        run.events.append(event)
        self.last_event = event

    def log_dns(self, run, tick, tid, domain, ip=""):
        """
        Log DNS name lookups for the emulation report
        """
        for evt in run.events:
            if isinstance(evt, NetDnsEvent) and evt.query == domain and evt.response == ip:
                return

        event = NetDnsEvent(
            tick=tick,
            tid=tid,
            query=domain,
            response=ip if ip else None,
        )
        run.events.append(event)

    def log_http(self, run, tick, tid, server, port, proto="http", headers="", body=b"", secure=False):
        """
        Log HTTP traffic that occur during emulation
        """
        proto_str = "https" if secure else "http"
        body_enc = None
        if body:
            body_enc = self.handle_binary_data(body[:0x3000])

        event = NetHttpEvent(
            tick=tick,
            tid=tid,
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

    def log_dyn_code(self, run, tag, base, size):
        """
        Log code that is generated at runtime and then executed
        """
        if base not in run.dyn_code["base_addrs"]:
            entry = {"tag": tag, "base": hex(base), "size": hex(size)}
            run.dyn_code["mmap"].append(entry)
            run.dyn_code["base_addrs"].add(base)

    def log_network(self, run, tick, tid, server, port, typ="unknown", proto="unknown", data=b"", method=""):
        """
        Log network activity for an emulation run
        """
        data_enc = None
        if data:
            data_enc = self.handle_binary_data(data[:0x3000])

        event = NetTrafficEvent(
            tick=tick,
            tid=tid,
            server=server,
            port=port,
            proto=proto,
            type=typ if typ != "unknown" else None,
            data=data_enc,
            method=method if method else None,
        )
        run.events.append(event)

    def log_exception(self, run, tick, tid, pc, instr, exception_code, handler_address, registers):
        """
        Log a handled exception event
        """
        event = ExceptionEvent(
            tick=tick,
            tid=tid,
            pc=hex(pc),
            instr=instr,
            exception_code=hex(exception_code),
            handler_address=hex(handler_address),
            registers=registers,
        )
        run.events.append(event)

    def get_json_report(self):
        """
        Retrieve the execution profile for the emulator as a json string
        """
        profile = self.get_report()
        return json.dumps(profile, indent=4, sort_keys=False)

    def get_report(self):
        """
        Retrieve the execution profile for the emulator
        """
        profile = {}

        meta = self.meta
        meta.update({"report_version": __report_version__})
        meta.update({"emulation_total_runtime": round(self.runtime, 3)})
        meta.update({"timestamp": int(self.start_time)})

        exec_paths = []

        for r in self.runs:
            if r.ret_val is not None:
                ret = hex(r.ret_val)
            else:
                ret = None

            args = []
            for a in r.args:
                if isinstance(a, int):
                    args.append(hex(a))
                else:
                    args.append(a)

            ep = {
                "ep_type": r.type,
                "start_addr": hex(r.start_addr),
                "ep_args": args,
            }

            if r.instr_cnt:
                ep.update({"instr_count": r.instr_cnt})

            ep.update({"apihash": r.api_hash.hexdigest(), "ret_val": ret, "error": r.error})

            if r.events:
                serialized_events = []
                for evt in r.events:
                    evt_dict = evt.model_dump(exclude_none=True, mode="json")
                    if isinstance(evt, (MemWriteEvent, MemReadEvent)):
                        evt_dict["data"] = self.handle_binary_data(evt.data[:1024])
                    serialized_events.append(evt_dict)
                ep.update({"events": serialized_events})

            if r.mem_access:
                mem_accesses = []
                for mmap, maccess in r.mem_access.items():
                    mem_accesses.append(
                        {
                            "tag": mmap.get_tag(),
                            "base": hex(mmap.get_base()),
                            "reads": maccess.reads,
                            "writes": maccess.writes,
                            "execs": maccess.execs,
                        }
                    )

                ep.update({"mem_access": mem_accesses})

                sym_accesses = []
                for address, maccess in r.sym_access.items():
                    sym_accesses.append(
                        {
                            "symbol": maccess.sym,
                            "reads": maccess.reads,
                            "writes": maccess.writes,
                            "execs": maccess.execs,
                        }
                    )
                if sym_accesses:
                    ep.update({"sym_accesses": sym_accesses})

            if r.dyn_code:
                ep.update({"dynamic_code_segments": r.dyn_code["mmap"]})

            if r.coverage:
                ep.update({"coverage": r.coverage})

            exec_paths.append(ep)

            if r.dropped_files:
                ep.update({"dropped_files": r.dropped_files})

        if (
            self.strings["ansi"]
            or self.strings["unicode"]
            or self.decoded_strings["ansi"]
            or self.decoded_strings["unicode"]
        ):
            meta.update({"strings": {"static": self.strings, "in_memory": self.decoded_strings}})  # noqa
        profile = {**profile, **meta}
        profile.update({"entry_points": exec_paths})
        return profile
