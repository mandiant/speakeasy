# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

# Data format versioning
__report_version__ = '1.1.0'

import time
import json
import hashlib

from collections import deque
from base64 import b64encode

from speakeasy.const import PROC_CREATE, MEM_ALLOC, MEM_WRITE, MEM_READ, MEM_PROTECT, THREAD_INJECT, THREAD_CREATE


class ProfileError(Exception):
    pass


class MemAccess(object):
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


class Run(object):
    """
    This class represents the basic execution primative for the emulation engine
    A "run" can represent any form of execution: a thread, a callback, an exported function,
    or even a child process.
    """
    def __init__(self):
        self.instr_cnt = 0
        self.ret_val = None
        self.apis = []
        self.sym_access = {}
        self.network = {'dns': [], 'traffic': []}
        self.file_access = []
        self.dropped_files = []
        self.registry_access = []
        self.process_events = []
        self.mem_access = {}
        self.dyn_code = {'mmap': [], 'base_addrs': set()}
        self.process_context = None
        self.thread = None
        self.unique_apis = []
        self.api_hash = hashlib.sha256()
        self.handled_exceptions = []
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

    def get_api_count(self):
        """
        Get the number of APIs that were called during the run
        """
        return self.num_apis


class Profiler(object):
    """
    The profiler class exists to generate an execution report
    for all runs that occur within a binary emulation.
    """
    def __init__(self):
        super(Profiler, self).__init__()

        self.start_time = 0
        self.strings = {'ansi': [], 'unicode': []}
        self.decoded_strings = {'ansi': [], 'unicode': []}
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
        return b64encode(data).decode('utf-8')

    def log_error(self, error):
        """
        Log a top level emulator error for the emulation report
        """
        if not self.meta.get('errors'):
            self.meta['errors'] = []
        self.meta['errors'].append(error)

    def log_dropped_files(self, run, files):
        for f in files:
            data = f.get_data()
            if data is None:
                continue

            _hash = f.get_hash()
            entry = {'path': f.get_path(), 'size': len(data), 'sha256': _hash}
            run.dropped_files.append(entry)

    def log_api(self, run, pc, name, ret, argv, ctx=[]):
        """
        Log a call to an OS API. This includes arguments, return address, and return value
        """

        run.num_apis += 1

        if name not in run.unique_apis:
            run.api_hash.update(name.lower().encode('utf-8'))
            run.unique_apis.append(name)

        if not run.apis:
            run.apis = []

        pc = hex(pc)

        if ret is not None:
            ret = hex(ret)

        args = argv.copy()
        for i, arg in enumerate(args):
            if isinstance(arg, int):
                args[i] = hex(arg)

        entry = {'pc': pc, 'api_name': name, 'args': args, 'ret_val': ret}

        if entry not in run.apis[-3:]:
            run.apis.append(entry)

    def log_file_access(self, run, path, event_type, data=None,
                        handle=0, disposition=[], access=[], buffer=0,
                        size=None):
        """
        Log file access events. This will include things like handles being opened,
        data reads, and data writes.
        """
        enc = None
        if data:
            enc = self.handle_binary_data(data[:1024])

        for et in ('write', 'read'):
            if event_type == et:
                for fa in run.file_access:
                    if path == fa.get('path') and fa['event'] == et:
                        if size:
                            fa['size'] += size
                        if enc:
                            fa["data"] += enc
                        return

        event = {'event': event_type, 'path': path}
        if enc:
            event.update({'data': enc})

        if handle:
            event.update({'handle': handle})

        if size is not None:
            event.update({'size': size})

        if buffer:
            event.update({'buffer': hex(buffer)})

        if disposition:
            event.update({'open_flags': disposition})

        if access:
            event.update({'access_flags': access})

        if event not in run.file_access:
            run.file_access.append(event)

    def log_registry_access(self, run, path, event_type, value_name=None, data=None,
                            handle=0, disposition=[], access=[], buffer=0,
                            size=None):
        """
        Log registry access events. This includes values and keys being accessed and
        being read/written
        """
        enc = None
        if data:
            enc = self.handle_binary_data(data[:1024])

        event = {'event': event_type, 'path': path}
        if enc:
            event.update({'data': enc})

        if handle:
            event.update({'handle': hex(handle)})

        if value_name:
            event.update({'value_name': value_name})

        if size is not None:
            event.update({'size': size})

        if buffer:
            event.update({'buffer': hex(buffer)})

        if disposition:
            event.update({'open_flags': disposition})

        if access:
            event.update({'access_flags': access})

        if event not in run.registry_access:
            run.registry_access.append(event)

    def log_process_event(self, run, proc, event_type, kwargs):
        """
        Log events related to a process accessing another process. This includes:
        creating a child process, reading/writing to a process, or creating a thread
        within another process.
        """
        event = {}
        if event_type == PROC_CREATE:
            event.update({'event': event_type})
            event.update({'pid': proc.get_id()})
            event.update({'path': proc.get_process_path()})
            event.update({'cmdline': proc.get_command_line()})

        elif event_type == MEM_ALLOC:
            event.update({'event': event_type})
            event.update({'pid': proc.get_id()})
            event.update({'path': proc.get_process_path()})
            event.update(kwargs)

        elif event_type == MEM_PROTECT:
            event.update({'event': event_type})
            event.update({'pid': proc.get_id()})
            event.update({'path': proc.get_process_path()})
            event.update(kwargs)

        elif event_type == MEM_WRITE:
            base = kwargs['base']
            size = kwargs['size']
            data = kwargs['data']
            last_base, last_size = self.last_data
            last_evt_type = self.last_event.get('event')
            if event_type == last_evt_type and (last_base + last_size) == base:
                self.last_event['data'] += data
                self.last_event['size'] += len(data)
                self.last_data = [base, size]
                return
            event.update({'event': event_type})
            event.update({'pid': proc.get_id()})
            event.update({'path': proc.get_process_path()})
            data = kwargs['data']
            event.update({'data': data})
            event.update({'base': base})
            event.update({'size': size})
            self.last_data = [base, size]

        elif event_type == MEM_READ:
            base = kwargs['base']
            size = kwargs['size']
            data = kwargs['data']
            last_base, last_size = self.last_data
            last_evt_type = self.last_event.get('event')
            if event_type == last_evt_type and (last_base + last_size) == base:
                self.last_event['data'] += data
                self.last_event['size'] += len(data)
                self.last_data = [base, size]
                return
            event.update({'event': event_type})
            event.update({'pid': proc.get_id()})
            event.update({'path': proc.get_process_path()})
            data = kwargs['data']
            event.update({'data': data})
            event.update({'size': size})
            event.update({'base': base})
            self.last_data = [base, size]

        elif event_type == THREAD_INJECT or event_type == THREAD_CREATE:
            event.update({'event': event_type})
            event.update({'pid': proc.get_id()})
            event.update({'path': proc.get_process_path()})
            event.update({'start_addr': hex(kwargs['start_addr'])})
            event.update({'param': hex(kwargs['param'])})

        run.process_events.append(event)
        self.last_event = event

    def log_dns(self, run, domain, ip=''):
        """
        Log DNS name lookups for the emulation report
        """

        query = {"query": domain, "response": ip}
        if query not in run.network['dns']:
            run.network['dns'].append(query)

    def log_http(self, run, server, port, proto='http',
                 headers='', body=b'', secure=False):
        """
        Log HTTP traffic that occur during emulation
        """
        conns = run.network['traffic']

        proto = 'http'
        if secure:
            proto = 'https'

        http_conn = {'server': server, 'proto': 'tcp.%s' % (proto), 'port': port,
                     'headers': headers}
        if body:
            data = self.handle_binary_data(body[:0x3000])
            http_conn.update({'body': data})

        if http_conn not in conns:
            conns.append(http_conn)

    def log_dyn_code(self, run, tag, base, size):
        """
        Log code that is generated at runtime and then executed
        """

        if base not in run.dyn_code['base_addrs']:
            entry = {'tag': tag, 'base': hex(base), 'size': hex(size)}
            run.dyn_code['mmap'].append(entry)
            run.dyn_code['base_addrs'].add(base)

    def log_network(self, run, server, port, typ='unknown', proto='unknown', data=b'', method=''):
        """
        Log network activity for an emulation run
        """
        conns = run.network['traffic']

        conn = {'server': server, 'proto': proto, 'port': port}
        if data:
            data = self.handle_binary_data(data[:0x3000])
            conn.update({'data': data})

        if method:
            conn.update({'method': method})

        conn.update({'type': typ})

        conns.append(conn)

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
        meta.update({'report_version': __report_version__})
        meta.update({'emulation_total_runtime': round(self.runtime, 3)})
        meta.update({'timestamp': int(self.start_time)})

        # For now, we only support single file emulation
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

            ep = {'ep_type': r.type,
                  'start_addr': hex(r.start_addr),
                  'ep_args': args,
                  }

            if r.instr_cnt:
                ep.update({'instr_count': r.instr_cnt})

            ep.update(
                  {
                   'apihash': r.api_hash.hexdigest(),
                   'apis': r.apis,
                   'ret_val': ret,
                   'error': r.error
                  }
            )

            if r.handled_exceptions:
                ep.update({"handled_exceptions": r.handled_exceptions})

            if r.network and (r.network.get('dns', []) or
                              r.network.get('traffic', {})):
                ep.update({'network_events': r.network})

            if r.file_access:
                ep.update({'file_access': r.file_access})

            if r.registry_access:
                ep.update({'registry_access': r.registry_access})

            if r.process_events:
                for evt in r.process_events:
                    if evt.get('event') in (MEM_WRITE, MEM_READ):
                        evt['data'] = self.handle_binary_data(evt['data'][:1024])
                    if evt.get('base'):
                        evt['base'] = hex(evt['base'])
                ep.update({'process_events': r.process_events})

            if r.mem_access:
                mem_accesses = []
                for mmap, maccess in r.mem_access.items():
                    mem_accesses.append({'tag': mmap.get_tag(),
                                         'base': hex(mmap.get_base()),
                                         'reads': maccess.reads,
                                         'writes': maccess.writes,
                                         'execs': maccess.execs})

                ep.update({'mem_access': mem_accesses})

                sym_accesses = []
                for address, maccess in r.sym_access.items():
                    sym_accesses.append({'symbol': maccess.sym,
                                         'reads': maccess.reads,
                                         'writes': maccess.writes,
                                         'execs': maccess.execs})
                if sym_accesses:
                    ep.update({'sym_accesses': sym_accesses})

            if r.dyn_code:
                ep.update({'dynamic_code_segments': r.dyn_code['mmap']})

            exec_paths.append(ep)

            if r.dropped_files:
                ep.update({'dropped_files': r.dropped_files})

        if (self.strings['ansi'] or self.strings['unicode'] or
           self.decoded_strings['ansi'] or self.decoded_strings['unicode']):
           meta.update({'strings': {'static':self.strings, 'in_memory': self.decoded_strings}})  # noqa
        profile = {**profile, **meta}
        profile.update({'entry_points': exec_paths})
        return profile
