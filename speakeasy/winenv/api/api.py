# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass, field

import speakeasy.common as common
import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.nt.ntoskrnl as ntos
from speakeasy.errors import ApiEmuError
from speakeasy.profiler import Run
from speakeasy.profiler_events import ApiArg, TracePosition
from speakeasy.struct import EmuStruct
from speakeasy.winenv.api import sigdb, sigfmt

logger = logging.getLogger(__name__)

FORMAT_SPEC = re.compile(
    r"%(?P<flags>[-+ #0]*)(?P<width>\*|\d+)?(?:\.(?P<precision>\*|\d*))?"
    r"(?P<length>hh|h|ll|l|L|I64|I32|I|q|z|j|t|w)?(?P<conv>[diouxXeEfFgGaAcCsSpPnZ%])"
)
MAX_FORMAT_FIELD = 0x10000
INT_BITS = {"hh": 8, "h": 16, "ll": 64, "I64": 64, "q": 64, "j": 64}


def get_format_slot_sizes(spec: re.Match, ptr_size: int) -> list[int]:
    """
    Get the size in bytes of each argument that one printf conversion reads,
    in order: the width, the precision and then the value.
    """
    sizes = [ptr_size] * [spec["width"], spec["precision"]].count("*")
    conv, length = spec["conv"], spec["length"]
    if conv in "diouxX":
        bits = INT_BITS.get(length, ptr_size * 8 if length in ("I", "z", "t") else 32)
        sizes.append(max(ptr_size, bits // 8))
    elif conv in "eEfFgGaA":
        sizes.append(8)
    elif conv != "%":
        sizes.append(ptr_size)
    return sizes


class HandlerArg:
    """
    One argument of a handled call, as recorded in the report. A handler sets
    ``display`` to show a value it decoded, such as the path behind a handle.
    """

    def __init__(self, arg: ApiArg, param: sigdb.ParamSig | None = None) -> None:
        self._arg = arg
        self._param = param

    @property
    def name(self) -> str | None:
        return self._arg.name

    @property
    def value(self) -> int | None:
        return self._arg.value

    @property
    def type(self) -> str:
        return self._arg.type

    @property
    def display(self) -> str:
        return self._arg.display

    @display.setter
    def display(self, text: object) -> None:
        """
        Show ``text`` for this argument. The type becomes ``str`` on a
        parameter declared as a string, and ``text`` otherwise. A parameter
        that the signature renders as an enum or flags keeps that rendering,
        so all such values have one format. A value that is not a string,
        such as ``None`` from a failed lookup or a NULL pointer the handler
        did not decode, keeps the current display.
        """
        if not isinstance(text, str) or (self._param is not None and self._arg.type in ("enum", "flags")):
            return
        self._arg.display = text
        self._arg.type = "str" if self._param is not None and self._param.kind in sigdb.STRING_KINDS else "text"


def _detached_arg() -> HandlerArg:
    return HandlerArg(ApiArg(type="int", display=""))


class HandlerArgs:
    """
    The arguments of a handled call. With a usable signature there is one
    entry per parameter, found by parameter name or index. Without one there
    is one entry per argument slot, found by slot index. A name or index that
    does not match an entry gives a detached argument whose changes are not
    recorded, so a missing signature never stops emulation.
    """

    def __init__(self, args: list[ApiArg], params: list[sigdb.ParamSig] | None = None, discard: bool = False) -> None:
        self._args = args
        self._params = params
        self._discard = discard

    @classmethod
    def from_signature(
        cls, sig: sigdb.FuncSig, ptr_size: int, rendered: list[sigfmt.RenderedArg], slots: list[int]
    ) -> HandlerArgs:
        """
        Raises:
            ValueError: the slots do not match the slots the signature consumes.
        """
        return cls(sigfmt.get_call_args(sig, ptr_size, rendered, slots), list(sig.params))

    @classmethod
    def from_slots(cls, slots: list[int]) -> HandlerArgs:
        return cls(sigfmt.get_slot_args(slots))

    def __len__(self) -> int:
        return len(self._args)

    def __getitem__(self, key: int | str) -> HandlerArg:
        if isinstance(key, str):
            for index, param in enumerate(self._params or []):
                if param.name == key:
                    return HandlerArg(self._args[index], param)
            logger.debug("no argument named %s", key)
            return _detached_arg()
        if not 0 <= key < len(self._args):
            logger.debug("no argument at index %d", key)
            return _detached_arg()
        params = self._params or []
        return HandlerArg(self._args[key], params[key] if key < len(params) else None)

    def append(self, display: str, type: str = "text") -> HandlerArg:
        """Add an argument without a raw value, such as the output of a printf call."""
        arg = ApiArg(type=type, display=display)
        if not self._discard:
            self._args.append(arg)
        return HandlerArg(arg)

    def clear(self) -> None:
        self._args.clear()
        self._params = None

    def get_report_args(self) -> list[ApiArg]:
        return list(self._args)


@dataclass
class ApiContext:
    """Call context that the emulator passes to an API handler."""

    func_name: str = ""
    args: HandlerArgs = field(default_factory=lambda: HandlerArgs([]))


NO_CONTEXT = ApiContext(args=HandlerArgs([], discard=True))


class ApiHandler:
    """
    Base class for handling exported functions
    """

    name = ""

    @staticmethod
    def apihook(impname=None, argc=0, conv=_arch.CALL_CONV_STDCALL, ordinal=None):
        def apitemp(f):
            if not callable(f):
                raise ApiEmuError(f"Invalid function type supplied: {str(f)}")
            if hasattr(f, "__apihook__"):
                raise ApiEmuError(f"{f.__name__} has more than one apihook decorator")
            f.__apihook__ = (impname or f.__name__, f, argc, conv, ordinal)
            return f

        return apitemp

    @staticmethod
    def impdata(impname):
        def datatmp(f):
            if not callable(f):
                raise ApiEmuError(f"Invalid function type supplied: {str(f)}")
            f.__datahook__ = (impname, f)
            return f

        return datatmp

    def __init__(self, emu):
        super().__init__()
        self.funcs = {}
        self.data = {}
        self.emu = emu
        arch = self.emu.get_arch()

        if arch == _arch.ARCH_X86:
            self.ptr_size = 4
        elif arch == _arch.ARCH_AMD64:
            self.ptr_size = 8
        else:
            raise ApiEmuError("Invalid architecture")

        for name in dir(self):
            val = getattr(self, name, None)
            if val is None:
                continue

            func_attrs = getattr(val, "__apihook__", None)
            data_attrs = getattr(val, "__datahook__", None)
            if func_attrs:
                name, func, argc, conv, ordinal = func_attrs
                self.funcs[name] = (name, func, argc, conv, ordinal)
                if ordinal:
                    self.funcs[ordinal] = (name, func, argc, conv, ordinal)

            elif data_attrs:
                name, func = data_attrs
                self.data[name] = func

    def __get_hook_attrs__(self, obj):
        for name in dir(obj):
            val = getattr(obj, name, None)
            if val is None:
                continue

            func_attrs = getattr(val, "__apihook__", None)
            data_attrs = getattr(val, "__datahook__", None)
            if func_attrs:
                name, func, argc, conv, ordinal = func_attrs
                obj.funcs[name] = (name, func, argc, conv, ordinal)
                if ordinal:
                    obj.funcs[ordinal] = (name, func, argc, conv, ordinal)

            elif data_attrs:
                name, func = data_attrs
                obj.data[name] = func

    def get_data_handler(self, exp_name):
        return self.data.get(exp_name)

    def get_func_handler(self, exp_name):
        if exp_name.startswith("ordinal_"):
            ord_num = exp_name.split("_")
            if len(ord_num) == 2 and ord_num[1].isdigit():
                ord_num = int(ord_num[1])
                handler = self.funcs.get(ord_num)
                if handler:
                    return handler
        return self.funcs.get(exp_name)

    def get_ptr_size(self):
        return self.ptr_size

    def sizeof(self, obj):
        if isinstance(obj, EmuStruct):
            return obj.sizeof()
        else:
            raise ApiEmuError("Invalid object")

    def get_bytes(self, obj):
        if isinstance(obj, EmuStruct):
            return obj.get_bytes()
        else:
            raise ApiEmuError("Invalid object")

    def cast(self, obj, bytez):
        if isinstance(obj, EmuStruct):
            return obj.cast(bytez)
        else:
            raise ApiEmuError("Invalid object")

    def write_back(self, addr, obj):
        bytez = self.get_bytes(obj)
        self.emu.mem_write(addr, bytez)

    def pool_alloc(self, pool_type, size, tag):
        return self.emu.pool_alloc(pool_type, size, tag)

    def heap_alloc(self, size, heap):
        return self.emu.heap_alloc(size, heap)

    def mem_alloc(self, size, base=None, tag=None, flags=0, perms=common.PERM_MEM_RWX, shared=False, process=None):
        return self.emu.mem_map(size, base=base, tag=tag, flags=flags, perms=perms, shared=shared, process=process)

    def mem_free(self, addr):
        return self.emu.mem_free(addr)

    def mem_reserve(self, size, base=None, tag=None):
        return self.emu.mem_reserve(size, base=base, tag=tag)

    def mem_cast(self, obj, addr):
        struct_bytes = self.emu.mem_read(addr, self.sizeof(obj))
        return self.cast(obj, struct_bytes)

    def mem_copy(self, dst, src, n):
        return self.emu.mem_copy(dst, src, n)

    def read_mem_string(self, addr, width, max_chars=0):
        string = self.emu.read_mem_string(addr, width=width, max_chars=max_chars)
        return string

    def mem_string_len(self, addr, width):
        return self.emu.mem_string_len(addr, width)

    def read_ansi_string(self, addr):
        ans = ntos.STRING(self.emu.get_ptr_size())
        ans = self.mem_cast(ans, addr)

        string = self.emu.read_mem_string(ans.Buffer, width=1, max_chars=ans.Length)
        return string

    def read_unicode_string(self, addr):
        us = ntos.UNICODE_STRING(self.emu.get_ptr_size())
        us = self.mem_cast(us, addr)

        string = self.emu.read_mem_string(us.Buffer, width=2, max_chars=us.Length // 2)
        return string

    def read_wide_string(self, addr, max_chars=0):
        string = self.emu.read_mem_string(addr, width=2, max_chars=max_chars)
        return string

    def read_string(self, addr, max_chars=0):
        string = self.emu.read_mem_string(addr, width=1, max_chars=max_chars)
        return string

    def write_mem_string(self, string, addr, width):
        return self.emu.write_mem_string(string, addr, width)

    def write_wide_string(self, string, addr):
        return self.write_mem_string(string, addr, width=2)

    def write_string(self, string, addr):
        return self.write_mem_string(string, addr, width=1)

    def queue_run(self, run_type, ep, run_args=[]):
        run = Run()
        if not isinstance(run_type, str):
            raise ApiEmuError("Invalid run type")
        if not isinstance(ep, int):
            raise ApiEmuError("Invalid run entry point")
        if not any((isinstance(run_args, list), isinstance(run_args, tuple))):
            raise ApiEmuError("Invalid run args")

        run.type = run_type
        run.start_addr = ep
        run.args = run_args
        self.emu.add_run(run)

    def _get_current_trace_position(self) -> TracePosition:
        run = self.emu.get_current_run()
        thread = self.emu.get_current_thread()
        proc = self.emu.get_current_process()
        tick = run.instr_cnt if run else 0
        tid = thread.tid if thread else 0
        pid = proc.id if proc else 0
        pc = None
        try:
            pc = self.emu.get_pc()
        except Exception:
            pc = None
        return TracePosition(tick=tick, tid=tid, pid=pid, pc=pc)

    def record_file_access_event(
        self, path, event_type, data=None, handle=0, disposition=[], access=[], buffer=0, size=None
    ):
        logger.debug("file_%s: %s", event_type, path)
        profiler = self.emu.get_profiler()
        if profiler:
            run = self.emu.get_current_run()
            pos = self._get_current_trace_position()
            profiler.record_file_access_event(
                run, pos, path, event_type, data, handle, disposition, access, buffer, size
            )

    def record_process_event(self, proc, event_type, **kwargs):
        logger.debug("process_%s: pid=%d", event_type, proc.id)
        profiler = self.emu.get_profiler()
        if profiler:
            run = self.emu.get_current_run()
            pos = self._get_current_trace_position()
            profiler.record_process_event(run, pos, proc, event_type, kwargs)

    def record_registry_access_event(
        self, path, event_type, value_name=None, data=None, handle=0, disposition=[], access=[], buffer=0, size=None
    ):
        logger.debug("reg_%s: %s", event_type, path)
        profiler = self.emu.get_profiler()
        if profiler:
            run = self.emu.get_current_run()
            pos = self._get_current_trace_position()
            profiler.record_registry_access_event(
                run, pos, path, event_type, value_name, data, handle, disposition, access, buffer, size
            )

    def record_dns_event(self, domain, ip=""):
        logger.debug("dns: %s -> %s", domain, ip)
        profiler = self.emu.get_profiler()
        if profiler:
            run = self.emu.get_current_run()
            pos = self._get_current_trace_position()
            profiler.record_dns_event(run, pos, domain, ip)

    def record_network_event(self, server, port, typ="unknown", proto="unknown", data=b"", method=""):
        logger.debug("net: %s:%d %s", server, port, proto)
        profiler = self.emu.get_profiler()
        if profiler:
            run = self.emu.get_current_run()
            pos = self._get_current_trace_position()
            profiler.record_network_event(run, pos, server, port, typ=typ, proto=proto, data=data, method=method)

    def record_http_event(self, server, port, headers="", body=b"", secure=False):
        logger.debug("http: %s:%d", server, port)
        profiler = self.emu.get_profiler()
        if profiler:
            run = self.emu.get_current_run()
            pos = self._get_current_trace_position()
            profiler.record_http_event(run, pos, server, port, headers=headers, body=body, secure=secure)

    def get_max_int(self):
        # Byte order is irrelevant here
        return int.from_bytes(b"\xff" * self.get_ptr_size(), "little")

    def mem_read(self, addr, size):
        return self.emu.mem_read(addr, size)

    def file_open(self, path, create=False, truncate=False):
        return self.emu.file_open(path, create, truncate=truncate)

    def file_create_mapping(self, hfile, name, size, prot):
        return self.emu.file_create_mapping(hfile, name, size, prot)

    def file_get(self, handle):
        return self.emu.file_get(handle)

    def does_file_exist(self, path):
        return self.emu.does_file_exist(path)

    def reg_open_key(self, path, create=False):
        return self.emu.reg_open_key(path, create)

    def reg_get_key(self, handle):
        return self.emu.reg_get_key(handle)

    def reg_get_subkeys(self, hkey):
        return self.emu.reg_get_subkeys(hkey)

    def get_encoding(self, char_width):
        if char_width == 2:
            enc = "utf-16le"
        elif char_width == 1:
            enc = "utf-8"
        else:
            raise ApiEmuError(f"No encoding found for char width: {char_width}")
        return enc

    def mem_write(self, addr, data):
        # If the data being written to a shared memory mapping, update all mappings
        # This will likely have to be made more robust to handle more complicated
        # scenarios with varying file offsets
        mm = self.emu.get_address_map(addr)
        if mm and mm.shared:
            fm = self.emu.get_file_manager()
            fmap = fm.get_mapping_from_addr(mm.base)
            if fmap:
                for base, view in fmap.views.items():
                    if base == mm.base:
                        continue
                    tgt_offset = addr - mm.base
                    self.emu.mem_write(base + tgt_offset, data)

        return self.emu.mem_write(addr, data)

    def create_thread(self, addr, ctx, hproc, thread_type="thread", is_suspended=False):
        return self.emu.create_thread(addr, ctx, hproc, thread_type=thread_type, is_suspended=is_suspended)

    def get_object_from_id(self, id):
        return self.emu.get_object_from_id(id)

    def get_object_from_addr(self, addr):
        return self.emu.get_object_from_addr(addr)

    def get_object_handle(self, obj):
        return self.emu.get_object_handle(obj)

    def get_object_from_handle(self, hnd):
        return self.emu.get_object_from_handle(hnd)

    def get_object_from_name(self, name):
        return self.emu.get_object_from_name(name)

    def exit_process(self):
        self.emu.exit_process()

    def get_char_width(self, ctx):
        """
        Based on the API name, determine the character width
        being used by the function
        """
        name = ctx.func_name
        if name.endswith("A"):
            return 1
        elif name.endswith("W"):
            return 2
        raise ApiEmuError(f"Failed to get character width from function: {name}")

    def get_va_arg_count(self, fmt):
        """
        Get the number of pointer-sized argument slots that a printf format reads
        """
        ptr_size = self.get_ptr_size()
        sizes = (size for spec in FORMAT_SPEC.finditer(fmt) for size in get_format_slot_sizes(spec, ptr_size))
        return sum(size // ptr_size for size in sizes)

    def va_args(self, va_list, num_args):
        """
        Get the variable argument list
        """
        args = []
        ptr = va_list
        ptrsize = self.get_ptr_size()

        for n in range(num_args):
            arg = int.from_bytes(self.emu.mem_read(ptr, ptrsize), "little")
            args.append(arg)
            ptr += ptrsize
        return args

    def setup_callback(self, func, args):
        """
        For APIs that call functions, we will setup the stack to make this flow
        naturally.
        """

        run = self.emu.get_current_run()

        frame = self.emu._active_api_frame
        if any(item is frame for item in run.guest_callbacks):
            frame.pending.append((func, tuple(args)))
            return
        self.emu.start_guest_callback(frame, func, args)
        run.guest_callbacks.append(frame)

    def do_str_format(self, string, argv, wide=False):
        """
        Format a string similar to msvcrt.printf. With ``wide``, %s and %S
        follow the wide-character functions: %s is a wide string and %S is
        an ANSI string, unless an h or l prefix gives the width. Missing
        arguments read as 0.
        """
        ptr_size = self.get_ptr_size()
        slots = list(argv)

        def next_value(size):
            value = 0
            for i in range(size // ptr_size):
                value |= (slots.pop(0) if slots else 0) << (i * ptr_size * 8)
            return value

        def to_signed(value, bits):
            value &= (1 << bits) - 1
            return value - (1 << bits) if value >> (bits - 1) else value

        out = []
        pos = 0
        for spec in FORMAT_SPEC.finditer(string):
            out.append(string[pos : spec.start()])
            pos = spec.end()
            conv, length = spec["conv"], spec["length"]
            if conv == "%":
                out.append("%")
                continue

            flags, width, precision = spec["flags"], spec["width"] or "", spec["precision"]
            sizes = get_format_slot_sizes(spec, ptr_size)
            if width == "*":
                value = to_signed(next_value(sizes.pop(0)), 32)
                flags += "-" if value < 0 else ""
                width = str(abs(value))
            if precision == "*":
                value = to_signed(next_value(sizes.pop(0)), 32)
                precision = str(value) if value >= 0 else None
            if width:
                width = str(min(int(width), MAX_FORMAT_FIELD))
            if precision:
                precision = str(min(int(precision), MAX_FORMAT_FIELD))
            fmt = f"%{flags}{width}" + (f".{precision}" if precision is not None else "")
            size = sizes.pop(0)
            value = next_value(size)
            bits = INT_BITS.get(length, size * 8 if length in ("I", "z", "t") else 32)

            if conv in "di":
                out.append((fmt + "d") % to_signed(value, bits))
            elif conv in "ouxX":
                out.append((fmt + conv.replace("u", "d")) % (value & ((1 << bits) - 1)))
            elif conv in "eEfFgG":
                out.append((fmt + conv) % struct.unpack("<d", struct.pack("<Q", value))[0])
            elif conv in "aA":
                text = struct.unpack("<d", struct.pack("<Q", value))[0].hex()
                out.append(text.upper() if conv == "A" else text)
            elif conv in "pP":
                out.append((fmt + ("x" if conv == "p" else "X")) % value)
            elif conv in "cCsSZ":
                is_wide = length in ("l", "w") or (length != "h" and (conv in "CS") != wide)
                if conv in "cC":
                    out.append((fmt + "c") % chr(value & (0xFFFF if is_wide else 0xFF)))
                elif not value:
                    out.append((fmt + "s") % "(null)")
                elif conv == "Z":
                    count = int.from_bytes(self.mem_read(value, 2), "little")
                    buf = int.from_bytes(self.mem_read(value + ptr_size, ptr_size), "little")
                    text = self.mem_read(buf, count).decode("utf-16le" if is_wide else "latin-1", "replace")
                    out.append((fmt + "s") % text)
                else:
                    text = self.read_wide_string(value) if is_wide else self.read_string(value)
                    out.append((fmt + "s") % text)
        out.append(string[pos:])
        return "".join(out)
