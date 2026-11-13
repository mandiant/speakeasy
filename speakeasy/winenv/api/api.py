# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

import logging
import re
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, TypeVar

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.nt.ntoskrnl as ntos
from speakeasy import common
from speakeasy.errors import ApiEmuError
from speakeasy.profiler import Run
from speakeasy.profiler_events import ApiArg, ApiArgType, EventType
from speakeasy.report import RunType
from speakeasy.struct import EmuStruct
from speakeasy.winenv.api import sigdb, sigfmt
from speakeasy.winenv.codepage import decode_ansi, encode_ansi
from speakeasy.winenv.defs.enums import PAGE_PROTECTION_FLAGS, REG_CREATE_KEY_DISPOSITION, REG_SAM_FLAGS
from speakeasy.winenv.defs.lookup import decode_flags

if TYPE_CHECKING:
    from speakeasy.windows.fileman import File
    from speakeasy.windows.regman import RegKey
    from speakeasy.windows.winemu import WindowsEmulator

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

FORMAT_SPEC = re.compile(
    r"%(?P<flags>[-+ #0]*)(?P<width>\*|\d+)?(?:\.(?P<precision>\*|\d*))?"
    r"(?P<length>hh|h|ll|l|L|I64|I32|I|q|z|j|t|w)?(?P<conv>[diouxXeEfFgGaAcCsSpPnZ%])"
)
MAX_FORMAT_FIELD = 0x10000
INT_BITS = {"hh": 8, "h": 16, "ll": 64, "I64": 64, "q": 64, "j": 64}


def get_format_slot_sizes(spec: re.Match, ptr_size: int) -> list[int]:
    """
    Get the size in bytes of each argument that one printf conversion reads.

    The order is the width, the precision, then the value.
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
    One argument of an API call, as the report shows it.

    A handler sets ``display`` to show a value that it decoded, such as the path of a handle.
    """

    def __init__(self, arg: ApiArg, param: sigdb.ParamSig | None = None) -> None:
        self._arg: ApiArg = arg
        self._param: sigdb.ParamSig | None = param

    @property
    def name(self) -> str | None:
        return self._arg.name

    @property
    def value(self) -> int | None:
        return self._arg.value

    @property
    def type(self) -> ApiArgType:
        return self._arg.type

    @property
    def display(self) -> str:
        return self._arg.display

    @display.setter
    def display(self, text: object) -> None:
        """
        Show ``text`` for this argument.

        The type changes to ``str`` for a parameter that the signature declares as a
        string, else to ``text``. A parameter that the signature shows as an enum or
        flags keeps that display, so that all these values have one format. If ``text``
        is not a string, for example ``None`` from a failed lookup or a NULL pointer
        that the handler did not decode, the display does not change.
        """
        if not isinstance(text, str) or (
            self._param is not None and self._arg.type in (ApiArgType.ENUM, ApiArgType.FLAGS)
        ):
            return
        self._arg.display = text
        self._arg.type = (
            ApiArgType.STR if self._param is not None and self._param.kind in sigdb.STRING_KINDS else ApiArgType.TEXT
        )


def _detached_arg() -> HandlerArg:
    return HandlerArg(ApiArg(type=ApiArgType.INT, display=""))


class HandlerArgs:
    """
    The arguments of an API call.

    If the emulator can use the signature of the API, there is one entry for each
    parameter, and a handler gets an entry by parameter name or index. Else there is
    one entry for each argument slot, and a handler gets an entry by slot index. A
    name or index without an entry gives a detached argument. The report does not
    record changes to a detached argument, so a missing signature does not stop emulation.
    """

    def __init__(self, args: list[ApiArg], params: list[sigdb.ParamSig] | None = None, discard: bool = False) -> None:
        self._args: list[ApiArg] = args
        self._params: list[sigdb.ParamSig] | None = params
        self._discard: bool = discard

    @classmethod
    def from_signature(
        cls, sig: sigdb.FuncSig, ptr_size: int, rendered: list[sigfmt.RenderedArg], slots: list[int]
    ) -> HandlerArgs:
        """
        Make the arguments from the rendered values of the signature parameters.

        Raises:
            ValueError: if the slots do not match the slots that the signature uses.
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

    def append(self, display: str, type: ApiArgType = ApiArgType.TEXT) -> HandlerArg:
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
    """Base class of the API handlers of one emulated DLL."""

    name = ""

    @staticmethod
    def apihook(
        impname: str | None = None, argc: int = 0, conv: int = _arch.CALL_CONV_STDCALL, ordinal: int | None = None
    ) -> Callable[[F], F]:
        def apitemp(f: F) -> F:
            if not callable(f):
                raise ApiEmuError(f"Invalid function type supplied: {str(f)}")
            if hasattr(f, "__apihook__"):
                raise ApiEmuError(f"{f.__name__} has more than one apihook decorator")
            f.__apihook__ = (impname or f.__name__, f, argc, conv, ordinal)  # type: ignore[attr-defined]
            return f

        return apitemp

    @staticmethod
    def impdata(impname: str) -> Callable[[F], F]:
        def datatmp(f: F) -> F:
            if not callable(f):
                raise ApiEmuError(f"Invalid function type supplied: {str(f)}")
            f.__datahook__ = (impname, f)  # type: ignore[attr-defined]
            return f

        return datatmp

    def __init__(self, emu):
        super().__init__()
        self.funcs: dict[str | int, tuple[str, Callable[..., Any], int, int, int | None]] = {}
        self.data: dict[str, Callable[..., Any]] = {}
        self.emu: WindowsEmulator = emu
        arch = self.emu.get_arch()

        if arch == _arch.ARCH_X86:
            self.ptr_size: int = 4
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

    def get_ptr_size(self) -> int:
        return self.ptr_size

    def sizeof(self, obj):
        if isinstance(obj, EmuStruct):
            return obj.sizeof()
        raise ApiEmuError("Invalid object")

    def get_bytes(self, obj):
        if isinstance(obj, EmuStruct):
            return obj.get_bytes()
        raise ApiEmuError("Invalid object")

    def cast(self, obj, bytez):
        if isinstance(obj, EmuStruct):
            return obj.cast(bytez)
        raise ApiEmuError("Invalid object")

    def write_back(self, addr, obj):
        bytez = self.get_bytes(obj)
        self.emu.mem_write(addr, bytez)

    def pool_alloc(self, pool_type, size, tag):
        return self.emu.pool_alloc(pool_type, size, tag)

    def create_heap(self, emu):
        """Map the header of a new heap and return its address, which is the heap handle."""
        return self.mem_alloc(20, tag="emu.process_heap")

    def heap_alloc(self, size, heap):
        return self.emu.heap_alloc(size, heap)

    def heap_size(self, addr):
        """Get the requested size of a block that ``heap_alloc`` returned, or None for any other address."""
        mm = self.emu.get_address_map(addr)
        if not mm or mm.free or mm.base != addr or not (mm.tag or "").startswith("api.heap"):
            return None
        return next((n for a, n, _ in reversed(self.emu.get_heap_allocs()) if a == addr), mm.size)

    def heap_free(self, addr):
        """Free a block that ``heap_alloc`` returned. Return False, and free nothing, for any other address."""
        if self.heap_size(addr) is None:
            return False
        self.emu.mem_free(addr)
        return True

    def mem_alloc(self, size, base=None, tag=None, flags=0, perms=common.PERM_MEM_RWX, shared=False, process=None):
        return self.emu.mem_map(size, base=base, tag=tag, flags=flags, perms=perms, shared=shared, process=process)

    def mem_free(self, addr):
        return self.emu.mem_free(addr)

    def win_perms_to_emu_perms(self, win_perms):
        """Get the emulator permissions for a Windows page protection."""
        new = 0
        if win_perms & (PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE | PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_WRITECOPY):
            new = common.PERM_MEM_RWX
        elif win_perms & PAGE_PROTECTION_FLAGS.PAGE_NOACCESS:
            new = common.PERM_MEM_NONE
        else:
            if win_perms & PAGE_PROTECTION_FLAGS.PAGE_EXECUTE or win_perms & PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READ:
                new |= common.PERM_MEM_EXEC
            if (
                win_perms & PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READ
                or win_perms & PAGE_PROTECTION_FLAGS.PAGE_READONLY
                or win_perms & PAGE_PROTECTION_FLAGS.PAGE_READWRITE
                or win_perms & PAGE_PROTECTION_FLAGS.PAGE_WRITECOPY
            ):
                new |= common.PERM_MEM_READ
            if win_perms & (PAGE_PROTECTION_FLAGS.PAGE_READWRITE | PAGE_PROTECTION_FLAGS.PAGE_WRITECOPY):
                new |= common.PERM_MEM_WRITE
        return new

    def emu_perms_to_win_perms(self, emu_perms):
        """Get the Windows page protection for emulator permissions."""
        if emu_perms & common.PERM_MEM_WRITE:
            if emu_perms & common.PERM_MEM_EXEC:
                new = PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE
            else:
                new = PAGE_PROTECTION_FLAGS.PAGE_READWRITE
        elif emu_perms & common.PERM_MEM_EXEC:
            if emu_perms & common.PERM_MEM_READ:
                new = PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READ
            else:
                new = PAGE_PROTECTION_FLAGS.PAGE_EXECUTE
        elif emu_perms & common.PERM_MEM_READ:
            new = PAGE_PROTECTION_FLAGS.PAGE_READONLY
        else:
            new = PAGE_PROTECTION_FLAGS.PAGE_NOACCESS
        return new

    def mem_reserve(self, size, base=None, tag=None):
        return self.emu.mem_reserve(size, base=base, tag=tag)

    def mem_cast(self, obj, addr):
        struct_bytes = self.emu.mem_read(addr, self.sizeof(obj))
        return self.cast(obj, struct_bytes)

    def mem_copy(self, dst, src, n):
        return self.emu.mem_copy(dst, src, n)

    def read_mem_string(self, addr, width, max_chars=0) -> str:
        string = self.emu.read_mem_string(addr, width=width, max_chars=max_chars)
        return string

    def normalize_res_identifier(self, emu, cw, val):
        if val >> 16:  # not an INTRESOURCE
            name = emu.read_mem_string(val, cw)
            if name.startswith("#"):
                try:
                    name = int(name[1:])
                except ValueError:
                    pass
        else:
            name = val

        return name

    def read_res_identifier(self, emu, ctx, arg, cw, val):
        """Read a resource name or integer ID (MAKEINTRESOURCE) and show it as the display of ``arg``."""
        name = self.normalize_res_identifier(emu, cw, val)
        ctx.args[arg].display = name if isinstance(name, str) else hex(name)
        return name

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

    def queue_run(self, run_type, ep, run_args=None, name=None):
        if run_args is None:
            run_args = []
        run = Run()
        if not isinstance(run_type, RunType):
            raise ApiEmuError("Invalid run type")
        if not isinstance(ep, int):
            raise ApiEmuError("Invalid run entry point")
        if not any((isinstance(run_args, list), isinstance(run_args, tuple))):
            raise ApiEmuError("Invalid run args")

        run.type = run_type
        run.name = name
        run.start_addr = ep
        run.args = run_args
        self.emu.add_run(run)

    def record_process_event(self, proc, event_type: EventType, **kwargs):
        logger.debug("%s: pid=%d", event_type.value, proc.id)
        profiler = self.emu.get_profiler()
        if profiler:
            run = self.emu.get_current_run()
            pos = self.emu.get_trace_position()
            profiler.record_process_event(run, pos, proc, event_type, kwargs)

    def get_max_int(self):
        return int.from_bytes(b"\xff" * self.get_ptr_size(), "little")

    def mem_read(self, addr, size):
        return self.emu.mem_read(addr, size)

    def file_open(self, path, create=False, truncate=False, disposition=None, access=None):
        return self.emu.file_open(path, create=create, truncate=truncate, disposition=disposition, access=access)

    def file_create_mapping(self, hfile, name, size, prot):
        return self.emu.file_create_mapping(hfile, name, size, prot)

    def file_get(self, handle):
        return self.emu.file_get(handle)

    def get_file(self, handle) -> File | None:
        """Get the file of an open handle, or None if the handle is not open or does not refer to a file."""
        return self.emu.fileman.get_file(handle)

    def does_file_exist(self, path):
        return self.emu.does_file_exist(path)

    def reg_open_key(self, path, create=False, disposition=None, access=None):
        """
        Open or optionally create a registry key, and return a new handle or None.

        ``disposition`` is a REG_CREATE_KEY_DISPOSITION value and ``access`` a REGSAM or ACCESS_MASK value
        of the call. The event gets their names.
        """
        disposition_names = decode_flags(REG_CREATE_KEY_DISPOSITION, disposition) if disposition else None
        access_names = decode_flags(REG_SAM_FLAGS, access) if access else None
        return self.emu.reg_open_key(path, create=create, disposition=disposition_names, access=access_names)

    def get_reg_key(self, handle) -> RegKey | None:
        """Get the key of a predefined key or an open key handle, or None if the handle refers to no key."""
        return self.emu.regman.get_key(handle)

    def reg_get_subkeys(self, hkey):
        return self.emu.reg_get_subkeys(hkey)

    def encode_string(self, string: str, width: int) -> bytes:
        """
        Encode ``string`` as guest characters of ``width`` bytes: ANSI for 1, UTF-16LE for 2.

        Raises:
            ApiEmuError: if ``width`` is not 1 or 2.
        """
        if width == 1:
            return encode_ansi(string)
        if width == 2:
            return string.encode("utf-16le")
        raise ApiEmuError(f"No encoding found for char width: {width}")

    def decode_string(self, data: bytes, width: int) -> str:
        """
        Decode guest characters of ``width`` bytes: ANSI for 1, UTF-16LE for 2.

        Raises:
            ApiEmuError: if ``width`` is not 1 or 2.
        """
        if width == 1:
            return decode_ansi(data)
        if width == 2:
            return data.decode("utf-16le", "replace")
        raise ApiEmuError(f"No encoding found for char width: {width}")

    def mem_write(self, addr, data):
        # A write to a view of a shared file mapping also goes to each other shared view that shows the same
        # bytes of the section. Only the part of the write that a view covers goes to it.
        mm = self.emu.get_address_map(addr)
        if mm and mm.shared:
            fm = self.emu.get_file_manager()
            fmap = fm.get_mapping_from_addr(mm.base)
            if fmap:
                src = fmap.views[mm.base]
                start = src.offset + (addr - src.base)
                end = start + len(data)
                for view in fmap.views.values():
                    if view is src:
                        continue
                    tgt = self.emu.get_address_map(view.base)
                    if not tgt or not tgt.shared:
                        continue
                    lo = max(start, view.offset)
                    hi = min(end, view.offset + view.size)
                    if lo < hi:
                        self.emu.mem_write(view.base + (lo - view.offset), data[lo - start : hi - start])

        return self.emu.mem_write(addr, data)

    def read_dword(self, addr: int) -> int:
        return int.from_bytes(self.mem_read(addr, 4), "little")

    def read_ptr(self, addr: int) -> int:
        return int.from_bytes(self.mem_read(addr, self.ptr_size), "little")

    def write_dword(self, addr: int, value: int) -> None:
        """Write the low 32 bits of ``value``. A negative value becomes its two's complement."""
        self.mem_write(addr, (value & 0xFFFFFFFF).to_bytes(4, "little"))

    def write_qword(self, addr: int, value: int) -> None:
        self.mem_write(addr, value.to_bytes(8, "little"))

    def write_ptr(self, addr: int, value: int) -> None:
        self.mem_write(addr, value.to_bytes(self.ptr_size, "little"))

    def create_thread(self, addr, ctx, hproc, name=None, is_suspended=False):
        return self.emu.create_thread(addr, ctx, hproc, name=name, is_suspended=is_suspended)

    def get_object_from_id(self, id):
        return self.emu.get_object_from_id(id)

    def get_object_from_addr(self, addr):
        return self.emu.get_object_from_addr(addr)

    def get_object_handle(self, obj):
        return self.emu.get_object_handle(obj)

    def get_object_from_name(self, name):
        return self.emu.get_object_from_name(name)

    def exit_process(self):
        self.emu.exit_process()

    def get_char_width(self, ctx):
        """
        Get the character width of the API from its name: 2 for a W suffix, else 1.

        An export without the A or W suffix, such as lstrcpy, is ANSI.
        """
        if ctx.func_name.endswith("W"):
            return 2
        return 1

    def get_va_arg_count(self, fmt):
        """Get the number of pointer-sized argument slots that a printf format reads."""
        ptr_size = self.get_ptr_size()
        sizes = (size for spec in FORMAT_SPEC.finditer(fmt) for size in get_format_slot_sizes(spec, ptr_size))
        return sum(size // ptr_size for size in sizes)

    def va_args(self, va_list, num_args):
        """Read ``num_args`` pointer-sized values from ``va_list``."""
        args = []
        ptr = va_list
        ptrsize = self.get_ptr_size()

        for _ in range(num_args):
            arg = self.read_ptr(ptr)
            args.append(arg)
            ptr += ptrsize
        return args

    def setup_callback(self, func, args):
        """
        Call the guest function ``func`` with ``args`` from the current API handler.

        If the API frame already has a guest call, add the call to the pending calls of
        the frame. The API returns to its caller after the last call.

        Raises:
            ApiEmuError: if no API call is active.
        """
        run = self.emu.get_current_run()

        frame = self.emu.active_api_frame
        if frame is None:
            raise ApiEmuError("No API call is active")
        if any(item is frame for item in run.guest_callbacks):
            frame.pending.append((func, tuple(args)))
            return
        self.emu.start_guest_callback(frame, func, args)
        run.guest_callbacks.append(frame)

    def do_str_format(self, string, argv, wide=False):
        """
        Format a string as msvcrt printf does.

        With ``wide``, %s and %S follow the wide-character functions: %s is a wide
        string and %S is an ANSI string, unless an h or l prefix gives the width.
        Missing arguments read as 0.
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
                # The CRT prints every hex digit of a pointer in uppercase and ignores the 0 flag
                fmt = f"%{flags.replace('0', '')}{width}.{2 * ptr_size}X"
                out.append(fmt % (value & ((1 << (8 * ptr_size)) - 1)))
            elif conv in "cCsSZ":
                is_wide = length in ("l", "w") or (length != "h" and (conv in "CS") != wide)
                if conv in "cC":
                    char = chr(value & 0xFFFF) if is_wide else decode_ansi(bytes([value & 0xFF]))
                    out.append((fmt + "c") % char)
                elif not value:
                    out.append((fmt + "s") % "(null)")
                elif conv == "Z":
                    count = int.from_bytes(self.mem_read(value, 2), "little")
                    buf = self.read_ptr(value + ptr_size)
                    text = self.decode_string(self.mem_read(buf, count), 2 if is_wide else 1)
                    out.append((fmt + "s") % text)
                else:
                    text = self.read_wide_string(value) if is_wide else self.read_string(value)
                    out.append((fmt + "s") % text)
        out.append(string[pos:])
        return "".join(out)
