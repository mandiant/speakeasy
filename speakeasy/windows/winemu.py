# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import logging
import multiprocessing.synchronize
import ntpath
import os
import random
import struct
import threading
import time
import traceback
from abc import abstractmethod
from collections import deque
from collections.abc import Callable, Generator
from dataclasses import dataclass
from enum import Enum
from functools import wraps
from types import MethodType
from typing import TYPE_CHECKING, Any, ClassVar, Concatenate, ParamSpec, TypeVar

import capstone as cs
import pefile
import unicorn as uc

import speakeasy.windows.common as winemu
import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy import common
from speakeasy.binemu import BinaryEmulator
from speakeasy.config import parse_start_time
from speakeasy.errors import FileSystemEmuError, OutOfMemoryError, WindowsEmuError
from speakeasy.gdb import GdbServer, ResumeAction, StopReason
from speakeasy.profiler import GuestCallbackFrame, MemAccess, Run
from speakeasy.profiler_events import ApiArg, ApiArgType, EventType, NetTrafficProtocol, NetTrafficType, TracePosition
from speakeasy.report import AccessType, Arch, EntryPointType, ErrorInfo, ErrorType, FileType, RegionInfo
from speakeasy.struct import EmuStruct
from speakeasy.windows import (
    api_resolution,
    cpu_exceptions,
    guest_callbacks,
    hardware_breakpoints,
    mapped_imports,
    objman,
    seh,
    seh32,
    seh64,
    thread_context,
    unwind,
)
from speakeasy.windows.api_image import ApiModuleLoader
from speakeasy.windows.api_registry import ApiEntry, ApiRegistry, module_name, symbol_ref
from speakeasy.windows.cryptman import CryptoManager
from speakeasy.windows.driveman import DriveManager
from speakeasy.windows.fileman import File, FileManager
from speakeasy.windows.hammer import ApiHammer
from speakeasy.windows.handles import (
    CURRENT_PROCESS_HANDLE,
    CURRENT_THREAD_HANDLE,
    HANDLE_MASK,
    HandleTable,
)
from speakeasy.windows.ioman import IoManager
from speakeasy.windows.loaders import LoadState, PeLoader, RuntimeModule, get_prot_string, relocate_image
from speakeasy.windows.module_loader import ModuleLoader
from speakeasy.windows.netman import NetworkManager
from speakeasy.windows.objman import HandleAllocator
from speakeasy.windows.regman import WINDOWS_CURRENT_VERSION_KEY, RegistryManager, RegKey, get_program_files_values
from speakeasy.winenv.api import sigdb, sigfmt
from speakeasy.winenv.api.api import NO_CONTEXT, ApiContext, HandlerArgs
from speakeasy.winenv.api.winapi import WindowsApi
from speakeasy.winenv.defs.nt import ddk

if TYPE_CHECKING:
    from speakeasy.speakeasy import Speakeasy

# The maximum number of exports of a module that the emulator runs when it emulates all exports
MAX_EXPORTS_TO_EMULATE = 10

# The signal number that the GDB server reports for memory faults
GDB_SIGSEGV = 11

# The maximum size of the static TLS data that the emulator copies for each thread
TLS_TEMPLATE_MAX = 0x1000000

# The registers that a callee must preserve. The emulator restores them after the guest callbacks of an API.
NONVOLATILE_X86 = (_arch.X86_REG_EBX, _arch.X86_REG_EBP, _arch.X86_REG_ESI, _arch.X86_REG_EDI)
NONVOLATILE_AMD64 = (
    _arch.AMD64_REG_RBX,
    _arch.AMD64_REG_RBP,
    _arch.AMD64_REG_RSI,
    _arch.AMD64_REG_RDI,
    _arch.AMD64_REG_R12,
    _arch.AMD64_REG_R13,
    _arch.AMD64_REG_R14,
    _arch.AMD64_REG_R15,
)

REPORT_ARCHES = {_arch.ARCH_X86: Arch.X86, _arch.ARCH_AMD64: Arch.X64}

logger = logging.getLogger(__name__)


@dataclass
class _ExecutionBudget:
    limit: float
    elapsed: float = 0.0
    exhausted: bool = False


@dataclass(frozen=True)
class SuspendedApiCall:
    """
    The guest called an API. The run loop calls the handler of the API next.

    The stack pointer, the return address and the code of the API are the values when the guest fetched the token.
    If a debugger changes one of them, the emulator drops the exit, and the guest runs the code of the API again.
    """

    entry: ApiEntry
    stack_pointer: int
    return_address: bytes | None
    code: bytes | None


@dataclass(frozen=True)
class RunReturn:
    """The guest returned to the return hook or the exit hook. The run is complete."""


@dataclass(frozen=True)
class CallbackReturn:
    """A guest callback returned to ``GUEST_CALLBACK_RETURN_ADDR``. The API handler that called it continues."""


@dataclass(frozen=True)
class RunEnd:
    """
    A fault, an API handler, a hook or the user ended the run. See ``WindowsEmulator.end_run``.

    The run loop completes the run after Unicorn stops, also if Unicorn raises an error. If ``stop_emulation`` is
    set, the loop then ends the emulation and does not start the next run.
    """

    stop_emulation: bool = False


@dataclass(frozen=True)
class ExecRecovery:
    """
    The guest fetched code from a guest PE page without execute permission.

    The run loop sets the protection of the page to ``perms`` and runs the code again.
    """

    page: int
    perms: int


@dataclass(frozen=True)
class RaisedCpuException:
    """A CPU exception that the run loop sends to the exception handlers of the guest."""

    exception: cpu_exceptions.CpuException
    error_type: ErrorType  # the error of the run if no handler takes the exception
    interrupt_num: int | None = None
    access_type: str | None = None
    rax: int | None = None  # the run loop restores RAX before dispatch, because the IN instruction writes it
    # (page, perms) of a guard page. The run loop restores perms on the page before dispatch.
    guard_page: tuple[int, int] | None = None


# The reason why Unicorn stopped. A hook records the exit and stops Unicorn, or _get_exit_at_pc gets the exit from
# the PC after Unicorn stops. Then the run loop handles the exit. If two hooks record an exit, the emulator keeps the
# first.
NativeExit = SuspendedApiCall | RunReturn | CallbackReturn | RunEnd | ExecRecovery | RaisedCpuException


@dataclass
class _ApiCallState:
    """State of the guest when it calls an API, before the API runs."""

    dll: str
    name: str
    frame: GuestCallbackFrame
    run: Run | None
    pc: int
    sp: int
    return_address: int
    call_pc: int

    @property
    def api_name(self) -> str:
        return f"{self.dll}.{self.name}"


S = TypeVar("S", bound="WindowsEmulator | Speakeasy")
P = ParamSpec("P")
R = TypeVar("R")


def execution_scope(func: Callable[Concatenate[S, P], R]) -> Callable[Concatenate[S, P], R]:
    """
    Apply one ``max_total_time`` limit to all emulation in a call of the decorated method.

    A nested call of a decorated method uses the limit of the outer call.
    """

    @wraps(func)
    def wrapped(self: S, *args: P.args, **kwargs: P.kwargs) -> R:
        emu = self if isinstance(self, WindowsEmulator) else self.emu
        if emu is None or emu._execution_budget is not None:
            return func(self, *args, **kwargs)
        emu._execution_budget = _ExecutionBudget(emu.config.max_total_time)
        try:
            return func(self, *args, **kwargs)
        finally:
            emu._execution_budget = None

    return wrapped


def _module_type_from_path(path: str, default: str = "dll") -> str:
    ext = ntpath.splitext(path)[1].lower()
    if ext == ".exe":
        return "exe"
    if ext == ".sys":
        return "driver"
    if ext == ".dll":
        return "dll"
    return default


def get_page_protection_runs(page_perms: dict[int, int], page_size: int) -> list[tuple[int, int, int]]:
    """Merge the permissions of single pages into (base, size, perms) ranges of adjacent pages with equal perms."""
    runs: list[tuple[int, int, int]] = []
    for page_base in sorted(page_perms):
        perms = page_perms[page_base]
        if runs:
            run_base, run_size, run_perms = runs[-1]
            if run_perms == perms and run_base + run_size == page_base:
                runs[-1] = (run_base, run_size + page_size, perms)
                continue
        runs.append((page_base, page_size, perms))
    return runs


class LimitKind(str, Enum):
    """A limit that ends a run. The value is the type of the error of the run, and the kind of the debugger stop."""

    TIMEOUT = "timeout"
    MAX_TOTAL_TIME = "max_total_time"
    MAX_INSTRUCTIONS = "max_instructions"


@dataclass
class _SehRepeat:
    """
    The last fault that the guest SEH handlers took, and how many times in a row it occurred.

    A handler that does not fix a fault can make an infinite loop, so the emulator stops the dispatch after the same
    fault occurs ``MAX_REPEAT`` times in a row.
    """

    MAX_REPEAT: ClassVar[int] = 4

    # (pc, faulting address) of the last fault, or None.
    fault: tuple[int, int | None] | None = None
    count: int = 0
    # A guest handler continued at the pc of the fault. The deferred work hook clears the count when pc leaves it.
    resume_pc: int | None = None

    def reset(self) -> None:
        self.fault = None
        self.count = 0
        self.resume_pc = None

    def record(self, fault: tuple[int, int | None]) -> bool:
        """Count the fault. Return False if it occurred ``MAX_REPEAT`` times in a row."""
        self.resume_pc = None
        if fault == self.fault:
            self.count += 1
            return self.count < self.MAX_REPEAT
        self.fault = fault
        self.count = 1
        return True


@dataclass
class RunLimits:
    """The time and instruction limits of one call of the run loop, and the instruction count of the call."""

    # When the call started, from time.monotonic().
    started: float
    # The execution time of the run before the call started.
    spent: float
    # The time limit of the run in seconds, or 0 for no limit.
    timeout: float
    # When the call must stop, from time.monotonic(), or None for no time limit.
    deadline: float | None
    # MAX_TOTAL_TIME if the total execution time gives the deadline, otherwise TIMEOUT.
    deadline_kind: LimitKind
    # The total execution time of all runs, or None for no total limit.
    total_budget: _ExecutionBudget | None
    # The instruction limit of the run, or 0 or less for no limit.
    budget: int
    # The instructions that the run can still execute, or -1 for no limit.
    remaining: int
    # The address of the last instruction that the accounting hook counted, or None.
    last_executed: int | None = None

    @classmethod
    def from_run(cls, run: Run, timeout: float, budget: int, total_budget: _ExecutionBudget | None) -> "RunLimits":
        """Get the limits that apply to ``run`` from now. The deadline is the nearer of the two time limits."""
        started = time.monotonic()
        spent = run.execution_elapsed
        deadline = started + max(timeout - spent, 0) if timeout > 0 else None
        deadline_kind = LimitKind.TIMEOUT
        if total_budget is not None and total_budget.limit > 0:
            total_deadline = started + max(total_budget.limit - total_budget.elapsed, 0)
            if deadline is None or total_deadline < deadline:
                deadline = total_deadline
                deadline_kind = LimitKind.MAX_TOTAL_TIME
        remaining = max(budget - run.budget_instructions, 0) if budget > 0 else -1
        return cls(started, spent, timeout, deadline, deadline_kind, total_budget, budget, remaining)

    def get_reached_limit(self) -> LimitKind | None:
        """Get the kind of the limit that the run reached, or None if it reached no limit."""
        if self.deadline is not None and time.monotonic() >= self.deadline:
            return self.deadline_kind
        if self.budget > 0 and self.remaining <= 0:
            return LimitKind.MAX_INSTRUCTIONS
        return None

    def is_total_time_reached(self) -> bool:
        """Get whether the run reached the total execution time of all runs."""
        return (
            self.deadline_kind == LimitKind.MAX_TOTAL_TIME
            and self.deadline is not None
            and time.monotonic() >= self.deadline
        )

    def get_native_timeout(self) -> float:
        """Get the timeout for the next start of Unicorn: the time to the deadline, or 0 for no deadline."""
        return max(self.deadline - time.monotonic(), 0.000001) if self.deadline is not None else 0

    def get_native_count(self) -> int:
        """
        Get the instruction count for the next start of Unicorn, or 0 for no limit.

        The count stops Unicorn at the instruction limit, so that the tracing
        hooks do not see an instruction after the limit. The accounting hook
        counts the instructions of all starts of Unicorn in one call.
        """
        return self.remaining if self.budget > 0 else 0


class WindowsEmulator(BinaryEmulator):
    """
    Base class of the user mode and kernel mode emulators.

    It adds processes, threads, modules, runs, API calls and SEH to BinaryEmulator. Win32Emulator sets ``peb_addr``
    to the address of the PEB pointer in the TEB (``fs:[0x30]`` or ``gs:[0x60]``).
    """

    _X64_EXEC_ADDR_MASK = (1 << 52) - 1

    _execution_budget: _ExecutionBudget | None = None
    peb_addr: int
    api: WindowsApi

    @abstractmethod
    def alloc_peb(self, proc: Any) -> None:
        """Allocate memory for the Process Environment Block (PEB)."""
        ...

    @abstractmethod
    def init_processes(self, processes: list[Any]) -> None:
        """Create the processes of the config."""
        ...

    def __init__(self, config, *, exit_event=None, debug=False, gdb_port=None, gdb_host=None):
        super().__init__(config)

        self.debug: bool = debug
        self.gdb_port: int | None = gdb_port
        self.gdb_host: str | None = gdb_host
        self.arch: int = 0
        self.modules: list[Any] = []
        self.module_change_listeners: list[Callable[[], None]] = []
        self.is_machine_ready: bool = False
        self.curr_run: Run | None = None
        self.api_ctx: ApiContext = NO_CONTEXT
        self._should_stop_on_faults: bool = False
        self._pending_fault_stop: StopReason | None = None
        self.curr_mod: Any | None = None
        self.runs: list[Run] = []
        self.input: dict[str, Any] | None = None
        self.exit_event: threading.Event | multiprocessing.synchronize.Event | None = exit_event
        self.max_runs: int = 100
        self.symbols: dict[int, tuple[str, str]] = {}
        self.ansi_strings: list[str] = []
        self.unicode_strings: list[str] = []
        self.run_queue: list[Run] = []
        self.suspended_runs: list[Run] = []
        self.is_reserved_range_unmapped: bool = True
        self.curr_process: Any | None = None
        self.om: objman.ObjectManager | None = None
        self._sigdb: sigdb.SignatureDatabase | None = None
        self._sigfmt: sigfmt.ArgFormatter | None = None
        self.api_registry: ApiRegistry = ApiRegistry(self)
        self._native_exit: NativeExit | None = None
        self._api_call_site: tuple[int, int] | None = None
        # Maps each guard page to the protection that its first access restores. Guard pages have no access.
        self.guard_pages: dict[int, int] = {}
        self.hardware_breakpoints = hardware_breakpoints.HardwareBreakpoints(self)
        self.module_loader: ModuleLoader = ModuleLoader(self)
        self._active_api_frame: GuestCallbackFrame | None = None
        self.mem_trace_hooks: list[Any] = []
        self.coverage_hook: Any | None = None
        self.debug_hook: Any | None = None
        self.is_kernel_mode: bool = False
        self.virtual_mem_base: int = 0x50000

        # Code hook for work that must wait until the next instruction: unmap the reserved range,
        # and clear the SEH repeat count. The emulator enables the hook only when there is such work.
        self.deferred_work_hook: Any | None = None

        # Only the run loop writes these two fields. To end a run, call end_run.
        # _run_completed: the result of curr_run is recorded, and the next run is not prepared yet.
        self._run_completed: bool = False
        self.is_emu_complete: bool = False
        self.processes: list[Any] = []
        # The processes that the guest creates with CreateProcess. self.processes does not include them.
        self.child_processes: list[Any] = []
        self.curr_thread: Any | None = None
        self.prev_pc: int = 0
        # The state of the kernel, and of a user mode emulator before a process exists. Each process has its own
        # copy of these fields. BinaryEmulator.env has the environment.
        self.cd: str = ""
        self.heap_allocs: list[tuple[int, int, str]] = []
        self.veh_handlers: list[int] = []
        self.unhandled_exception_filter: int = 0
        self.function_tables: list[unwind.FunctionTable] = []
        self._seh_repeat: _SehRepeat = _SehRepeat()

        self.fs_addr: int = 0
        self.gs_addr: int = 0

        self.return_hook: int = winemu.EMU_RETURN_ADDR
        self.exit_hook: int = winemu.EXIT_RETURN_ADDR
        # A jump in kernel32 to the return hook. The EXE entry point and thread start routines return to it.
        self.thread_return_addr: int | None = None
        self._parse_config(config)

        self.wintypes = windefs
        self.handle_allocator: HandleAllocator = HandleAllocator()
        # The handles of the kernel, and of a user-mode emulator before a process exists
        self.handles: HandleTable = HandleTable(self.handle_allocator, self.dec_ref, self.get_pseudo_handle_object)
        self.regman: RegistryManager = RegistryManager(
            self.get_handle_table, self.config.registry, os_ver=self.config.os_ver, emu=self
        )
        self.fileman: FileManager = FileManager(config, self)
        self.netman: NetworkManager = NetworkManager(self.handle_allocator, config=self.config.network, emu=self)
        self.driveman: DriveManager = DriveManager(config=self.config.drives)
        self.cryptman: CryptoManager = CryptoManager(self.handle_allocator)
        self.rng: random.Random = random.Random(self.config.random_seed)
        self.start_time: int = winemu.get_filetime(parse_start_time(self.config.start_time))
        self._user_shared_data_bases: list[int] = []
        self.hammer: ApiHammer = ApiHammer(self)
        self._io_manager: Any | None = None

    def _parse_config(self, config):
        super()._parse_config(config)
        self.cd = self.config.current_dir
        self.command_line: str = self.config.command_line

    def init_machine(self, arch):
        """
        Create the Unicorn engine, the disassembler and the API layer for ``arch``.

        Then create the Windows structures and the modules of the machine. Load images after this. The container image
        of a DLL or shellcode input is not part of the machine. Win32Emulator.load_container loads it.

        Raises:
            WindowsEmuError: if the machine is already initialized, or arch is not x86 or amd64.
        """
        if self.arch:
            raise WindowsEmuError("the machine is already initialized")
        if arch not in (_arch.ARCH_X86, _arch.ARCH_AMD64):
            raise WindowsEmuError(f"unsupported architecture: {arch}")
        self.arch = arch
        self.set_ptr_size(arch)
        self.env.setdefault("processor_architecture", "AMD64" if arch == _arch.ARCH_AMD64 else "x86")
        if arch == _arch.ARCH_AMD64:
            program_files = self.env.get("programfiles", "C:\\Program Files")
            self.env.setdefault("programfiles(x86)", f"{program_files} (x86)")
            self.env.setdefault("commonprogramfiles(x86)", f"{program_files} (x86)\\Common Files")
            self.env.setdefault("programw6432", program_files)
        self.regman.add_default_values(
            WINDOWS_CURRENT_VERSION_KEY, get_program_files_values(self.env, arch == _arch.ARCH_AMD64)
        )
        if self.emu_eng and not self.emu_eng.emu:
            self.emu_eng.init_engine(_arch.ARCH_X86, arch)
        self.disasm_eng = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64 if arch == _arch.ARCH_AMD64 else cs.CS_MODE_32)
        self.api = WindowsApi(self)

        with self.allocations_from(winemu.MACHINE_BASE):
            self.init_machine_structures()
            self.is_machine_ready = True
            for entry in tuple(self.api_registry.entries.values()):
                if entry.export.kind == "data":
                    self._initialize_api_data(entry)

    @abstractmethod
    def init_machine_structures(self) -> None:
        """Create the object manager, segments, shared data and modules of the machine."""

    def get_object_manager(self, reason: str) -> objman.ObjectManager:
        """
        Get the object manager of the machine.

        Raises:
            WindowsEmuError: if the machine structures are not initialized yet.
        """
        if self.om is None:
            raise WindowsEmuError(f"{reason} requires initialized object services")
        return self.om

    def on_run_complete(self):
        """
        Record the result of the current run. Only the run loop calls this, from ``_complete_run``.

        A subclass can add runs to the queue here. The run loop starts the next run after this.
        """
        raise NotImplementedError()

    @property
    def end_requested(self) -> bool:
        """Get whether a fault, an API handler, a hook or the user ended the current run with ``end_run``."""
        return isinstance(self._native_exit, RunEnd)

    @property
    def is_run_complete(self) -> bool:
        """Get whether the current run ended: ``end_run`` was called, or the run loop completed the run."""
        return self._run_completed or self.end_requested

    def end_run(self, error: ErrorInfo | None = None, *, stop_emulation: bool = False) -> None:
        """
        End the current run, with ``error`` as its error. API handlers and hooks use this to end a run.

        The run loop completes the run after the handler or the hook returns and Unicorn stops. Then it starts the
        next run, or, if ``stop_emulation`` is set, it ends the emulation. If the run already ended, keep its error.
        """
        if self.end_requested:
            if stop_emulation:
                self._native_exit = RunEnd(stop_emulation=True)
            return
        if error is not None:
            self._set_run_error(error)
        # An end replaces other native exits, such as a CPU exception that a hook raised before.
        self._native_exit = RunEnd(stop_emulation=stop_emulation)
        self.emu_eng.stop()

    def stop(self) -> None:
        """End the current run and the emulation. The runs in the queue do not run."""
        self._cancel_execution_runs()
        self.end_run(stop_emulation=True)
        super().stop()

    def end_run_on_fault(self):
        """
        End the current run after a handled memory fault.

        With a debugger attached, stop Unicorn at the fault, and end the run after the debugger resumes.
        A fault at a PC in the reserved range, such as the return hook, is not a fault of the guest, so it does not
        stop the debugger.
        """
        pc = self.get_pc()
        in_reserved = winemu.EMU_RESERVED <= pc < winemu.EMU_RESERVED + winemu.EMU_RESERVE_SIZE
        if not self._should_stop_on_faults or in_reserved:
            # The run loop goes to the next run only after Unicorn stops, also if Unicorn raises an error
            # after the stop. Otherwise the rest of the fault can change the next run.
            self.end_run()
            return
        self._pending_fault_stop = StopReason(signal=GDB_SIGSEGV, kind="exception", address=pc)
        self.emu_eng.stop()

    def enable_deferred_work_hook(self):
        if not self.deferred_work_hook:
            self.deferred_work_hook = self.add_code_hook(cb=self._hook_code_deferred_work)

        if self.deferred_work_hook:
            self.deferred_work_hook.enable()

    def disable_deferred_work_hook(self):
        if self.deferred_work_hook:
            self.deferred_work_hook.disable()

    def set_mem_tracing_hooks(self):
        if not self.config.analysis.memory_tracing:
            return

        if len(self.mem_trace_hooks) > 0:
            return

        logger.debug("installing memory tracing hooks")
        self.mem_trace_hooks = [
            self.add_code_hook(cb=self._hook_code_tracing),
            self.add_mem_read_hook(cb=self._hook_mem_read),
            self.add_mem_write_hook(cb=self._hook_mem_write),
        ]

    def set_coverage_hooks(self):
        if not self.config.analysis.coverage:
            return

        if self.coverage_hook:
            return

        logger.debug("installing coverage hooks")
        self.coverage_hook = self.add_code_hook(cb=self._hook_code_coverage)

    def set_debug_hooks(self):
        if not self.debug:
            return

        if self.debug_hook:
            return

        self.debug_hook = self.add_code_hook(cb=self._hook_code_debug)

    def cast(self, obj, bytez):
        """Create a formatted structure from bytes."""
        if not isinstance(obj, EmuStruct):
            raise WindowsEmuError("Invalid object for cast")
        return obj.cast(bytez)

    def file_open(self, path, *, create=False, truncate=False, disposition=None, access=None):
        """Open an emulated file using the file manager."""
        return self.fileman.file_open(path, create, truncate=truncate, disposition=disposition, access=access)

    def pipe_open(self, path, mode, num_instances, out_size, in_size):
        """Open an emulated named pipe."""
        return self.fileman.pipe_open(path, mode, num_instances, out_size, in_size)

    def does_file_exist(self, path):
        """Get whether the emulated file at path exists."""
        return self.fileman.does_file_exist(path)

    def file_create_mapping(self, hfile, name, size, prot):
        """Create a memory mapping for an emulated file."""
        return self.fileman.file_create_mapping(hfile, name, size, prot)

    def file_get(self, handle):
        """Get a file object from a handle."""
        return self.fileman.get_file_from_handle(handle)

    def file_delete(self, path):
        """Delete a file."""
        return self.fileman.delete_file(path)

    def get_file_manager(self):
        """Get the file emulation manager."""
        return self.fileman

    def get_network_manager(self):
        """Get the network emulation manager."""
        return self.netman

    def get_crypt_manager(self):
        """Get the crypto manager."""
        return self.cryptman

    def get_drive_manager(self):
        """Get the drive manager."""
        return self.driveman

    def dev_ioctl(self, arch, dev, ioctl, inbuf):
        rv = ddk.STATUS_INVALID_DEVICE_REQUEST
        outbuf = b""

        if not dev or not hasattr(dev, "driver"):
            return rv, outbuf

        parent = dev.driver
        if not parent:
            return rv, outbuf

        if self._io_manager is None:
            self._io_manager = IoManager()

        return self._io_manager.dev_ioctl(arch, dev, ioctl, inbuf)

    def reg_open_key(self, path, *, create=False, disposition=None, access=None):
        """Open a key of the emulated registry. If create is set, create the key if it does not exist."""
        return self.regman.open_key(path, create, disposition=disposition, access=access)

    def reg_get_subkeys(self, hkey):
        """Get subkeys for a given registry key."""
        return self.regman.get_subkeys(hkey)

    def reg_get_key(self, handle: int = 0, path: str = "") -> RegKey | None:
        """Get registry key by path or handle."""
        if path:
            return self.regman.get_key_from_path(path)
        return self.regman.get_key_from_handle(handle)

    def get_trace_position(self) -> TracePosition:
        """Get the position of the current run, thread, process and program counter, for a report event."""
        run = self.get_current_run()
        thread = self.get_current_thread()
        proc = self.get_current_process()
        tick = run.instr_cnt if run else 0
        tid = thread.tid if thread else 0
        pid = proc.id if proc else 0
        pc = None
        try:
            pc = self.get_pc()
        except Exception:
            pc = None
        return TracePosition(tick=tick, tid=tid, pid=pid, pc=pc)

    def record_file_event(
        self, path, event_type: EventType, data=None, handle=0, disposition=None, access=None, buffer=0, size=None
    ):
        """Record a file or directory event in the report."""
        logger.debug("%s: %s", event_type.value, path)
        if self.profiler:
            self.profiler.record_file_access_event(
                self.get_current_run(),
                self.get_trace_position(),
                path,
                event_type,
                data,
                handle,
                disposition,
                access,
                buffer,
                size,
            )

    def record_registry_event(
        self,
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
        """Record a registry key or value event in the report."""
        logger.debug("%s: %s", event_type.value, path)
        if self.profiler:
            self.profiler.record_registry_access_event(
                self.get_current_run(),
                self.get_trace_position(),
                path,
                event_type,
                value_name,
                data,
                handle,
                disposition,
                access,
                buffer,
                size,
            )

    def record_dns_event(self, domain, ip=""):
        """Record a DNS name lookup in the report."""
        logger.debug("dns: %s -> %s", domain, ip)
        if self.profiler:
            self.profiler.record_dns_event(self.get_current_run(), self.get_trace_position(), domain, ip)

    def record_network_event(
        self,
        server,
        port,
        typ: NetTrafficType | None = None,
        proto: NetTrafficProtocol = NetTrafficProtocol.UNKNOWN,
        data=b"",
        method="",
    ):
        """Record socket activity in the report."""
        logger.debug("net: %s:%d %s", server, port, proto.value)
        if self.profiler:
            self.profiler.record_network_event(
                self.get_current_run(),
                self.get_trace_position(),
                server,
                port,
                typ=typ,
                proto=proto,
                data=data,
                method=method,
            )

    def record_http_event(self, server, port, headers="", body=b"", secure=False):
        """Record an HTTP request in the report."""
        logger.debug("http: %s:%d", server, port)
        if self.profiler:
            self.profiler.record_http_event(
                self.get_current_run(),
                self.get_trace_position(),
                server,
                port,
                headers=headers,
                body=body,
                secure=secure,
            )

    def _unmap_reserved_range(self):
        """Unmap the reserved range, so that a return to the return hook or the exit hook faults."""
        if not self.is_reserved_range_unmapped:
            self.mem_unmap(winemu.EMU_RETURN_ADDR, winemu.EMU_RESERVE_SIZE)
            self.is_reserved_range_unmapped = True

    def _map_reserved_range(self):
        """
        Map the reserved memory range, so that Unicorn can complete an access to it.

        The deferred work hook or the next run unmaps it again.
        """
        if self.is_reserved_range_unmapped:
            self.emu_eng.mem_map(winemu.EMU_RETURN_ADDR, winemu.EMU_RESERVE_SIZE)
        self.is_reserved_range_unmapped = False

    def get_valid_ranges(self, size, addr=None):
        """
        Get a free range for an allocation outside the reserved range.

        The emulator keeps the reserved range unmapped, so that a return to the return hook faults.
        """
        base, total = super().get_valid_ranges(size, addr=addr)
        if base < winemu.EMU_RESERVED_END and base + total > winemu.EMU_RESERVED:
            base, total = super().get_valid_ranges(size, addr=winemu.EMU_RESERVED_END)
        return base, total

    def add_run(self, run):
        """Add a run to the emulation run queue."""
        self.run_queue.append(run)

    def _complete_run(self) -> None:
        """
        Record the result of the current run. Only the run loop calls this. Then it calls ``_start_next_run``.

        If ``stop`` ended the run, also end the emulation.
        """
        run = self.curr_run
        stop_emulation = isinstance(self._native_exit, RunEnd) and self._native_exit.stop_emulation
        self._native_exit = None
        self._run_completed = True
        self.on_run_complete()
        if run is not None:
            self._finish_run_initializers(run)
        if stop_emulation:
            # on_run_complete can add runs, for example the routines of a driver after DriverEntry.
            self._cancel_execution_runs()
            self.on_emu_complete()

    def _start_next_run(self) -> Run | None:
        """
        Prepare the next run from the queue. Only the run loop calls this, after ``_complete_run``.

        Return the prepared run. If the queue is empty or the emulation is complete, complete the emulation and
        return None.
        """
        if self.is_emu_complete or not self.run_queue:
            self.on_emu_complete()
            return None
        run = self.run_queue.pop(0)
        self.reset_stack(self.stack_base)
        self.reset_cpu_context()
        mm = self.get_address_map(self.stack_base - 1)
        self.mem_write(mm.base, b"\x00" * mm.size)
        prepared: Run = self._prepare_run_context(run)
        return prepared

    def _queue_startup_initializers(self):
        """
        Add a run for each DllMain and TLS callback of the DLLs that the process loaded at start.

        Put these runs before the first run in the queue.
        """
        if self.is_kernel_mode or not self.run_queue:
            return
        queued = []
        for routine in self.module_loader.collect_initializers():
            run = Run()
            if routine.is_entry_point:
                run.type = EntryPointType.DEPENDENCY_DLL_ENTRY
            else:
                run.type = EntryPointType.DEPENDENCY_TLS_CALLBACK
            run.name = routine.module.name
            run.start_addr = routine.address
            run.args = routine.args
            run.thread = self.run_queue[0].thread or self.curr_thread
            run.process_context = self.curr_process
            run.guest_initialization = routine
            queued.append(run)
        self.run_queue[:0] = queued

    def _finish_run_initializers(self, run):
        """
        Undo the loads that the run did not complete.

        If the run is a startup initializer and it failed, set the state of its module to INIT_ERROR, and remove the
        other startup initializers of the module from the queue.
        """
        for frame in run.guest_callbacks:
            self.module_loader.rollback_guest_load(frame)
        run.guest_callbacks.clear()
        routine = run.guest_initialization
        if routine is None or self.module_loader.finish_initializer(
            routine, self.get_return_val(), faulted=run.error is not None
        ):
            return
        run.error = run.error or ErrorInfo(type=ErrorType.DLL_INITIALIZATION_FAILED, pc=self.get_pc())
        logger.warning(
            "guest initializer failed for %s in process %s: %s", routine.module.name, routine.pid, run.error.type.value
        )
        # Keep the module mapped, because bound import slots can point into it.
        routine.module.load_states[routine.pid] = LoadState.INIT_ERROR
        self.run_queue[:] = [
            queued
            for queued in self.run_queue
            if not (
                (pending := queued.guest_initialization) is not None
                and pending.module is routine.module
                and pending.pid == routine.pid
            )
        ]

    def call(self, addr, params=None) -> None:
        """Add a run that starts at addr. If the queue is empty, start the emulation."""
        self.reset_stack(self.stack_base)
        self.reset_cpu_context()
        mm = self.get_address_map(self.stack_base - 1)
        self.mem_write(mm.base, b"\x00" * mm.size)
        run = Run()
        run.type = EntryPointType.CALL
        run.start_addr = addr
        run.args = params or []

        if not self.run_queue:
            self.add_run(run)
            self.start()
        else:
            self.add_run(run)

    def _prepare_run_context(self, run):
        """Set the registers, the stack, the process and the thread for run. Do not start Unicorn."""
        logger.info("* exec: %s", run.get_label())

        self.curr_run = run
        self._run_completed = False
        self._seh_repeat.reset()
        self.curr_mod = self.get_module_from_addr(run.start_addr)
        if self.profiler:
            self.profiler.add_run(run)

        self.runs.append(self.curr_run)

        stk_ptr = self.get_stack_ptr()
        if self.ptr_size == 8:
            # Win64 callees expect RSP + 8 to be 16-byte aligned at entry
            stk_ptr &= ~0xF
            if max(len(run.args) - 4, 0) % 2:
                stk_ptr -= 8

        self.set_func_args(stk_ptr, self.get_run_return_address(run), *run.args, conv=_arch.CALL_CONV_STDCALL)
        for reg, value in run.registers.items():
            self.reg_write(reg, value)
        stk_ptr = self.get_stack_ptr()
        stk_map = self.get_address_map(stk_ptr)

        self.curr_run.stack = MemAccess(base=stk_map.base, size=stk_map.size)

        if run.process_context:
            if run.process_context != self.get_current_process():
                self.alloc_peb(run.process_context)
            self.set_current_process(run.process_context)
        if run.thread:
            self.set_current_thread(run.thread)
        elif not self.is_kernel_mode:
            thread = objman.Thread(self, stack_base=self.stack_base)
            self.get_object_manager("thread registration").add_object(thread)
            if self.curr_process:
                thread.process = self.curr_process
                self.curr_process.threads.append(thread)
            run.thread = thread
            self.set_current_thread(thread)

        if not self.is_kernel_mode:
            thread = self.get_current_thread()
            if thread:
                thread.exit_code = None
                if self.curr_process is not None:
                    self.init_teb(thread, self.curr_process.peb)
                self.init_tls(thread)

        if winemu.EMU_RESERVED <= run.start_addr <= winemu.EMU_RESERVED_END:
            # A run that starts in the reserved range must fault at its first fetch.
            self._unmap_reserved_range()

        self.set_pc(run.start_addr)
        return run

    def get_run_return_address(self, run: Run) -> int:
        """Get the return address that the code of run returns to. A return to it ends the run."""
        return self.return_hook

    def mem_cast(self, obj, addr):
        """Read a structure of the type of obj from guest memory at addr."""
        size = obj.sizeof()
        struct_bytes = self.mem_read(addr, size)
        return self.cast(obj, struct_bytes)

    def setup_user_shared_data(self):
        """Map KUSER_SHARED_DATA at its user mode address and its kernel mode address, and write its data."""
        aliases = []
        if self.get_arch() == _arch.ARCH_X86:
            aliases.append(0xFFDF0000)
        elif self.get_arch() == _arch.ARCH_AMD64:
            aliases.append(0xFFFFF78000000000)

        # On x64, Unicorn truncates the address of a guest memory access to 52 bits, so a read from the kernel
        # address goes to the truncated address. Map the page there too.
        mirrors = {a & self._X64_EXEC_ADDR_MASK for a in aliases if a & self._X64_EXEC_ADDR_MASK != a}

        # The user mode address is the same on x86 and x64.
        bases = [0x7FFE0000] + aliases + list(mirrors)

        kuser_tag = "emu.struct.KUSER_SHARED_DATA"

        data = self._build_user_shared_data()
        self._user_shared_data_bases = []
        for base in bases:
            mm = self.get_address_map(base)
            if mm and not (mm.tag or "").startswith(kuser_tag):
                # Another mapping uses this address. A second map fails and stops the kernel mode load, and
                # a write changes the data of the other mapping.
                continue
            if not mm:
                self.mem_map(self.page_size, base=base, tag=kuser_tag)
            self.mem_write(base, data)
            self._user_shared_data_bases.append(base)

    def update_user_shared_time(self, tick_ms: int) -> None:
        """Write the time fields for the tick count tick_ms to each mapped copy of KUSER_SHARED_DATA."""
        data = bytearray(0x400)
        self._pack_user_shared_time(data, tick_ms)
        for base in self._user_shared_data_bases:
            self.mem_write(base + 0x008, bytes(data[0x008:0x020]))
            self.mem_write(base + 0x320, bytes(data[0x320:0x32C]))

    def _pack_user_shared_time(self, data: bytearray, tick_ms: int) -> None:
        # InterruptTime (offset 0x008): KSYSTEM_TIME {LowPart, High1Time, High2Time}
        interrupt_100ns = tick_ms * 10000
        struct.pack_into(
            "<IiI", data, 0x008, interrupt_100ns & 0xFFFFFFFF, interrupt_100ns >> 32, interrupt_100ns >> 32
        )
        # SystemTime (offset 0x014): KSYSTEM_TIME
        now_100ns = self.start_time + (tick_ms - winemu.START_TICK_COUNT) * 10000
        struct.pack_into("<IiI", data, 0x014, now_100ns & 0xFFFFFFFF, now_100ns >> 32, now_100ns >> 32)
        # TickCount (offset 0x320): KSYSTEM_TIME
        struct.pack_into("<IiI", data, 0x320, tick_ms & 0xFFFFFFFF, tick_ms >> 32, tick_ms >> 32)

    def get_native_machine(self) -> int:
        """Get the IMAGE_FILE_MACHINE value of the emulated host, which matches the guest architecture."""
        if self.get_arch() == _arch.ARCH_AMD64:
            return windefs.IMAGE_FILE_MACHINE_AMD64
        return windefs.IMAGE_FILE_MACHINE_I386

    def _build_user_shared_data(self):
        data = bytearray(0x400)
        # TickCountMultiplier (offset 0x004) is 1.0 in 8.24 fixed point, so TickCount counts milliseconds.
        struct.pack_into("<I", data, 0x004, 1 << 24)
        self._pack_user_shared_time(data, winemu.START_TICK_COUNT)
        # ImageNumberLow, ImageNumberHigh (offset 0x02C)
        machine = self.get_native_machine()
        struct.pack_into("<HH", data, 0x02C, machine, machine)
        # NtBuildNumber (offset 0x260), a reserved field before Windows 10
        struct.pack_into("<I", data, 0x260, self.config.os_ver.build or 0)
        # NtProductType (offset 0x264): NtProductWinNt, and ProductTypeIsValid (offset 0x268): TRUE
        struct.pack_into("<IB", data, 0x264, 1, 1)
        # NtMajorVersion (offset 0x26C), NtMinorVersion (offset 0x270)
        struct.pack_into("<II", data, 0x26C, self.config.os_ver.major or 0, self.config.os_ver.minor or 0)
        # QpcFrequency (offset 0x3B8)
        struct.pack_into("<q", data, 0x3B8, 10_000_000)

        return bytes(data)

    def _execute_current_run(self, address, timeout=0, count=-1, debugger=None):
        """
        Run the current run from address until it ends, it reaches a limit, or the debugger stops.

        Unicorn runs guest code until a hook records a native exit and stops Unicorn.
        Then the loop handles the exit, for example it calls the handler of an API, and starts Unicorn again.
        """
        address = self._drop_stale_exit(address)
        origin_run = self.curr_run
        assert origin_run is not None
        budget = self.config.max_instructions if debugger is not None else count
        limits = RunLimits.from_run(origin_run, timeout, budget, self._execution_budget)
        hook = self._add_accounting_hook(limits, origin_run, debugger) if limits.budget > 0 else None
        stepping = debugger is not None and count == 1

        try:
            while not self.is_emu_complete and not self._run_completed:
                if self.exit_event and self.exit_event.is_set():
                    self.emu_eng.stop()
                    return
                if self._native_exit is None:
                    reached = limits.get_reached_limit()
                    if reached is not None:
                        self._stop_at_limit(reached, limits, origin_run, debugger)
                        return
                    if not self._start_unicorn(address, limits, origin_run, debugger, stepping):
                        return
                    if self._native_exit is None:
                        self._native_exit = self._get_exit_at_pc()
                    if not isinstance(self._native_exit, RaisedCpuException):
                        if debugger is not None and debugger.has_pending_stop():
                            return
                        if self._native_exit is None:
                            self._stop_without_exit(limits, origin_run, debugger)
                            return
                        continue
                if not self._handle_exit(limits, origin_run, debugger):
                    return
                address = self.get_pc()
                if self._pending_fault_stop is not None:
                    return
                if debugger is not None and (debugger.has_pending_stop() or stepping):
                    return
        finally:
            self._finish_current_run_execution(limits, origin_run, debugger)
            if hook is not None:
                self.remove_hook(hook)

    def _start_unicorn(
        self, address: int, limits: RunLimits, origin_run: Run, debugger: GdbServer | None, stepping: bool
    ) -> bool:
        """
        Run guest code in Unicorn from address until it stops, and raise the CPU exception of a ``hlt`` that ran.

        Return False if a fault stops the debugger.

        Raises:
            uc.UcError: if Unicorn fails and no native exit explains the failure.
        """
        try:
            native_timeout = limits.get_native_timeout()
            native_count = limits.get_native_count()
            if stepping:
                native_count = 1
                registers = self.get_register_state()
                counted = (limits.remaining, origin_run.budget_instructions, origin_run.instr_cnt)
                if limits.budget <= 0:
                    # There is no accounting hook, so record the instruction of the step here.
                    limits.last_executed = address
            self.emu_eng.start(address, timeout=native_timeout, count=native_count)
            if stepping and self._step_had_no_effect(registers, debugger):
                # When an instruction writes to the page of its own code, Unicorn
                # translates the page again and runs the instruction again. This
                # uses up the count of 1. Undo the counts of the first start, so
                # that the second start counts the instruction once.
                limits.remaining, origin_run.budget_instructions, origin_run.instr_cnt = counted
                self.emu_eng.start(address, timeout=native_timeout, count=2)
        except uc.UcError as exc:
            if self._pending_fault_stop is not None:
                return False
            if not self._exit_explains_error(exc):
                raise
        if self._stopped_at_hlt(limits.deadline, limits.last_executed, native_count, debugger):
            self.raise_cpu_exception(
                cpu_exceptions.privileged_instruction(self.get_pc() - 1), ErrorType.PRIVILEGED_INSTRUCTION
            )
        return True

    def _exit_explains_error(self, exc: uc.UcError) -> bool:
        """Get whether the native exit is the cause of the Unicorn error. Then the run loop handles the exit."""
        match self._native_exit:
            case None:
                return False
            case RaisedCpuException() | RunEnd():
                return True
            case ExecRecovery() if exc.errno == uc.UC_ERR_FETCH_PROT:
                return True
        return bool(exc.errno == uc.UC_ERR_FETCH_UNMAPPED)

    def _record_exit(self, native_exit: NativeExit) -> None:
        """Record native_exit and stop Unicorn. If an exit is already recorded, keep that exit."""
        if self._native_exit is None:
            self._native_exit = native_exit
        self.emu_eng.stop()

    def _get_exit_at_pc(self) -> NativeExit | None:
        """
        Get the exit at the address where Unicorn stopped, if no hook recorded one.

        The exit is the call of an API, the return of a guest callback, or the return of the run.
        """
        pc = self.get_pc()
        entry = self.api_registry.traps.get(pc)
        if entry is not None:
            return self._get_suspended_api_call(entry)
        run = self.curr_run
        if pc == winemu.GUEST_CALLBACK_RETURN_ADDR and run is not None and run.guest_callbacks:
            return CallbackReturn()
        if pc in (self.return_hook, self.exit_hook):
            return RunReturn()
        return None

    def _add_accounting_hook(self, limits: RunLimits, origin_run: Run, debugger: GdbServer | None):
        """Add a code hook that counts each instruction and stops Unicorn at the instruction limit."""

        def account_instruction(_emu, address, _size):
            if debugger is not None and debugger.has_pending_stop():
                return
            if limits.remaining <= 0:
                self.emu_eng.stop()
                return
            limits.remaining -= 1
            limits.last_executed = address
            origin_run.budget_instructions += 1
            if not self.config.analysis.memory_tracing:
                run = self.curr_run
                if run is not None:
                    run.instr_cnt += 1

        return self.add_code_hook(account_instruction)

    def _finish_current_run_execution(self, limits: RunLimits, origin_run: Run, debugger: GdbServer | None) -> None:
        """
        Add the time of the call to origin_run and to the total execution time.

        End the run if the exit event stopped it, and cancel all runs if the total time ran out.
        """
        elapsed = time.monotonic() - limits.started
        origin_run.execution_elapsed = limits.spent + elapsed
        stopped = self.exit_event is not None and self.exit_event.is_set()
        if stopped and debugger is None and not self.is_run_complete:
            if origin_run.error is None:
                origin_run.error = ErrorInfo(type=ErrorType.TIMEOUT, pc=self.get_pc())
            self._cancel_execution_runs()
        total_budget = limits.total_budget
        if total_budget is not None:
            total_budget.elapsed += elapsed
            if total_budget.limit > 0 and total_budget.elapsed >= total_budget.limit:
                if not total_budget.exhausted:
                    logger.error("* Total execution time of %d sec(s) reached.", total_budget.limit)
                total_budget.exhausted = True
                self._cancel_execution_runs()
                if not self.is_run_complete and origin_run.error is None:
                    origin_run.error = ErrorInfo(type=ErrorType.MAX_TOTAL_TIME, pc=self.get_pc())
                if debugger is not None:
                    debugger._request_stop(StopReason(kind=LimitKind.MAX_TOTAL_TIME.value, address=self.get_pc()))

    def _handle_exit(self, limits: RunLimits, origin_run: Run, debugger: GdbServer | None) -> bool:
        """
        Handle the native exit.

        Return False if the run loop must return, because the debugger stops, a limit is reached, or the run ended.
        """
        native_exit = self._native_exit
        match native_exit:
            case RaisedCpuException():
                self._native_exit = None
                self._dispatch_cpu_exception(native_exit)
                return True
            case SuspendedApiCall():
                reached = limits.get_reached_limit()
                if reached is not None:
                    self._stop_at_limit(reached, limits, origin_run, debugger)
                    return False
                if debugger is not None and debugger.has_pending_stop():
                    return False
                return self._dispatch_api_entry(native_exit.entry, limits, origin_run, debugger)
        if debugger is not None and debugger.has_pending_stop():
            return False
        if limits.is_total_time_reached():
            self._stop_at_limit(LimitKind.MAX_TOTAL_TIME, limits, origin_run, debugger)
            return False
        if isinstance(native_exit, (RunReturn, RunEnd)):
            self._complete_run()
            return False
        self._native_exit = None
        match native_exit:
            case ExecRecovery(page=page, perms=perms):
                self.mem_protect(page, self.page_size, perms)
            case CallbackReturn():
                self._continue_guest_callback()
        return True

    def _dispatch_api_entry(
        self, entry: ApiEntry, limits: RunLimits, origin_run: Run, debugger: GdbServer | None
    ) -> bool:
        """
        Call the handler of the API that the guest called, and complete the run if the handler ended it.

        Return False if the call of the run loop must return, because the debugger stops at an API with no
        implementation, a fault stops the debugger, or the total execution time ran out.
        """
        # With a debugger, an API without an implementation stops the debugger at the API, and the run continues.
        if debugger is not None and isinstance(
            self.resolve_api_implementation(entry.dll, entry.name), api_resolution.UnsupportedImplementation
        ):
            self.set_pc(entry.address)
            debugger._request_stop(StopReason(kind="unsupported_api", address=entry.address))
            return False
        self._native_exit = None
        site, self._api_call_site = self._api_call_site, None
        self.prev_pc = site[1] if site is not None and site[0] == entry.address else 0
        self.dispatch_api_call(entry.dll, entry.name)
        if self._pending_fault_stop is not None:
            return False
        if self.end_requested:
            if limits.is_total_time_reached():
                self._stop_at_limit(LimitKind.MAX_TOTAL_TIME, limits, origin_run, debugger)
                return False
            self._complete_run()
        return True

    def _stop_without_exit(self, limits: RunLimits, origin_run: Run, debugger: GdbServer | None) -> None:
        """
        Stop origin_run after Unicorn stopped with no native exit.

        If a limit is reached, stop at the limit. Otherwise, end the run with an ``engine_stopped`` error, if the run is
        not complete and no debugger is attached.
        """
        reached = limits.get_reached_limit()
        if reached is not None:
            self._stop_at_limit(reached, limits, origin_run, debugger)
        elif debugger is None and not self.is_run_complete:
            logger.error("0x%x: Emulation engine stopped", self.get_pc())
            origin_run.error = self.get_error_info(ErrorType.ENGINE_STOPPED, self.get_pc())
            self._complete_run()

    def _stop_at_limit(self, kind: LimitKind, limits: RunLimits, origin_run: Run, debugger: GdbServer | None) -> None:
        """
        Stop origin_run at the limit of the given kind.

        Without a debugger, the limit becomes the error of the run and the run ends. With a debugger, the debugger
        stops.
        """
        if isinstance(self._native_exit, SuspendedApiCall):
            self.set_pc(self._native_exit.entry.address)
        if kind == LimitKind.TIMEOUT:
            # Each debugger resume of a timed out run stops at once; log only the first stop.
            if limits.spent < limits.timeout:
                logger.error("* Timeout of %d sec(s) reached.", limits.timeout)
        elif kind == LimitKind.MAX_TOTAL_TIME:
            assert limits.total_budget is not None
            logger.error("* Total execution time of %d sec(s) reached.", limits.total_budget.limit)
            limits.total_budget.exhausted = True
            self._cancel_execution_runs()
            # If the run already has an error, such as a fault, keep that error.
            if not self._run_completed and origin_run.error is None:
                origin_run.error = ErrorInfo(type=ErrorType(kind.value), pc=self.get_pc())
        else:
            logger.error("* Instruction limit of %d reached.", limits.budget)
        if debugger is not None:
            debugger._request_stop(StopReason(kind=kind.value, address=self.get_pc()))
        elif not self._run_completed:
            if origin_run.error is None:
                origin_run.error = ErrorInfo(
                    type=ErrorType(kind.value),
                    pc=self.get_pc(),
                    count=limits.budget if kind == LimitKind.MAX_INSTRUCTIONS else None,
                )
            self._complete_run()

    def _drop_stale_exit(self, address: int) -> int:
        """
        Drop the native exit that a debugger made stale while the target was stopped.

        Returns:
            The address where execution continues.
        """
        native_exit = self._native_exit
        if isinstance(native_exit, SuspendedApiCall):
            entry = native_exit.entry
            if address not in (entry.address, entry.trap):
                # The debugger changed PC, so the guest does not call the API.
                self._native_exit = None
            elif self._get_suspended_api_call(entry) != native_exit:
                # The debugger changed the stack or the code of the API. Run the
                # code of the API again, so that the changes take effect.
                self._native_exit = None
                address = entry.address
                self.set_pc(address)
        elif isinstance(native_exit, (RunReturn, CallbackReturn, RunEnd)) and address not in (
            winemu.GUEST_CALLBACK_RETURN_ADDR,
            self.return_hook,
            self.exit_hook,
        ):
            self._native_exit = None
        return address

    def _take_pending_fault_stop(self) -> StopReason | None:
        """Get the fault stop that a hook set during the last run, and clear it."""
        stop, self._pending_fault_stop = self._pending_fault_stop, None
        return stop

    def _cancel_execution_runs(self, prepared=None):
        """
        Remove the runs in the queue, the suspended runs and the run ``prepared``.

        Clear the ``INITIALIZING`` state of the DllMain and TLS callbacks of these runs.
        """
        canceled = [*self.run_queue, *self.suspended_runs]
        if prepared is not None:
            canceled.append(prepared)
        self.module_loader.cancel_initializers(
            run.guest_initialization for run in canceled if run.guest_initialization is not None
        )
        self.run_queue.clear()
        self.suspended_runs.clear()

    def resume(self, addr, count=-1) -> None:
        """
        Continue the current run at addr, without the GDB server.

        The current run continues also if it ended before. With the GDB server, use ``start``.
        """
        if self.curr_run is None:
            self.curr_run = Run()
        self.is_emu_complete = False
        self._run_completed = False
        if self.end_requested:
            self._native_exit = None
        timeout = 0 if self.gdb_port is not None else self.config.max_run_time
        self._execute_current_run(addr, timeout=timeout, count=count)

    @execution_scope
    def start(self) -> None:
        """Add the runs of the startup initializers, then run all runs in the queue."""
        total_budget = self._execution_budget
        assert total_budget is not None
        if total_budget.exhausted:
            self._cancel_execution_runs()
            return
        self._queue_startup_initializers()
        try:
            run = self.run_queue.pop(0)
        except IndexError:
            return

        # An exit that a stop() before the emulation recorded does not end the first run.
        self._native_exit = None
        self.is_emu_complete = False
        self.set_hooks()
        self._unmap_reserved_range()

        # Prepare the first run before the GDB server starts, so that the first
        # stop shows the registers of the run.
        self._prepare_run_context(run)

        completed = True
        if self.gdb_port is not None:
            if self.gdb_host is None:
                raise WindowsEmuError("A GDB bind host is required when gdb_port is set")
            with GdbServer(self, self.gdb_port, self.gdb_host) as debugger:
                debug_action = debugger.command_loop()
                if debug_action.kill:
                    completed = True
                elif debug_action.detach:
                    debugger.close()
                    completed = self._execute_runs()
                else:
                    completed = self._execute_runs(debugger, debug_action)
        else:
            completed = self._execute_runs()

        if completed:
            self.on_emu_complete()

    def _execute_runs(
        self,
        debugger: GdbServer | None = None,
        debug_action: ResumeAction = ResumeAction(),
    ) -> bool:
        """
        Run the current run and the runs in the queue, with or without a GDB session.

        Return False if the user or the exit event stopped the emulation.
        """
        total_budget = self._execution_budget
        assert total_budget is not None
        detached_resume_addr: int | None = None
        terminal_signal = 0
        self._should_stop_on_faults = debugger is not None
        self._pending_fault_stop = None

        if self.profiler:
            self.profiler.start_clock()

        while True:
            try:
                executing_run = self.curr_run
                if executing_run is None:
                    break
                if debugger is not None:
                    resume_addr = self.get_pc()
                else:
                    start_addr = detached_resume_addr or executing_run.start_addr
                    if start_addr is None:
                        raise WindowsEmuError("the run has no start address")
                    resume_addr = start_addr
                    detached_resume_addr = None
                instruction_count = 1 if debugger is not None and debug_action.step else self.config.max_instructions
                should_execute = debugger is None or debugger.begin_run(debug_action)
                if should_execute:
                    self._execute_current_run(
                        resume_addr, timeout=self.config.max_run_time, count=instruction_count, debugger=debugger
                    )
                if debugger is None and total_budget.exhausted:
                    self._end_at_total_budget()
                    break
                completed = self._run_completed
                if completed and not total_budget.exhausted:
                    self._start_next_run()
                if debugger is not None:
                    stop_reason = debugger.finish_run(debug_action)
                    if stop_reason is not None and stop_reason.kind == "step" and self.is_emu_complete:
                        # A step that ends emulation gets the final stop instead.
                        stop_reason = None
                    fault_stop = self._take_pending_fault_stop()
                    if fault_stop is not None:
                        stop_reason = fault_stop
                        terminal_signal = fault_stop.signal
                    if stop_reason is not None:
                        debug_action = debugger.command_loop(stop_reason)
                        if debug_action.kill and not total_budget.exhausted:
                            return True
                        if debug_action.detach:
                            self._detach_debugger(debugger)
                            debugger = None
                        if total_budget.exhausted:
                            self._end_at_total_budget(debugger if not debug_action.kill else None)
                            return True
                        if fault_stop is not None:
                            self._complete_run()
                            if self._start_next_run() is None:
                                break
                            terminal_signal = 0
                        if debugger is None:
                            detached_resume_addr = self.get_pc()
                        continue
                if completed and not self.is_emu_complete:
                    continue
            except KeyboardInterrupt:
                logger.error("* User exited.")
                if debugger is not None:
                    debugger.notify_signal(2)
                return False
            except Exception as e:
                if self.exit_event and self.exit_event.is_set():
                    return False
                stack_trace = traceback.format_exc()

                try:
                    mnem, op, instr = self.get_disasm(self.get_pc(), _arch.DISASM_SIZE)
                except Exception as dis_err:
                    logger.error(str(dis_err))

                if isinstance(e, uc.UcError) and e.errno == uc.UC_ERR_INSN_INVALID:
                    error = self.get_error_info(ErrorType.INVALID_INSTRUCTION, self.get_pc(), traceback=stack_trace)
                else:
                    error = self.get_error_info(
                        ErrorType.INTERNAL_ERROR,
                        self.get_pc(),
                        traceback=stack_trace,
                        message=str(e) or type(e).__name__,
                    )
                self._set_run_error(error)
                terminal_signal = GDB_SIGSEGV

                if debugger is not None:
                    # finish_run keeps a pending Ctrl-C. Then report the fault
                    # while the registers of the fault are available.
                    debugger.finish_run(debug_action)
                    debug_action = debugger.command_loop(
                        StopReason(signal=terminal_signal, kind="exception", address=self.get_pc())
                    )
                    if debug_action.kill:
                        return True
                    if debug_action.detach:
                        self._detach_debugger(debugger)
                        debugger = None

                if not self._run_completed:
                    self._complete_run()
                if self._start_next_run() is None:
                    break
                terminal_signal = 0
                continue
            break

        if debugger is not None:
            if terminal_signal:
                debugger.notify_signal(terminal_signal)
            else:
                # Stop once more while the memory is mapped, so that the client
                # can read the final state before the exit reply.
                debug_action = debugger.command_loop(StopReason(kind="exit"))
                if debug_action.kill:
                    return True
                if debug_action.detach:
                    debugger.close()
                    return True
                debugger.notify_exit(0)
        return True

    def _end_at_total_budget(self, debugger: GdbServer | None = None) -> None:
        """
        Cancel the runs that are left and end the emulation, because the total time limit is reached.

        Args:
            debugger: the GDB session to send the exit reply to, if the client still waits for one.
        """
        self._cancel_execution_runs()
        if not self._run_completed:
            self._complete_run()
        if debugger is not None:
            debugger.notify_exit(0)
        self.on_emu_complete()

    def _detach_debugger(self, debugger: GdbServer) -> None:
        """Close the GDB session, so that the runs continue without a debugger."""
        debugger.close()
        self._should_stop_on_faults = False

    def get_current_run(self):
        """Get the current run that is being emulated."""
        return self.curr_run

    def get_current_module(self):
        """Get the currently running module."""
        return self.curr_mod

    def get_dropped_files(self) -> list[File]:
        """Get all files written by the sample from the file manager."""
        return self.fileman.get_dropped_files()

    def set_hooks(self):
        """Add the hooks in the hook lists to Unicorn."""
        super().set_hooks()

    def get_processes(self):
        """Get the process list. It does not include the child processes."""
        return self.processes

    def open_process(self, pid: int) -> int:
        """Open a handle to the process with the ID pid in the process list. Return 0 if no process has the ID."""
        proc = next((p for p in self.get_processes() if p.pid == pid), None)
        if proc is None:
            return 0
        if not self.get_object_from_addr(proc.address):
            self.add_object(proc)
        hnd: int = self.get_object_handle(proc)
        return hnd

    def kill_process(self, proc):
        """Remove proc from the process list."""
        try:
            self.processes.remove(proc)
        except ValueError:
            pass

    def get_current_thread(self):
        """Get the current thread."""
        return self.curr_thread

    def set_last_error(self, code):
        """Set the last error code for the current thread."""
        if self.curr_thread:
            self.curr_thread.last_error = code

    def get_last_error(self):
        """Get the last error code for the current thread."""
        if self.curr_thread:
            return self.curr_thread.last_error

    def heap_alloc(self, size, heap="None"):
        """Map a block for a heap, and record it in the heap allocations. Return 0 if there is no free memory."""
        try:
            addr = self.mem_map(size, base=None, tag=f"api.heap.{heap}")
        except OutOfMemoryError:
            return 0
        self.get_heap_allocs().append((addr, size, heap))
        return addr

    def pool_alloc(self, pooltype, size, tag="None") -> int:
        """
        Allocate memory in the emulated pool.

        Raises:
            WindowsEmuError: if the emulator runs in user mode, which has no pool.
        """
        raise WindowsEmuError("pool allocations need kernel mode")

    def exit_process(self) -> None:
        """
        Signal that the current process ends.

        Raises:
            WindowsEmuError: if the emulator runs in kernel mode, which has no process to end.
        """
        raise WindowsEmuError("process exit needs user mode")

    def get_current_process(self):
        """Get the current process."""
        return self.curr_process

    def set_current_process(self, process):
        """Set the current process."""
        self.curr_process = process

    def set_current_thread(self, thread):
        """Set the current thread."""
        self.curr_thread = thread
        self.hardware_breakpoints.update()

    def set_debug_registers(self, thread, ctx):
        """Give thread the debug registers of ctx, which arm its hardware breakpoints."""
        thread_context.set_debug_registers(thread, ctx)
        if thread is self.get_current_thread():
            self.hardware_breakpoints.update()

    def _setup_gdt(self, arch):
        """
        Map the GDT and the TEB segment, and load the segment registers.

        The guest reads the TEB through FS on x86 and through GS on x64.
        """
        GDT_SIZE = 0x1000
        SEG_SIZE = 0x1000
        ENTRY_SIZE = 0x8
        num_gdt_entries = 31
        fs_addr = 0
        gs_addr = 0
        gdt_addr = None

        # The format of a descriptor: https://wiki.osdev.org/Global_Descriptor_Table

        def _make_entry(index, base, access, limit=0xFFFFF000):
            access = access | (winemu.GDT_ACCESS_BITS.PresentBit | winemu.GDT_ACCESS_BITS.DirectionConformingBit)
            entry = 0xFFFF & limit
            entry |= (0xFFFFFF & base) << 16
            entry |= (0xFF & access) << 40
            entry |= (0xFF & (limit >> 16)) << 48
            entry |= (0xFF & winemu.GDT_ACCESS_BITS.ProtMode32) << 52
            entry |= (0xFF & (base >> 24)) << 56
            entry = entry.to_bytes(8, "little")

            offset = index * ENTRY_SIZE
            self.mem_write(gdt_addr + offset, entry)

        def _create_selector(index, flags):
            return flags | (index << 3)

        # x86 user mode uses the selectors of native 32-bit Windows: CS 0x1B, DS and ES 0x23, FS 0x3B.
        # SS is a ring 0 selector, because Unicorn runs the guest at CPL 0 and rejects an RPL 3 SS.
        native_x86 = arch == _arch.ARCH_X86 and not self.is_kernel_mode
        data_index, code_index, fs_index = (4, 3, 7) if native_x86 else (16, 17, 19)

        gdt_addr, gdt_size = self.get_valid_ranges(GDT_SIZE)
        self.mem_map(gdt_size, base=gdt_addr, tag="emu.gdt")
        seg_addr, seg_size = self.get_valid_ranges(SEG_SIZE)
        self.mem_map(seg_size, base=seg_addr, tag="emu.segment.gdt")

        access = winemu.GDT_ACCESS_BITS.Data | winemu.GDT_ACCESS_BITS.DataWritable | winemu.GDT_ACCESS_BITS.Ring3
        _make_entry(data_index, 0, access)

        access = winemu.GDT_ACCESS_BITS.Code | winemu.GDT_ACCESS_BITS.CodeReadable | winemu.GDT_ACCESS_BITS.Ring3
        _make_entry(code_index, 0, access)

        access = winemu.GDT_ACCESS_BITS.Data | winemu.GDT_ACCESS_BITS.DataWritable | winemu.GDT_ACCESS_BITS.Ring0
        _make_entry(18, 0, access)

        self.reg_write(_arch.X86_REG_GDTR, (0, gdt_addr, num_gdt_entries * ENTRY_SIZE - 1, 0x0))
        selector = _create_selector(data_index, winemu.GDT_FLAGS.Ring3)
        self.reg_write(_arch.X86_REG_DS, selector)
        if native_x86:
            self.reg_write(_arch.X86_REG_ES, selector)
        selector = _create_selector(code_index, winemu.GDT_FLAGS.Ring3)
        self.reg_write(_arch.X86_REG_CS, selector)
        selector = _create_selector(18, winemu.GDT_FLAGS.Ring0)
        self.reg_write(_arch.X86_REG_SS, selector)

        teb_addr = None if self.is_kernel_mode else winemu.TEB_ADDRESS
        if arch == _arch.ARCH_X86:
            # The guest reads the TEB through FS, for example the PEB pointer at fs:[0x30]
            fs_addr, fs_size = self.get_valid_ranges(SEG_SIZE, addr=teb_addr)
            self.mem_map(fs_size, base=fs_addr, tag="emu.segment.fs")

            access = winemu.GDT_ACCESS_BITS.Data | winemu.GDT_ACCESS_BITS.DataWritable | winemu.GDT_ACCESS_BITS.Ring3
            _make_entry(fs_index, fs_addr, access)

            selector = _create_selector(fs_index, winemu.GDT_FLAGS.Ring3)
            self.reg_write(_arch.X86_REG_FS, selector)

        elif arch == _arch.ARCH_AMD64:
            # The guest reads the TEB through GS, for example the PEB pointer at gs:[0x60]
            gs_addr, gs_size = self.get_valid_ranges(SEG_SIZE, addr=teb_addr)
            self.mem_map(gs_size, base=gs_addr, tag="emu.segment.gs")

            access = winemu.GDT_ACCESS_BITS.Data | winemu.GDT_ACCESS_BITS.DataWritable | winemu.GDT_ACCESS_BITS.Ring3
            _make_entry(15, gs_addr, access, limit=SEG_SIZE)

            selector = _create_selector(15, winemu.GDT_FLAGS.Ring3)
            self.reg_write(_arch.X86_REG_GS, selector)

        self.fs_addr = fs_addr
        self.gs_addr = gs_addr

        return fs_addr, gs_addr

    def init_peb(self, user_mods, proc=None):
        """Initialize the PEB of proc or of the current process. For the current process, write the PEB pointer."""
        p = proc
        if not p:
            p = self.curr_process
        p.init_peb(user_mods)
        if p is self.get_current_process():
            self.mem_write(self.peb_addr, p.peb.address.to_bytes(self.get_ptr_size(), "little"))
        return p.peb

    def init_teb(self, thread, peb):
        """Initialize the TEB of thread at the base of the FS or GS segment."""
        if self.get_arch() == _arch.ARCH_X86:
            thread.init_teb(self.fs_addr, peb.address)
        elif self.get_arch() == _arch.ARCH_AMD64:
            thread.init_teb(self.gs_addr, peb.address)

    def init_tls(self, thread):
        """
        Copy the static TLS data of the module of the current run to thread.

        Call this after init_teb.
        """
        run = self.curr_run
        if run is None:
            return
        module = self.get_mod_from_addr(run.start_addr)

        if module:
            if isinstance(module, RuntimeModule):
                modname = ntpath.basename(module.emu_path)
                if module._image and module._image.tls_directory:
                    data = self.read_tls_template(module._image.tls_directory)
                    thread.init_tls(data, os.path.splitext(modname)[0])
            else:
                modname = module.emu_path
                tokens = modname.split("\\")
                modname = tokens[len(tokens) - 1]
                tls_dirp = module.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress
                tls_dirp += module.OPTIONAL_HEADER.ImageBase
                data = self.read_tls_template(tls_dirp)
                thread.init_tls(data, os.path.splitext(modname)[0])

        return

    def read_tls_template(self, tls_dirp: int) -> bytes:
        """
        Get the static TLS data of a module from its IMAGE_TLS_DIRECTORY at tls_dirp.

        Set the TLS index of the module to 0. A directory with an invalid or too large range gives empty data.
        """
        ptrsz = self.get_ptr_size()
        fmt = "<4QI" if ptrsz == 8 else "<5I"
        try:
            start, end, index_addr, _, zero_fill = struct.unpack(fmt, self.mem_read(tls_dirp, struct.calcsize(fmt)))
        except Exception:
            return b""
        size = end - start if start <= end else 0
        if size + zero_fill > TLS_TEMPLATE_MAX:
            size, zero_fill = 0, 0
        data = b""
        if size:
            try:
                data = self.mem_read(start, size)
            except Exception:
                data = b""
        if index_addr:
            try:
                self.mem_write(index_addr, b"\0\0\0\0")
            except Exception:
                pass
        return data + bytes(zero_fill)

    def load_pe(self, path=None, data=None):
        """Parse a PE file or buffer without loading it into the emulator."""
        if not data:
            if path is None:
                raise WindowsEmuError("No PE data to parse")
            if not os.path.exists(path):
                raise WindowsEmuError(f"File: {path} not found")

        try:
            return winemu._PeParser(path=path, data=data)
        except pefile.PEFormatError as e:
            raise WindowsEmuError(f"Invalid PE: {e}") from e

    def get_mod_from_addr(self, addr):
        if self.curr_mod and self.curr_mod.base <= addr < self.curr_mod.base + self.curr_mod.image_size:
            return self.curr_mod
        for m in self.modules:
            if m.base <= addr < m.base + m.image_size:
                return m
        return None

    def ensure_pe_import_hooks(self, base_addr):
        """
        Bind the imports of a PE that the guest mapped itself, for example by process hollowing.

        Bind each valid IAT slot, and skip the invalid slots. If OriginalFirstThunk is zero, the IAT can have
        addresses that this method bound in an earlier call. The emulator records its bindings, so that it skips
        these slots and does not read their addresses as RVAs.
        """
        ptr_size = self.get_ptr_size()
        import_errors = (ValueError, struct.error, uc.UcError, WindowsEmuError)

        def read(address, size):
            try:
                return self.mem_read(address, size)
            except uc.UcError as error:
                raise ValueError(str(error)) from error

        pending = []
        try:
            for slot in mapped_imports.get_import_slots(read, base_addr, ptr_size):
                bindings = self.module_loader.import_bindings
                if bindings.get(slot.iat) == slot.current:
                    continue
                if slot.iat in bindings and (not slot.has_ilt or slot.current != slot.thunk):
                    # The guest changed an entry that the emulator bound. Keep the value of
                    # the guest, unless the guest wrote back the original value from the ILT.
                    continue
                if slot.is_bound_externally:
                    continue
                try:
                    reference = slot.get_reference()
                    address = self.get_proc(slot.dll, reference)
                    if not address:
                        raise WindowsEmuError(f"unresolved import {slot.dll}!{reference}")
                    if not 0 <= address < 1 << (ptr_size * 8):
                        raise ValueError("import address does not fit pointer size")
                except import_errors as error:
                    logger.warning("skipping injected PE import slot at %#x: %s", slot.iat, error)
                    continue
                pending.append((slot.iat, address))

            for iat, address in pending:
                self.mem_write(iat, address.to_bytes(ptr_size, "little"))
            self.module_loader.import_bindings.update(pending)
        except import_errors:
            logger.warning("invalid injected PE import table at %#x", base_addr, exc_info=True)

    def get_mod_by_name(self, name):
        name_lower = name.lower()
        for mod in self.modules:
            mod_name = ntpath.basename(mod.emu_path)
            base_name = os.path.splitext(mod_name)[0]
            if base_name.lower() == name_lower:
                return mod
            if mod.name and mod.name.lower() == name_lower:
                return mod
        return None

    def get_peb_modules(self):
        return [mod for mod in self.modules if mod.visible_in_peb]

    def _set_input_metadata(self, path, data):
        if not self.profiler:
            return
        pe = winemu._PeParser(path=path, data=data, fast_load=True)
        file_type = None
        if pe.is_driver():
            file_type = FileType.DRIVER
        elif pe.is_dll():
            file_type = FileType.DLL
        elif pe.is_exe():
            file_type = FileType.EXE
        self.input = {
            "path": pe.path or None,
            "sha256": pe.hash,
            "size": pe.file_size,
            "arch": REPORT_ARCHES.get(pe.arch),
            "file_type": file_type,
            "emu_version": self.get_emu_version(),
            "os_run": self.get_osver_string(),
        }
        self.profiler.add_input_metadata(self.input)

    def load_image(self, image, base: int | None = None, *, is_input: bool = False) -> RuntimeModule:
        """
        Load an image and its dependencies.

        Set is_input for the input image. The input image is the first module in modules, and the emulator
        allocates the stack only for the input image.
        """
        return self.module_loader.load_image(image, base, is_input=is_input)

    def _load_image(self, image, base=None, *, is_input=False):
        """
        Map an image at base, or at its preferred base, or at the next free range after it.

        An image with preferred base 0 loads at any free address.

        Raises:
            ValueError: if the image cannot move to the free base, for example because it has no relocation data.
            WindowsEmuError: if the machine is not initialized, or the image does not match the machine.
        """
        if not self.arch:
            raise WindowsEmuError("the machine is not initialized: call init_machine before loading images")
        if image.arch in (_arch.ARCH_X86, _arch.ARCH_AMD64) and self.arch != image.arch:
            raise WindowsEmuError("module architecture does not match the emulated process")
        if image.source == "synthetic" and not image.image_base:
            raise WindowsEmuError("synthetic image addresses must be finalized before mapping")

        for region in image.regions:
            if region.base < 0 or region.base + len(region.data) > image.image_size:
                raise WindowsEmuError("module region is outside its image span")
        requested_base = base or image.image_base
        if requested_base:
            base, _ = self.get_valid_ranges(image.image_size, addr=requested_base)
            if base != requested_base:
                logger.debug("module %s: base %#x is in use, loading at %#x", image.name, requested_base, base)
            image = relocate_image(image, base)
        base = self.mem_map(
            image.image_size,
            base=base or None,
            tag=f"emu.module.{image.name}",
            process=self.get_current_process() if self.is_kernel_mode else None,
        )
        if not requested_base:
            image = relocate_image(image, base)
        for region in image.regions:
            self.mem_write(region.base, region.data)

        mod = RuntimeModule(image)
        if is_input:
            self.modules.insert(0, mod)
            for problem in image.problems:
                self.profiler.record_error_event(ErrorInfo(type=ErrorType.INVALID_IMAGE, context_summary=problem))
        else:
            self.modules.append(mod)
        self.api_registry.register_module(mod)
        if is_input and image.source == "guest_pe" and not self.stack_base and image.stack_size:
            self.stack_base, _stack_addr = self.alloc_stack(self.config.stack_size or image.stack_size)

        ptr_size = self.get_ptr_size()
        for imp in image.imports:
            try:
                if not mod.base <= imp.iat_address <= mod.base + mod.image_size - ptr_size:
                    raise WindowsEmuError("import IAT slot outside image")
                address = self.get_proc(imp.dll_name, imp.func_name)
                if not address:
                    raise WindowsEmuError(f"unresolved import {imp.dll_name}!{imp.func_name}")
                encoded = address.to_bytes(ptr_size, "little")
            except (ValueError, OverflowError, uc.UcError, WindowsEmuError) as error:
                logger.warning("skipping import %s!%s in %s: %s", imp.dll_name, imp.func_name, image.name, error)
                continue
            self.mem_write(imp.iat_address, encoded)
            self.module_loader.import_bindings[imp.iat_address] = address

        for entry in tuple(self.api_registry.entries.values()):
            if entry.export.kind == "data":
                self._initialize_api_data(entry)

        if image.sections and image.module_type != "shellcode":
            first_rva = min(section.virtual_address for section in image.sections)
            if first_rva:
                self.mem_protect(
                    mod.base, (first_rva + self.page_size - 1) & ~(self.page_size - 1), common.PERM_MEM_READ
                )
            page_perms: dict[int, int] = {}
            for section in image.sections:
                start = (mod.base + section.virtual_address) & ~(self.page_size - 1)
                end = (mod.base + section.virtual_address + section.virtual_size + self.page_size - 1) & ~(
                    self.page_size - 1
                )
                # Sections can be smaller than a page, and two sections can share a page. Merge the
                # permissions of each page, so that a small read-only section does not remove the
                # write or execute permission of an earlier section on the same page.
                for page in range(start, end, self.page_size):
                    page_perms[page] = page_perms.get(page, 0) | section.perms
            # Each mem_protect call of Unicorn splits a region, and the cost of a call grows with the
            # number of regions. So protect each range of adjacent pages with equal perms in one call.
            for start, length, perms in get_page_protection_runs(page_perms, self.page_size):
                self.mem_protect(start, length, perms)

        if (
            image.source in ("guest_pe", "guest_shellcode")
            and self.profiler
            and self.config.analysis.strings
            and image.regions
        ):
            raw = image.regions[0].data
            self.profiler.strings["ansi"] = [a[1] for a in self.get_ansi_strings(raw)]
            self.profiler.strings["unicode"] = [u[1] for u in self.get_unicode_strings(raw)]
        process = self.get_current_process()
        is_before_peb = process is None or not process.is_peb_active
        if not self.is_kernel_mode and is_before_peb and mod.visible_in_peb and mod.is_dll():
            self.module_loader.shared_peb_modules.add(mod.base)
        self._add_module_to_current_peb(mod)
        return mod

    def get_system_root(self):
        """Get the path of the "SYSTEMROOT" environment variable."""
        sysroot = self.get_env().get("systemroot", "C:\\Windows")
        if not sysroot.endswith("\\"):
            sysroot += "\\"
        return sysroot

    def get_cd(self):
        """Get the path of the current directory of the current process."""
        state = self._get_process_state()
        if not state.cd:
            state.cd = state.env.get("cd", "C:\\WINDOWS\\system32")
            if not state.cd.endswith("\\"):
                state.cd += "\\"
        return state.cd

    def set_cd(self, cd):
        """Set the path of the current directory of the current process."""
        self._get_process_state().cd = cd

    def get_env(self):
        """Get the environment variables of the current process, by lower-case name."""
        return self._get_process_state().env

    def set_env(self, var, val):
        return self.get_env().update({var.lower(): val})

    def get_object_from_addr(self, addr):
        om = self.get_object_manager("object lookup by address")
        return om.get_object_from_addr(addr)

    def get_object_from_id(self, id):
        om = self.get_object_manager("object lookup by id")
        return om.get_object_from_id(id)

    def get_object_from_name(self, name):
        om = self.get_object_manager("object lookup by name")
        return om.get_object_from_name(name)

    def get_object_from_handle(self, handle):
        om = self.get_object_manager("object lookup by handle")
        return om.get_object_from_handle(handle)

    def get_object_handle(self, obj):
        om = self.get_object_manager("object handle lookup")
        obj = om.objects.get(obj.address)
        if obj:
            return om.new_handle(obj)

    def get_handle_table(self) -> HandleTable:
        """Get the handle table of the current process, or the table of the emulator if no process exists."""
        proc = self.get_current_process()
        return proc.handles if proc is not None else self.handles

    def _get_process_state(self) -> "objman.Process | WindowsEmulator":
        """Get the current process, or the emulator if no process exists, for the state that each process has."""
        proc = self.get_current_process()
        return proc if proc is not None else self

    def get_veh_handlers(self) -> list[int]:
        """Get the vectored exception handlers of the current process, in the order that the dispatcher calls them."""
        return self._get_process_state().veh_handlers

    def get_unhandled_exception_handler(self) -> int:
        """Get the filter that SetUnhandledExceptionFilter set for the current process, or 0."""
        return self._get_process_state().unhandled_exception_filter

    def get_function_tables(self) -> list[unwind.FunctionTable]:
        """Get the function tables that the current process registered at runtime."""
        return self._get_process_state().function_tables

    def get_heap_allocs(self) -> list[tuple[int, int, str]]:
        """Get the address, size and heap name of each block that heap_alloc returned in the current process."""
        return self._get_process_state().heap_allocs

    def get_pseudo_handle_object(self, handle: int) -> Any:
        """Get the current process for the pseudo handle -1, the current thread for -2, else None."""
        handle &= HANDLE_MASK
        if handle == CURRENT_PROCESS_HANDLE:
            return self.get_current_process()
        if handle == CURRENT_THREAD_HANDLE:
            return self.get_current_thread()
        return None

    def add_object(self, obj):
        om = self.get_object_manager("object registration")
        om.add_object(obj)

    def new_object(self, otype):
        om = self.get_object_manager("object creation")
        return om.new_object(otype)

    def create_process(self, path=None, cmdline=None, image=None, *, child=False, cd=""):
        """
        Create a process with one thread for the program in path, or in cmdline if path is empty.

        Add the process to child_processes if child is set, else to processes. An empty cd gives the process the
        current directory of the current process.

        Raises:
            IsADirectoryError: if the program path is a directory.
            FileSystemEmuError: if there is no program name, or the path ends in a separator.
        """
        om = self.get_object_manager("process creation")

        if path:
            file_path = path.strip().strip('"')
        else:
            # As CreateProcess does: a quoted program name ends at the next quote, any other at white space
            head = (cmdline or "").lstrip()
            if head.startswith('"'):
                file_path = head[1:].partition('"')[0]
            else:
                file_path = head.split(maxsplit=1)[0] if head else ""
        if not file_path:
            raise FileSystemEmuError("process creation needs a program name")
        if self.fileman.is_directory(file_path):
            raise IsADirectoryError(file_path)
        if file_path.endswith(("\\", "/")):
            raise FileSystemEmuError(f"process creation needs a file name: {file_path}")

        p = om.new_object(objman.Process)

        mod_data = self.get_module_data_from_emu_file(file_path)

        if mod_data:
            p.pe_data = mod_data
        else:
            new_mod = self.load_module_by_name(file_path, emu_path=file_path)
            p.pe = new_mod

        p.path = file_path
        p.image = ntpath.basename(file_path)
        p.cmdline = cmdline
        if cd:
            p.cd = cd

        t = om.new_object(objman.Thread)
        t.process = p

        peb_addr = p.peb.address
        mod_base = 0
        if p.pe:
            mod_base = getattr(p.pe, "base", 0) or 0
        if mod_base:
            p.peb.object.ImageBaseAddress = mod_base
            p.peb.write_back()

        ep_addr = 0
        if p.pe:
            ep_addr = (getattr(p.pe, "base", 0) or 0) + (getattr(p.pe, "ep", 0) or 0)

        if t.ctx and self.get_arch() == _arch.ARCH_AMD64:
            t.ctx.Rip = 0
            t.ctx.Rcx = ep_addr
            t.ctx.Rdx = peb_addr
        elif t.ctx and self.get_arch() == _arch.ARCH_X86:
            t.ctx.Eip = 0
            t.ctx.Eax = ep_addr
            t.ctx.Ebx = peb_addr

        p.threads.append(t)

        if child:
            self.child_processes.append(p)
        else:
            self.processes.append(p)

        return p

    def create_thread(self, addr, ctx, proc_obj, name=None, *, is_suspended=False):
        """
        Create a thread of proc_obj and a run that starts at addr.

        Add the run to the queue, or to the suspended runs if is_suspended is set. Return the handle and the thread,
        or (0, None) if the queue has max_runs runs.
        """
        om = self.get_object_manager("thread creation")

        if len(self.run_queue) >= self.max_runs:
            return 0, None

        thread = om.new_object(objman.Thread)
        thread.process = proc_obj
        hnd = om.new_handle(thread)

        run = Run()
        run.type = EntryPointType.THREAD
        run.name = name
        run.start_addr = addr
        run.instr_cnt = 0
        run.args = (ctx,)
        run.process_context = proc_obj
        run.thread = thread

        if not is_suspended:
            self.run_queue.append(run)
        else:
            thread.suspend_count = 1
            self.suspended_runs.append(run)

        return hnd, thread

    def resume_thread(self, thread):
        """Move the suspended run of thread to the queue. Return False if thread has no suspended run."""
        for r in self.suspended_runs:
            if r.thread == thread:
                _run = self.suspended_runs.pop(self.suspended_runs.index(r))
                self.run_queue.append(_run)
                return True
        return False

    def get_process_peb(self, process):
        return process.peb

    def add_callback(self, mod_name, func_name):
        """
        Get the address of an entry for the handler mod_name!func_name in the speakeasy_callbacks module.

        The guest calls such a function through a pointer that a handler wrote, for example in a function table or a
        vtable, not through an import.
        """
        module = self.get_mod_by_name("speakeasy_callbacks")
        if module is None:
            base, _ = self.get_valid_ranges(0x20000, addr=0x6E000000)
            image = ApiModuleLoader(
                name="speakeasy_callbacks",
                arch=self.arch,
                base=base,
                emu_path="speakeasy_callbacks.dll",
                signature_db=self.get_signature_db(),
            ).make_image()
            image.visible_in_peb = False
            module = self.load_image(image)
        entry = self.api_registry.dynamic(module, mod_name + "!" + func_name)
        entry.binding_module = mod_name
        entry.binding_name = func_name
        return entry.address

    def _initialize_api_data(self, entry):
        if not self.is_machine_ready:
            return
        if entry.dll == "ntoskrnl" and not self.is_kernel_mode:
            return
        if entry.initialized or entry.module._image.source != "synthetic":
            return
        mod, handler = self.api.get_data_export_handler(entry.dll, entry.name)
        if handler:
            address = self.api.call_data_func(mod, handler, entry.address)
            if address and address != entry.address:
                raise WindowsEmuError(f"data initializer for {entry.symbol} ignored its provided storage")
            if not address:
                return
        entry.initialized = True

    def resolve_export(self, module, reference, *, allow_dynamic=False, _seen=None, strict=False):
        reference = symbol_ref(reference)
        if isinstance(reference, int):
            if not 0 < reference <= 0xFFFF:
                return 0
        elif not isinstance(reference, str) or not reference or "\x00" in reference or len(reference) > 4096:
            return 0
        entry = self.api_registry.lookup(module, reference)
        if entry is None:
            if strict:
                return 0
            hooks = self.get_api_hooks(module.name, str(reference))
            eligible = allow_dynamic or self.config.modules.functions_always_exist or hooks
            # A function in the signature database resolves even if the module does not
            # export it, because other Windows builds export it.
            eligible = eligible or (isinstance(reference, str) and self.has_api_signature(module.name, reference))
            # A synthetic module without exports gives a dynamic entry for each name.
            eligible = eligible or (module._image.source == "synthetic" and not module.get_exports())
            if not eligible or module._image.source != "synthetic" or module is getattr(self, "container_image", None):
                return 0
            try:
                entry = self.api_registry.dynamic(module, reference)
            except WindowsEmuError:
                logger.debug("cannot allocate API entry for %s!%s", module.name, reference, exc_info=True)
                return 0
        forwarder = entry.export.forwarder
        if module._image.source != "synthetic":
            # Windows decides a forwarder by the export directory range in the mapped header.
            directory = self._get_export_directory(module)
            if directory is not None:
                rva, size = directory
                forwarder = (forwarder or "") if rva <= entry.address - module.base < rva + size else None
        if forwarder is not None:
            seen = set() if _seen is None else _seen
            key = (id(module), reference)
            if key in seen or len(seen) >= 32:
                return 0
            seen.add(key)
            target = forwarder
            if module._image.source != "synthetic":
                # Windows reads the forwarder from the mapped image when it resolves it.
                try:
                    target = self.read_mem_string(entry.address, 1, max_chars=4096)
                except Exception:
                    return 0
            if "." not in target:
                return 0
            dll, name = target.rsplit(".", 1)
            target_name = winemu.normalize_dll_name(module_name(dll))
            target_module = self.get_mod_by_name(target_name)
            if target_module is None:
                target_module = self.load_module_by_name(target_name)
            ref = int(name[1:]) if name.startswith("#") and name[1:].isdigit() else name
            return self.resolve_export(target_module, ref, _seen=seen, strict=True)
        if entry.export.kind == "data":
            self._initialize_api_data(entry)
        return entry.address

    def _get_export_directory(self, module):
        """Read the (RVA, size) of the export directory from the mapped header, or None if the read fails."""
        try:
            nt = module.base + struct.unpack("<I", self.mem_read(module.base + 0x3C, 4))[0]
            magic = struct.unpack("<H", self.mem_read(nt + 0x18, 2))[0]
            directories = nt + 0x18 + (112 if magic == 0x20B else 96)
            if not struct.unpack("<I", self.mem_read(directories - 4, 4))[0]:
                return 0, 0
            return struct.unpack("<II", self.mem_read(directories, 8))
        except (uc.UcError, struct.error):
            return None

    def get_import_host(self, dll: str, name: str | int) -> str:
        """
        Get the module that handles an import of dll!name.

        When the functions of an API set are in more than one module, use the first module that has a handler for the
        name.
        """
        hosts = winemu.get_dll_hosts(module_name(dll))
        if len(hosts) > 1 and isinstance(name, str):
            for host in hosts:
                if self.get_api_handler(host, name)[1] or self.api.get_data_export_handler(host, name)[1]:
                    return host
        return hosts[0]

    def get_proc(self, mod_name, func_name):
        """Get the address of func_name in the module that implements mod_name. Load the module if it is not loaded."""
        host = self.get_import_host(mod_name, func_name)
        module = self.get_mod_by_name(host)
        if module is None:
            module = self.load_module_by_name(host)
        return self.resolve_export(module, func_name, allow_dynamic=True)

    def _intercept_api_trap(self, access, address, size):
        """
        Record the native exit of a fetch from a return address or an API token, and fault other token accesses.

        Return True if the access is one of these, so that the other hooks for invalid memory do not run.
        """
        if self.emu_eng.mem_access.get(access) == common.INVALID_MEM_EXEC:
            if address in (self.return_hook, self.exit_hook) and self.curr_run:
                self._record_exit(RunReturn())
                return True
            if address == winemu.GUEST_CALLBACK_RETURN_ADDR and self.curr_run and self.curr_run.guest_callbacks:
                self._record_exit(CallbackReturn())
                return True
            entry = self.api_registry.traps.get(address)
            if entry is not None:
                self._record_exit(self._get_suspended_api_call(entry))
                return True
        if self.api_registry.overlaps_traps(address, size):
            kind = {
                common.INVALID_MEM_READ: "read",
                common.INVALID_MEM_WRITE: "write",
                common.INVALID_MEM_EXEC: "fetch",
            }.get(self.emu_eng.mem_access.get(access, common.INVALID_MEM_READ), "read")
            self._raise_memory_fault(address, kind)
            return True
        return False

    def _raise_memory_fault(self, address, access_type):
        """From a Unicorn hook: raise the access violation of an access to unmapped memory."""
        pc = address if access_type == "fetch" else self.get_pc()
        exception = cpu_exceptions.memory_fault(pc, address, access_type)
        self.raise_cpu_exception(exception, ErrorType(f"invalid_{access_type}"), access_type=access_type)
        return False

    def raise_cpu_exception(self, exception, error_type: ErrorType, **details):
        """From a Unicorn hook: record the exception as a native exit and stop Unicorn. Then the run loop sends it."""
        self._record_exit(RaisedCpuException(exception, error_type, **details))

    def _dispatch_cpu_exception(self, raised: RaisedCpuException) -> None:
        exception = raised.exception
        if raised.rax is not None:
            self.reg_write(
                _arch.AMD64_REG_RAX if self.get_arch() == _arch.ARCH_AMD64 else _arch.X86_REG_EAX, raised.rax
            )
        if raised.guard_page is not None:
            page, perms = raised.guard_page
            self.mem_protect(page, self.page_size, perms)
        self.set_pc(exception.pc)
        self.prev_pc = exception.pc
        faulting_address = exception.params[1] if raised.access_type else None
        error = guest_callbacks.CallbackError(
            raised.error_type,
            exception.address if faulting_address is None else faulting_address,
            raised.access_type,
            pc=exception.pc,
            interrupt_num=raised.interrupt_num,
        )
        dispatch = self.config.exceptions.dispatch_handlers
        if dispatch and self.dispatch_seh(faulting_address, exception, error):
            return
        guest_callbacks.fail(self, error)

    def _can_raise_api_fault(self):
        return not self.is_kernel_mode and self.config.exceptions.dispatch_handlers

    def _raise_api_fault(self, frame, access_type, address):
        """
        Raise an access violation in the caller of an API, because the handler of the API accessed a bad pointer.

        On Windows, the code of the API raises this access violation.

        Return False if the dispatch fails before it calls guest code.
        """
        params = (cpu_exceptions.ACCESS_CODES[access_type], address)
        try:
            dispatch_exception = self.exception_dispatcher().dispatch_exception
            fault = seh.raise_in_caller(self, ddk.STATUS_ACCESS_VIOLATION, 0, params, dispatch_exception)
            guest_callbacks.start(self, frame, fault)
        except guest_callbacks.CallbackError:
            self.get_current_run().guest_callbacks.remove(frame)
            return False
        return True

    def set_guard_pages(self, address, size, perms):
        """Remove all access from the pages. The first access restores perms and raises a guard page exception."""
        base = address & ~(self.page_size - 1)
        end = (address + size + self.page_size - 1) & ~(self.page_size - 1)
        for page in range(base, end, self.page_size):
            self.guard_pages[page] = perms
        self.mem_protect(base, end - base, common.PERM_MEM_NONE)

    def clear_guard_pages(self, address, size):
        for page in range(address & ~(self.page_size - 1), address + size, self.page_size):
            self.guard_pages.pop(page, None)

    def _raise_protection_fault(self, address, access_type):
        """From a Unicorn hook: raise the exception for an access that page protections deny."""
        page = address & ~(self.page_size - 1)
        pc = address if access_type == "fetch" else self.get_pc()
        perms = self.guard_pages.pop(page, None)
        if perms is not None:
            exception = cpu_exceptions.memory_fault(
                pc, address, access_type, code=cpu_exceptions.STATUS_GUARD_PAGE_VIOLATION
            )
            self.raise_cpu_exception(
                exception, ErrorType.GUARD_PAGE_VIOLATION, access_type=access_type, guard_page=(page, perms)
            )
        else:
            exception = cpu_exceptions.memory_fault(pc, address, access_type)
            self.raise_cpu_exception(exception, ErrorType(f"invalid_protect_{access_type}"), access_type=access_type)
        return False

    def _step_had_no_effect(self, registers, debugger):
        """Get whether a single step did not change the registers, and no stop or exit is pending."""
        if debugger.has_pending_stop() or self._native_exit is not None:
            return False
        return self._pending_fault_stop is None and self.get_register_state() == registers

    def _stopped_at_hlt(self, deadline, last_executed, counted, debugger):
        """
        Get whether Unicorn stopped because the guest ran ``hlt``, which user mode cannot run.

        Unicorn stops without an error after ``hlt``, and also for other reasons. So report a ``hlt`` only if it ran:
        it is the last instruction that the accounting hook counted or that a debugger step ran, or nothing else
        stopped Unicorn.

        Unicorn has no better way to report ``hlt``. Of the x86 instructions, Unicorn hooks only ``in``, ``out``,
        ``syscall``, ``sysenter`` and ``cpuid``. ``hlt`` raises no interrupt, and a code hook on each instruction
        makes all emulation slower.
        """
        if self.is_kernel_mode or not self.config.exceptions.dispatch_handlers:
            return False
        if self._native_exit is not None:
            return False
        if deadline is not None and time.monotonic() >= deadline:
            return False
        if debugger is not None and debugger.has_pending_stop():
            return False
        pc = self.get_pc()
        if last_executed is not None:
            if last_executed != pc - 1:
                return False
        elif counted or (self.exit_event and self.exit_event.is_set()):
            return False
        try:
            return self.mem_read(pc - 1, 1) == b"\xf4"
        except uc.UcError:
            return False

    def _hook_invalid_instruction(self, emu):
        if not self.config.exceptions.dispatch_handlers:
            return False
        pc = self.get_pc()
        exception = cpu_exceptions.from_invalid_instruction(pc, self.mem_read(pc, 1))
        self.raise_cpu_exception(exception, ErrorType.INVALID_INSTRUCTION)
        return False

    def _hook_in_instruction(self, emu, port, size):
        rax = self.get_return_val()
        self.raise_cpu_exception(
            cpu_exceptions.privileged_instruction(self.get_pc()), ErrorType.PRIVILEGED_INSTRUCTION, rax=rax
        )
        return rax & 0xFFFFFFFF

    def _hook_out_instruction(self, emu, port, size, value):
        self.raise_cpu_exception(cpu_exceptions.privileged_instruction(self.get_pc()), ErrorType.PRIVILEGED_INSTRUCTION)

    def _get_suspended_api_call(self, entry: ApiEntry) -> SuspendedApiCall:
        sp = self.get_stack_ptr()
        try:
            return_address = self.mem_read(sp, self.ptr_size)
        except uc.UcError:
            return_address = None
        try:
            code = self.mem_read(entry.address, 16)
        except uc.UcError:
            code = None
        return SuspendedApiCall(entry, sp, return_address, code)

    def _handle_invalid_fetch(self, emu, address, size, value):
        """Handle a fetch from unmapped memory."""
        if address == self.return_hook or address == self.exit_hook:
            self._map_reserved_range()
            return True

        # The fetch is the rest of an instruction that crosses into the next page. The fault at its start ends the run.
        if isinstance(self._native_exit, RunEnd) or self._pending_fault_stop is not None:
            return False

        return self._raise_memory_fault(address, "fetch")

    def _resolve_module_offset(self, addr: int) -> tuple[str, int] | None:
        """Return the name of the loaded module that contains addr and the offset of addr in it, or None."""
        mod = self.get_module_from_addr(addr)
        if mod:
            name = getattr(mod, "name", None) or getattr(mod, "path", None) or "unknown"
            return name, addr - mod.base
        return None

    def _format_module_offset(self, addr: int) -> str:
        """Return 'module+0xoffset' for an address inside a loaded module, or the address in hex."""
        resolved = self._resolve_module_offset(addr)
        if resolved is None:
            return hex(addr)
        name, offset = resolved
        return f"{name}+{offset:#x}"

    def _resolve_region_info(self, addr: int) -> RegionInfo | None:
        """Return a RegionInfo for the region containing addr, or None if unmapped."""
        for m in self.get_mem_maps():
            if m.base <= addr <= (m.base + m.size) - 1:
                prot = get_prot_string(m.prot) if m.prot is not None else None
                return RegionInfo(tag=m.tag or "unknown", base=m.base, size=m.size, perms=prot)
        return None

    def _find_nearby_regions(self, addr: int, count: int = 2) -> list[RegionInfo]:
        """Return up to ``count`` memory regions nearest to an unmapped address."""
        maps = self.get_mem_maps()
        if not maps:
            return []
        distances = []
        for m in maps:
            end = m.base + m.size - 1
            if addr < m.base:
                dist = m.base - addr
            elif addr > end:
                dist = addr - end
            else:
                continue
            prot = get_prot_string(m.prot) if m.prot is not None else None
            distances.append((dist, RegionInfo(tag=m.tag or "unknown", base=m.base, size=m.size, perms=prot)))
        distances.sort(key=lambda x: x[0])
        return [r for _, r in distances[:count]]

    def _build_context_summary(
        self,
        desc: str,
        pc: int,
        address: int,
        access_type: str | None,
        pc_module: str | None,
        address_region: RegionInfo | None,
        nearby_regions: list[RegionInfo] | None,
    ) -> str:
        """
        Build a one-line summary of an error for the report.

        Examples:
            read of unmapped 0x12345678 from sample.exe+0x8d14; nearest: heap [0x12340000-0x12340fff]
            write of 0x401500 from sample.exe+0x2000; in .text [0x401000-0x405fff]
            fetch at 0xdeadbeef from pc=0xdeadbeef
        """
        parts = []
        access_str = access_type or desc
        if address != pc:
            parts.append(f"{access_str} of {'unmapped ' if not address_region else ''}0x{address:x}")
        else:
            parts.append(f"{access_str} at 0x{address:x}")
        if pc_module:
            parts.append(f"from {pc_module}")
        else:
            parts.append(f"from pc=0x{pc:x}")
        if address_region:
            ri = address_region
            parts.append(f"in {ri.tag} [0x{ri.base:x}-0x{ri.base + ri.size - 1:x}]")
        elif nearby_regions:
            nearest = nearby_regions[0]
            parts.append(f"nearest: {nearest.tag} [0x{nearest.base:x}-0x{nearest.base + nearest.size - 1:x}]")
        return "; ".join(parts)

    def get_error_info(
        self,
        desc: ErrorType,
        address: int,
        traceback: str | None = None,
        access_type: str | None = None,
        api_name: str | None = None,
        message: str | None = None,
    ) -> ErrorInfo:
        """
        Get the state of the emulator for an error.

        For an error at an API call, give the API name, and the return address
        as address, because the token has no instruction to show.
        For an ``internal_error``, give the text of the Python exception as message.
        """
        run = self.get_current_run()
        pc = self.get_pc()

        if api_name:
            instr = f"api_trap {api_name}"
        else:
            try:
                mnem, op, instr = self.get_disasm(pc, _arch.DISASM_SIZE)
            except Exception as e:
                logger.error(str(e))
                instr = "disasm_failed"

        registers = self.get_register_state()
        stack = self.get_stack_trace()
        pc_module, pc_offset = self._resolve_module_offset(pc) or (None, None)
        address_region = self._resolve_region_info(address)
        nearby_regions = self._find_nearby_regions(address) if not address_region else None
        tid = self.curr_thread.tid if self.curr_thread else None
        pid = self.curr_process.id if self.curr_process else None

        label = f"{desc.value}: {message}" if message else desc.value
        if api_name:
            summary = f"{label} {api_name} called from {self._format_module_offset(address)}"
        else:
            summary = self._build_context_summary(
                label,
                pc,
                address,
                access_type,
                self._format_module_offset(pc) if pc_module else None,
                address_region,
                nearby_regions,
            )

        logger.error(
            "0x%x: %s: Caught error: %s\n  summary: %s\n  instr: %s\n  regs: %s",
            pc,
            run.get_label(),
            label,
            summary,
            instr,
            "  ".join(f"{k}={v:#x}" for k, v in registers.items()),
        )

        return ErrorInfo(
            type=desc,
            pc=pc,
            address=address,
            access_type=AccessType(access_type) if access_type else None,
            instruction=instr,
            registers=registers,
            stack=stack,
            pc_module=pc_module,
            pc_offset=pc_offset,
            address_region=address_region,
            nearby_regions=nearby_regions,
            tid=tid,
            pid=pid,
            context_summary=summary,
            traceback=traceback,
            message=message,
        )

    def get_api_handler(self, dll: str, name: str) -> tuple[Any, Any]:
        """
        Get the module and attributes of the handler for dll!name.

        If there is no handler for the name, try the names from get_handler_candidates. Return (None, None) if no
        handler is found.
        """
        for cand_dll, cand_name in ((dll, name), *api_resolution.get_handler_candidates(dll, name)):
            mod, func_attrs = self.api.get_export_func_handler(cand_dll, cand_name)
            if func_attrs:
                return mod, func_attrs
        return None, None

    def read_unicode_string(self, addr):
        """Read string data from a UNICODE_STRING object located at the specified address."""
        us = windefs.UNICODE_STRING(self.get_ptr_size())
        us = self.mem_cast(us, addr)

        return self.read_mem_string(us.Buffer, width=2)

    @staticmethod
    def format_api_arg(arg: ApiArg) -> str:
        """Render a single API argument the way it appears in the API trace."""
        text = arg.display
        if arg.type == ApiArgType.STR or (arg.name is None and arg.type == ApiArgType.TEXT):
            text = sigfmt.quote_string(text)
        return f"{arg.name}: {text}" if arg.name is not None else text

    def log_api(self, pc: int, imp_api: str, rv: int | None, args: list[ApiArg], *, run=None) -> None:
        """Log an API call and record it in the report."""
        call_str = f"{imp_api}({', '.join(self.format_api_arg(arg) for arg in args)})"

        rv = self.get_machine_word(rv)
        rv_str = hex(rv) if rv is not None else None
        logger.info("%s: %s -> %s", hex(pc), repr(call_str), rv_str)
        run = self.curr_run if run is None else run
        if self.profiler and run:
            tick = run.instr_cnt
            thread = run.thread or self.curr_thread
            process = run.process_context or (thread.process if thread else None) or self.curr_process
            tid = thread.tid if thread else 0
            pid = process.id if process else 0
            pos = TracePosition(tick=tick, tid=tid, pid=pid, pc=pc)
            frame = self._active_api_frame
            if frame is not None and not any(item is frame for item in run.guest_callbacks):
                frame = None
            event = self.profiler.record_api_event(run, pos, imp_api, rv, args, deduplicate=frame is None)
            if frame is not None:
                frame.event = event

    def get_signature_db(self) -> sigdb.SignatureDatabase:
        """Get the API signature database used to emulate imports without a handler."""
        if self._sigdb is None:
            self._sigdb = sigdb.get_default_database()
        return self._sigdb

    def _get_signature_arch(self) -> str:
        return sigdb.ARCH_X86 if self.get_arch() == _arch.ARCH_X86 else sigdb.ARCH_X64

    def _lookup_api_declaration(self, dll: str, name: str) -> sigdb.FuncSig | None:
        """
        Get the declaration of dll!name, also a declaration that lookup_api_signature rejects.

        Raises:
            WindowsEmuError: if the signature database fails.
        """
        db = self.get_signature_db()
        arch = self._get_signature_arch()
        try:
            sig = db.get_functions(dll, arch).get(name)
            if sig is None:
                alt_dll = winemu.normalize_dll_name(dll)
                if alt_dll.lower() != dll.lower():
                    sig = db.get_functions(alt_dll, arch).get(name)
            if sig is None:
                sig = self._lookup_api_set_declaration(dll, name)
        except Exception as exc:
            raise WindowsEmuError(f"signature provider failed for {dll}!{name}: {exc}") from exc
        return sig

    def _lookup_api_set_declaration(self, dll: str, name: str) -> sigdb.FuncSig | None:
        """Get a declaration that the signature database has under an API set whose host is ``dll``."""
        db = self.get_signature_db()
        arch = self._get_signature_arch()
        sig = db.lookup(dll, name, arch)
        if sig is None or not sig.dll.lower().startswith(("api-ms-win-", "ext-ms-win-")):
            return None
        if winemu.normalize_dll_name(sig.dll).lower() != winemu.normalize_dll_name(dll).lower():
            return None
        return db.get_functions(sig.dll, arch).get(name)

    def lookup_api_signature(self, dll: str, name: str) -> sigdb.FuncSig | None:
        sig = self._lookup_api_declaration(dll, name)
        if sig is not None and not sig.supports_emulation(self.get_ptr_size()):
            logger.debug("signature for %s.%s cannot be emulated safely", dll, name)
            return None
        return sig

    def _can_stub_unknown_api(self, dll: str, name: str) -> bool:
        # A function with a declaration that the emulator cannot use is not
        # unknown, so it does not get a stub.
        return self.config.modules.functions_always_exist and self._lookup_api_declaration(dll, name) is None

    def has_api_signature(self, dll: str, name: str) -> bool:
        return self.lookup_api_signature(dll, name) is not None

    def get_handler_signature(self, dll: str, name: str, argc: int) -> sigdb.FuncSig | None:
        """
        Get the signature that names the arguments of a call to a handler.

        Return None if the function is unknown or variadic, or if its declaration does not use exactly the ``argc``
        slots that the handler reads.
        """
        try:
            sig = self.get_signature_db().lookup(dll, name, self._get_signature_arch())
        except Exception:
            logger.debug("handler argument signature unavailable for %s!%s", dll, name, exc_info=True)
            return None
        if sig is None or sig.skip or sig.variadic or sig.slot_count(self.get_ptr_size()) != argc:
            return None
        return sig

    def get_signature_formatter(self) -> sigfmt.ArgFormatter:
        """
        Get the formatter that renders API arguments from their signatures for the report.

        The formatter renders strings, enums, flags and struct contents.
        """
        if self._sigfmt is None:
            xmm = (_arch.X86_REG_XMM0, _arch.X86_REG_XMM1, _arch.X86_REG_XMM2, _arch.X86_REG_XMM3)
            self._sigfmt = sigfmt.ArgFormatter(
                self.get_signature_db(),
                self.get_ptr_size(),
                self.mem_read,
                read_xmm=lambda index: self.reg_read(xmm[index]),
            )
        return self._sigfmt

    def _render_signature_arg(self, param: sigdb.ParamSig, value: int, index: int) -> sigfmt.RenderedArg:
        try:
            return self.get_signature_formatter().render_param(param, value, index)
        except Exception:
            logger.debug("failed to render %s (%s)", param.name, param.code, exc_info=True)
            return sigfmt.RenderedArg(hex(value), ApiArgType.INT)

    def _render_signature_args(self, sig: sigdb.FuncSig, argv: list[int]) -> list[sigfmt.RenderedArg]:
        values = sig.values_from_slots(argv, self.get_ptr_size())
        return [self._render_signature_arg(param, value, i) for i, (param, value) in enumerate(zip(sig.params, values))]

    # The maximum number of bytes that the emulator zeroes for one Out parameter
    MAX_OUT_ZERO_FILL = 0x10000

    def _read_uint_for_signature(self, addr: int, size: int) -> int | None:
        try:
            return int.from_bytes(self.mem_read(addr, size), "little")
        except Exception:
            return None

    def _zero_fill_out_params(self, sig: sigdb.FuncSig, values: list[int], ptr_size: int) -> None:
        """
        Zero the buffers of the Out parameters that are not also In parameters.

        A call from a signature returns success but writes no data. So the caller reads zeros, such as empty strings,
        NULL handles and zero counts, and not old stack data.
        """
        db = self.get_signature_db()
        for index, (param, value) in enumerate(zip(sig.params, values)):
            if not param.is_out or param.is_in or not value:
                continue
            size = sigdb.out_buffer_size(sig, index, values, ptr_size, db.lookup_struct, self._read_uint_for_signature)
            if not size or size < 0:
                continue
            size = min(size, self.MAX_OUT_ZERO_FILL)
            try:
                self.mem_write(value, b"\x00" * size)
            except Exception:
                logger.debug(
                    "%s: could not zero %d bytes at %s for Out param %s", sig.name, size, hex(value), param.name
                )

    def _default_return_for_signature(self, sig: sigdb.FuncSig) -> int | None:
        """Get a success value for the return type of a call from a signature."""
        kind = sig.ret_kind
        if kind == "v":
            return None
        if kind in sigdb.BOOL_KINDS:
            return 1
        if kind == "h":
            if self.om is not None:
                return self.om.allocate_handle()
            return 4
        # For status codes (HRESULT, NTSTATUS, WIN32_ERROR), 0 is success. For
        # counts and pointers, 0 means no data.
        return 0

    def _handle_api_from_signature(self, dll: str, name: str, sig: sigdb.FuncSig, call_pc: int) -> int | None:
        """
        Run an API that has no handler from its signature.

        Read the arguments, log the call, zero the Out buffers, and return a success value for the return type. Remove
        the arguments from the stack as the calling convention requires.
        """
        imp_api = f"{dll}.{name}"
        ptr_size = self.get_ptr_size()
        conv = _arch.CALL_CONV_CDECL if sig.conv == sigdb.CONV_CDECL else _arch.CALL_CONV_STDCALL
        argc = sig.slot_count(ptr_size)

        argv = self.get_func_argv(conv, argc)
        values = sig.values_from_slots(argv, ptr_size)
        args = sigfmt.get_call_args(sig, ptr_size, self._render_signature_args(sig, argv), argv)

        rv = self._default_return_for_signature(sig)
        logger.debug(
            "%s: no handler for %s; emulating from %s signature (%d params, %s, argc=%d)",
            hex(call_pc),
            imp_api,
            sig.source,
            len(sig.params),
            sig.conv,
            argc,
        )

        self.hammer.handle_import_func(imp_api, conv, argc)
        self._zero_fill_out_params(sig, values, ptr_size)
        if sig.set_last_error:
            set_last_error = getattr(self, "set_last_error", None)
            if set_last_error:
                set_last_error(0)

        ret = self.get_ret_address()
        self.log_api(call_pc, imp_api, rv, args)
        self.do_call_return(argc, ret, rv, conv=conv)
        if not self.is_run_complete:
            self.enable_deferred_work_hook()
        return rv

    def get_api_args(self) -> list[ApiArg]:
        """
        Get the arguments of the hooked API call in progress, as the report shows them.

        An API hook calls this after it calls the original handler to see the
        values the handler decoded, such as the strings behind pointer arguments.
        Outside an API hook the list is empty.
        """
        return self.api_ctx.args.get_report_args()

    def resolve_api_implementation(self, dll: str, name: str) -> api_resolution.ApiImplementation:
        """
        Find the code to run for dll!name.

        Look in this order: a handler, user hooks, the signature database, a stub.
        """
        mod, func_attrs = self.get_api_handler(dll, name)
        if func_attrs:
            handler_name, func, argc, conv, _ = func_attrs
            if name.startswith("ordinal_"):
                name = handler_name
            return api_resolution.HandlerImplementation(mod, name, func, argc, conv)
        hooks = self.get_api_hooks(dll, name)
        if hooks:
            return api_resolution.UserHookImplementation(hooks)
        sig = self.lookup_api_signature(dll, name)
        if sig is not None:
            return api_resolution.SignatureImplementation(sig)
        if self._can_stub_unknown_api(dll, name):
            return api_resolution.StubImplementation()
        return api_resolution.UnsupportedImplementation()

    def dispatch_api_call(self, dll: str, name: str) -> None:
        """
        Run the code for the API that the guest called.

        End the run if the code changed the stack pointer but did not return.
        """
        frame = GuestCallbackFrame(self.get_stack_ptr(), self.get_ret_address())
        previous = self._active_api_frame
        self._active_api_frame = frame
        origin_run = self.curr_run
        entry_pc = self.get_pc()
        try:
            self._call_api_implementation(dll, name, frame)
            if (
                origin_run is not None
                and self.curr_run is origin_run
                and not self.is_run_complete
                and not self.is_emu_complete
                and self.get_pc() == entry_pc
                and self.get_stack_ptr() != frame.stack_pointer
                and self._native_exit is None
                and not origin_run.guest_callbacks
            ):
                origin_run.error = self.get_error_info(ErrorType.API_HANDLER_DID_NOT_RETURN, entry_pc)
                origin_run.error.api_name = f"{dll}.{name}"
                logger.error("API handler %s.%s changed SP without returning", dll, name)
                self.end_run_on_fault()
        except uc.UcError as e:
            # The API code accessed unmapped memory when it read the arguments or wrote the results
            kind, address, access_type, _ = guest_callbacks.get_handler_fault(self, e, entry_pc)
            if access_type is None or self._should_stop_on_faults:
                raise
            logger.error("0x%x: %s in the call of %s.%s", entry_pc, kind.value, dll, name)
            guest_callbacks.fail(self, guest_callbacks.CallbackError(kind, address, access_type))
        finally:
            self._active_api_frame = previous

    def _call_api_implementation(self, dll: str, name: str, frame: GuestCallbackFrame) -> None:
        """Find the code for the API and run it. Then check the API count limit."""
        ret = self.get_ret_address()
        call = _ApiCallState(
            dll=dll,
            name=name,
            frame=frame,
            run=self.curr_run,
            pc=self.get_pc(),
            sp=self.get_stack_ptr(),
            return_address=ret,
            call_pc=self.prev_pc if self.prev_pc != 0 else ret,
        )
        impl = self.resolve_api_implementation(dll, name)
        api_name = call.api_name
        match impl:
            case api_resolution.HandlerImplementation():
                api_name = f"{dll}.{impl.name}"
                if not self._handle_api_with_handler(call, impl):
                    return
            case api_resolution.UserHookImplementation():
                self._handle_api_hook(call, impl.hooks)
            case api_resolution.SignatureImplementation():
                self._handle_api_from_signature(dll, name, impl.sig, call.call_pc)
            case api_resolution.StubImplementation():
                self._handle_api_stub(call)
            case api_resolution.UnsupportedImplementation():
                self._handle_unsupported_api(call)
        self._check_api_limit(call.run, api_name)

    def _handle_api_with_handler(self, call: _ApiCallState, impl: api_resolution.HandlerImplementation) -> bool:
        """
        Run the handler of the API, or the user hooks for the API.

        Return False if the handler failed, and the run ended or a guest exception started.
        """
        dll, name = call.dll, impl.name
        imp_api = f"{dll}.{name}"
        frame = call.frame
        frame.argc = impl.argc
        frame.convention = impl.conv
        argv = self.get_func_argv(impl.conv, impl.argc)

        # Render the arguments before the handler runs, while the memory
        # they point to still holds what the caller passed.
        sig = self.get_handler_signature(dll, name, impl.argc)
        if sig is not None:
            rendered = self._render_signature_args(sig, argv)
            args = HandlerArgs.from_signature(sig, self.get_ptr_size(), rendered, argv)
        else:
            args = HandlerArgs.from_slots(argv)
        ctx = ApiContext(func_name=imp_api, args=args)

        self.hammer.handle_import_func(imp_api, impl.conv, impl.argc)
        hooks = self.get_api_hooks(dll, name)
        if hooks:
            hooked_func = MethodType(impl.func, impl.module)
            orig = lambda args: hooked_func(self, args, ctx)  # noqa
            # All hooks run in the order of get_api_hooks. The return value of the last hook is the result.
            prev_ctx, self.api_ctx = self.api_ctx, ctx
            try:
                for hook in hooks:
                    rv = hook.cb(hook.emu, imp_api, orig, argv)
            finally:
                self.api_ctx = prev_ctx
        else:
            try:
                rv = self.api.call_api_func(impl.module, impl.func, argv, ctx=ctx)
            except Exception as e:
                if self._should_stop_on_faults:
                    # _execute_runs reports the fault to the debugger before it ends the run.
                    raise
                desc, address, access_type, message = guest_callbacks.get_handler_fault(self, e, self.get_pc())
                if access_type and self._can_raise_api_fault():
                    self.log_api(call.call_pc, imp_api, None, ctx.args.get_report_args(), run=call.run)
                    if self._raise_api_fault(frame, access_type, address):
                        return False
                logger.exception("0x%x: Error while calling API handler for %s:", call.return_address, imp_api)
                error = self.get_error_info(
                    desc, address, traceback=traceback.format_exc(), access_type=access_type, message=message
                )
                self.end_run(error)
                return False

        if isinstance(rv, Generator):
            rv = guest_callbacks.start_api_handler(self, frame, rv)
        elif isinstance(rv, guest_callbacks.Resume):
            guest_callbacks.transfer(self, rv.context)
            rv = None

        ret = self.get_ret_address()
        pc = self.get_pc()
        frame.result = rv
        mm = self.get_address_map(ret)

        # The return address is in memory that VirtualAlloc or ZwAllocateVirtualMemory allocated.
        if mm and mm.tag and any(name in mm.tag.lower() for name in ("virtualalloc", "allocatevirtualmemory")):
            self._fire_dyn_code_hooks(ret)

        self.log_api(call.call_pc, imp_api, rv, ctx.args.get_report_args(), run=call.run)

        if (
            self.curr_run is call.run
            and not self.is_run_complete
            and ret == call.return_address
            and pc == call.pc
            and self.get_stack_ptr() == call.sp
        ):
            self.do_call_return(impl.argc, ret, rv, conv=impl.conv)

        if not self.is_run_complete:
            self.enable_deferred_work_hook()
        return True

    def _handle_api_hook(self, call: _ApiCallState, hooks: list[common.ApiHook]) -> None:
        """
        Run the user hook of an API that has no handler.

        The hook gives the argument count and the calling convention. The hooks can give different values, so only the
        last hook from get_api_hooks runs.
        """
        if len(hooks) > 1:
            logger.warning(
                "%d hooks registered for unsupported API %s; only the last registered hook will be called",
                len(hooks),
                call.api_name,
            )
        hook = hooks[-1]
        if hook.call_conv is None:
            hook.call_conv = _arch.CALL_CONV_STDCALL

        argv = self.get_func_argv(hook.call_conv, hook.argc)
        call.frame.argc = hook.argc
        call.frame.convention = hook.call_conv
        self.hammer.handle_import_func(call.api_name, hook.call_conv, hook.argc)
        rv = hook.cb(hook.emu, call.api_name, None, argv)
        call.frame.result = rv
        ret = self.get_ret_address()
        self.log_api(call.call_pc, call.api_name, rv, sigfmt.get_slot_args(argv), run=call.run)
        if (
            self.curr_run is call.run
            and self.get_pc() == call.pc
            and ret == call.return_address
            and self.get_stack_ptr() == call.sp
        ):
            self.do_call_return(hook.argc, ret, rv, conv=hook.call_conv)
        if not self.is_run_complete:
            self.enable_deferred_work_hook()

    def _handle_api_stub(self, call: _ApiCallState) -> None:
        """
        Return 1 from an unknown API so that execution can continue.

        The argument count and the calling convention are not known, so guess stdcall with four arguments.
        """
        logger.warning("Stubbed unknown API %s with return 1", call.api_name)
        conv = _arch.CALL_CONV_STDCALL
        argc = 4
        argv = self.get_func_argv(conv, argc)
        call.frame.argc = argc
        call.frame.convention = conv
        call.frame.result = 1
        self.log_api(call.call_pc, call.api_name, 1, sigfmt.get_slot_args(argv), run=call.run)
        self.do_call_return(argc, call.return_address, 1, conv=conv)

    def _handle_unsupported_api(self, call: _ApiCallState) -> None:
        """End the run with an ``unsupported_api`` error."""
        error = self.get_error_info(ErrorType.UNSUPPORTED_API, call.return_address, api_name=call.api_name)
        logger.error("Unsupported API: %s (ret: 0x%x)", call.api_name, call.return_address)
        self.log_api(call.call_pc, call.api_name, None, [], run=call.run)
        error.api_name = call.api_name
        self.end_run(error)

    def _check_api_limit(self, origin_run, imp_api):
        run = self.get_current_run()
        if run is origin_run and run and not self.end_requested and run.get_api_count() > self.config.max_api_calls:
            logger.info("* Maximum number of API calls reached. Stopping current run.")
            self.end_run(
                ErrorInfo(
                    type=ErrorType.MAX_API_COUNT,
                    pc=self.get_pc(),
                    count=self.config.max_api_calls,
                    last_api=imp_api,
                )
            )

    def start_guest_callback(self, frame, function, args, sp=None):
        """Call function with args as a guest callback of frame, on the stack of frame or below sp."""
        if frame.saved_registers is None:
            registers = NONVOLATILE_AMD64 if self.get_arch() == _arch.ARCH_AMD64 else NONVOLATILE_X86
            frame.saved_registers = tuple((register, self.reg_read(register)) for register in registers)
        frame.function = function
        sp = frame.stack_pointer if sp is None else sp
        if self.ptr_size == 8:
            # Win64 callees expect RSP + 8 to be 16-byte aligned at entry, and
            # each argument after the fourth uses one 8-byte stack slot.
            sp &= ~0xF
            if max(len(args) - 4, 0) % 2:
                sp -= 8
        self.set_func_args(sp, winemu.GUEST_CALLBACK_RETURN_ADDR, *args, conv=_arch.CALL_CONV_STDCALL)
        self.set_pc(function)

    def _continue_guest_callback(self):
        """
        Continue the API handler after one of its guest callbacks returned.

        Resume the handler generator, start the next pending callback of the frame, or return from the API.
        """
        run = self.get_current_run()
        # Drop the frames of nested callbacks that the guest left without a return
        while len(run.guest_callbacks) > 1 and run.guest_callbacks[-1].stack_pointer < self.get_stack_ptr():
            run.guest_callbacks.pop()
        frame = run.guest_callbacks[-1]
        if frame.handler is not None:
            guest_callbacks.resume(self, frame)
            return
        routine = frame.initializers.get(frame.function)
        if routine is not None and not self.module_loader.finish_initializer(routine, self.get_return_val()):
            self._fail_library_initializer(frame, routine)
        self.set_stack_ptr(frame.stack_pointer)
        if frame.pending:
            function, args = frame.pending.pop(0)
            self.start_guest_callback(frame, function, args)
        else:
            run.guest_callbacks.pop()
            if frame.event is not None:
                frame.event.return_value = self.get_machine_word(frame.result)
            self.restore_caller_registers(frame)
            self.do_call_return(frame.argc, frame.return_address, frame.result, conv=frame.convention)

    def _fail_library_initializer(self, frame, routine):
        """
        Make the load call of the frame fail, and undo the loads that it made.

        Windows does this when a DllMain returns FALSE.
        """
        frame.result = frame.failure_result
        for address, data in frame.failure_writes:
            self.mem_write(address, data)
        self.set_last_error(1114)  # ERROR_DLL_INIT_FAILED
        self.module_loader.remove_failed_module_from_peb(routine.module, routine.pid)
        self.module_loader.rollback_guest_load(frame)

    def restore_caller_registers(self, frame):
        """Restore the nonvolatile registers that the guest callbacks of frame can change. Windows keeps them."""
        for register, value in frame.saved_registers or ():
            self.reg_write(register, value)

    def _hook_mem_unmapped(self, emu, access, address, size, value):
        """Handle an access to unmapped memory, or an access that the page protection denies."""
        try:
            access = self.emu_eng.mem_access.get(access)
            logger.debug("mem_unmapped: access=%s addr=0x%x size=0x%x", access, address, size)
            if access != common.INVALID_MEM_EXEC:
                self.prev_pc = self.get_pc()

            self.enable_deferred_work_hook()

            if access == common.INVALID_MEM_EXEC:
                return self._handle_invalid_fetch(emu, address, size, value)

            if access == common.INVALID_MEM_READ:
                return self._handle_invalid_read(emu, address, size, value)

            if access == common.INVAL_PERM_MEM_EXEC:
                if address & ~(self.page_size - 1) in self.guard_pages:
                    return self._raise_protection_fault(address, "fetch")
                return self._handle_prot_fetch(emu, address, size, value)
            if access == common.INVAL_PERM_MEM_READ and not self.is_kernel_mode:
                return self._raise_protection_fault(address, "read")
            if access == common.INVALID_MEM_WRITE:
                return self._handle_invalid_write(emu, address, size, value)
            if access == common.INVAL_PERM_MEM_WRITE:
                return self._handle_prot_write(emu, address, size, value)
        except Exception as e:
            return self._end_run_on_hook_error("Invalid memory exception", e)

    def _handle_prot_write(self, emu, address, size, value):
        guarded = address & ~(self.page_size - 1) in self.guard_pages
        if not guarded and size <= 8 and self._unprotect_resource_write(address):
            # Unicorn drops a store that a protection hook handles, so do the store here.
            self.mem_write(address, (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little"))
            return True
        if not self.is_kernel_mode and (guarded or self.config.exceptions.dispatch_handlers):
            return self._raise_protection_fault(address, "write")

        error = self.get_error_info(ErrorType.INVALID_PROTECT_WRITE, address, access_type="write")
        self._set_run_error(error)
        self.end_run_on_fault()
        return True

    def _unprotect_resource_write(self, address: int) -> bool:
        """
        Make the resource pages of an image writable when the guest writes into its resource data.

        The unhandled exception filter of Windows does the same for an access violation in resource data.
        """
        module = self.get_mod_from_addr(address)
        image = getattr(module, "_image", None)
        if image is None or image.resource_directory is None:
            return False
        start, size = image.resource_directory
        if not start <= address < start + size:
            return False
        base = start & ~0xFFF
        end = min((start + size + 0xFFF) & ~0xFFF, module.base + module.image_size)
        self.mem_protect(base, end - base, common.PERM_MEM_RW)
        return True

    def get_symbol_from_address(self, address) -> str | None:
        """Get the symbol at address as "dll.name", or None."""
        symbol = self.api_registry.symbol(address)
        if symbol is not None:
            return symbol
        if self.api_registry.overlaps_traps(address):
            return None
        auxiliary = self.symbols.get(address)
        return "{}.{}".format(*auxiliary) if auxiliary else None

    def get_symbols(self) -> dict[int, tuple[str, str]]:
        """
        Get a copy of the symbols as {address: (dll, name)}.

        If two symbols have the same address, the API registry entry wins.
        The result does not include forwarder strings or API tokens.
        """
        symbols = {
            address: value
            for address, value in self.symbols.items()
            if not self.api_registry.overlaps_traps(address)
            and not (
                address in self.api_registry.entries and self.api_registry.entries[address].export.forwarder is not None
            )
        }
        symbols.update(
            (address, (entry.dll, entry.name))
            for address, entry in self.api_registry.entries.items()
            if entry.export.forwarder is None
        )
        return symbols

    def get_api_symbols(self) -> dict[int, str]:
        """Get a copy of the symbols of get_symbols as {address: "dll.name"}."""
        return {address: "{}.{}".format(*value) for address, value in self.get_symbols().items()}

    def _set_run_error(self, error: ErrorInfo) -> None:
        """Save error as the error of the current run, if a run is active."""
        if self.curr_run is not None:
            self.curr_run.error = error

    def _end_run_on_hook_error(self, description: str, exception: Exception) -> bool:
        """Log the current exception, save it as the error of the run, and end the emulation."""
        logger.exception(description)
        error = self.get_error_info(
            ErrorType.INTERNAL_ERROR,
            self.get_pc(),
            traceback=traceback.format_exc(),
            message=str(exception) or type(exception).__name__,
        )
        self._set_run_error(error)
        self.stop()
        return False

    def _count_symbol_access(self, counter: str, address: int, symbol: str) -> None:
        """Count a read, write or execute of a symbol. counter is "reads", "writes" or "execs"."""
        run = self.curr_run
        assert run is not None
        access = run.sym_access.get(address) or MemAccess(sym=symbol)
        setattr(access, counter, getattr(access, counter) + 1)
        run.sym_access[address] = access

    def _get_cached_region_access(self, address: int, cache: deque[MemAccess]) -> MemAccess | None:
        """
        Get the access counts of the section or memory map that contains address.

        Look in cache first. Return None if address is not mapped.
        """
        for access in cache:
            if access.base is not None and access.base <= address < access.base + access.size:
                return access
        region = self._get_region_access(address)
        if region is not None:
            cache.appendleft(region)
        return region

    def _get_region_access(self, address: int) -> MemAccess | None:
        run = self.curr_run
        assert run is not None
        mod = self.get_mod_from_addr(address)
        if mod and mod.sections:
            sect = mod.get_section_for_addr(address)
            if sect:
                key = (mod.base, sect.virtual_address)
                if key not in run.section_access:
                    run.section_access[key] = MemAccess(base=mod.base + sect.virtual_address, size=sect.virtual_size)
                return run.section_access[key]

        mmap = self.get_address_map(address)
        if not mmap:
            return None
        return run.mem_access.setdefault(mmap, MemAccess(base=mmap.base, size=mmap.size))

    def _hook_mem_read(self, emu, access, address, size, value):
        """Count the reads of each symbol, section and memory map."""
        try:
            symbol = self.get_symbol_from_address(address)
            if symbol:
                self._count_symbol_access("reads", address, symbol)
                logger.debug("mem_read: addr=0x%x size=0x%x sym=%s", address, size, symbol)
            run = self.curr_run
            if run is None:
                return True
            region = self._get_cached_region_access(address, run.read_cache)
            if region is None:
                return False
            region.reads += 1
            return True
        except Exception as e:
            return self._end_run_on_hook_error("Exception during memory read", e)

    def _hook_mem_write(self, emu, access, address, size, value):
        """Count the writes of each symbol, section and memory map."""
        try:
            symbol = self.get_symbol_from_address(address)
            if symbol:
                self._count_symbol_access("writes", address, symbol)
                logger.debug("mem_write: addr=0x%x size=0x%x sym=%s", address, size, symbol)
            run = self.curr_run
            if run is None:
                return True
            region = self._get_cached_region_access(address, run.write_cache)
            if region is None:
                return False
            region.writes += 1
            return True
        except Exception as e:
            return self._end_run_on_hook_error("Exception during memory write", e)

    def _handle_invalid_read(self, emu, address, size, value):
        """Handle a read from unmapped memory."""
        if winemu.EMU_RESERVED <= address < winemu.EMU_RESERVED_END:
            return self._complete_reserved_access(address, size, "read")

        return self._raise_memory_fault(address, "read")

    def _handle_prot_fetch(self, emu, address, size, value):
        """Handle a fetch from memory without execute permission."""
        # Without a debugger, the guest can run code in its own memory without execute permission.
        # A fetch from a synthetic module or the token range, or any fetch with a debugger, is a fault.
        module = self.get_mod_from_addr(address)
        if (
            not self._should_stop_on_faults
            and (module is None or module._image.source != "synthetic")
            and not self.api_registry.overlaps_traps(address)
        ):
            if module is not None and module._image.source == "guest_pe":
                # A change of protection while Unicorn handles this fetch can make
                # the current translation incorrect. Change the protection after Unicorn stops.
                native_perms = next(perms for start, end, perms in self.get_mem_regions() if start <= address <= end)
                perms = next(perms for perms, native in self.emu_eng.perms.items() if native == native_perms)
                page = address & ~(self.page_size - 1)
                self._record_exit(ExecRecovery(page, perms | common.PERM_MEM_EXEC))
                return False
            return True
        error = self.get_error_info(ErrorType.INVALID_PROTECT_FETCH, address, access_type="fetch")
        self._set_run_error(error)
        self.end_run_on_fault()
        return False

    def _handle_invalid_write(self, emu, address, size, value):
        """Handle a write to unmapped memory."""
        if winemu.EMU_RESERVED <= address < winemu.EMU_RESERVED_END:
            return self._complete_reserved_access(address, size, "write")

        return self._raise_memory_fault(address, "write")

    def _complete_reserved_access(self, address, size, access_type):
        """Map the reserved range for an access to it. An access past its end faults at the first unmapped byte."""
        self._map_reserved_range()
        first = guest_callbacks.get_first_unmapped(self, address, size)
        if first != address:
            self._unmap_reserved_range()
            return self._raise_memory_fault(first, access_type)
        return True

    def _hook_code_deferred_work(self, emu, addr, size):
        """
        Code hook that runs at the next instruction after an API call or a fault.

        End the run at the return hook, and unmap the reserved range. Disable the hook when there is no more work.
        """
        try:
            if addr == self.return_hook:
                self._record_exit(RunReturn())
                return False

            # A guest exception handler continued at the fault address. Clear the repeat count of the fault
            # when PC leaves that address.
            if self._seh_repeat.resume_pc is not None and addr != self._seh_repeat.resume_pc:
                self._seh_repeat.reset()

            self._unmap_reserved_range()
            if self._seh_repeat.resume_pc is None:
                self.disable_deferred_work_hook()
            return True
        except Exception as e:
            return self._end_run_on_hook_error("Exception during code hook (deferred work)", e)

    def _hook_code_coverage(self, emu, addr, size):
        """Record the address of each instruction that runs, for coverage."""
        try:
            if self.curr_run is not None:
                self.curr_run.coverage.add(addr)
            return True
        except Exception as e:
            return self._end_run_on_hook_error("Exception during code hook (coverage)", e)

    def _hook_code_tracing(self, emu, addr, size):
        """Count the instructions, and the executes of each symbol, section and memory map."""
        try:
            if logger.isEnabledFor(logging.DEBUG):
                disasm = self.get_disasm(addr, size)[2]
                logger.debug("exec: 0x%x %s", addr, disasm)

            symbol = self.get_symbol_from_address(addr)
            if symbol:
                self._count_symbol_access("execs", addr, symbol)
                entry = self.api_registry.entries.get(addr)
                if entry is not None and entry.trap is not None:
                    self._api_call_site = (addr, self.prev_pc)

            self.prev_pc = addr
            run = self.curr_run
            if run is None:
                return True
            run.instr_cnt += 1
            region = self._get_cached_region_access(addr, run.exec_cache)
            if region is None:
                return False
            region.execs += 1
            return True
        except Exception as e:
            return self._end_run_on_hook_error("Exception during code hook (tracing)", e)

    def _hook_code_debug(self, emu, addr, size):
        """Log the disassembly and the registers of each instruction in debug mode."""
        x = self.get_disasm(addr, size)[2]
        if self.get_arch() == _arch.ARCH_AMD64:
            regs: tuple[str, ...] = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9")
        else:
            regs = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        vals = " : ".join(f"{r}=0x{self.reg_read(r):x}" for r in regs)
        logger.debug("0x%x: %s, %s", addr, x, vals)
        return True

    def get_native_module_path(self, mod_name=""):
        """Get the path of a DLL with this name in the configured module directory."""
        attr = "module_directory_x64" if self.get_arch() == _arch.ARCH_AMD64 else "module_directory_x86"
        path = common.normalize_package_path(getattr(self.config.modules, attr) or "")
        if not os.path.isdir(path):
            return None
        mod_name = mod_name.lower()
        for fn in os.listdir(path):
            if os.path.splitext(fn.lower())[0] == mod_name:
                return os.path.join(path, fn)
        return None

    def _add_module_to_current_peb(self, module):
        if self.is_kernel_mode or not module.visible_in_peb or module.is_driver():
            return
        process = self.get_current_process()
        if process is None or not self.get_address_map(process.peb_ldr_data.address):
            return
        if process.initializing_peb:
            return
        if module.is_exe() and module is not process.pe and module.base != process.base:
            return
        process.add_module_to_peb(module)

    def load_library(self, mod_name):
        original_modules = list(self.modules)
        original_peb_modules = self.module_loader.snapshot_peb_modules()
        name = winemu.normalize_dll_name(module_name(mod_name))
        module = self.get_mod_by_name(name)
        data = self.get_module_data_from_emu_file(mod_name) if module is None else None
        if data and data.startswith(b"MZ"):
            try:
                module = self.load_module_by_name(name, emu_path=self.fileman.get_full_path(mod_name), data=data)
            except (WindowsEmuError, ValueError, pefile.PEFormatError) as error:
                logger.warning("failed to load %s: %s", mod_name, error)
                return 0
        elif module is None:
            known = self.get_native_module_path(name) or self.api.load_api_handler(name)
            known = known or self.get_signature_db().get_functions(name, self._get_signature_arch())
            if not known and not self.config.modules.modules_always_exist:
                return 0
            try:
                module = self.load_module_by_name(name)
            except WindowsEmuError as error:
                logger.warning("failed to load %s: %s", name, error)
                return 0
        self._add_module_to_current_peb(module)
        new_modules = [m for m in self.modules if m not in original_modules]
        # Each module that the load maps gets a module_load event, its dependencies included.
        profiler = self.get_profiler()
        if profiler and self.curr_run is not None:
            pos = self.get_trace_position()
            for mod in new_modules:
                profiler.record_module_load_event(self.curr_run, pos, mod.name, mod.emu_path, mod.base, mod.image_size)
        frame = self._active_api_frame
        if frame is not None and not self.is_kernel_mode:
            # Keep the earliest snapshot for each process across reentrant loads.
            tracked = {process.id for process, _ in frame.peb_module_snapshot}
            frame.peb_module_snapshot.extend(item for item in original_peb_modules if item[0].id not in tracked)
            frame.created_modules.extend(new_modules)
            handler = self.api.load_api_handler("kernel32")
            for routine in self.module_loader.collect_initializers():
                handler.setup_callback(routine.address, routine.args)
                frame.initializers[routine.address] = routine
        return module.base

    def load_module_by_name(self, name, emu_path=None, base=None, native_path=None, data=None):
        """
        Load the module name, or get it if it is loaded.

        Load the module from data, else from the module directory, else as a synthetic API module.
        """
        name = module_name(name)
        existing = self.get_mod_by_name(name)
        if existing is not None:
            self._add_module_to_current_peb(existing)
            return existing
        if not emu_path:
            emu_path = (self.config.current_dir or r"C:\Windows\system32") + "\\" + name + ".dll"
        native_path = native_path or self.get_native_module_path(mod_name=name)
        if base is None and not native_path and data is None:
            base = 0x6F000000
        handler = self.api.load_api_handler(name)
        if handler and name == "ntdll":
            nt_handler = self.api.load_api_handler("ntoskrnl")
            if nt_handler:
                handler._nt_handler = nt_handler

        if data is not None:
            image = PeLoader(data=data, emu_path=emu_path).make_image()
        elif native_path:
            image = PeLoader(path=native_path, emu_path=emu_path).make_image()
        else:
            image = ApiModuleLoader(
                name=name,
                api=handler,
                arch=self.get_arch(),
                base=base,
                emu_path=emu_path,
                signature_db=self.get_signature_db(),
            ).make_image()
        image.name = name
        image.module_type = _module_type_from_path(emu_path)
        module = self.load_image(image, base)
        if image.source == "guest_pe" and module.is_dll() and not self.is_kernel_mode:
            self.module_loader.guest_dependencies.append(module)
        return module

    def get_module_data_from_emu_file(self, file_path):
        """Get the contents of the file at file_path in the emulated file system, or None if there is no file."""
        if not self.does_file_exist(file_path):
            return None

        mod_file = self.fileman.get_file_from_path(file_path)

        if not mod_file:
            return None

        # get_contents keeps the file pointer of the guest.
        return mod_file.get_contents()

    def init_sys_modules(self, modules_config):
        return self._init_module_group(modules_config)

    def init_user_modules(self, modules_config):
        return self._init_module_group(modules_config, default_base=0x6F000000)

    def _init_module_group(self, modules_config, default_base=None):
        rtmods = []
        for modconf in modules_config:
            name = modconf.name or "unknown"
            base = modconf.base_addr or default_base
            path = modconf.path or name + ".dll"
            rtmods.append(self.load_module_by_name(name, emu_path=path, base=base))
        return rtmods

    def get_thread_context(self, thread=None):
        """Get the saved CONTEXT of thread, or the CONTEXT of the CPU if thread is None."""
        if thread:
            return thread.get_context()
        if self.get_arch() == _arch.ARCH_AMD64:
            ctx = self.wintypes.CONTEXT64(self.get_ptr_size())
            ctx.ContextFlags = thread_context.CONTEXT_ALL_AMD64
            registers = thread_context.CPU_REGISTERS_AMD64
        else:
            ctx = self.wintypes.CONTEXT(self.get_ptr_size())
            ctx.ContextFlags = thread_context.CONTEXT_ALL_I386
            registers = thread_context.CPU_REGISTERS_I386
        for name, reg in registers.items():
            setattr(ctx, name, self.reg_read(reg))
        thread = self.get_current_thread()
        if thread is not None:
            thread_context.get_debug_registers(thread, ctx)
        return ctx

    def load_thread_context(self, ctx):
        """Write ctx to the CPU registers, and its debug registers to the current thread."""
        if self.get_arch() == _arch.ARCH_AMD64:
            registers = thread_context.CPU_REGISTERS_AMD64
        else:
            registers = thread_context.CPU_REGISTERS_I386
        for name, reg in registers.items():
            self.reg_write(reg, getattr(ctx, name))
        thread = self.get_current_thread()
        if thread is not None and thread_context.has(ctx.ContextFlags, thread_context.CONTEXT_DEBUG_REGISTERS):
            self.set_debug_registers(thread, ctx)
        if ctx.EFlags & hardware_breakpoints.RESUME_FLAG:
            self.reg_write(_arch.X86_REG_EFLAGS, ctx.EFlags & ~hardware_breakpoints.RESUME_FLAG)
            self.hardware_breakpoints.resume_at(thread_context.instruction_pointer(ctx))

    def record_exception(self, code, address, handler, registers, faulting_address=None):
        """Log an exception at address that is offered to a guest handler, and record it in the report."""
        try:
            _, _, instr = self.get_disasm(address, _arch.DISASM_SIZE)
        except Exception as e:
            logger.error(str(e))
            instr = "disasm_failed"
        pc_module, pc_offset = self._resolve_module_offset(address) or (None, None)
        handler_desc = f"0x{handler:x}"
        if self._resolve_module_offset(handler):
            handler_desc += f" ({self._format_module_offset(handler)})"
        logger.info(
            '0x%x: Exception caught: code=0x%x handler=%s instr="%s"\n  pc: %s\n  regs: %s',
            address,
            code,
            handler_desc,
            instr,
            self._format_module_offset(address),
            "  ".join(f"{k}={v:#x}" for k, v in registers.items()),
        )
        if self.profiler:
            run = self.get_current_run()
            tick = run.instr_cnt if run else 0
            tid = self.curr_thread.tid if self.curr_thread else 0
            pid = self.curr_process.id if self.curr_process else 0
            self.profiler.record_exception_event(
                run,
                TracePosition(tick=tick, tid=tid, pid=pid, pc=address),
                instr,
                code,
                handler,
                registers,
                address=faulting_address,
                pc_module=pc_module,
                pc_offset=pc_offset,
                stack=self.get_stack_trace(),
            )

    def dispatch_seh(self, faulting_address, exception, error):
        """
        Send exception to the guest handlers with SEH dispatch. Return True if a handler takes it.

        Return False if the same fault occurs ``_SehRepeat.MAX_REPEAT`` times in a row, so that a handler that does not
        fix the fault cannot make an infinite loop.
        """
        if not self._seh_repeat.record((self.get_pc(), faulting_address)):
            return False
        return self.exception_dispatcher().dispatch_fault(self, exception, error)

    @property
    def active_api_frame(self) -> GuestCallbackFrame | None:
        """The frame of the API call that the emulator runs, or None."""
        return self._active_api_frame

    def exception_dispatcher(self):
        """Get the SEH dispatch module of the architecture."""
        return seh64 if self.get_arch() == _arch.ARCH_AMD64 else seh32

    def note_seh_resume(self, pc):
        """
        Record that a guest exception handler continues execution at pc.

        If pc is not the address of the last fault, clear the repeat count. If pc is the address of the fault, keep the
        count until the deferred work hook sees PC move away.
        """
        fault = self._seh_repeat.fault
        if fault is None:
            return
        if pc == fault[0]:
            self._seh_repeat.resume_pc = pc
            self.enable_deferred_work_hook()
        else:
            self._seh_repeat.reset()

    def _new_object_handle(self, otype, name):
        """
        Create an object of type otype with one handle.

        The handle takes the reference of the object manager, so the last close of a handle removes the object.
        """
        om = self.get_object_manager("object creation")
        obj = om.new_object(otype)
        obj.name = name
        hnd = om.new_handle(obj)
        om.dec_ref(obj)
        return hnd, obj

    def create_event(self, name=""):
        """Create a kernel event object."""
        return self._new_object_handle(objman.Event, name)

    def dec_ref(self, obj):
        """Decrement the reference count of obj."""
        om = self.get_object_manager("object dereference")
        return om.dec_ref(obj)

    def create_mutant(self, name=""):
        """Create a kernel mutant object."""
        if name == 0:
            name = ""
        return self._new_object_handle(objman.Mutant, name)

    def create_semaphore(self, name=""):
        """Create a kernel semaphore object."""
        return self._new_object_handle(objman.Semaphore, name)

    def _hook_interrupt(self, emu, intnum):
        """Handle a software interrupt."""
        self.emu_eng.clear_exception_state()
        if (
            not self.is_kernel_mode
            and self.config.exceptions.dispatch_handlers
            and intnum not in cpu_exceptions.SYSTEM_GATES[self.get_arch()]
        ):
            pc = self.get_pc()
            try:
                code_bytes = self.mem_read(pc - 2, 2)
            except uc.UcError:
                code_bytes = b""
            trap_flag = bool(self.reg_read(_arch.X86_REG_EFLAGS) & seh.TRAP_FLAG)
            exception = cpu_exceptions.from_interrupt(intnum, pc, code_bytes, self.get_return_val(), trap_flag)
            if exception is None:
                self.set_pc(cpu_exceptions.skip_debug_service(pc))
            else:
                self.raise_cpu_exception(exception, ErrorType.UNHANDLED_INTERRUPT, interrupt_num=intnum)
            return True

        # int 0x29 is __fastfail (Windows 8 and later)
        if intnum == 0x29:
            ecx = self.reg_read(_arch.X86_REG_ECX)
            # __security_init_cookie raises FAST_FAIL_GS_COOKIE_INIT (6). Return to its caller.
            if ecx == 6:

                def _tmp_hook(emu, addr, size):
                    ret = self.pop_stack()
                    self.set_pc(ret)
                    hook.disable()

                hook = self.add_code_hook(cb=_tmp_hook)
                return True

        pc = self.get_pc()
        logger.debug("interrupt: intnum=0x%x", intnum)
        logger.error("0x%x: Unhandled interrupt: intnum=0x%x", pc, intnum)
        error = self.get_error_info(ErrorType.UNHANDLED_INTERRUPT, pc)
        error.interrupt_num = intnum
        self._set_run_error(error)
        self.end_run_on_fault()
        return False
