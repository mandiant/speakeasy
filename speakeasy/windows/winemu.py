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
from functools import wraps
from types import MethodType
from typing import Any

import capstone as cs
import pefile
import unicorn as uc

import speakeasy.common as common
import speakeasy.windows.api_resolution as api_resolution
import speakeasy.windows.common as winemu
import speakeasy.windows.cpu_exceptions as cpu_exceptions
import speakeasy.windows.guest_callbacks as guest_callbacks
import speakeasy.windows.hardware_breakpoints as hardware_breakpoints
import speakeasy.windows.mapped_imports as mapped_imports
import speakeasy.windows.objman as objman
import speakeasy.windows.seh as seh
import speakeasy.windows.seh32 as seh32
import speakeasy.windows.seh64 as seh64
import speakeasy.windows.thread_context as thread_context
import speakeasy.windows.unwind as unwind
import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.nt.ddk as ddk
import speakeasy.winenv.defs.windows.windows as windef
from speakeasy.binemu import BinaryEmulator
from speakeasy.config import parse_start_time
from speakeasy.errors import FileSystemEmuError, OutOfMemoryError, WindowsEmuError
from speakeasy.gdb import GdbServer, ResumeAction, StopReason
from speakeasy.profiler import GuestCallbackFrame, MemAccess, Run
from speakeasy.profiler_events import ApiArg, TracePosition
from speakeasy.report import ErrorInfo, RegionInfo
from speakeasy.struct import EmuStruct
from speakeasy.windows.api_image import ApiModuleLoader
from speakeasy.windows.api_registry import ApiEntry, ApiRegistry, module_name, symbol_ref
from speakeasy.windows.cryptman import CryptoManager
from speakeasy.windows.driveman import DriveManager
from speakeasy.windows.fileman import File, FileManager
from speakeasy.windows.hammer import ApiHammer
from speakeasy.windows.ioman import IoManager
from speakeasy.windows.loaders import LoadState, PeLoader, RuntimeModule, get_prot_string, relocate_image
from speakeasy.windows.module_loader import ModuleLoader
from speakeasy.windows.netman import NetworkManager
from speakeasy.windows.objman import HandleAllocator
from speakeasy.windows.regman import WINDOWS_CURRENT_VERSION_KEY, RegistryManager, get_program_files_values
from speakeasy.winenv.api import sigdb, sigfmt
from speakeasy.winenv.api.api import NO_CONTEXT, ApiContext, HandlerArgs
from speakeasy.winenv.api.winapi import WindowsApi

# When disassembling, a minimum instruction size needs to be supplied
# This number is arbitrary and just needs to be large enough to cover
# the size of the current disasm target
DISASM_SIZE = 0x20

# GDB signal number reported for memory faults
SIGSEGV = 11

# Upper bound on the static TLS data copied for each thread
TLS_TEMPLATE_MAX = 0x1000000

# Registers a callee must preserve; guest callbacks of an API return them to its caller unchanged
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

logger = logging.getLogger(__name__)


@dataclass
class _ExecutionBudget:
    limit: float
    elapsed: float = 0.0
    exhausted: bool = False


@dataclass(frozen=True)
class SuspendedApiCall:
    """
    The guest reached the trap of an API. The handler of the API runs next.

    The stack pointer, the return address and the code of the API are the values at the trap.
    If a debugger changes one of them, the guest runs the code of the API again, and the handler does not run.
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
    """A guest callback returned to GUEST_CALLBACK_RETURN_ADDR. The API handler that called it continues."""


@dataclass(frozen=True)
class FaultReturn:
    """A fault ended the run. The run completes after Unicorn stops, also if Unicorn then raises an error."""


@dataclass(frozen=True)
class ExecRecovery:
    """
    The guest fetched code from a guest PE page without execute permission.
    The run loop sets perms on the page and runs the code again.
    """

    page: int
    perms: int


@dataclass(frozen=True)
class RaisedCpuException:
    """A CPU exception that goes to the exception handlers of the guest."""

    exception: cpu_exceptions.CpuException
    error_type: str  # the run's error if no handler takes it
    interrupt_num: int | None = None
    access_type: str | None = None
    rax: int | None = None  # restored before dispatch, since IN overwrites it
    # (page, perms) of a guard page, whose protection the access restores
    guard_page: tuple[int, int] | None = None


# The reason why Unicorn stopped. A hook records it and stops Unicorn, and then the run loop handles it.
# If a second hook records an exit before Unicorn stops, the first exit stays.
NativeExit = SuspendedApiCall | RunReturn | CallbackReturn | FaultReturn | ExecRecovery | RaisedCpuException


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


def execution_scope(func):
    """Share one active-time cap across every start in a public invocation."""

    @wraps(func)
    def wrapped(self, *args, **kwargs):
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
    """Merge per-page permissions into (base, size, perms) runs of contiguous pages with equal permissions."""
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


@dataclass
class RunLimits:
    """The time and instruction limits of one call of the run loop, and the instructions it counts."""

    # When the call started, from time.monotonic().
    started: float
    # The execution time of the run before the call started.
    spent: float
    # The time limit of the run in seconds, or 0 for no limit.
    timeout: float
    # When the call must stop, from time.monotonic(), or None for no time limit.
    deadline: float | None
    # "max_total_time" if the total execution time gives the deadline, otherwise "timeout".
    deadline_kind: str
    # The total execution time of all runs, or None for no total limit.
    total_budget: _ExecutionBudget | None
    # The instruction limit of the run, or 0 or less for no limit.
    budget: int
    # The instructions that the run can still execute, or -1 for no limit.
    remaining: int
    # The last instruction that the accounting hook saw start, when there is one.
    last_executed: int | None = None

    @classmethod
    def from_run(cls, run: Run, timeout: float, budget: int, total_budget: _ExecutionBudget | None) -> "RunLimits":
        """Get the limits that apply to run from now, with the nearer of the two time limits as the deadline."""
        started = time.monotonic()
        spent = run.execution_elapsed
        deadline = started + max(timeout - spent, 0) if timeout > 0 else None
        deadline_kind = "timeout"
        if total_budget is not None and total_budget.limit > 0:
            total_deadline = started + max(total_budget.limit - total_budget.elapsed, 0)
            if deadline is None or total_deadline < deadline:
                deadline = total_deadline
                deadline_kind = "max_total_time"
        remaining = max(budget - run.budget_instructions, 0) if budget > 0 else -1
        return cls(started, spent, timeout, deadline, deadline_kind, total_budget, budget, remaining)

    def get_reached_limit(self) -> str | None:
        """Get the kind of the limit that the run reached, or None if it reached no limit."""
        if self.deadline is not None and time.monotonic() >= self.deadline:
            return self.deadline_kind
        if self.budget > 0 and self.remaining <= 0:
            return "max_instructions"
        return None

    def is_total_time_reached(self) -> bool:
        """Get whether the run reached the total execution time of all runs."""
        return (
            self.deadline_kind == "max_total_time" and self.deadline is not None and time.monotonic() >= self.deadline
        )

    def get_native_timeout(self) -> float:
        """Get the timeout for the next native start: the time to the deadline, or 0 for none."""
        return max(self.deadline - time.monotonic(), 0.000001) if self.deadline is not None else 0

    def get_native_count(self) -> int:
        """Get the instruction count for the next native start, or 0 for no limit.

        The count stops native execution at the instruction limit, so that
        tracing hooks do not see an instruction beyond it. The accounting hook
        counts the instructions across the native starts of one call.
        """
        return self.remaining if self.budget > 0 else 0


class WindowsEmulator(BinaryEmulator):
    """
    Base class providing emulation of all Windows modules and shellcode.
    This class is meant to provide overlapping functionality for both
    user mode and kernel mode samples.

    Subclasses must define:
        peb_addr: Address of the Process Environment Block
    """

    _X64_EXEC_ADDR_MASK = (1 << 52) - 1

    _execution_budget: _ExecutionBudget | None = None
    peb_addr: int
    api: WindowsApi

    @abstractmethod
    def alloc_peb(self, proc: Any) -> None:
        """Allocate memory for the Process Environment Block (PEB). Subclasses must implement."""
        ...

    @abstractmethod
    def init_processes(self, processes: list[Any]) -> None:
        """Initialize configured processes. Subclasses must implement."""
        ...

    def __init__(self, config, exit_event=None, debug=False, gdb_port=None, gdb_host=None):
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
        self.cd: str = ""
        self.is_reserved_range_unmapped: bool = True
        self.curr_process: Any | None = None
        self.om: objman.ObjectManager | None = None
        self._sigdb: sigdb.SignatureDatabase | None = None
        self._sigfmt: sigfmt.ArgFormatter | None = None
        self.api_registry: ApiRegistry = ApiRegistry(self)
        self._native_exit: NativeExit | None = None
        self._api_call_site: tuple[int, int] | None = None
        # Guard pages, mapped without access, with the protection their first access restores
        self.guard_pages: dict[int, int] = {}
        self.hardware_breakpoints = hardware_breakpoints.HardwareBreakpoints(self)
        # Unwind data registered at runtime for code outside loaded images
        self.function_tables: list[unwind.FunctionTable] = []
        self.module_loader: ModuleLoader = ModuleLoader(self)
        self._active_api_frame: GuestCallbackFrame | None = None
        self.mem_trace_hooks: list[Any] = []
        self.coverage_hook: Any | None = None
        self.debug_hook: Any | None = None
        self.is_kernel_mode: bool = False
        self.virtual_mem_base: int = 0x50000

        # Code hook for work that must wait until the next instruction, such as the end
        # of a run. It is enabled only when there is such work.
        self.deferred_work_hook: Any | None = None
        self.veh_handlers: list[int] = []

        self.is_run_complete: bool = False
        self.is_emu_complete: bool = False
        self.processes: list[Any] = []
        self.heap_allocs: list[tuple[int, int, str]] = []
        # Child processes created by calls to CreateProcess
        # by any module. This is separate from self.processes in order
        # to not mix up config processes with child processes
        self.child_processes: list[Any] = []
        self.curr_thread: Any | None = None
        self.prev_pc: int = 0
        self.unhandled_exception_filter: int = 0
        self._seh_last_fault: tuple[int, int | None] | None = None
        self._seh_repeat_count: int = 0
        self._seh_resume_pc: int | None = None

        self.fs_addr: int = 0
        self.gs_addr: int = 0

        self.return_hook: int = winemu.EMU_RETURN_ADDR
        self.exit_hook: int = winemu.EXIT_RETURN_ADDR
        self._parse_config(config)

        self.wintypes = windef
        self.handle_allocator: HandleAllocator = HandleAllocator()
        # OS resource managers
        self.regman: RegistryManager = RegistryManager(
            self.handle_allocator, self.config.registry, os_ver=self.config.os_ver
        )
        self.fileman: FileManager = FileManager(config, self)
        self.netman: NetworkManager = NetworkManager(self.handle_allocator, config=self.config.network)
        self.driveman: DriveManager = DriveManager(config=self.config.drives)
        self.cryptman: CryptoManager = CryptoManager(self.handle_allocator)
        self.rng: random.Random = random.Random(self.config.random_seed)
        self.start_time: int = winemu.get_filetime(parse_start_time(self.config.start_time))
        self.hammer: ApiHammer = ApiHammer(self)
        self._io_manager: Any | None = None

    def _parse_config(self, config):
        """
        Parse the emulation config file
        """
        super()._parse_config(config)
        self.cd = self.config.current_dir
        self.command_line: str = self.config.command_line

    def init_machine(self, arch):
        """
        Create the CPU, the disassembler and the API layer for arch. Then create the
        Windows structures and the modules of the machine. Load images after this.
        The container image of a DLL or shellcode input is not part of the machine:
        Win32Emulator.load_container loads it.

        Raises:
            WindowsEmuError: the machine is already initialized, or arch is not x86 or amd64.
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
        """
        Create the object manager, segments, shared data and modules of the machine
        """

    def get_object_manager(self, reason: str) -> objman.ObjectManager:
        """
        Get the object manager of the machine.

        Raises:
            WindowsEmuError: the machine structures are not initialized yet.
        """
        if self.om is None:
            raise WindowsEmuError(f"{reason} requires initialized object services")
        return self.om

    def on_run_complete(self):
        """
        Clean up after a run completes (implemented in the child class) since
        this may mean different things depending. This function will pop the
        next run from the run queue and emulate it.
        """
        # Implemented by a subclass (e.g. kernel/user mode emulators)
        raise NotImplementedError()

    def end_run_on_fault(self):
        """
        End the current run after a handled memory fault. With a debugger attached,
        stop the engine at the fault instead, and end the run after the debugger resumes.
        Faults at a PC in the reserved emulator range, such as the return hook, are not
        sample faults, so they do not stop the debugger.
        """
        pc = self.get_pc()
        in_reserved = winemu.EMU_RESERVED <= pc < winemu.EMU_RESERVED + winemu.EMU_RESERVE_SIZE
        if not self._should_stop_on_faults or in_reserved:
            # The fault belongs to this run. Go to the next run only after Unicorn stops,
            # also if Unicorn raises an error after emu_stop. Otherwise the fault can change the next run.
            self._record_exit(FaultReturn())
            return
        self._pending_fault_stop = StopReason(signal=SIGSEGV, kind="exception", address=pc)
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
        """
        Create a formatted structure from bytes
        """
        if not isinstance(obj, EmuStruct):
            raise WindowsEmuError("Invalid object for cast")
        return obj.cast(bytez)

    def file_open(self, path, create=False, truncate=False):
        """
        Open an emulated from using the file manager
        """
        return self.fileman.file_open(path, create, truncate=truncate)

    def pipe_open(self, path, mode, num_instances, out_size, in_size):
        """
        Open an emulated named pipe
        """
        return self.fileman.pipe_open(path, mode, num_instances, out_size, in_size)

    def does_file_exist(self, path):
        """
        Test if a file handler for a specified emulated file exists
        """
        return self.fileman.does_file_exist(path)

    def file_create_mapping(self, hfile, name, size, prot):
        """
        Create a memory mapping for an emulated file
        """
        return self.fileman.file_create_mapping(hfile, name, size, prot)

    def file_get(self, handle):
        """
        Get a file object from a handle
        """
        return self.fileman.get_file_from_handle(handle)

    def file_delete(self, path):
        """
        Delete a file
        """
        return self.fileman.delete_file(path)

    def pipe_get(self, handle):
        """
        Get a pipe object from a handle
        """
        return self.fileman.get_pipe_from_handle(handle)

    def get_file_manager(self):
        """
        Get the file emulation manager
        """
        return self.fileman

    def get_network_manager(self):
        """
        Get the network emulation manager
        """
        return self.netman

    def get_crypt_manager(self):
        """
        Get the crypto manager
        """
        return self.cryptman

    def get_drive_manager(self):
        """
        Get the drive manager
        """
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

    def reg_open_key(self, path, create=False):
        """
        Open or create a registry key in the emulation space
        """
        return self.regman.open_key(path, create)

    def reg_get_subkeys(self, hkey):
        """
        Get subkeys for a given registry key
        """
        return self.regman.get_subkeys(hkey)

    def reg_get_key(self, handle=0, path=""):
        """
        Get registry key by path or handle
        """
        if path:
            return self.regman.get_key_from_path(path)
        return self.regman.get_key_from_handle(handle)

    def _unmap_reserved_range(self):
        """
        Unmap reserved memory space so we can handle events (e.g. import APIs,
        entry point returns, etc.)
        """
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
        Keep allocations out of the reserved emulator range, which stays unmapped
        so that a return to the return hook faults
        """
        base, total = super().get_valid_ranges(size, addr=addr)
        if base < winemu.EMU_RESERVED_END and winemu.EMU_RESERVED < base + total:
            base, total = super().get_valid_ranges(size, addr=winemu.EMU_RESERVED_END)
        return base, total

    def add_run(self, run):
        """
        Add a run to the emulation run queue
        """
        self.run_queue.append(run)

    def _prepare_next_run(self):
        """
        Execute the next run from the emulation queue
        """
        self._finish_run_initializers(self.curr_run)
        self._native_exit = None
        try:
            run = self.run_queue.pop(0)
        except IndexError:
            self.on_emu_complete()
            return None

        self.is_run_complete = False
        self.reset_stack(self.stack_base)
        self.reset_cpu_context()
        mm = self.get_address_map(self.stack_base - 1)
        self.mem_write(mm.base, b"\x00" * mm.size)
        prepared = self._prepare_run_context(run)
        self.emu_eng.stop()
        return prepared

    def _queue_startup_initializers(self):
        """
        Add a run for each initializer of the guest DLLs that the process loaded at start.
        These runs go before the first run in the queue.
        """
        if self.is_kernel_mode or not self.run_queue:
            return
        queued = []
        for routine in self.module_loader.collect_initializers():
            run = Run()
            run.type = f"dependency.{routine.module.name}.{'dll_entry' if routine.is_entry_point else 'tls_callback'}"
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
        If the run is a startup initializer and it failed, set the state of its module to INIT_ERROR,
        and remove the other startup initializers of the module from the queue.
        """
        for frame in run.guest_callbacks:
            self.module_loader.rollback_guest_load(frame)
        run.guest_callbacks.clear()
        routine = run.guest_initialization
        if routine is None or self.module_loader.finish_initializer(
            routine, self.get_return_val(), faulted=run.error is not None
        ):
            return
        run.error = run.error or ErrorInfo(type="dll_initialization_failed", pc=self.get_pc())
        logger.warning(
            "guest initializer failed for %s in process %s: %s", routine.module.name, routine.pid, run.error.type
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

    def call(self, addr, params=[]) -> None:
        """
        Start emulating at the specified address
        """
        self.reset_stack(self.stack_base)
        self.reset_cpu_context()
        mm = self.get_address_map(self.stack_base - 1)
        self.mem_write(mm.base, b"\x00" * mm.size)
        run = Run()
        run.type = f"call_0x{addr:x}"
        run.start_addr = addr
        run.args = params

        if not self.run_queue:
            self.add_run(run)
            self.start()
        else:
            self.add_run(run)

    def _prepare_run_context(self, run):
        """
        Prepare CPU and memory state for the given run without starting emulation.
        """
        logger.info("* exec: %s", run.type)

        self.curr_run = run
        self._seh_last_fault = None
        self._seh_repeat_count = 0
        self._seh_resume_pc = None
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

        self.set_func_args(stk_ptr, self.return_hook, *run.args, conv=_arch.CALL_CONV_STDCALL)
        for reg, value in run.registers.items():
            self.reg_write(reg, value)
        stk_ptr = self.get_stack_ptr()
        stk_map = self.get_address_map(stk_ptr)

        self.curr_run.stack = MemAccess(base=stk_map.base, size=stk_map.size)

        # Set the process context if possible
        if run.process_context:
            # Init a new peb if the process context changed:
            if run.process_context != self.get_current_process():
                self.alloc_peb(run.process_context)
            self.set_current_process(run.process_context)
        if run.thread:
            self.set_current_thread(run.thread)
        elif not self.is_kernel_mode:
            thread = objman.Thread(self, stack_base=self.stack_base)
            self.get_object_manager("thread registration").objects.update({thread.address: thread})
            if self.curr_process:
                thread.process = self.curr_process
                self.curr_process.threads.append(thread)
            run.thread = thread
            self.set_current_thread(thread)

        if not self.is_kernel_mode:
            # Reset the TIB data
            thread = self.get_current_thread()
            if thread:
                thread.exit_code = None
                if self.curr_process is not None:
                    self.init_teb(thread, self.curr_process.peb)
                self.init_tls(thread)

        if winemu.EMU_RESERVED <= run.start_addr <= winemu.EMU_RESERVED_END:
            try:
                self.mem_unmap(winemu.EMU_RESERVED, winemu.EMU_RESERVE_SIZE)
            except Exception:
                pass
            self.is_reserved_range_unmapped = True

        self.set_pc(run.start_addr)
        return run

    def mem_cast(self, obj, addr):
        """
        Turn bytes from an emulated memory pointer into an object
        """
        size = obj.sizeof()
        struct_bytes = self.mem_read(addr, size)
        return self.cast(obj, struct_bytes)

    def setup_user_shared_data(self):
        """
        Setup the shared user data section that is often used to share data
        between user mode and kernel mode
        """
        aliases = []
        if self.get_arch() == _arch.ARCH_X86:
            aliases.append(0xFFDF0000)
        elif self.get_arch() == _arch.ARCH_AMD64:
            aliases.append(0xFFFFF78000000000)

        mirrors = {a & self._X64_EXEC_ADDR_MASK for a in aliases if a & self._X64_EXEC_ADDR_MASK != a}

        # This is a read-only address for KUSER_SHARED_DATA,
        # and this is the same address for 32-bit and 64-bit.
        bases = [0x7FFE0000] + aliases + list(mirrors)

        kuser_tag = "emu.struct.KUSER_SHARED_DATA"

        data = self._build_user_shared_data()
        for base in bases:
            mm = self.get_address_map(base)
            if mm and not (mm.tag or "").startswith(kuser_tag):
                # Another mapping already owns this alias: leave it completely
                # alone rather than colliding with it while mapping (which
                # breaks every kernel-mode load) or stomping its contents here.
                continue
            if not mm:
                self.mem_map(self.page_size, base=base, tag=kuser_tag)
            self.mem_write(base, data)

    def get_native_machine(self) -> int:
        """Get the IMAGE_FILE_MACHINE value of the emulated host, which matches the guest architecture."""
        if self.get_arch() == _arch.ARCH_AMD64:
            return windef.IMAGE_FILE_MACHINE_AMD64
        return windef.IMAGE_FILE_MACHINE_I386

    def _build_user_shared_data(self):
        now_100ns = self.start_time
        tick_ms = winemu.START_TICK_COUNT

        data = bytearray(0x400)

        # InterruptTime (offset 0x008): KSYSTEM_TIME {LowPart, High1Time, High2Time}
        interrupt_100ns = winemu.START_TICK_COUNT * 10000
        struct.pack_into(
            "<IiI", data, 0x008, interrupt_100ns & 0xFFFFFFFF, interrupt_100ns >> 32, interrupt_100ns >> 32
        )
        # SystemTime (offset 0x014): KSYSTEM_TIME
        struct.pack_into("<IiI", data, 0x014, now_100ns & 0xFFFFFFFF, now_100ns >> 32, now_100ns >> 32)
        # ImageNumberLow, ImageNumberHigh (offset 0x02C)
        machine = self.get_native_machine()
        struct.pack_into("<HH", data, 0x02C, machine, machine)
        # NtMajorVersion (offset 0x260)
        struct.pack_into("<I", data, 0x260, self.config.os_ver.major or 0)
        # NtMinorVersion (offset 0x264)
        struct.pack_into("<I", data, 0x264, self.config.os_ver.minor or 0)
        # NtBuildNumber (offset 0x268)
        struct.pack_into("<I", data, 0x268, self.config.os_ver.build or 0)
        # TickCount (offset 0x320): KSYSTEM_TIME
        struct.pack_into("<IiI", data, 0x320, tick_ms, 0, 0)
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
            while not self.is_emu_complete:
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
                        if self.curr_run is not origin_run or self.is_emu_complete:
                            return
                        if debugger is not None and debugger.has_pending_stop():
                            return
                        if self._native_exit is None:
                            self._stop_without_exit(limits, origin_run, debugger)
                            return
                        continue
                if not self._handle_exit(limits, origin_run, debugger):
                    return
                address = self.get_pc()
                if self._pending_fault_stop is not None or self.curr_run is not origin_run:
                    return
                if debugger is not None and (debugger.has_pending_stop() or stepping):
                    return
        finally:
            self._finish_current_run_execution(limits, origin_run, debugger)
            if hook is not None:
                self.remove_code_hook(hook)

    def _start_unicorn(
        self, address: int, limits: RunLimits, origin_run: Run, debugger: GdbServer | None, stepping: bool
    ) -> bool:
        """
        Run guest code in Unicorn from address until it stops, and raise the CPU exception
        of a `hlt` that ran. Get False if a fault stops the debugger.

        Raises:
            uc.UcError: Unicorn failed, and no native exit explains the failure.
        """
        try:
            native_timeout = limits.get_native_timeout()
            native_count = limits.get_native_count()
            if stepping:
                native_count = 1
                registers = self.get_register_state()
                counted = (limits.remaining, origin_run.budget_instructions, origin_run.instr_cnt)
                if limits.budget <= 0:
                    # No accounting hook records the instruction of the step,
                    # which is the one at its start address.
                    limits.last_executed = address
            self.emu_eng.start(address, timeout=native_timeout, count=native_count)
            if stepping and self._step_had_no_effect(registers, debugger):
                # Unicorn translates a store into the page of its own code
                # again and runs it again, which uses up a count of 1. The
                # second start counts the instruction as a run without a
                # debugger does, so the first start must not count it.
                limits.remaining, origin_run.budget_instructions, origin_run.instr_cnt = counted
                self.emu_eng.start(address, timeout=native_timeout, count=2)
        except uc.UcError as exc:
            if self._pending_fault_stop is not None:
                return False
            if not self._exit_explains_error(exc):
                raise
        if self.curr_run is origin_run and self._stopped_at_hlt(
            limits.deadline, limits.last_executed, native_count, debugger
        ):
            self.raise_cpu_exception(cpu_exceptions.privileged_instruction(self.get_pc() - 1), "privileged_instruction")
        return True

    def _exit_explains_error(self, exc: uc.UcError) -> bool:
        """Get whether the native exit is the cause of the Unicorn error. Then the run loop handles the exit."""
        match self._native_exit:
            case None:
                return False
            case RaisedCpuException() | FaultReturn():
                return True
            case ExecRecovery() if exc.errno == uc.UC_ERR_FETCH_PROT:
                return True
        return bool(exc.errno == uc.UC_ERR_FETCH_UNMAPPED)

    def _record_exit(self, native_exit: NativeExit) -> None:
        """Record native_exit and stop Unicorn. If an exit is already recorded, it stays."""
        if self._native_exit is None:
            self._native_exit = native_exit
        self.emu_eng.stop()

    def _get_exit_at_pc(self) -> NativeExit | None:
        """
        Get the exit at the address where Unicorn stopped, if no hook recorded one:
        the call of an API, the return of a guest callback, or the return of the run.
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
        """Add a code hook that counts each instruction against the instruction limit and stops the engine at it."""

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
        Add the time of the call to origin_run and to the total execution time. End the
        run if the exit event stopped it, and cancel all runs if the total time ran out.
        """
        elapsed = time.monotonic() - limits.started
        origin_run.execution_elapsed = limits.spent + elapsed
        stopped = self.exit_event is not None and self.exit_event.is_set()
        if stopped and debugger is None and self.curr_run is origin_run and not self.is_run_complete:
            if origin_run.error is None:
                origin_run.error = ErrorInfo(type="timeout", pc=self.get_pc())
            self._cancel_execution_runs()
        total_budget = limits.total_budget
        if total_budget is not None:
            total_budget.elapsed += elapsed
            if total_budget.limit > 0 and total_budget.elapsed >= total_budget.limit:
                if not total_budget.exhausted:
                    logger.error("* Total execution time of %d sec(s) reached.", total_budget.limit)
                total_budget.exhausted = True
                self._cancel_execution_runs()
                prepared = self.curr_run
                if prepared is origin_run:
                    if not self.is_run_complete and origin_run.error is None:
                        origin_run.error = ErrorInfo(type="max_total_time", pc=self.get_pc())
                elif prepared is not None:
                    # Completing the run already prepared the next one. It
                    # did not execute and must not appear as a started run.
                    self._cancel_execution_runs(prepared)
                    if prepared.execution_elapsed == 0 and prepared.get_api_count() == 0:
                        self.runs[:] = [run for run in self.runs if run is not prepared]
                        if self.profiler:
                            self.profiler.runs[:] = [run for run in self.profiler.runs if run is not prepared]
                        self.curr_run = origin_run
                        self.is_run_complete = True
                if debugger is not None:
                    debugger._request_stop(StopReason(kind="max_total_time", address=self.get_pc()))

    def _handle_exit(self, limits: RunLimits, origin_run: Run, debugger: GdbServer | None) -> bool:
        """
        Handle the native exit.
        Get False if the run loop must return, because the debugger stops, a limit is reached, or the run ended.
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
            self._stop_at_limit("max_total_time", limits, origin_run, debugger)
            return False
        self._native_exit = None
        match native_exit:
            case RunReturn() | FaultReturn():
                self.on_run_complete()
                return False
            case ExecRecovery(page=page, perms=perms):
                self.mem_protect(page, self.page_size, perms)
            case CallbackReturn():
                self._continue_guest_callback()
        return True

    def _dispatch_api_entry(
        self, entry: ApiEntry, limits: RunLimits, origin_run: Run, debugger: GdbServer | None
    ) -> bool:
        """
        Run the handler of the API whose trap the guest reached, and end the run if the
        handler completed it. Get False if the call of the run loop must return, because
        the debugger stops at an API with no handler, a fault stops the debugger, or the
        total execution time ran out.
        """
        # A missing ABI remains a suspended call under the debugger.
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
        if self.is_run_complete and not self.is_emu_complete and self.curr_run is origin_run:
            if limits.is_total_time_reached():
                self._stop_at_limit("max_total_time", limits, origin_run, debugger)
                return False
            self.on_run_complete()
        return True

    def _stop_without_exit(self, limits: RunLimits, origin_run: Run, debugger: GdbServer | None) -> None:
        """
        Stop origin_run after Unicorn stopped with no native exit.
        If a limit is reached, stop at the limit.
        Otherwise, end the run with an engine_stopped error, if the run is not complete and no debugger is attached.
        """
        reached = limits.get_reached_limit()
        if reached is not None:
            self._stop_at_limit(reached, limits, origin_run, debugger)
        elif debugger is None and not self.is_run_complete:
            logger.error("0x%x: Emulation engine stopped", self.get_pc())
            origin_run.error = self.get_error_info("engine_stopped", self.get_pc())
            self.on_run_complete()

    def _stop_at_limit(self, kind: str, limits: RunLimits, origin_run: Run, debugger: GdbServer | None) -> None:
        """
        Stop origin_run at the limit of the given kind. Without a debugger, the limit
        becomes the error of the run and the run ends. With a debugger, the debugger stops.
        """
        if isinstance(self._native_exit, SuspendedApiCall):
            self.set_pc(self._native_exit.entry.address)
        if kind == "timeout":
            # Each debugger resume of a timed out run stops at once; log only the first stop.
            if limits.spent < limits.timeout:
                logger.error("* Timeout of %d sec(s) reached.", limits.timeout)
        elif kind == "max_total_time":
            assert limits.total_budget is not None
            logger.error("* Total execution time of %d sec(s) reached.", limits.total_budget.limit)
            limits.total_budget.exhausted = True
            self._cancel_execution_runs()
            # A limit that expires while a fault is completing keeps the fault as
            # the run's error.
            if self.curr_run is origin_run and origin_run.error is None:
                origin_run.error = ErrorInfo(type=kind, pc=self.get_pc())
        else:
            logger.error("* Instruction limit of %d reached.", limits.budget)
        if debugger is not None:
            debugger._request_stop(StopReason(kind=kind, address=self.get_pc()))
        elif self.curr_run is origin_run:
            if origin_run.error is None:
                origin_run.error = ErrorInfo(
                    type=kind, pc=self.get_pc(), count=limits.budget if kind == "max_instructions" else None
                )
            self.on_run_complete()

    def _drop_stale_exit(self, address: int) -> int:
        """
        Drop the native exit that a debugger made stale while the target was stopped,
        and get the address where execution continues.
        """
        native_exit = self._native_exit
        if isinstance(native_exit, SuspendedApiCall):
            entry = native_exit.entry
            if address not in (entry.address, entry.trap):
                # A debugger register edit abandons the suspended dispatch.
                self._native_exit = None
            elif self._get_suspended_api_call(entry) != native_exit:
                # Patches and frame edits while stopped must execute the revised
                # public bytes instead of bypassing them through a retained trap.
                self._native_exit = None
                address = entry.address
                self.set_pc(address)
        elif isinstance(native_exit, (RunReturn, CallbackReturn, FaultReturn)) and address not in (
            winemu.GUEST_CALLBACK_RETURN_ADDR,
            self.return_hook,
            self.exit_hook,
        ):
            self._native_exit = None
        return address

    def _cancel_execution_runs(self, prepared=None):
        """Cancel unexecuted work without leaving DLL attachments initializing."""
        canceled = [*self.run_queue, *self.suspended_runs]
        if prepared is not None:
            canceled.append(prepared)
        self.module_loader.cancel_initializers(
            run.guest_initialization for run in canceled if run.guest_initialization is not None
        )
        self.run_queue.clear()
        self.suspended_runs.clear()

    def resume(self, addr, count=-1) -> None:
        """Resume emulation directly at an address.

        This low-level API bypasses the GDB command loop; callers that enable
        GDB should drive execution through :meth:`start` instead.
        """
        if self.curr_run is None:
            self.curr_run = Run()
        self.is_emu_complete = False
        timeout = 0 if self.gdb_port is not None else self.config.timeout
        self._execute_current_run(addr, timeout=timeout, count=count)

    @execution_scope
    def start(self, addr=None, size=None):
        """
        Begin emulation executing each run in the specified run queue
        """
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

        self.is_run_complete = False
        self.is_emu_complete = False
        self.set_hooks()
        self._unmap_reserved_range()

        # Initialize run context/register state before exposing the target to GDB,
        # so the first stop reports a meaningful PC/SP/etc.
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
        """Execute prepared runs, optionally under control of an active GDB session."""
        total_budget = self._execution_budget
        assert total_budget is not None
        detached_resume_addr: int | None = None
        terminal_signal = 0
        self._should_stop_on_faults = debugger is not None
        self._pending_fault_stop = None

        if self.profiler:
            self.profiler.set_start_time()

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
                        resume_addr, timeout=self.config.timeout, count=instruction_count, debugger=debugger
                    )
                if debugger is None and total_budget.exhausted:
                    self._end_at_total_budget()
                    break
                if debugger is not None:
                    stop_reason = debugger.finish_run(debug_action)
                    if stop_reason is not None and stop_reason.kind == "step" and self.is_emu_complete:
                        # A step that ends emulation gets the final stop instead.
                        stop_reason = None
                    fault_stop, self._pending_fault_stop = self._pending_fault_stop, None
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
                            if not self.on_run_complete():
                                break
                            terminal_signal = 0
                        if debugger is None:
                            detached_resume_addr = self.get_pc()
                        continue
                if self.curr_run is not executing_run and not self.is_emu_complete:
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
                    mnem, op, instr = self.get_disasm(self.get_pc(), DISASM_SIZE)
                except Exception as dis_err:
                    logger.error(str(dis_err))

                if isinstance(e, uc.UcError) and e.errno == uc.UC_ERR_INSN_INVALID:
                    error = self.get_error_info(str(e), self.get_pc(), traceback=stack_trace)
                else:
                    error = self.get_error_info(
                        "internal_error", self.get_pc(), traceback=stack_trace, message=str(e) or type(e).__name__
                    )
                self._set_run_error(error)
                terminal_signal = SIGSEGV

                if debugger is not None:
                    # Ensure a pending Ctrl-C cannot be lost, then report the
                    # target fault while its register state is still available.
                    debugger.finish_run(debug_action)
                    debug_action = debugger.command_loop(
                        StopReason(signal=terminal_signal, kind="exception", address=self.get_pc())
                    )
                    if debug_action.kill:
                        return True
                    if debug_action.detach:
                        self._detach_debugger(debugger)
                        debugger = None

                run = self.on_run_complete()
                if not run:
                    break
                terminal_signal = 0
                continue
            break

        if debugger is not None:
            if terminal_signal:
                debugger.notify_signal(terminal_signal)
            else:
                # Stop once more while memory is still mapped, so the client
                # can inspect the final state before the exit reply.
                debug_action = debugger.command_loop(StopReason(kind="exit"))
                if debug_action.kill:
                    return True
                if debug_action.detach:
                    debugger.close()
                    return True
                debugger.notify_exit(0)
        return True

    def _end_at_total_budget(self, debugger: GdbServer | None = None) -> None:
        """Cancel the runs that are left and end the emulation, because the total budget is spent.

        Args:
            debugger: the GDB session to send the exit reply to, if the client still waits for one.
        """
        self._cancel_execution_runs()
        if not self.is_run_complete:
            self.on_run_complete()
        if debugger is not None:
            debugger.notify_exit(0)
        self.on_emu_complete()

    def _detach_debugger(self, debugger: GdbServer) -> None:
        """Close the GDB session, so that the runs continue without a debugger."""
        debugger.close()
        self._should_stop_on_faults = False

    def get_current_run(self):
        """
        Get the current run that is being emulated
        """
        return self.curr_run

    def get_current_module(self):
        """
        Get the currently running module
        """
        return self.curr_mod

    def get_dropped_files(self) -> list[File]:
        """
        Get all files written by the sample from the file manager
        """
        return self.fileman.get_dropped_files()

    def set_hooks(self):
        """
        Reserves memory that will be used to handle events that occur
        during emulation
        """
        super().set_hooks()

    def get_processes(self):
        """
        Get the current processes that exist in the emulation space
        """
        if not self.processes:
            self.init_processes(self.config.processes)
        return self.processes

    def kill_process(self, proc):
        """
        Terminate a process (i.e. remove it from the known process list)
        """
        try:
            self.processes.remove(proc)
        except ValueError:
            pass

    def get_current_thread(self):
        """
        Get the current thread that is emulating
        """
        return self.curr_thread

    def set_last_error(self, code):
        """
        Set the last error code for the current thread
        """
        if self.curr_thread:
            self.curr_thread.last_error = code

    def get_last_error(self):
        """
        Get the last error code for the current thread
        """
        if self.curr_thread:
            return self.curr_thread.last_error

    def heap_alloc(self, size, heap="None"):
        """
        Allocate a memory chunk and add it to the "heap"
        """
        try:
            addr = self.mem_map(size, base=None, tag=f"api.heap.{heap}")
        except OutOfMemoryError:
            return 0
        self.heap_allocs.append((addr, size, heap))
        return addr

    def pool_alloc(self, pooltype, size, tag="None") -> int:
        """
        Allocate memory in the emulated pool

        Raises:
            WindowsEmuError: the emulator runs in user mode, which has no pool.
        """
        raise WindowsEmuError("pool allocations need kernel mode")

    def exit_process(self) -> None:
        """
        Signal that the current process ends

        Raises:
            WindowsEmuError: the emulator runs in kernel mode, which has no process to end.
        """
        raise WindowsEmuError("process exit needs user mode")

    def get_current_process(self):
        """
        Get the current process that is emulating
        """
        return self.curr_process

    def set_current_process(self, process):
        """
        Set the current process that is emulating
        """
        self.curr_process = process

    def set_current_thread(self, thread):
        """
        Set the current thread
        """
        self.curr_thread = thread
        self.hardware_breakpoints.update()

    def set_debug_registers(self, thread, ctx):
        """Give thread the debug registers of ctx, which arm its hardware breakpoints."""
        thread_context.set_debug_registers(thread, ctx)
        if thread is self.get_current_thread():
            self.hardware_breakpoints.update()

    def _setup_gdt(self, arch):
        """
        Set up the GDT so we can access segment registers correctly
        This will be done a little differently depending on architecture
        """

        GDT_SIZE = 0x1000
        SEG_SIZE = 0x1000
        ENTRY_SIZE = 0x8
        num_gdt_entries = 31
        fs_addr = 0
        gs_addr = 0
        gdt_addr = None

        # For a detailed explaination of whats happening here, see:
        # https://wiki.osdev.org/Global_Descriptor_Table
        # We need to init the GDT so that shellcode can accurately access
        # segment registers which is needed for TEB access in user mode

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
        # SS stays a ring 0 selector because Unicorn runs the guest at CPL 0 and rejects an RPL 3 SS.
        native_x86 = _arch.ARCH_X86 == arch and not self.is_kernel_mode
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
        if _arch.ARCH_X86 == arch:
            # FS segment needed for PEB access at fs:[0x30]
            fs_addr, fs_size = self.get_valid_ranges(SEG_SIZE, addr=teb_addr)
            self.mem_map(fs_size, base=fs_addr, tag="emu.segment.fs")

            access = winemu.GDT_ACCESS_BITS.Data | winemu.GDT_ACCESS_BITS.DataWritable | winemu.GDT_ACCESS_BITS.Ring3
            _make_entry(fs_index, fs_addr, access)

            selector = _create_selector(fs_index, winemu.GDT_FLAGS.Ring3)
            self.reg_write(_arch.X86_REG_FS, selector)

        elif _arch.ARCH_AMD64 == arch:
            # GS Segment needed for PEB access at gs:[0x60]
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
        """
        Initialize the Process Environment Block
        """
        p = proc
        if not p:
            p = self.curr_process
        p.init_peb(user_mods)
        if p is self.get_current_process():
            self.mem_write(self.peb_addr, p.peb.address.to_bytes(self.get_ptr_size(), "little"))
        return p.peb

    def init_teb(self, thread, peb):
        """
        Initialize the Thread Information Block
        """
        if self.get_arch() == _arch.ARCH_X86:
            thread.init_teb(self.fs_addr, peb.address)
        elif self.get_arch() == _arch.ARCH_AMD64:
            thread.init_teb(self.gs_addr, peb.address)

    def init_tls(self, thread):
        """
        Initialize implicit thread local storage. Meant to be
        called after init_teb.
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
        Return the initial TLS data of a module, from its IMAGE_TLS_DIRECTORY.

        Set the TLS index of the module to 0. A directory with an invalid range gives an empty template.
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
        """
        Parse a PE file or buffer without loading it into the emulator
        """

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
        """Bind imports of an injected mapped PE using the public API registry.

        Bind each valid IAT slot independently and skip invalid slots.
        A zero OriginalFirstThunk may reuse an already bound IAT; recorded
        bindings preserve idempotence without interpreting code addresses as RVAs.

        Intended for PEs injected via WriteProcessMemory (process hollowing)
        that bypass the normal module loader.
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
                    # The guest changed an entry that we bound. Keep the guest's value,
                    # unless the guest wrote back the original value from the ILT.
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

    def load_image(self, image, base: int | None = None, *, is_input: bool = False) -> RuntimeModule:
        """
        Load an image and its dependencies. Set is_input for the input image. The input
        image is the first module in modules, and only the input image allocates the stack.
        """
        return self.module_loader.load_image(image, base, is_input=is_input)

    def _load_image(self, image, base=None, *, is_input=False):
        """
        Map an image at base, or at its preferred base, or at the next free range after it.
        An image with preferred base 0 loads at any free address.

        Raises:
            ValueError: the image must move, but it has no relocation data.
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
                self.profiler.record_error_event(ErrorInfo(type="invalid_image", context_summary=problem))
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
                # PE sections can be smaller than a page and multiple sections can share one page.
                # Merge permissions per page so a later tiny read-only section does not clobber
                # earlier writable/executable permissions already required on that same page.
                for page in range(start, end, self.page_size):
                    page_perms[page] = page_perms.get(page, 0) | section.perms
            # Each unicorn mem_protect call splits a region, and the cost grows with the region
            # count, so protect runs of contiguous same-permission pages with one call each.
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
        """
        Get the path of the "SYSTEMROOT" environment variable
        """
        sysroot = self.env.get("systemroot", "C:\\WINDOWS\\system32")
        if not sysroot.endswith("\\"):
            sysroot += "\\"
        return sysroot

    def get_cd(self):
        """
        Get the path of the current directory
        """
        if not self.cd:
            self.cd = self.env.get("cd", "C:\\WINDOWS\\system32")
            if not self.cd.endswith("\\"):
                self.cd += "\\"
        return self.cd

    def set_cd(self, cd):
        """
        Sets the current directory path
        """
        self.cd = cd

    def get_env(self):
        return self.env

    def set_env(self, var, val):
        return self.env.update({var.lower(): val})

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
        obj = om.get_object_from_handle(handle)
        if obj:
            return obj
        obj = self.fileman.get_object_from_handle(handle)
        if obj:
            return obj

    def get_object_handle(self, obj):
        om = self.get_object_manager("object handle lookup")
        obj = om.objects.get(obj.address)
        if obj:
            return om.get_handle(obj)

    def add_object(self, obj):
        om = self.get_object_manager("object registration")
        om.add_object(obj)

    def new_object(self, otype):
        om = self.get_object_manager("object creation")
        return om.new_object(otype)

    def create_process(self, path=None, cmdline=None, image=None, child=False):
        """
        Create a process object that will exist in the emulator
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

        # Create a thread object for the new process
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

    def create_thread(self, addr, ctx, proc_obj, thread_type="thread", is_suspended=False):
        """
        Create a thread object that will exist in the emulator
        """
        om = self.get_object_manager("thread creation")

        if len(self.run_queue) >= self.max_runs:
            return 0, None

        thread = om.new_object(objman.Thread)
        thread.process = proc_obj
        hnd = om.get_handle(thread)

        run = Run()
        run.type = thread_type
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

        # Returns handle
        return hnd, thread

    def resume_thread(self, thread):
        """
        Resume a previously suspended thread
        """
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
        Adds a callback to the emulation callback list. A "callback" in this
        context refers to a function that in not imported statically or dynamically.

        For example, a pointer that is set in a function table
        (e.g. PsSetCreateProcessNotifyRoutine).
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
            # Declared functions that the physical manifest lacks still resolve,
            # because other Windows builds export them.
            eligible = eligible or (isinstance(reference, str) and self.has_api_signature(module.name, reference))
            # Empty placeholder modules deliberately offer dynamic-only functions.
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
        """Read the export directory (RVA, size) from the mapped header, or None when it cannot be read."""
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
        Get the module that handles an import of dll!name. When the functions of
        an API set are in more than one module, use the first module that has a
        handler for the name.
        """
        hosts = winemu.get_dll_hosts(module_name(dll))
        if len(hosts) > 1 and isinstance(name, str):
            for host in hosts:
                if self.get_api_handler(host, name)[1] or self.api.get_data_export_handler(host, name)[1]:
                    return host
        return hosts[0]

    def get_proc(self, mod_name, func_name):
        """Resolve an explicit import request to stable mapped code or storage."""
        host = self.get_import_host(mod_name, func_name)
        module = self.get_mod_by_name(host)
        if module is None:
            module = self.load_module_by_name(host)
        return self.resolve_export(module, func_name, allow_dynamic=True)

    def _intercept_api_trap(self, access, address, size):
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
        self.raise_cpu_exception(exception, f"invalid_{access_type}", access_type=access_type)
        return False

    def raise_cpu_exception(self, exception, error_type, **details):
        """From a Unicorn hook: stop Unicorn. The run loop then sends the exception to the guest."""
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
        Raise an access violation in the caller of an API whose handler touched an invalid
        guest pointer, as the API's own code would. Return False when no handler looks at it.
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
        """Map pages without access until their first access, which restores perms and raises an exception."""
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
                exception, "guard_page_violation", access_type=access_type, guard_page=(page, perms)
            )
        else:
            exception = cpu_exceptions.memory_fault(pc, address, access_type)
            self.raise_cpu_exception(exception, f"invalid_protect_{access_type}", access_type=access_type)
        return False

    def _step_had_no_effect(self, registers, debugger):
        """Get whether a single step stopped before its instruction with nothing pending."""
        if debugger.has_pending_stop() or self._native_exit is not None:
            return False
        return self._pending_fault_stop is None and self.get_register_state() == registers

    def _stopped_at_hlt(self, deadline, last_executed, counted, debugger):
        """
        Unicorn ends emulation without an error after `hlt`, which user mode cannot execute.
        Unicorn also stops that way for other reasons, so only report a `hlt` that surely ran:
        the last instruction the accounting hook saw or a debugger step ran, or with nothing
        else that stops the engine.

        Nothing better reports `hlt`: Unicorn hooks only `in`, `out`, `syscall`, `sysenter`
        and `cpuid` among x86 instructions, `hlt` raises no interrupt, and a code hook on
        every instruction would slow all emulation down.
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
        self.raise_cpu_exception(exception, "Invalid instruction (UC_ERR_INSN_INVALID)")
        return False

    def _hook_in_instruction(self, uc_engine, port, size, user_data):
        rax = self.get_return_val()
        self.raise_cpu_exception(
            cpu_exceptions.privileged_instruction(self.get_pc()), "privileged_instruction", rax=rax
        )
        return rax & 0xFFFFFFFF

    def _hook_out_instruction(self, uc_engine, port, size, value, user_data):
        self.raise_cpu_exception(cpu_exceptions.privileged_instruction(self.get_pc()), "privileged_instruction")

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
        """
        Called when an attempt to emulate an instruction from an invalid address
        """
        if address == self.return_hook or address == self.exit_hook:
            self._map_reserved_range()
            return True

        # The rest of an instruction that crosses into the next page; the run already ends at its start
        if isinstance(self._native_exit, FaultReturn) or self._pending_fault_stop is not None:
            return False

        return self._raise_memory_fault(address, "fetch")

    def _resolve_module_offset(self, addr: int) -> str | None:
        """Return 'module+0xoffset' string for an address inside a loaded module, or None."""
        mod = self.get_module_from_addr(addr)
        if mod:
            offset = addr - mod.base
            name = getattr(mod, "name", None) or getattr(mod, "path", "unknown")
            return f"{name}+{offset:#x}"
        return None

    def _resolve_region_info(self, addr: int) -> RegionInfo | None:
        """Return a RegionInfo for the region containing addr, or None if unmapped."""
        for m in self.get_mem_maps():
            if m.base <= addr <= (m.base + m.size) - 1:
                prot = get_prot_string(m.prot) if m.prot is not None else None
                return RegionInfo(tag=m.tag or "unknown", base=m.base, size=m.size, prot=prot)
        return None

    def _find_nearby_regions(self, addr: int, count: int = 2) -> list[RegionInfo]:
        """Return up to `count` nearest memory regions to an unmapped address."""
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
            distances.append((dist, RegionInfo(tag=m.tag or "unknown", base=m.base, size=m.size, prot=prot)))
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
        """Build a human-readable one-line triage summary.

        Examples::

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
        desc: str,
        address: int,
        traceback: str | None = None,
        access_type: str | None = None,
        api_name: str | None = None,
        message: str | None = None,
    ) -> ErrorInfo:
        """Collect emulator state information in the event of an error.

        For an error at an API trap, give the API name and its return address
        as the address, because the trap holds no instruction to show.
        For an internal_error, give the text of the Python exception as message.
        """
        run = self.get_current_run()
        pc = self.get_pc()

        if api_name:
            instr = f"api_trap {api_name}"
        else:
            try:
                mnem, op, instr = self.get_disasm(pc, DISASM_SIZE)
            except Exception as e:
                logger.error(str(e))
                instr = "disasm_failed"

        regs = self.get_register_state()
        stack = self.get_stack_trace()
        pc_module = self._resolve_module_offset(pc)
        address_region = self._resolve_region_info(address)
        nearby_regions = self._find_nearby_regions(address) if not address_region else None
        tid = self.curr_thread.tid if self.curr_thread else None
        pid = self.curr_process.id if self.curr_process else None

        label = f"{desc}: {message}" if message else desc
        if api_name:
            summary = f"{label} {api_name} called from {self._resolve_module_offset(address) or hex(address)}"
        else:
            summary = self._build_context_summary(
                label, pc, address, access_type, pc_module, address_region, nearby_regions
            )

        logger.error(
            "0x%x: %s: Caught error: %s\n  summary: %s\n  instr: %s\n  regs: %s",
            pc,
            run.type,
            label,
            summary,
            instr,
            "  ".join(f"{k}={v}" for k, v in regs.items()),
        )

        return ErrorInfo(
            type=desc,
            pc=pc,
            address=address,
            access_type=access_type,
            instr=instr,
            regs=regs,
            stack=stack,
            pc_module=pc_module,
            address_region=address_region,
            nearby_regions=nearby_regions,
            thread_id=tid,
            process_id=pid,
            context_summary=summary,
            traceback=traceback,
            message=message,
        )

    def get_api_handler(self, dll: str, name: str) -> tuple[Any, Any]:
        """
        Get the module and attributes of the handler for dll!name. If there is no
        handler for the name, try the names from get_handler_candidates. Return
        (None, None) if no handler is found.
        """
        for cand_dll, cand_name in ((dll, name), *api_resolution.get_handler_candidates(dll, name)):
            mod, func_attrs = self.api.get_export_func_handler(cand_dll, cand_name)
            if func_attrs:
                return mod, func_attrs
        return None, None

    def read_unicode_string(self, addr):
        """
        Read string data from a UNICODE_STRING object located at the specified address
        """
        us = windef.UNICODE_STRING(self.get_ptr_size())
        us = self.mem_cast(us, addr)

        string = self.read_mem_string(us.Buffer, width=2)
        return string

    @staticmethod
    def format_api_arg(arg: ApiArg) -> str:
        """
        Render a single API argument the way it appears in the API trace
        """
        text = arg.display
        if arg.type == "str" or (arg.name is None and arg.type == "text"):
            text = sigfmt.quote_string(text)
        return f"{arg.name}: {text}" if arg.name is not None else text

    def log_api(self, pc: int, imp_api: str, rv: int | None, args: list[ApiArg], *, run=None) -> None:
        """
        Log an API call and record it with the profiler
        """
        call_str = f"{imp_api}({', '.join(self.format_api_arg(arg) for arg in args)})"

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
        """
        Get the API signature database used to emulate imports without a handler
        """
        if self._sigdb is None:
            self._sigdb = sigdb.get_default_database()
        return self._sigdb

    def _get_signature_arch(self) -> str:
        return sigdb.ARCH_X86 if self.get_arch() == _arch.ARCH_X86 else sigdb.ARCH_X64

    def _lookup_api_declaration(self, dll: str, name: str) -> sigdb.FuncSig | None:
        """Find the authoritative declaration without choosing an execution ABI."""
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
        """Find a declaration that win32metadata files under an API set that maps to ``dll``."""
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
        # A known unsupported declaration is not unknown and still requires a
        # handler.
        return self.config.modules.functions_always_exist and self._lookup_api_declaration(dll, name) is None

    def has_api_signature(self, dll: str, name: str) -> bool:
        return self.lookup_api_signature(dll, name) is not None

    def get_handler_signature(self, dll: str, name: str, argc: int) -> sigdb.FuncSig | None:
        """
        Find the signature that names the arguments of a call served by a
        handler. Returns None when the function is unknown, variadic, or its
        declaration does not consume exactly the ``argc`` slots the handler reads.
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
        Get the formatter that renders arguments of signature-emulated calls
        (strings, enums, flags and struct contents) for the API trace
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
            return sigfmt.RenderedArg(hex(value), "int")

    def _render_signature_args(self, sig: sigdb.FuncSig, argv: list[int]) -> list[sigfmt.RenderedArg]:
        values = sig.values_from_slots(argv, self.get_ptr_size())
        return [self._render_signature_arg(param, value, i) for i, (param, value) in enumerate(zip(sig.params, values))]

    # Upper bound on how much memory a single Out parameter is zero-filled with
    MAX_OUT_ZERO_FILL = 0x10000

    def _read_uint_for_signature(self, addr: int, size: int) -> int | None:
        try:
            return int.from_bytes(self.mem_read(addr, size), "little")
        except Exception:
            return None

    def _zero_fill_out_params(self, sig: sigdb.FuncSig, values: list[int], ptr_size: int) -> None:
        """
        Give Out-only pointer parameters deterministic contents. A call we
        only know the signature of reports success without producing any
        data, so the memory the caller reads back is zeroed (empty strings,
        NULL handles, zero counts) rather than left as uninitialized stack.
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
        """
        Pick a plausible "success" return value for a call we only know the signature of
        """
        kind = sig.ret_kind
        if kind == "v":
            return None
        if kind in sigdb.BOOL_KINDS:
            return 1
        if kind == "h":
            if self.om is not None:
                return self.om.new_handle()
            return 4
        # Status codes (HRESULT, NTSTATUS, WIN32_ERROR), counts and pointers all
        # read as "nothing happened" at zero.
        return 0

    def _handle_api_from_signature(self, dll: str, name: str, sig: sigdb.FuncSig, call_pc: int) -> int | None:
        """
        Emulate an import that has no handler using only its declared signature:
        consume the right number of argument slots, log the call with decoded
        arguments, return a type-appropriate success value and clean up the
        stack according to the calling convention.
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
        Find the code to run for dll!name. Look in this order: a handler, user
        hooks, the signature database, a stub.
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
        Run the code for the API that the guest called. End the run if the code
        changed the stack pointer but did not return.
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
                origin_run.error = self.get_error_info("api_handler_did_not_return", entry_pc)
                origin_run.error.api_name = f"{dll}.{name}"
                logger.error("API handler %s.%s changed SP without returning", dll, name)
                self.end_run_on_fault()
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
        Run the handler of the API, or the user hooks for the API. Return False if
        the handler failed, and the run ended or a guest exception started.
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
            # Hooks execute in FIFO order (first registered, first called).
            # All hooks run; the last hook's return value is used.
            prev_ctx, self.api_ctx = self.api_ctx, ctx
            try:
                for hook in hooks:
                    rv = hook.cb(self, imp_api, orig, argv)
            finally:
                self.api_ctx = prev_ctx
        else:
            try:
                rv = self.api.call_api_func(impl.module, impl.func, argv, ctx=ctx)
            except Exception as e:
                if self._should_stop_on_faults:
                    # Let the outer GDB fault path expose the failed frame
                    # before run cleanup and report signal termination.
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
                self._set_run_error(error)
                self.on_run_complete()
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

        # Is this function being called from a dynamcially allocated memory segment?
        if mm and mm.tag and "virtualalloc" in mm.tag.lower():
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

        # Deferred lifecycle/SEH work is processed before guest execution resumes.
        if not self.is_run_complete:
            self.enable_deferred_work_hook()
        return True

    def _handle_api_hook(self, call: _ApiCallState, hooks: list[common.ApiHook]) -> None:
        """
        Run the user hook of an API that has no handler. The hook gives the
        argument count and the calling convention. Only the last hook that was
        added runs, because the hooks can give different values.
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
        rv = hook.cb(self, call.api_name, None, argv)
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
        Return 1 from an unknown API so that execution can continue. The argument
        count and the calling convention are not known, so guess stdcall with four
        arguments.
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
        """End the run with an unsupported_api error."""
        error = self.get_error_info("unsupported_api", call.return_address, api_name=call.api_name)
        logger.error("Unsupported API: %s (ret: 0x%x)", call.api_name, call.return_address)
        self.log_api(call.call_pc, call.api_name, None, [], run=call.run)
        error.api_name = call.api_name
        self._set_run_error(error)
        self.on_run_complete()

    def _check_api_limit(self, origin_run, imp_api):
        run = self.get_current_run()
        if run is origin_run and run and run.get_api_count() > self.config.max_api_count:
            logger.info("* Maximum number of API calls reached. Stopping current run.")
            run.error = ErrorInfo(
                type="max_api_count",
                pc=self.get_pc(),
                count=self.config.max_api_count,
                last_api=imp_api,
            )
            self.on_run_complete()

    def start_guest_callback(self, frame, function, args, sp=None):
        """Enter a guest callback on the stack of its frame, or below sp."""
        if frame.saved_registers is None:
            registers = NONVOLATILE_AMD64 if self.get_arch() == _arch.ARCH_AMD64 else NONVOLATILE_X86
            frame.saved_registers = tuple((register, self.reg_read(register)) for register in registers)
        frame.function = function
        sp = frame.stack_pointer if sp is None else sp
        if self.ptr_size == 8:
            # Win64 callees expect RSP + 8 to be 16-byte aligned at entry, and
            # each argument after the fourth occupies one 8-byte stack slot.
            sp &= ~0xF
            if max(len(args) - 4, 0) % 2:
                sp -= 8
        self.set_func_args(sp, winemu.GUEST_CALLBACK_RETURN_ADDR, *args, conv=_arch.CALL_CONV_STDCALL)
        self.set_pc(function)

    def _continue_guest_callback(self):
        """Resume a typed guest callback continuation outside Unicorn callbacks."""
        run = self.get_current_run()
        # Frames below the one returning were left without returning
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
                frame.event.ret_val = hex(frame.result) if frame.result is not None else None
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
        """Restore the nonvolatile registers the guest calls of frame may have changed, as Windows keeps them."""
        for register, value in frame.saved_registers or ():
            self.reg_write(register, value)

    def _hook_mem_unmapped(self, emu, access, address, size, value):
        """
        High level function used to catch all invalid memory accesses that occur during
        emulation
        """
        try:
            access = self.emu_eng.mem_access.get(access)
            logger.debug("mem_unmapped: access=%s addr=0x%x size=0x%x", access, address, size)
            if access != common.INVALID_MEM_EXEC:
                self.prev_pc = self.get_pc()

            self.enable_deferred_work_hook()

            if access == common.INVALID_MEM_EXEC:
                return self._handle_invalid_fetch(emu, address, size, value)

            elif access == common.INVALID_MEM_READ:
                return self._handle_invalid_read(emu, address, size, value)

            elif access == common.INVAL_PERM_MEM_EXEC:
                if address & ~(self.page_size - 1) in self.guard_pages:
                    return self._raise_protection_fault(address, "fetch")
                return self._handle_prot_fetch(emu, address, size, value)
            elif access == common.INVAL_PERM_MEM_READ and not self.is_kernel_mode:
                return self._raise_protection_fault(address, "read")
            elif access == common.INVALID_MEM_WRITE:
                return self._handle_invalid_write(emu, address, size, value)
            elif access == common.INVAL_PERM_MEM_WRITE:
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

        error = self.get_error_info("invalid_protect_write", address, access_type="write")
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
        """
        If the supplied address is related to a known symbol, look it up here
        """
        symbol = self.api_registry.symbol(address)
        if symbol is not None:
            return symbol
        if self.api_registry.overlaps_traps(address):
            return None
        auxiliary = self.symbols.get(address)
        return "{}.{}".format(*auxiliary) if auxiliary else None

    def get_symbols(self) -> dict[int, tuple[str, str]]:
        """Snapshot public addresses as legacy (dll, name) tuples.

        Registry entries take precedence over auxiliary labels at the same address.
        Forwarder strings and private dispatch tokens are not public symbols.
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
        """Snapshot public function/data and auxiliary symbols as string labels."""
        return {address: "{}.{}".format(*value) for address, value in self.get_symbols().items()}

    def _set_run_error(self, error: ErrorInfo) -> None:
        """Save error as the error of the current run, if a run is active."""
        if self.curr_run is not None:
            self.curr_run.error = error

    def _end_run_on_hook_error(self, description: str, exception: Exception) -> bool:
        """Log the current exception, save it as the run error, and stop emulation."""
        logger.exception(description)
        error = self.get_error_info(
            "internal_error",
            self.get_pc(),
            traceback=traceback.format_exc(),
            message=str(exception) or type(exception).__name__,
        )
        self._set_run_error(error)
        self.on_emu_complete()
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
        """
        Hook each memory read event that occurs. This hook is used to lookup symbols and modules
        that are read from during emulation.
        """
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
        """
        Hook each memory write event that occurs. This hook is used to track memory modifications
        to interesting memory locations.
        """
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
        """
        Hook each invalid memory read event that occurs.
        """
        mod = self.get_mod_from_addr(address)
        if mod:
            return True

        if address >= winemu.EMU_RESERVED and address <= (winemu.EMU_RESERVED + winemu.EMU_RESERVE_SIZE):
            self._map_reserved_range()
            return True

        return self._raise_memory_fault(address, "read")

    def _handle_prot_fetch(self, emu, address, size, value):
        """
        Called when non-executable code is emulated
        """
        # Ordinary analysis recovers execution in non-X guest sections.
        # Synthetic API protections and debugger stops are always
        # authoritative; a symbol never causes dispatch from this hook.
        module = self.get_mod_from_addr(address)
        if (
            not self._should_stop_on_faults
            and (module is None or module._image.source != "synthetic")
            and not self.api_registry.overlaps_traps(address)
        ):
            if module is not None and module._image.source == "guest_pe":
                # A change of protection while Unicorn handles this fetch can
                # make its current translation incorrect. Change it after Unicorn stops.
                native_perms = next(perms for start, end, perms in self.get_mem_regions() if start <= address <= end)
                perms = next(perms for perms, native in self.emu_eng.perms.items() if native == native_perms)
                page = address & ~(self.page_size - 1)
                self._record_exit(ExecRecovery(page, perms | common.PERM_MEM_EXEC))
                return False
            return True
        error = self.get_error_info("invalid_protect_fetch", address, access_type="fetch")
        self._set_run_error(error)
        self.end_run_on_fault()
        return False

    def _handle_invalid_write(self, emu, address, size, value):
        """
        Called when non-writable address is written to
        """
        # ignore patches to APIs
        if address >= winemu.EMU_RESERVED and address <= (winemu.EMU_RESERVED + winemu.EMU_RESERVE_SIZE):
            self._map_reserved_range()
            return True

        return self._raise_memory_fault(address, "write")

    def _hook_code_deferred_work(self, emu, addr, size):
        """
        Code hook that runs at the next instruction after an API call, a fault or a request to end the run.
        It ends the run if it is complete and unmaps the reserved range.
        It disables itself when it has no more work.
        """
        try:
            if addr == self.return_hook or self.is_run_complete:
                self.on_run_complete()
                return False

            # Handler instructions are not progress at the original fault site.
            # After continuation, retain the guard until the guest advances.
            if self._seh_resume_pc is not None and addr != self._seh_resume_pc:
                self._seh_last_fault = None
                self._seh_repeat_count = 0
                self._seh_resume_pc = None

            self._unmap_reserved_range()
            if self._seh_resume_pc is None:
                self.disable_deferred_work_hook()
            return True
        except Exception as e:
            return self._end_run_on_hook_error("Exception during code hook (deferred work)", e)

    def _hook_code_coverage(self, emu, addr, size):
        """
        Persistent code hook that records every executed address for coverage.
        """
        try:
            if self.curr_run is not None:
                self.curr_run.coverage.add(addr)
            return True
        except Exception as e:
            return self._end_run_on_hook_error("Exception during code hook (coverage)", e)

    def _hook_code_tracing(self, emu, addr, size):
        """
        Persistent code hook for memory tracing: instruction counting,
        symbol execution tracking, and per-region execution tracking.
        """
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
        """
        Persistent code hook that prints disassembly and register state
        for every instruction when debug mode is enabled.
        """
        x = self.get_disasm(addr, size)[2]
        if self.get_arch() == _arch.ARCH_AMD64:
            regs: tuple[str, ...] = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9")
        else:
            regs = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        vals = " : ".join(f"{r}=0x{self.reg_read(r):x}" for r in regs)
        print(f"0x{addr:x}: {x}, {vals}")
        return True

    def get_native_module_path(self, mod_name=""):
        """
        Get the path of a DLL with this name in the configured module directory
        """
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
        frame = self._active_api_frame
        if frame is not None and not self.is_kernel_mode:
            # Keep the earliest snapshot for each process across reentrant loads.
            tracked = {process.id for process, _ in frame.peb_module_snapshot}
            frame.peb_module_snapshot.extend(item for item in original_peb_modules if item[0].id not in tracked)
            frame.created_modules.extend(module for module in self.modules if module not in original_modules)
            handler = self.api.load_api_handler("kernel32")
            for routine in self.module_loader.collect_initializers():
                handler.setup_callback(routine.address, routine.args)
                frame.initializers[routine.address] = routine
        return module.base

    def load_module_by_name(self, name, emu_path=None, base=None, native_path=None, data=None):
        """Load one coherent native or catalog-generated module instance."""
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

    # This will create a module from a file inside Speakeasy's
    # object manager. file_path is expected to point to a valid PE
    # file, like it would on a real Windows machine
    # Returns: raw data that represents a PE file
    def get_module_data_from_emu_file(self, file_path):
        if not self.does_file_exist(file_path):
            return None

        mod_file = self.fileman.get_file_from_path(file_path)

        if not mod_file:
            return None

        # This file could have been read from, so don't mess
        # with its file offset pointer. Just get the raw bytes
        # from the BytesIO object
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
            if isinstance(base, str):
                base = int(base, 16)
            path = modconf.path or name + ".dll"
            native = None
            for image in getattr(modconf, "images", ()):
                if image.arch == self.get_arch():
                    native = self.get_native_module_path(image.name)
            rtmods.append(self.load_module_by_name(name, emu_path=path, base=base, native_path=native))
        return rtmods

    def get_thread_context(self, thread=None):
        """
        Get the current thread CPU context
        """
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

    def load_thread_context(self, ctx, thread=None):
        """
        Set the current thread CPU context
        """
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
            _, _, instr = self.get_disasm(address, DISASM_SIZE)
        except Exception as e:
            logger.error(str(e))
            instr = "disasm_failed"
        pc_module = self._resolve_module_offset(address)
        handler_module = self._resolve_module_offset(handler)
        handler_desc = f"0x{handler:x}" + (f" ({handler_module})" if handler_module else "")
        logger.info(
            '0x%x: Exception caught: code=0x%x handler=%s instr="%s"\n  pc: %s\n  regs: %s',
            address,
            code,
            handler_desc,
            instr,
            pc_module or f"0x{address:x}",
            "  ".join(f"{k}={v}" for k, v in registers.items()),
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
                faulting_address=hex(faulting_address) if faulting_address is not None else None,
                pc_module=pc_module,
                stack_trace=self.get_stack_trace(),
            )

    _SEH_MAX_REPEAT = 4

    def dispatch_seh(self, faulting_address, exception, error):
        """Dispatch exception to the guest handlers. Return whether a handler takes it."""
        self._seh_resume_pc = None
        fault_key = (self.get_pc(), faulting_address)
        if fault_key == self._seh_last_fault:
            self._seh_repeat_count += 1
            if self._seh_repeat_count >= self._SEH_MAX_REPEAT:
                return False
        else:
            self._seh_last_fault = fault_key
            self._seh_repeat_count = 1

        return self.exception_dispatcher().dispatch_fault(self, exception, error)

    @property
    def active_api_frame(self) -> GuestCallbackFrame | None:
        """The frame of the API call being handled, if any."""
        return self._active_api_frame

    def exception_dispatcher(self):
        """The exception dispatch of the architecture"""
        return seh64 if self.get_arch() == _arch.ARCH_AMD64 else seh32

    def note_seh_resume(self, pc):
        """
        A handler continues execution at pc. Resuming elsewhere than the fault is progress;
        at the fault, the guard against repeating it holds until execution moves on.
        """
        if self._seh_last_fault is None:
            return
        if pc == self._seh_last_fault[0]:
            self._seh_resume_pc = pc
            self.enable_deferred_work_hook()
        else:
            self._seh_last_fault = None
            self._seh_repeat_count = 0
            self._seh_resume_pc = None

    def create_event(self, name=""):
        """
        Create a kernel event object
        """
        om = self.get_object_manager("event creation")
        evt = self.new_object(objman.Event)
        evt.name = name
        hnd = om.get_handle(evt)
        return hnd, evt

    def dec_ref(self, obj):
        """
        Dereference an object
        """
        om = self.get_object_manager("object dereference")
        return om.dec_ref(obj)

    def create_mutant(self, name=""):
        """
        Create a kernel mutant object
        """
        om = self.get_object_manager("mutant creation")
        if name == 0:
            name = ""
        mtx = self.new_object(objman.Mutant)
        mtx.name = name
        hnd = om.get_handle(mtx)
        return hnd, mtx

    def create_semaphore(self, name=""):
        """
        Create a kernel semaphore object
        """
        om = self.get_object_manager("semaphore creation")
        sem = self.new_object(objman.Semaphore)
        sem.name = name
        hnd = om.get_handle(sem)
        return hnd, sem

    def _hook_interrupt(self, emu, intnum):
        """
        Called when software interrupts occur
        """
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
                self.raise_cpu_exception(exception, "unhandled_interrupt", interrupt_num=intnum)
            return True

        # Handle __fastfail interrupt introduced in Windows 8
        if intnum == 0x29:
            ecx = self.reg_read(_arch.X86_REG_ECX)
            # Cookie security init failed, just return since we are in __security_init_cookie
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
        error = self.get_error_info("unhandled_interrupt", pc)
        error.interrupt_num = intnum
        self._set_run_error(error)

        if self._should_stop_on_faults:
            self.end_run_on_fault()
            return False
        self.on_run_complete()
        return False
