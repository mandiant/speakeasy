# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import logging
import ntpath
import os
import shlex
import time
import traceback
from abc import abstractmethod
from collections.abc import Callable
from enum import IntEnum
from typing import Any

import unicorn as uc

import speakeasy.common as common
import speakeasy.windows.common as winemu
import speakeasy.windows.objman as objman
import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.nt.ddk as ddk
import speakeasy.winenv.defs.windows.windows as windef
from speakeasy.binemu import BinaryEmulator
from speakeasy.errors import WindowsEmuError
from speakeasy.gdb import GdbServer, ResumeAction, StopReason
from speakeasy.profiler import ApiCallbackFrame, MemAccess, Run
from speakeasy.profiler_events import ApiArg, TracePosition
from speakeasy.report import ErrorInfo, RegionInfo
from speakeasy.struct import EmuStruct
from speakeasy.windows.api_registry import ApiRegistry, module_name, symbol_ref
from speakeasy.windows.cryptman import CryptoManager
from speakeasy.windows.driveman import DriveManager
from speakeasy.windows.fileman import FileManager
from speakeasy.windows.hammer import ApiHammer
from speakeasy.windows.loaders import get_prot_string
from speakeasy.windows.netman import NetworkManager
from speakeasy.windows.objman import HandleAllocator
from speakeasy.windows.regman import RegistryManager
from speakeasy.winenv.api import sigdb, sigfmt
from speakeasy.winenv.api.api import NO_CONTEXT, ApiContext, HandlerArgs

# When disassembling, a minimum instruction size needs to be supplied
# This number is arbitrary and just needs to be large enough to cover
# the size of the current disasm target
DISASM_SIZE = 0x20

# GDB signal number reported for memory faults
SIGSEGV = 11

logger = logging.getLogger(__name__)


def _normalize_mod_name(name: str) -> str:
    return module_name(name)


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


class BootstrapPhase(IntEnum):
    INITIALIZED = 0
    ENGINE_API_READY = 1
    OBJECT_MANAGER_READY = 2
    FULL_SETUP_READY = 3


class WindowsEmulator(BinaryEmulator):
    """
    Base class providing emulation of all Windows modules and shellcode.
    This class is meant to provide overlapping functionality for both
    user mode and kernel mode samples.

    Subclasses must define:
        peb_addr: Address of the Process Environment Block
    """

    peb_addr: int

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
        self._setup_done: bool = False
        self.bootstrap_phase: BootstrapPhase = BootstrapPhase.INITIALIZED
        self.curr_run: Run | None = None
        self.api_ctx: ApiContext = NO_CONTEXT
        self.restart_curr_run: bool = False
        self._stop_on_faults: bool = False
        self._pending_fault_stop: StopReason | None = None
        self.curr_mod: Any | None = None
        self.runs: list[Run] = []
        self.input: dict[str, Any] | None = None
        self.exit_event: Any | None = exit_event
        self.page_size: int = 4096
        self.ptr_size: int | None = None
        self.max_runs: int = 100
        self.symbols: dict[int, str] = {}
        self.ansi_strings: list[str] = []
        self.unicode_strings: list[str] = []
        self.tmp_maps: list[tuple[int, int]] = []
        self.run_queue: list[Run] = []
        self.suspended_runs: list[Run] = []
        self.cd: str = ""
        self.emu_hooks_set: bool = True
        self.api: Any | None = None
        self.curr_process: Any | None = None
        self.om: objman.ObjectManager | None = None
        self._sigdb: sigdb.SignatureDatabase | None = None
        self._sigfmt: sigfmt.ArgFormatter | None = None
        self.api_registry = ApiRegistry(self)
        self._pending_api_entry = None
        self._pending_api_snapshot = None
        self._pending_control = None
        self._pending_exec_recovery: tuple[int, int] | None = None
        self._pending_trap_fault: tuple[str, int] | None = None
        self._guest_dependencies = []
        self._failed_guest_modules = []
        self._shared_peb_modules = set()
        self._import_bindings: dict[int, int] = {}
        self._load_depth: int = 0
        self._active_api_frame: ApiCallbackFrame | None = None
        self.mem_trace_hooks: list[Any] = []
        self.coverage_hook: Any | None = None
        self.debug_hook: Any | None = None
        self.kernel_mode: bool = False
        self.virtual_mem_base: int = 0x50000

        self.tmp_code_hook: Any | None = None
        self.veh_handlers: list[int] = []

        self.run_complete: bool = False
        self.emu_complete: bool = False
        self.processes: list[Any] = []
        # Child processes created by calls to CreateProcess
        # by any module. This is separate from self.processes in order
        # to not mix up config processes with child processes
        self.child_processes: list[Any] = []
        self.curr_thread: Any | None = None
        self.curr_exception_code: int = 0
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
        self.regman: RegistryManager = RegistryManager(self.handle_allocator, self.config.registry)
        self.fileman: FileManager = FileManager(config, self)
        self.netman: NetworkManager = NetworkManager(self.handle_allocator, config=self.config.network)
        self.driveman: DriveManager = DriveManager(config=self.config.drives)
        self.cryptman: CryptoManager = CryptoManager(self.handle_allocator)
        self.hammer: ApiHammer = ApiHammer(self)
        self._io_manager: Any | None = None

    def _parse_config(self, config):
        """
        Parse the emulation config file
        """
        super()._parse_config(config)
        self.cd = self.config.current_dir
        self.command_line = self.config.command_line

    def advance_bootstrap_phase(self, phase):
        if phase <= self.bootstrap_phase:
            return

        # Keep bootstrap ordering explicit so object-dependent APIs fail fast
        # if loader/setup sequencing regresses.
        transitions = {
            BootstrapPhase.INITIALIZED: {BootstrapPhase.ENGINE_API_READY},
            BootstrapPhase.ENGINE_API_READY: {BootstrapPhase.OBJECT_MANAGER_READY, BootstrapPhase.FULL_SETUP_READY},
            BootstrapPhase.OBJECT_MANAGER_READY: {BootstrapPhase.FULL_SETUP_READY},
            BootstrapPhase.FULL_SETUP_READY: set(),
        }

        allowed = transitions[self.bootstrap_phase]
        if phase not in allowed:
            raise WindowsEmuError(f"invalid bootstrap transition {self.bootstrap_phase.name} -> {phase.name}")

        self.bootstrap_phase = phase

    def get_bootstrap_phase(self):
        return self.bootstrap_phase

    def validate_bootstrap_phase(self, phase, reason):
        if self.bootstrap_phase < phase:
            raise WindowsEmuError(
                f"{reason} requires bootstrap phase {phase.name}, current phase is {self.bootstrap_phase.name}"
            )

    def bootstrap_object_services(self):
        return None

    def validate_object_services(self, reason):
        if self.om is None:
            raise WindowsEmuError(f"{reason} requires initialized object services")

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
        if not self._stop_on_faults or in_reserved:
            # A fault callback still belongs to the native invocation of this
            # run. Advance only after Unicorn unwinds, even if it raises after
            # emu_stop; otherwise the old fault can overwrite the next run.
            self._pending_control = "fault_return"
            self.emu_eng.stop()
            return
        self._pending_fault_stop = StopReason(signal=SIGSEGV, kind="exception", address=pc)
        self.emu_eng.stop()  # type: ignore[union-attr]

    def enable_code_hook(self):
        if not self.tmp_code_hook:
            self.tmp_code_hook = self.add_code_hook(cb=self._hook_code_core)

        if self.tmp_code_hook:
            self.tmp_code_hook.enable()

    def disable_code_hook(self):
        if self.tmp_code_hook:
            self.tmp_code_hook.disable()

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

    def _unset_emu_hooks(self):
        """
        Create a formatted structure from bytes
        """
        if self.emu_hooks_set:
            self.emu_eng.mem_map(winemu.EMU_RETURN_ADDR, winemu.EMU_RESERVE_SIZE)  # type: ignore[union-attr]
        self.emu_hooks_set = False

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
            from speakeasy.windows.ioman import IoManager

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

    def reg_create_key(self, path):
        """
        Create a registry key
        """
        return self.regman.create_key(path)

    def _set_emu_hooks(self):
        """
        Unmap reserved memory space so we can handle events (e.g. import APIs,
        entry point returns, etc.)
        """
        if not self.emu_hooks_set:
            self.mem_unmap(winemu.EMU_RETURN_ADDR, winemu.EMU_RESERVE_SIZE)
            self.emu_hooks_set = True

    def add_run(self, run):
        """
        Add a run to the emulation run queue
        """
        self.run_queue.append(run)

    def _exec_next_run(self):
        """
        Execute the next run from the emulation queue
        """
        for frame in self.curr_run.api_callbacks:
            self._rollback_guest_load(frame)
        self.curr_run.api_callbacks.clear()
        self._pending_api_entry = None
        self._pending_control = None
        self._pending_trap_fault = None
        self._pending_exec_recovery = None
        stage = self.curr_run.guest_initialization
        if stage is not None:
            module, last, is_dll, pid = stage
            if self.curr_run.error or (is_dll and not self._dll_main_succeeded()):
                self.curr_run.error = self.curr_run.error or ErrorInfo(
                    type="dll_initialization_failed", pc=self.get_pc()
                )
                logger.warning(
                    "guest initializer failed for %s in process %s: %s", module.name, pid, self.curr_run.error.type
                )
                if self.config.modules.strict_loading:
                    if self._detach_failed_guest_initialization(module, pid):
                        self._failed_guest_modules.append(module)
                    for queued in self.run_queue:
                        pending = queued.guest_initialization
                        if pending is not None and pending[3] == pid:
                            pending[0]._initialization.pop(pid, None)
                    self.run_queue[:] = [
                        queued
                        for queued in self.run_queue
                        if queued.guest_initialization is None or queued.guest_initialization[3] != pid
                    ]
                    self.on_emu_complete()
                    return None
                # Keep mapped exports alive for already bound IAT slots, while
                # recording failure rather than claiming successful attachment.
                module._initialization[pid] = "failed"
                self.run_queue[:] = [
                    queued
                    for queued in self.run_queue
                    if not (
                        (pending := queued.guest_initialization) is not None
                        and pending[0] is module
                        and pending[3] == pid
                    )
                ]
            elif last:
                module._initialization[pid] = "ready"
        try:
            run = self.run_queue.pop(0)
        except IndexError:
            self.on_emu_complete()
            return None

        self.run_complete = False
        self.reset_stack(self.stack_base)
        self.reset_cpu_context()
        mm = self.get_address_map(self.stack_base - 1)
        self.mem_write(mm.base, b"\x00" * mm.size)
        prepared = self._prepare_run_context(run)
        self.emu_eng.stop()
        return prepared

    def call(self, addr, params=[]):
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

        self.set_func_args(stk_ptr, self.return_hook, *run.args, conv=_arch.CALL_CONV_STDCALL)
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
        elif not self.kernel_mode:
            thread = objman.Thread(self, stack_base=self.stack_base)
            self.om.objects.update({thread.address: thread})
            if self.curr_process:
                thread.process = self.curr_process
                self.curr_process.threads.append(thread)
            run.thread = thread
            self.set_current_thread(thread)

        if not self.kernel_mode:
            # Reset the TIB data
            thread = self.get_current_thread()
            if thread:
                self.init_teb(thread, self.curr_process.peb)  # type: ignore[union-attr]
                self.init_tls(thread)

        if winemu.EMU_RESERVED <= run.start_addr <= winemu.EMU_RESERVED_END:
            try:
                self.mem_unmap(winemu.EMU_RESERVED, winemu.EMU_RESERVE_SIZE)
            except Exception:
                pass
            self.emu_hooks_set = True

        self.set_pc(run.start_addr)
        return run

    def mem_cast(self, obj, addr):
        """
        Turn bytes from an emulated memory pointer into an object
        """
        size = obj.sizeof()
        struct_bytes = self.mem_read(addr, size)
        return self.cast(obj, struct_bytes)

    def mem_purge(self):
        """
        Unmap all memory chunks
        """
        self.purge_memory()

    def setup_user_shared_data(self):
        """
        Setup the shared user data section that is often used to share data
        between user mode and kernel mode
        """
        if self.get_arch() == _arch.ARCH_X86:
            self.mem_map(self.page_size, base=0xFFDF0000, tag="emu.struct.KUSER_SHARED_DATA")
        elif self.get_arch() == _arch.ARCH_AMD64:
            self.mem_map(self.page_size, base=0xFFFFF78000000000, tag="emu.struct.KUSER_SHARED_DATA")

        # This is a read-only address for KUSER_SHARED_DATA,
        # and this is the same address for 32-bit and 64-bit.
        self.mem_map(self.page_size, base=0x7FFE0000, tag="emu.struct.KUSER_SHARED_DATA")
        self._populate_user_shared_data(0x7FFE0000)

    def _populate_user_shared_data(self, base):
        import struct
        import time

        now_100ns = int(time.time() * 10_000_000) + 116444736000000000
        tick_ms = int(time.monotonic() * 1000) & 0xFFFFFFFF

        data = bytearray(0x400)

        # InterruptTime (offset 0x008): KSYSTEM_TIME {LowPart, High1Time, High2Time}
        interrupt_100ns = int(time.monotonic() * 10_000_000)
        struct.pack_into(
            "<IiI", data, 0x008, interrupt_100ns & 0xFFFFFFFF, interrupt_100ns >> 32, interrupt_100ns >> 32
        )
        # SystemTime (offset 0x014): KSYSTEM_TIME
        struct.pack_into("<IiI", data, 0x014, now_100ns & 0xFFFFFFFF, now_100ns >> 32, now_100ns >> 32)
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

        self.mem_write(base, bytes(data))

    def _run_api_engine(self, address, timeout=0, count=-1, debugger=None):
        """Keep one logical execution action across private API trap yields."""
        pending = self._pending_api_entry
        if pending is not None and address not in (pending.address, pending.trap):
            # A debugger register edit abandons the suspended dispatch.
            self._pending_api_entry = None
        elif pending is not None and self._api_call_snapshot(pending) != self._pending_api_snapshot:
            # Patches and frame edits while stopped must execute the revised
            # public bytes instead of bypassing them through a retained trap.
            self._pending_api_entry = None
            address = pending.address
            self.set_pc(address)
        if (
            self._pending_control
            and self._pending_control != "exec_recovery"
            and address
            not in (
                winemu.API_CALLBACK_HANDLER_ADDR,
                self.return_hook,
                self.exit_hook,
            )
        ):
            self._pending_control = None
        started = time.monotonic()
        spent = self.curr_run.execution_elapsed
        deadline = started + max(timeout - spent, 0) if timeout > 0 else None
        budget = self.config.max_instructions if debugger is not None else count
        used = self.curr_run.budget_instructions
        remaining = [max(budget - used, 0) if budget > 0 else -1]
        limit = [False]
        origin_run = self.curr_run
        hook = None

        def recover_execution():
            assert self._pending_exec_recovery is not None
            page, perms = self._pending_exec_recovery
            self._pending_exec_recovery = None
            self.mem_protect(page, self.page_size, perms)

        def stop_limit(kind):
            if self._pending_api_entry is not None:
                self.set_pc(self._pending_api_entry.address)
            if kind == "timeout":
                logger.error("* Timeout of %d sec(s) reached.", timeout)
            else:
                logger.error("* Instruction limit of %d reached.", budget)
            # A limit that expires while a fault is completing keeps the fault as
            # the run's error.
            if debugger is not None:
                debugger._request_stop(StopReason(kind=kind, address=self.get_pc()))
            elif self.curr_run is origin_run:
                if origin_run.error is None:
                    origin_run.error = ErrorInfo(
                        type=kind, pc=self.get_pc(), count=budget if kind == "max_instructions" else None
                    )
                self.on_run_complete()

        if budget > 0:

            def account_instruction(_emu, _address, _size):
                if debugger is not None and debugger.has_pending_stop():
                    return
                if remaining[0] <= 0:
                    limit[0] = True
                    self.emu_eng.stop()
                    return
                remaining[0] -= 1
                origin_run.budget_instructions += 1
                if not self.config.analysis.memory_tracing:
                    self.curr_run.instr_cnt += 1

            hook = self.add_code_hook(account_instruction)
        try:
            while not self.emu_complete:
                if self.exit_event and self.exit_event.is_set():
                    self.emu_eng.stop()
                    return
                if self._pending_control:
                    if debugger is not None and debugger.has_pending_stop():
                        return
                    control, self._pending_control = self._pending_control, None
                    if control in ("run_return", "fault_return"):
                        self.on_run_complete()
                        return
                    if control == "exec_recovery":
                        recover_execution()
                    else:
                        self._continue_api_callback()
                    address = self.get_pc()
                    if debugger is not None and (debugger.has_pending_stop() or count == 1):
                        return
                if deadline is not None and time.monotonic() >= deadline:
                    stop_limit("timeout")
                    return
                if limit[0] or (budget > 0 and remaining[0] <= 0):
                    stop_limit("max_instructions")
                    return
                if self._pending_api_entry is None and not self._pending_control:
                    try:
                        native_timeout = max(deadline - time.monotonic(), 0.000001) if deadline is not None else 0
                        # Native count is a ceiling for this invocation, preventing
                        # tracing hooks from seeing an instruction beyond the cap.
                        # The hook carries exact consumption across private yields.
                        native_count = remaining[0] if budget > 0 else 0
                        if debugger is not None and count == 1:
                            native_count = min(native_count, 1) if native_count else 1
                        self.emu_eng.start(address, timeout=native_timeout, count=native_count)
                    except uc.UcError as exc:
                        if self._pending_fault_stop is not None:
                            return
                        if self._pending_trap_fault is not None:
                            pass
                        elif self._pending_control == "exec_recovery" and exc.errno == uc.UC_ERR_FETCH_PROT:
                            pass
                        elif self._pending_control == "fault_return":
                            pass
                        elif exc.errno != uc.UC_ERR_FETCH_UNMAPPED or (
                            self._pending_api_entry is None and not self._pending_control
                        ):
                            raise
                    if self._pending_trap_fault is not None:
                        self._dispatch_trap_fault()
                        address = self.get_pc()
                        if self._pending_fault_stop is not None:
                            return
                        if debugger is not None and (debugger.has_pending_stop() or count == 1):
                            return
                        continue
                    if self._pending_api_entry is None:
                        candidate = self.api_registry.traps.get(self.get_pc())
                        if candidate is not None:
                            self._suspend_api_call(candidate)
                    if self.get_pc() == winemu.API_CALLBACK_HANDLER_ADDR and self.curr_run.api_callbacks:
                        self._pending_control = "callback_return"
                    elif self.get_pc() in (self.return_hook, self.exit_hook):
                        self._pending_control = "run_return"
                if self.curr_run is not origin_run or self.emu_complete:
                    return
                entry = self._pending_api_entry
                if debugger is not None and debugger.has_pending_stop():
                    return
                if self._pending_control:
                    continue
                if deadline is not None and time.monotonic() >= deadline:
                    stop_limit("timeout")
                    return
                if budget > 0 and remaining[0] <= 0:
                    stop_limit("max_instructions")
                    return
                if entry is None:
                    return
                self._pending_api_entry = None
                self._pending_api_snapshot = None
                self.prev_pc = entry.address
                self.handle_import_func(entry.dll, entry.name)
                if self._pending_fault_stop is not None:
                    return
                if self.run_complete and not self.emu_complete and self.curr_run is origin_run:
                    self.on_run_complete()
                address = self.get_pc()
                if self.curr_run is not origin_run:
                    return
                if debugger is not None and (debugger.has_pending_stop() or count == 1):
                    return
        finally:
            origin_run.execution_elapsed = spent + time.monotonic() - started
            for module in self._failed_guest_modules:
                self._discard_loaded_module(module)
            self._failed_guest_modules.clear()
            if hook is not None:
                if hook.added:
                    self.emu_eng.hook_remove(hook.handle)
                self.hooks[common.HOOK_CODE].remove(hook)

    def resume(self, addr, count=-1):
        """Resume emulation directly at an address.

        This low-level API bypasses the GDB command loop; callers that enable
        GDB should drive execution through :meth:`start` instead.
        """
        if self.curr_run is None:
            self.curr_run = Run()
        self.emu_complete = False
        timeout = 0 if self.gdb_port is not None else self.config.timeout
        self._run_api_engine(addr, timeout=timeout, count=count)

    def start(self, addr=None, size=None):
        """
        Begin emulation executing each run in the specified run queue
        """
        if not self.kernel_mode and self.run_queue:
            initializers = self._collect_guest_initializers()
            queued = []
            for module, function, last, is_dll, pid in initializers:
                run = Run()
                run.type = f"dependency.{module.name}.{'dll_entry' if is_dll else 'tls_callback'}"
                run.start_addr = function
                run.args = (module.base, 1, 0)
                run.thread = self.run_queue[0].thread or self.curr_thread
                run.process_context = self.curr_process
                run.guest_initialization = (module, last, is_dll, pid)
                queued.append(run)
            self.run_queue[:0] = queued
        try:
            run = self.run_queue.pop(0)
        except IndexError:
            return

        self.run_complete = False
        self.emu_complete = False
        self.set_hooks()
        self._set_emu_hooks()

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
            for module in self._failed_guest_modules:
                self._discard_loaded_module(module)
            self._failed_guest_modules.clear()
            self.on_emu_complete()

    def _execute_runs(
        self,
        debugger: GdbServer | None = None,
        debug_action: ResumeAction | None = None,
    ) -> bool:
        """Execute prepared runs, optionally under control of an active GDB session."""
        if debugger is not None:
            assert debug_action is not None
        detached_resume_addr = None
        terminal_signal = 0
        timeout = 0 if debugger is not None else self.config.timeout
        self._stop_on_faults = debugger is not None
        self._pending_fault_stop = None

        if self.profiler:
            self.profiler.set_start_time()

        while True:
            try:
                if debugger is not None:
                    resume_addr = self.get_pc()
                else:
                    resume_addr = detached_resume_addr or self.curr_run.start_addr  # type: ignore[union-attr]
                    detached_resume_addr = None
                instruction_count = 1 if debugger is not None and debug_action.step else self.config.max_instructions
                should_execute = debugger is None or debugger.begin_run(debug_action)
                executing_run = self.curr_run
                if should_execute:
                    self._run_api_engine(resume_addr, timeout=timeout, count=instruction_count, debugger=debugger)
                if debugger is not None:
                    stop_reason = debugger.finish_run(debug_action)
                    fault_stop, self._pending_fault_stop = self._pending_fault_stop, None
                    if fault_stop is not None:
                        stop_reason = fault_stop
                        terminal_signal = fault_stop.signal
                    if stop_reason is not None:
                        debug_action = debugger.command_loop(stop_reason)
                        if debug_action.kill:
                            return True
                        if debug_action.detach:
                            debugger.close()
                            debugger = None
                            self._stop_on_faults = False
                            timeout = self.config.timeout
                        if fault_stop is not None and not self.on_run_complete():
                            break
                        if debugger is None:
                            detached_resume_addr = self.get_pc()
                        continue
                if self.curr_run is not executing_run and not self.emu_complete:
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

                error = self.get_error_info(str(e), self.get_pc(), traceback=stack_trace)
                self.curr_run.error = error  # type: ignore[union-attr]
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
                        debugger.close()
                        debugger = None
                        self._stop_on_faults = False
                        timeout = self.config.timeout

                run = self.on_run_complete()
                if not run:
                    break
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

    def get_dropped_files(self):
        """
        Get all files written by the sample from the file manager
        """
        if self.fileman:
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

        gdt_addr, gdt_size = self.get_valid_ranges(GDT_SIZE)
        self.mem_map(gdt_size, base=gdt_addr, tag="emu.gdt")
        seg_addr, seg_size = self.get_valid_ranges(SEG_SIZE)
        self.mem_map(seg_size, base=seg_addr, tag="emu.segment.gdt")

        access = winemu.GDT_ACCESS_BITS.Data | winemu.GDT_ACCESS_BITS.DataWritable | winemu.GDT_ACCESS_BITS.Ring3
        _make_entry(16, 0, access)

        access = winemu.GDT_ACCESS_BITS.Code | winemu.GDT_ACCESS_BITS.CodeReadable | winemu.GDT_ACCESS_BITS.Ring3
        _make_entry(17, 0, access)

        access = winemu.GDT_ACCESS_BITS.Data | winemu.GDT_ACCESS_BITS.DataWritable | winemu.GDT_ACCESS_BITS.Ring0
        _make_entry(18, 0, access)

        self.reg_write(_arch.X86_REG_GDTR, (0, gdt_addr, num_gdt_entries * ENTRY_SIZE - 1, 0x0))
        selector = _create_selector(16, winemu.GDT_FLAGS.Ring3)
        self.reg_write(_arch.X86_REG_DS, selector)
        selector = _create_selector(17, winemu.GDT_FLAGS.Ring3)
        self.reg_write(_arch.X86_REG_CS, selector)
        selector = _create_selector(18, winemu.GDT_FLAGS.Ring0)
        self.reg_write(_arch.X86_REG_SS, selector)

        if _arch.ARCH_X86 == arch:
            # FS segment needed for PEB access at fs:[0x30]
            fs_addr, fs_size = self.get_valid_ranges(SEG_SIZE)
            self.mem_map(fs_size, base=fs_addr, tag="emu.segment.fs")

            access = winemu.GDT_ACCESS_BITS.Data | winemu.GDT_ACCESS_BITS.DataWritable | winemu.GDT_ACCESS_BITS.Ring3
            _make_entry(19, fs_addr, access)

            selector = _create_selector(19, winemu.GDT_FLAGS.Ring3)
            self.reg_write(_arch.X86_REG_FS, selector)

        elif _arch.ARCH_AMD64 == arch:
            # GS Segment needed for PEB access at gs:[0x60]
            gs_addr, gs_size = self.get_valid_ranges(SEG_SIZE)
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
        from speakeasy.windows.loaders import RuntimeModule

        ptrsz = self.get_ptr_size()
        run = self.curr_run
        module = self.get_mod_from_addr(run.start_addr)  # type: ignore[union-attr]

        if module:
            if isinstance(module, RuntimeModule):
                modname = ntpath.basename(module.emu_path)
                if module._image and module._image.tls_directory_va:
                    tls_dirp = module._image.tls_directory_va
                    tls_dir = self.mem_read(tls_dirp, ptrsz)
                    thread.init_tls(tls_dir, os.path.splitext(modname)[0])
            else:
                modname = module.emu_path
                tokens = modname.split("\\")
                modname = tokens[len(tokens) - 1]
                tls_dirp = module.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress
                tls_dirp += module.OPTIONAL_HEADER.ImageBase
                tls_dir = self.mem_read(tls_dirp, ptrsz)
                thread.init_tls(tls_dir, os.path.splitext(modname)[0])

        return

    def load_pe(self, path=None, data=None):
        """
        Parse a PE that will be used during emulation. PE type and architecture
        are automatically determined.
        """

        if not data and not os.path.exists(path):
            raise WindowsEmuError(f"File: {path} not found")

        pe = winemu._PeParser(path=path, data=data)

        pe_type = "unknown"
        if pe.is_driver():
            pe_type = "driver"
        elif pe.is_dll():
            pe_type = "dll"
        elif pe.is_exe():
            pe_type = "exe"

        arch = "unknown"
        if pe.arch == _arch.ARCH_AMD64:
            arch = "x64"
        elif pe.arch == _arch.ARCH_X86:
            arch = "x86"

        self.input = {
            "path": pe.path,
            "sha256": pe.hash,
            "size": pe.file_size,
            "arch": arch,
            "filetype": pe_type,
            "emu_version": self.get_emu_version(),
            "os_run": self.get_osver_string(),
        }
        if self.profiler:
            self.profiler.add_input_metadata(self.input)
        return pe

    def get_mod_from_addr(self, addr):
        if self.curr_mod:
            end = self.curr_mod.base + self.curr_mod.image_size
            if addr >= self.curr_mod.base and addr <= end:
                return self.curr_mod

        for m in self.modules:
            base = m.base
            size = m.image_size
            if addr >= base and addr < base + size:
                return m
        return None

    def ensure_pe_import_hooks(self, base_addr):
        """Bind imports of an injected mapped PE using the public API registry.

        Validate every RVA against SizeOfImage and bound both table walks.
        Stage valid IAT writes independently by default; strict PE parsing
        requires every import to validate.
        A zero OriginalFirstThunk may reuse an already bound IAT; recorded
        bindings preserve idempotence without interpreting code addresses as RVAs.

        Intended for PEs injected via WriteProcessMemory (process hollowing)
        that bypass the normal module loader.
        """
        import struct

        import pefile

        ptr_size = self.get_ptr_size()
        strict = self.config.modules.strict_loading
        import_errors = (ValueError, UnicodeError, struct.error, uc.UcError, WindowsEmuError)
        try:
            dos = self.mem_read(base_addr, 0x40)
            if dos[:2] != b"MZ":
                return
            nt_rva = struct.unpack_from("<I", dos, 0x3C)[0]
            if nt_rva > 0x100000:
                return
            header = self.mem_read(base_addr + nt_rva, 24)
            if header[:4] != b"PE\x00\x00":
                return
            opt_size = struct.unpack_from("<H", header, 20)[0]
            if opt_size < (0x80 if ptr_size == 8 else 0x70) or opt_size > 0x1000:
                return
            opt = self.mem_read(base_addr + nt_rva + 24, opt_size)
            magic = struct.unpack_from("<H", opt)[0]
            if magic != (0x20B if ptr_size == 8 else 0x10B):
                return
            image_size = struct.unpack_from("<I", opt, 56)[0]
            directory_offset = 112 if ptr_size == 8 else 96
            if struct.unpack_from("<I", opt, directory_offset - 4)[0] < 2:
                return
            import_rva, import_size = struct.unpack_from("<II", opt, directory_offset + 8)
            if not import_rva and not import_size:
                return
            if not import_rva or not import_size or import_rva + import_size > image_size:
                raise ValueError("import directory outside image")

            def read_rva(rva, size):
                if rva < 0 or size < 0 or rva + size > image_size:
                    raise ValueError("import RVA outside image")
                return self.mem_read(base_addr + rva, size)

            def read_name(rva, *, dll=False):
                # Bounded byte reads also support names ending at a page boundary.
                if not 0 <= rva < image_size:
                    raise ValueError("import name RVA outside image")
                value = bytearray()
                for offset in range(min(4096, image_size - rva)):
                    byte = read_rva(rva + offset, 1)
                    if byte == b"\x00":
                        if not value:
                            raise ValueError("invalid import name")
                        if dll:
                            ascii_name = bytes(byte if byte < 128 else ord("x") for byte in value)
                            if not pefile.is_valid_dos_filename(ascii_name):
                                raise ValueError("invalid import DLL name")
                            try:
                                return value.decode("ascii")
                            except UnicodeError:
                                if strict:
                                    raise
                                name = value.decode("latin-1")
                                logger.warning("non-ASCII injected import DLL name decoded as Latin-1: %r", name)
                                return name
                        if not pefile.is_valid_function_name(bytes(value)):
                            raise ValueError("invalid import function name")
                        return value.decode("ascii")
                    value.extend(byte)
                raise ValueError("unterminated import name")

            pending = []
            for index in range(min(import_size // 20, 4096)):
                try:
                    descriptor = read_rva(import_rva + index * 20, 20)
                except import_errors as error:
                    if strict:
                        raise
                    logger.warning("unreadable injected PE import descriptor at %#x: %s", base_addr, error)
                    break
                if descriptor == b"\x00" * 20:
                    break
                ilt_rva, _, _, name_rva, iat_rva = struct.unpack("<5I", descriptor)
                try:
                    if not name_rva or not iat_rva:
                        raise ValueError("incomplete import descriptor")
                    dll_name = read_name(name_rva, dll=True)
                except import_errors as error:
                    if strict:
                        raise
                    logger.warning("skipping injected PE import descriptor %s at %#x: %s", index, base_addr, error)
                    continue
                thunk_rva = ilt_rva or iat_rva
                for offset in range(min(image_size // ptr_size, 65536)):
                    iat = iat_rva + offset * ptr_size
                    try:
                        thunk = int.from_bytes(read_rva(thunk_rva + offset * ptr_size, ptr_size), "little")
                        if not thunk:
                            break
                        current = int.from_bytes(read_rva(iat, ptr_size), "little")
                    except import_errors as error:
                        if strict:
                            raise
                        # Without readable slots, the remainder of this table
                        # cannot be walked safely; other descriptors are independent.
                        logger.warning("skipping injected PE import table %s at %#x: %s", dll_name, base_addr, error)
                        break
                    if self._import_bindings.get(base_addr + iat) == current:
                        continue
                    if base_addr + iat in self._import_bindings and (not ilt_rva or current != thunk):
                        # Preserve a guest hook. A separate ILT can identify an
                        # explicitly restored unbound slot; zero-OFT images cannot.
                        continue
                    if not ilt_rva and not thunk & (1 << (ptr_size * 8 - 1)) and thunk >= image_size:
                        # Already bound externally, with no surviving name table.
                        continue
                    try:
                        if thunk & (1 << (ptr_size * 8 - 1)):
                            if thunk & ~((1 << (ptr_size * 8 - 1)) | 0xFFFF):
                                raise ValueError("reserved bits in ordinal import")
                            reference = f"ordinal_{thunk & 0xFFFF}"
                        else:
                            reference = read_name(thunk + 2)
                        address = self.get_proc(dll_name, reference)
                        if not address:
                            raise WindowsEmuError(f"unresolved import {dll_name}!{reference}")
                        if not 0 <= address < 1 << (ptr_size * 8):
                            raise ValueError("import address does not fit pointer size")
                    except import_errors as error:
                        if strict:
                            raise
                        logger.warning("skipping injected PE import slot at %#x: %s", base_addr + iat, error)
                        continue
                    pending.append((base_addr + iat, address))
                else:
                    if strict:
                        raise ValueError("unterminated import thunk table")
                    logger.warning("unterminated injected PE import thunk table at %#x", base_addr)
            else:
                if strict:
                    raise ValueError("unterminated import descriptor table")
                logger.warning("unterminated injected PE import descriptor table at %#x", base_addr)

            for iat, address in pending:
                self.mem_write(iat, address.to_bytes(ptr_size, "little"))
            self._import_bindings.update(pending)
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

    def load_image(self, image):
        """Publish a coherent load graph, rolling back module ownership on failure."""
        outer = not self._load_depth
        if outer:
            original_modules = list(self.modules)
            original_maps = {id(mapping) for mapping in self.maps}
            original_bindings = dict(self._import_bindings)
            original_shared = set(self._shared_peb_modules)
            original_attachments = self._snapshot_peb_attachments()
        self._load_depth += 1
        try:
            module = self._load_image(image)
        except Exception:
            if outer:
                removed = [module for module in self.modules if module not in original_modules]
                for module in reversed(removed):
                    processes = list(self.processes)
                    if self.curr_process is not None and self.curr_process not in processes:
                        processes.append(self.curr_process)
                    for process in processes:
                        if process.is_peb_active and self.get_address_map(process.peb_ldr_data.address):
                            process.remove_module_from_peb(module)
                    self.api_registry.unregister_module(module)
                self._rollback_peb_attachments(original_attachments)
                self.modules[:] = original_modules
                self._import_bindings = original_bindings
                self._shared_peb_modules = original_shared
                self._guest_dependencies[:] = [
                    module for module in self._guest_dependencies if module in original_modules
                ]
                for mapping in tuple(self.maps):
                    if id(mapping) not in original_maps and (mapping.tag or "").startswith("emu.module."):
                        self.mem_unmap(mapping.base, mapping.size)
                        self.maps.remove(mapping)
            raise
        finally:
            self._load_depth -= 1
        if outer:
            self._notify_module_change()
        return module

    def _notify_module_change(self):
        """Notify every observer without letting one failure disrupt publication."""
        for listener in tuple(self.module_change_listeners):
            try:
                listener()
            except Exception:
                logger.exception("module change listener failed: %r", listener)

    def _discard_loaded_module(self, module):
        processes = list(self.processes)
        if self.curr_process is not None and self.curr_process not in processes:
            processes.append(self.curr_process)
        for process in processes:
            if process.is_peb_active and self.get_address_map(process.peb_ldr_data.address):
                process.remove_module_from_peb(module)
        self.api_registry.unregister_module(module)
        self._shared_peb_modules.discard(module.base)
        if module in self.modules:
            self.modules.remove(module)
        if module in self._guest_dependencies:
            self._guest_dependencies.remove(module)
        mapping = self.get_address_map(module.base)
        if mapping is not None:
            self.mem_unmap(mapping.base, mapping.size)
            self.maps.remove(mapping)
        self._import_bindings = {
            address: target
            for address, target in self._import_bindings.items()
            if not module.base <= address < module.base + module.image_size
        }
        self._notify_module_change()

    def _snapshot_peb_attachments(self):
        processes = list(self.processes)
        if self.curr_process is not None and self.curr_process not in processes:
            processes.append(self.curr_process)
        return [(process, dict(process._peb_modules)) for process in processes]

    def _rollback_peb_attachments(self, snapshot):
        for process, original in snapshot:
            for base, module in tuple(process._peb_modules.items()):
                if base not in original:
                    process.remove_module_from_peb(module)

    def _detach_failed_guest_initialization(self, module, pid):
        """Fail one process attachment without destroying other owners."""
        module._initialization.pop(pid, None)
        for process, _ in self._snapshot_peb_attachments():
            if process.id == pid:
                process.remove_module_from_peb(module)
        return not any(module.base in process._peb_modules for process, _ in self._snapshot_peb_attachments())

    def _rollback_guest_load(self, frame):
        # Callback frames retain the attachment delta separately from newly
        # allocated images. Cached images belong to the surviving load graph.
        self._rollback_peb_attachments(frame.loader_attachments)
        original = {process.id: modules for process, modules in frame.loader_attachments}
        for module, _last, _is_dll, pid in frame.initializers.values():
            if module._initialization.get(pid) == "initializing" or module.base not in original.get(pid, {}):
                module._initialization.pop(pid, None)
        for module in reversed(frame.created_modules):
            if not any(module.base in process._peb_modules for process, _ in self._snapshot_peb_attachments()):
                self._discard_loaded_module(module)
        frame.pending[:] = [(function, args) for function, args in frame.pending if function not in frame.initializers]
        frame.initializers.clear()
        frame.created_modules.clear()
        frame.loader_attachments = []

    def _collect_guest_initializers(self):
        process = self.get_current_process()
        if process is None:
            return []
        result = []
        for module in self._guest_dependencies:
            if (
                module not in self.modules
                or module.base not in process._peb_modules
                or module._initialization.get(process.id)
            ):
                continue
            module._initialization[process.id] = "initializing"
            functions = [(function, False) for function in module.get_tls_callbacks()]
            if module.ep:
                functions.append((module.base + module.ep, True))
            if not functions:
                module._initialization[process.id] = "ready"
            for index, (function, is_dll) in enumerate(functions):
                result.append((module, function, index == len(functions) - 1, is_dll, process.id))
        return result

    def _load_image(self, image):
        import capstone as cs

        from speakeasy.windows.loaders import RuntimeModule

        valid_arch = image.arch in (_arch.ARCH_X86, _arch.ARCH_AMD64)
        if self.arch and valid_arch and self.arch != image.arch:
            raise WindowsEmuError("module architecture does not match the emulated process")
        if not self.arch:
            if valid_arch:
                self.arch = image.arch
            else:
                self.arch = _arch.ARCH_X86
            self.set_ptr_size(self.arch)

        if self.emu_eng and not self.emu_eng.emu:
            engine_arch = image.arch if valid_arch else _arch.ARCH_X86
            self.emu_eng.init_engine(_arch.ARCH_X86, engine_arch)

        if not self.ptr_size:
            self.ptr_size = 4

        if not self.disasm_eng:
            if self.arch == _arch.ARCH_AMD64:
                self.disasm_eng = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
            else:
                self.disasm_eng = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)

        if not self.api:
            from speakeasy.winenv.api.winapi import WindowsApi

            self.api = WindowsApi(self)

        self.advance_bootstrap_phase(BootstrapPhase.ENGINE_API_READY)
        self.bootstrap_object_services()

        if image.source == "synthetic" and not image.image_base:
            raise WindowsEmuError("synthetic image addresses must be finalized before mapping")
        requested_base = image.image_base
        for region in image.regions:
            offset = region.base - requested_base
            if offset < 0 or offset + len(region.data) > image.image_size:
                raise WindowsEmuError("module region is outside its image span")
        base = self.mem_map(
            image.image_size,
            base=requested_base or None,
            tag=f"emu.module.{image.name}",
            process=self.get_current_process() if self.kernel_mode else None,
        )
        if requested_base and base != requested_base:
            raise WindowsEmuError(f"cannot map module {image.name} at {requested_base:#x}: address range is in use")
        image.image_base = base
        for region in image.regions:
            self.mem_write(base + region.base - requested_base, region.data)

        mod = RuntimeModule(image)
        self.modules.append(mod)
        self.api_registry.register_module(mod)
        is_guest = image.source == "guest_pe"
        if is_guest and not self.stack_base and image.stack_size:
            self.stack_base, _stack_addr = self.alloc_stack(self.config.stack_size or image.stack_size)
        if not self._setup_done:
            self._setup_done = True
            self.setup()
            self.advance_bootstrap_phase(BootstrapPhase.FULL_SETUP_READY)

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
                if self.config.modules.strict_loading:
                    raise
                logger.warning("skipping import %s!%s in %s: %s", imp.dll_name, imp.func_name, image.name, error)
                continue
            self.mem_write(imp.iat_address, encoded)
            self._import_bindings[imp.iat_address] = address

        for entry in tuple(self.api_registry.entries.values()):
            if entry.export.kind == "data":
                self._initialize_api_data(entry)

        if image.sections and image.module_type != "shellcode":
            first_rva = min(section.virtual_address for section in image.sections)
            if first_rva:
                self.mem_protect(
                    mod.base, (first_rva + self.page_size - 1) & ~(self.page_size - 1), common.PERM_MEM_READ
                )
            page_perms = {}
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
            (is_guest or image.source == "guest_shellcode")
            and self.profiler
            and self.config.analysis.strings
            and image.regions
        ):
            raw = image.regions[0].data
            self.profiler.strings["ansi"] = [a[1] for a in self.get_ansi_strings(raw)]
            self.profiler.strings["unicode"] = [u[1] for u in self.get_unicode_strings(raw)]
        if not self.kernel_mode and self.get_current_process() is None and mod.visible_in_peb and mod.is_dll():
            self._shared_peb_modules.add(mod.base)
        self._attach_module_to_current_process(mod)
        return mod

    def setup(self):
        pass

    def get_system_root(self):
        """
        Get the path of the "SYSTEMROOT" environment variable
        """
        sysroot = self.env.get("systemroot", "C:\\WINDOWS\\system32")
        if not sysroot.endswith("\\"):
            sysroot += "\\"
        return sysroot

    def get_windows_dir(self):
        """
        Get the path of the "WINDIR" environment variable
        """
        sysroot = self.env.get("windir", "C:\\WINDOWS")
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
        self.validate_object_services("object lookup by address")
        return self.om.get_object_from_addr(addr)  # type: ignore[union-attr]

    def get_object_from_id(self, id):
        self.validate_object_services("object lookup by id")
        return self.om.get_object_from_id(id)  # type: ignore[union-attr]

    def get_object_from_name(self, name):
        self.validate_object_services("object lookup by name")
        return self.om.get_object_from_name(name)  # type: ignore[union-attr]

    def get_object_from_handle(self, handle):
        self.validate_object_services("object lookup by handle")
        obj = self.om.get_object_from_handle(handle)  # type: ignore[union-attr]
        if obj:
            return obj
        obj = self.fileman.get_object_from_handle(handle)
        if obj:
            return obj

    def get_object_handle(self, obj):
        self.validate_object_services("object handle lookup")
        obj = self.om.objects.get(obj.address)  # type: ignore[union-attr]
        if obj:
            return self.om.get_handle(obj)  # type: ignore[union-attr]

    def add_object(self, obj):
        self.validate_object_services("object registration")
        self.om.add_object(obj)  # type: ignore[union-attr]

    def search_path(self, file_name):
        # For now, return the current directory, add emulated path walking later
        if "\\" in file_name:
            return file_name
        fp = self.get_cd()
        if not fp.endswith("\\"):
            fp += "\\"
        return fp + file_name

    def new_object(self, otype):
        self.validate_object_services("object creation")
        return self.om.new_object(otype)  # type: ignore[union-attr]

    def create_process(self, path=None, cmdline=None, image=None, child=False):
        """
        Create a process object that will exist in the emulator
        """
        self.validate_object_services("process creation")

        if not path and cmdline:
            path = cmdline

        # See if we are trying to create a process based off a file
        # inside the object manager and serve that
        # Setting posix to false makes shlex not treat '\' as an
        # escape character, but if each token was surrounded with
        # quotes, those are kept, so we have to delete them
        file_path = shlex.split(path, posix=False)[0]

        if file_path[0] == '"' and file_path[len(file_path) - 1] == '"':
            file_path = file_path[1:-1]

        p = self.om.new_object(objman.Process)  # type: ignore[union-attr]

        mod_data = self.get_module_data_from_emu_file(file_path)

        if mod_data:
            p.pe_data = mod_data
        else:
            new_mod = self.load_module_by_name(file_path, emu_path=path)
            p.pe = new_mod

        p.path = file_path
        p.cmdline = cmdline

        # Create a thread object for the new process
        t = self.om.new_object(objman.Thread)  # type: ignore[union-attr]
        t.process = p
        t.tid = self.om.new_id()  # type: ignore[union-attr]

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
        self.validate_object_services("thread creation")

        if len(self.run_queue) >= self.max_runs:
            return 0, None

        thread = self.om.new_object(objman.Thread)  # type: ignore[union-attr]
        thread.process = proc_obj
        hnd = self.om.get_handle(thread)  # type: ignore[union-attr]

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

    @property
    def callbacks(self):
        return [
            (entry.address, entry.dll, entry.name) for entry in self.api_registry.entries.values() if entry.callback
        ]

    def add_callback(self, mod_name, func_name):
        """
        Adds a callback to the emulation callback list. A "callback" in this
        context refers to a function that in not imported statically or dynamically.

        For example, a pointer that is set in a function table
        (e.g. PsSetCreateProcessNotifyRoutine).
        """
        from speakeasy.windows.loaders import ApiModuleLoader

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
        entry.callback = True
        entry.binding_module = mod_name
        entry.binding_name = func_name
        return entry.address

    def _initialize_api_data(self, entry):
        if self.bootstrap_phase < BootstrapPhase.FULL_SETUP_READY:
            return
        if entry.dll == "ntoskrnl" and not self.kernel_mode:
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
            if not eligible or module._image.source != "synthetic":
                return 0
            try:
                entry = self.api_registry.dynamic(module, reference)
            except WindowsEmuError:
                logger.debug("cannot allocate API entry for %s!%s", module.name, reference, exc_info=True)
                return 0
        if entry.export.forwarder:
            seen = set() if _seen is None else _seen
            key = (id(module), reference)
            if key in seen or len(seen) >= 32:
                return 0
            seen.add(key)
            target = entry.export.forwarder
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

    def get_proc(self, mod_name, func_name):
        """Resolve an explicit import request to stable mapped code or storage."""
        name = module_name(mod_name)
        host = winemu.normalize_dll_name(name)
        module = self.get_mod_by_name(host)
        if module is None:
            module = self.load_module_by_name(host)
        return self.resolve_export(module, func_name, allow_dynamic=True)

    def _intercept_api_trap(self, access, address, size):
        if self.emu_eng.mem_access.get(access) == common.INVALID_MEM_EXEC:
            if address in (self.return_hook, self.exit_hook) and self.curr_run:
                self._pending_control = "run_return"
                self.emu_eng.stop()
                return True
            if address == winemu.API_CALLBACK_HANDLER_ADDR and self.curr_run and self.curr_run.api_callbacks:
                self._pending_control = "callback_return"
                self.emu_eng.stop()
                return True
            entry = self.api_registry.traps.get(address)
            if entry is not None:
                self._suspend_api_call(entry)
                self.emu_eng.stop()
                return True
        if self.api_registry.overlaps_traps(address, size):
            # No fake-page recovery may ever materialize the private reservation.
            kind = {
                common.INVALID_MEM_READ: "read",
                common.INVALID_MEM_WRITE: "write",
                common.INVALID_MEM_EXEC: "fetch",
            }.get(self.emu_eng.mem_access.get(access), "read")
            self._pending_trap_fault = (kind, address)
            self.emu_eng.stop()
            return True
        return False

    def _dispatch_trap_fault(self):
        """Deliver private-reservation faults after native execution unwinds.

        Unlike ordinary recovery, this path must not map a temporary page at
        the target. Guest SEH may redirect execution or repair its registers.
        """
        kind, address = self._pending_trap_fault
        self._pending_trap_fault = None
        self.prev_pc = self.get_pc()
        if self.config.exceptions.dispatch_handlers and self.dispatch_seh(ddk.STATUS_ACCESS_VIOLATION, address):
            self.enable_code_hook()
            return
        self.curr_run.error = self.get_error_info(f"invalid_{kind}", address, access_type=kind)
        self.end_run_on_fault()

    def _api_call_snapshot(self, entry):
        sp = self.get_stack_ptr()
        try:
            return_address = self.mem_read(sp, self.ptr_size)
        except uc.UcError:
            return_address = None
        try:
            code = self.mem_read(entry.address, 16)
        except uc.UcError:
            code = None
        return sp, return_address, code

    def _suspend_api_call(self, entry):
        self._pending_api_entry = entry
        self._pending_api_snapshot = self._api_call_snapshot(entry)

    def _handle_invalid_fetch(self, emu, address, size, value):
        """
        Called when an attempt to emulate an instruction from an invalid address
        """
        if address == self.return_hook or address == self.exit_hook:
            self._unset_emu_hooks()
            return True

        # Are there any SEH handlers registered?
        if self.config.exceptions.dispatch_handlers:
            rv = self.dispatch_seh(ddk.STATUS_ACCESS_VIOLATION, address)
            if rv:
                return True

        fakeout = address & 0xFFFFFFFFFFFFF000
        self.mem_map(self.page_size, base=fakeout)

        error = self.get_error_info("invalid_fetch", address, access_type="fetch")
        self.curr_run.error = error  # type: ignore[union-attr]
        self.tmp_maps.append((fakeout, self.page_size))
        self.end_run_on_fault()
        return True

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
        self, desc: str, address: int, traceback: str | None = None, access_type: str | None = None
    ) -> ErrorInfo:
        """Collect emulator state information in the event of an error."""
        run = self.get_current_run()
        pc = self.get_pc()

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

        summary = self._build_context_summary(desc, pc, address, access_type, pc_module, address_region, nearby_regions)

        logger.error(
            "0x%x: %s: Caught error: %s\n  summary: %s\n  instr: %s\n  regs: %s",
            pc,
            run.type,
            desc,
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
        )

    def normalize_import_miss(self, dll, name):
        """
        This function attempts to fold as many function handlers together as possible.
        For example, ntdll functions will be handled by the ntoskrnl handlers, multiple versions
        of the C runtime are folded together, and Zw/Nt functions use the same handler.
        """
        alt_imp_api = ""
        alt_imp_dll = ""
        mod, func_attrs = None, None

        # Handle ANSI vs UNICODE functions
        if name.endswith("A") or name.endswith("W"):
            alt_imp_api = name[:-1]

        # Handle Zw*/Nt* function overlap
        if dll.lower().startswith("ntoskrnl"):
            if name.startswith("Zw"):
                alt_imp_api = f"Nt{name[2:]}"
            elif name.startswith("Nt"):
                name = "Zw" + name[2:]
                alt_imp_api = f"Zw{name[2:]}"

        alt_imp_dll = winemu.normalize_dll_name(dll)

        # Bridge ntdll funcs to ntoskrnl if supported
        if dll.lower().startswith("ntdll"):
            alt_imp_dll = "ntoskrnl"
            mod, func_attrs = self.api.get_export_func_handler(alt_imp_dll, name)  # type: ignore[union-attr]
            if not func_attrs:
                if name.startswith("Zw"):
                    alt_imp_api = f"Nt{name[2:]}"
                elif name.startswith("Nt"):
                    name = "Zw" + name[2:]
                    alt_imp_api = f"Zw{name[2:]}"
                mod, func_attrs = self.api.get_export_func_handler(alt_imp_dll, alt_imp_api)  # type: ignore[union-attr]
            return mod, func_attrs

        if alt_imp_api:
            mod, func_attrs = self.api.get_export_func_handler(dll, alt_imp_api)  # type: ignore[union-attr]
        if not func_attrs and alt_imp_dll:
            mod, func_attrs = self.api.get_export_func_handler(alt_imp_dll, name)  # type: ignore[union-attr]
        if not func_attrs and alt_imp_dll and alt_imp_api:
            mod, func_attrs = self.api.get_export_func_handler(alt_imp_dll, alt_imp_api)  # type: ignore[union-attr]
        return mod, func_attrs

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
            deferred = frame is not None and any(item is frame for item in run.api_callbacks)
            event = self.profiler.record_api_event(run, pos, imp_api, rv, args, deduplicate=not deferred)
            if deferred:
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
            sig = db.lookup_exact(dll, name, arch)
            if sig is None:
                alt_dll = winemu.normalize_dll_name(dll)
                if alt_dll.lower() != dll.lower():
                    sig = db.lookup_exact(alt_dll, name, arch)
        except Exception as exc:
            raise WindowsEmuError(f"signature provider failed for {dll}!{name}: {exc}") from exc
        return sig

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

    def emulate_api_from_signature(self, dll: str, name: str, sig: sigdb.FuncSig, call_pc: int) -> int | None:
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
        if not self.run_complete:
            self.enable_code_hook()
        return rv

    def get_api_args(self) -> list[ApiArg]:
        """
        Get the arguments of the hooked API call in progress, as the report shows them.

        An API hook calls this after it calls the original handler to see the
        values the handler decoded, such as the strings behind pointer arguments.
        Outside an API hook the list is empty.
        """
        return self.api_ctx.args.get_report_args()

    def handle_import_func(self, dll, name):
        frame = ApiCallbackFrame(self.get_stack_ptr(), self.get_ret_address())
        previous = self._active_api_frame
        self._active_api_frame = frame
        origin_run = self.curr_run
        entry_pc = self.get_pc()
        try:
            self._dispatch_import_func(dll, name, frame)
            if (
                self.curr_run is origin_run
                and not self.run_complete
                and not self.emu_complete
                and self.get_pc() == entry_pc
                and self.get_stack_ptr() != frame.stack_pointer
                and not self._pending_control
                and not origin_run.api_callbacks
            ):
                origin_run.error = self.get_error_info("api_handler_did_not_return", entry_pc)
                origin_run.error.api_name = f"{dll}.{name}"
                logger.error("API handler %s.%s changed SP without returning", dll, name)
                self.end_run_on_fault()
        finally:
            self._active_api_frame = previous

    def _dispatch_import_func(self, dll, name, frame):
        """
        Forward imported functions to the corresponding handler (if any).
        """
        imp_api = f"{dll}.{name}"
        oret = self.get_ret_address()
        opc = self.get_pc()
        osp = self.get_stack_ptr()
        origin_run = self.curr_run
        call_pc = self.prev_pc if self.prev_pc != 0 else oret
        mod, func_attrs = self.api.get_export_func_handler(dll, name)  # type: ignore[union-attr]
        if not func_attrs:
            mod, func_attrs = self.normalize_import_miss(dll, name)

        if func_attrs:
            handler_name, func, argc, conv, ordinal = func_attrs
            frame.argc = argc
            frame.convention = conv

            if name.startswith("ordinal_"):
                name = handler_name

            argv = self.get_func_argv(conv, argc)
            imp_api = f"{dll}.{name}"

            # Render the arguments before the handler runs, while the memory
            # they point to still holds what the caller passed.
            sig = self.get_handler_signature(dll, name, argc)
            if sig is not None:
                rendered = self._render_signature_args(sig, argv)
                args = HandlerArgs.from_signature(sig, self.get_ptr_size(), rendered, argv)
            else:
                args = HandlerArgs.from_slots(argv)
            ctx = ApiContext(func_name=imp_api, args=args)

            self.hammer.handle_import_func(imp_api, conv, argc)
            hooks = self.get_api_hooks(dll, name)
            if hooks:
                from types import MethodType

                hooked_func = MethodType(func, mod)
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
                    rv = self.api.call_api_func(mod, func, argv, ctx=ctx)  # type: ignore[union-attr]
                except Exception as e:
                    if self._stop_on_faults:
                        # Let the outer GDB fault path expose the failed frame
                        # before run cleanup and report signal termination.
                        raise
                    logger.exception("0x%x: Error while calling API handler for %s:", oret, imp_api)
                    error = self.get_error_info(str(e), self.get_pc(), traceback=traceback.format_exc())
                    self.curr_run.error = error  # type: ignore[union-attr]
                    self.on_run_complete()
                    return

            ret = self.get_ret_address()
            pc = self.get_pc()
            frame.result = rv
            mm = self.get_address_map(ret)

            # Is this function being called from a dynamcially allocated memory segment?
            if mm and "virtualalloc" in mm.tag.lower():
                self._fire_dyn_code_hooks(ret)

            # Log the API args and return value
            self.log_api(call_pc, imp_api, rv, ctx.args.get_report_args(), run=origin_run)

            if (
                self.curr_run is origin_run
                and not self.run_complete
                and ret == oret
                and pc == opc
                and self.get_stack_ptr() == osp
            ):
                self.do_call_return(argc, ret, rv, conv=conv)

            # Deferred lifecycle/SEH work is processed before guest execution resumes.
            if not self.run_complete:
                self.enable_code_hook()

        else:
            # Unsupported API: no speakeasy handler exists, so argc/call_conv
            # must come from the hook itself. Only the last registered hook
            # (FIFO-consistent: last = highest priority return value) is called
            # because hooks may disagree on argc/call_conv.
            hooks = self.get_api_hooks(dll, name)
            if hooks:
                if len(hooks) > 1:
                    logger.warning(
                        "%d hooks registered for unsupported API %s.%s; only the last registered hook will be called",
                        len(hooks),
                        dll,
                        name,
                    )
                hook = hooks[-1]
                imp_api = f"{dll}.{name}"

                if hook.call_conv is None:
                    hook.call_conv = _arch.CALL_CONV_STDCALL

                argv = self.get_func_argv(hook.call_conv, hook.argc)
                frame.argc = hook.argc
                frame.convention = hook.call_conv
                self.hammer.handle_import_func(imp_api, hook.call_conv, hook.argc)
                rv = hook.cb(self, imp_api, None, argv)
                frame.result = rv
                ret = self.get_ret_address()
                self.log_api(call_pc, imp_api, rv, sigfmt.get_slot_args(argv), run=origin_run)
                if self.curr_run is origin_run and self.get_pc() == opc and ret == oret and self.get_stack_ptr() == osp:
                    self.do_call_return(hook.argc, ret, rv, conv=hook.call_conv)
                if not self.run_complete:
                    self.enable_code_hook()
                self._check_api_limit(origin_run, imp_api)
                return

            # No handler and no user hook: fall back to the declared signature
            # so the call is at least traced and cleaned up correctly.
            sig = self.lookup_api_signature(dll, name)
            if sig is not None:
                self.emulate_api_from_signature(dll, name, sig, call_pc)
            elif self._can_stub_unknown_api(dll, name):
                # Guess a four-argument stdcall function that succeeds so that
                # execution can continue.
                logger.warning("Stubbed unknown API %s with return 1", imp_api)
                conv = _arch.CALL_CONV_STDCALL
                argc = 4
                argv = self.get_func_argv(conv, argc)
                frame.argc = argc
                frame.convention = conv
                frame.result = 1
                self.log_api(call_pc, imp_api, 1, sigfmt.get_slot_args(argv), run=origin_run)
                self.do_call_return(argc, oret, 1, conv=conv)
            else:
                error = self.get_error_info("unsupported_api", self.get_pc())
                logger.error("Unsupported API: %s (ret: 0x%x)", imp_api, oret)
                self.log_api(call_pc, imp_api, None, [], run=origin_run)
                error.api_name = imp_api
                self.curr_run.error = error  # type: ignore[union-attr]
                self.on_run_complete()

        self._check_api_limit(origin_run, imp_api)

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

    def _dll_main_succeeded(self):
        # The loader truncates the BOOL result of DllMain to a BOOLEAN, so only
        # the low byte decides success.
        return bool(self.get_return_val() & 0xFF)

    def start_api_callback(self, frame, function, args):
        """Enter a guest callback on the stack of its API frame."""
        frame.function = function
        sp = frame.stack_pointer
        if self.ptr_size == 8:
            # Win64 callees expect RSP + 8 to be 16-byte aligned at entry, and
            # each argument after the fourth occupies one 8-byte stack slot.
            sp &= ~0xF
            if max(len(args) - 4, 0) % 2:
                sp -= 8
        self.set_func_args(sp, winemu.API_CALLBACK_HANDLER_ADDR, *args, conv=_arch.CALL_CONV_STDCALL)
        self.set_pc(function)

    def _continue_api_callback(self):
        """Resume a typed guest callback continuation outside Unicorn callbacks."""
        run = self.get_current_run()
        frame = run.api_callbacks[-1]
        stage = frame.initializers.get(frame.function)
        if stage is not None:
            module, last, is_dll, pid = stage
            if is_dll and not self._dll_main_succeeded():
                frame.result = frame.failure_result
                for address, data in frame.failure_writes:
                    self.mem_write(address, data)
                self.set_last_error(1114)  # ERROR_DLL_INIT_FAILED
                self._detach_failed_guest_initialization(module, pid)
                self._rollback_guest_load(frame)
            elif last:
                module._initialization[pid] = "ready"
        self.set_stack_ptr(frame.stack_pointer)
        if frame.pending:
            function, args = frame.pending.pop(0)
            self.start_api_callback(frame, function, args)
        else:
            run.api_callbacks.pop()
            if frame.event is not None:
                frame.event.ret_val = hex(frame.result) if frame.result is not None else None
            self.do_call_return(frame.argc, frame.return_address, frame.result, conv=frame.convention)

    def _hook_mem_unmapped(self, emu, access, address, size, value):
        """
        High level function used to catch all invalid memory accesses that occur during
        emulation
        """
        try:
            access = self.emu_eng.mem_access.get(access)  # type: ignore[union-attr]
            logger.debug("mem_unmapped: access=%s addr=0x%x size=0x%x", access, address, size)
            if access != common.INVALID_MEM_EXEC:
                self.prev_pc = self.get_pc()

            if not self.tmp_code_hook:
                self.tmp_code_hook = self.add_code_hook(cb=self._hook_code_core)

            self.enable_code_hook()

            if access == common.INVALID_MEM_EXEC:
                if address == winemu.SEH_RETURN_ADDR:
                    self.continue_seh()
                    self._unset_emu_hooks()
                    return True
                return self._handle_invalid_fetch(emu, address, size, value)

            elif access == common.INVALID_MEM_READ:
                return self._handle_invalid_read(emu, address, size, value)

            elif access == common.INVAL_PERM_MEM_EXEC:
                return self._handle_prot_fetch(emu, address, size, value)
            elif access == common.INVALID_MEM_WRITE:
                fakeout = address & 0xFFFFFFFFFFFFF000
                self.mem_map(self.page_size, base=fakeout)
                self.tmp_maps.append((fakeout, self.page_size))

                return self._handle_invalid_write(emu, address, size, value)
            elif access == common.INVAL_PERM_MEM_WRITE:
                return self._handle_prot_write(emu, address, size, value)
        except Exception as e:
            logger.exception("Invalid memory exception")
            error = self.get_error_info(str(e), self.get_pc(), traceback=traceback.format_exc())
            self.curr_run.error = error  # type: ignore[union-attr]
            self.on_emu_complete()
            return False

    def _handle_prot_write(self, emu, address, size, value):
        fakeout = address & 0xFFFFFFFFFFFFF000
        self.mem_map(self.page_size, base=fakeout)

        error = self.get_error_info("invalid_protect_write", address, access_type="write")
        self.curr_run.error = error  # type: ignore[union-attr]

        self.tmp_maps.append((fakeout, self.page_size))
        self.end_run_on_fault()
        return True

    def restart_run(self, run):
        """
        Restart the current run
        """
        run.instr_cnt = 0
        self.set_pc(run.start_addr)

    def get_symbol_from_address(self, address):
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

    def get_symbols(self):
        """Snapshot public addresses as legacy (dll, name) tuples.

        Registry entries take precedence over auxiliary labels at the same address.
        Forwarder strings and private dispatch tokens are not public symbols.
        """
        from typing import cast

        # The legacy storage annotation says str, but producers store tuples.
        auxiliary_symbols = cast(dict[int, tuple[str, str]], self.symbols)
        symbols = {
            address: value
            for address, value in auxiliary_symbols.items()
            if not self.api_registry.overlaps_traps(address)
            and not (address in self.api_registry.entries and self.api_registry.entries[address].export.forwarder)
        }
        symbols.update(
            (address, (entry.dll, entry.name))
            for address, entry in self.api_registry.entries.items()
            if not entry.export.forwarder
        )
        return symbols

    def get_api_symbols(self):
        """Snapshot public function/data and auxiliary symbols as string labels."""
        return {address: "{}.{}".format(*value) for address, value in self.get_symbols().items()}

    def _hook_mem_read(self, emu, access, address, size, value):
        """
        Hook each memory read event that occurs. This hook is used to lookup symbols and modules
        that are read from during emulation.
        """

        try:
            symbol = self.get_symbol_from_address(address)

            if symbol:
                logger.debug("mem_read: addr=0x%x size=0x%x sym=%s", address, size, symbol)
                mac = self.curr_run.sym_access.get(address)
                if not mac:
                    mac = MemAccess(sym=symbol)
                mac.reads += 1
                self.curr_run.sym_access.update({address: mac})

            for read_access in self.curr_run.read_cache:  # type: ignore[union-attr]
                if read_access.base <= address <= (read_access.base + read_access.size) - 1:
                    read_access.reads += 1
                    return True

            mod = self.get_mod_from_addr(address)
            if mod and mod.sections:
                sect = mod.get_section_for_addr(address)
                if sect:
                    key = (mod.base, sect.virtual_address)
                    maccess = self.curr_run.section_access.get(key)  # type: ignore[union-attr]
                    if not maccess:
                        maccess = MemAccess(base=mod.base + sect.virtual_address, size=sect.virtual_size)
                        self.curr_run.section_access[key] = maccess  # type: ignore[union-attr]
                    self.curr_run.read_cache.appendleft(maccess)  # type: ignore[union-attr]
                    maccess.reads += 1
                    return True

            mmap = self.get_address_map(address)
            if not mmap:
                return False

            maccess = self.curr_run.mem_access.get(mmap)  # type: ignore[union-attr]
            if not maccess:
                maccess = MemAccess(base=mmap.base, size=mmap.size)
            self.curr_run.read_cache.appendleft(maccess)  # type: ignore[union-attr]
            self.curr_run.mem_access.update({mmap: maccess})  # type: ignore[union-attr]
            maccess.reads += 1

            return True
        except Exception as e:
            logger.exception("Exception during memory read")
            error = self.get_error_info(str(type(e).__name__), self.get_pc(), traceback=traceback.format_exc())
            self.curr_run.error = error  # type: ignore[union-attr]
            self.on_emu_complete()
            return False

    def _hook_mem_write(self, emu, access, address, size, value):
        """
        Hook each memory write event that occurs. This hook is used to track memory modifications
        to interesting memory locations.
        """
        try:
            symbol = self.get_symbol_from_address(address)
            if symbol:
                logger.debug("mem_write: addr=0x%x size=0x%x sym=%s", address, size, symbol)
                mac = self.curr_run.sym_access.get(address)  # type: ignore[union-attr]
                if not mac:
                    mac = MemAccess(sym=symbol)
                mac.writes += 1
                self.curr_run.sym_access.update({address: mac})  # type: ignore[union-attr]

            for write_access in self.curr_run.write_cache:  # type: ignore[union-attr]
                if write_access.base <= address <= (write_access.base + write_access.size) - 1:
                    write_access.writes += 1
                    return True

            mod = self.get_mod_from_addr(address)
            if mod and mod.sections:
                sect = mod.get_section_for_addr(address)
                if sect:
                    key = (mod.base, sect.virtual_address)
                    maccess = self.curr_run.section_access.get(key)  # type: ignore[union-attr]
                    if not maccess:
                        maccess = MemAccess(base=mod.base + sect.virtual_address, size=sect.virtual_size)
                        self.curr_run.section_access[key] = maccess  # type: ignore[union-attr]
                    self.curr_run.write_cache.appendleft(maccess)  # type: ignore[union-attr]
                    maccess.writes += 1
                    return True

            mmap = self.get_address_map(address)
            if not mmap:
                return False

            maccess = self.curr_run.mem_access.get(mmap)  # type: ignore[union-attr]
            if not maccess:
                maccess = MemAccess(base=mmap.base, size=mmap.size)
            self.curr_run.write_cache.appendleft(maccess)  # type: ignore[union-attr]
            self.curr_run.mem_access.update({mmap: maccess})  # type: ignore[union-attr]
            maccess.writes += 1

            return True

        except Exception as e:
            logger.exception("Exception during memory write")
            error = self.get_error_info(str(type(e).__name__), self.get_pc(), traceback=traceback.format_exc())
            self.curr_run.error = error  # type: ignore[union-attr]
            self.on_emu_complete()
            return False

    def _handle_invalid_read(self, emu, address, size, value):
        """
        Hook each invalid memory read event that occurs.
        """
        mod = self.get_mod_from_addr(address)
        if mod:
            return True

        if address >= winemu.EMU_RESERVED and address <= (winemu.EMU_RESERVED + winemu.EMU_RESERVE_SIZE):
            self._unset_emu_hooks()
            return True

        if self.config.exceptions.dispatch_handlers:
            rv = self.dispatch_seh(ddk.STATUS_ACCESS_VIOLATION, address)
            if rv:
                return True
        fakeout = address & 0xFFFFFFFFFFFFF000
        self.mem_map(self.page_size, base=fakeout)

        error = self.get_error_info("invalid_read", address, access_type="read")
        self.curr_run.error = error  # type: ignore[union-attr]

        # Let the next run know to remove this map since its
        # technically invalid
        self.tmp_maps.append((fakeout, self.page_size))
        self.end_run_on_fault()
        return True

    def _handle_prot_fetch(self, emu, address, size, value):
        """
        Called when non-executable code is emulated
        """
        # Ordinary analysis recovers execution in non-X guest sections.
        # Synthetic API protections and debugger stops are always
        # authoritative; a symbol never causes dispatch from this hook.
        module = self.get_mod_from_addr(address)
        if (
            not self._stop_on_faults
            and (module is None or module._image.source != "synthetic")
            and not self.api_registry.overlaps_traps(address)
        ):
            if module is not None and module._image.source == "guest_pe":
                # Changing protection while Unicorn is handling this fetch can
                # invalidate its active translation. Apply it after unwinding.
                native_perms = next(perms for start, end, perms in self.get_mem_regions() if start <= address <= end)
                perms = next(perms for perms, native in self.emu_eng.perms.items() if native == native_perms)
                page = address & ~(self.page_size - 1)
                self._pending_exec_recovery = (page, perms | common.PERM_MEM_EXEC)
                self._pending_control = "exec_recovery"
                self.emu_eng.stop()
                return False
            return True
        error = self.get_error_info("invalid_protect_fetch", address, access_type="fetch")
        self.curr_run.error = error
        self.end_run_on_fault()
        return False

    def _handle_invalid_write(self, emu, address, size, value):
        """
        Called when non-writable address is written to
        """
        # ignore patches to APIs
        if address >= winemu.EMU_RESERVED and address <= (winemu.EMU_RESERVED + winemu.EMU_RESERVE_SIZE):
            return True

        if self.config.exceptions.dispatch_handlers:
            rv = self.dispatch_seh(ddk.STATUS_ACCESS_VIOLATION, address)
            if rv:
                return True

        fakeout = address & 0xFFFFFFFFFFFFF000
        self.mem_map(self.page_size, base=fakeout)

        error = self.get_error_info("invalid_write", address, access_type="write")
        self.curr_run.error = error  # type: ignore[union-attr]

        self.tmp_maps.append((fakeout, self.page_size))
        self.end_run_on_fault()
        return True

    def _hook_code_core(self, emu, addr, size):
        """
        Transient code hook for deferred work: SEH dispatch, run lifecycle,
        and temporary fault-map cleanup. Enabled on demand
        and disables itself once the pending work is drained.
        """
        try:
            if self.curr_exception_code != 0:
                self.dispatch_seh(self.curr_exception_code)
                self.curr_exception_code = 0
                self.disable_code_hook()
                return True

            if self.restart_curr_run:
                self.set_pc(self.curr_run.start_addr)  # type: ignore[union-attr]
                self.restart_curr_run = False
                return False

            if addr == self.return_hook or self.run_complete:
                self.on_run_complete()
                return False

            # Handler instructions are not progress at the original fault site.
            # After continuation, retain the guard until the guest advances.
            if self._seh_resume_pc is not None and addr != self._seh_resume_pc:
                self._seh_last_fault = None
                self._seh_repeat_count = 0
                self._seh_resume_pc = None

            if self.tmp_maps:
                for base, size in self.tmp_maps:
                    try:
                        self.mem_unmap(base, size)
                    except Exception:
                        if self._seh_resume_pc is None:
                            self.disable_code_hook()
                        return True
                self.tmp_maps = []

            self._set_emu_hooks()
            if self._seh_resume_pc is None:
                self.disable_code_hook()
            return True

        except Exception as e:
            logger.exception("Exception during code hook (core)")
            error = self.get_error_info(str(e), self.get_pc(), traceback=traceback.format_exc())
            self.curr_run.error = error  # type: ignore[union-attr]
            self.on_emu_complete()
            return False

    def _hook_code_coverage(self, emu, addr, size):
        """
        Persistent code hook that records every executed address for coverage.
        """
        try:
            self.curr_run.coverage.add(addr)  # type: ignore[union-attr]
            return True
        except Exception as e:
            logger.exception("Exception during code hook (coverage)")
            error = self.get_error_info(str(e), self.get_pc(), traceback=traceback.format_exc())
            self.curr_run.error = error  # type: ignore[union-attr]
            self.on_emu_complete()
            return False

    def _hook_code_tracing(self, emu, addr, size):
        """
        Persistent code hook for memory tracing: instruction counting,
        symbol execution tracking, and per-region execution tracking.
        """
        try:
            if logger.isEnabledFor(logging.DEBUG):
                disasm = self.get_disasm(addr, size)[2]
                logger.debug("exec: 0x%x %s", addr, disasm)

            self.curr_instr_size = size

            symbol = self.get_symbol_from_address(addr)
            if symbol:
                mac = self.curr_run.sym_access.get(addr)  # type: ignore[union-attr]
                if not mac:
                    mac = MemAccess(sym=symbol)
                mac.execs += 1
                self.curr_run.sym_access.update({addr: mac})  # type: ignore[union-attr]

            self.prev_pc = addr
            self.curr_run.instr_cnt += 1  # type: ignore[union-attr]

            for exec_access in self.curr_run.exec_cache:  # type: ignore[union-attr]
                if exec_access.base <= addr <= (exec_access.base + exec_access.size) - 1:
                    exec_access.execs += 1
                    return True

            mod = self.get_mod_from_addr(addr)
            if mod and mod.sections:
                sect = mod.get_section_for_addr(addr)
                if sect:
                    key = (mod.base, sect.virtual_address)
                    maccess = self.curr_run.section_access.get(key)  # type: ignore[union-attr]
                    if not maccess:
                        maccess = MemAccess(base=mod.base + sect.virtual_address, size=sect.virtual_size)
                        self.curr_run.section_access[key] = maccess  # type: ignore[union-attr]
                    self.curr_run.exec_cache.appendleft(maccess)  # type: ignore[union-attr]
                    maccess.execs += 1
                    return True

            mmap = self.get_address_map(addr)
            if not mmap:
                return False
            maccess = self.curr_run.mem_access.get(mmap)  # type: ignore[union-attr]
            if not maccess:
                maccess = MemAccess(base=mmap.base, size=mmap.size)
            self.curr_run.exec_cache.appendleft(maccess)  # type: ignore[union-attr]
            self.curr_run.mem_access.update({mmap: maccess})  # type: ignore[union-attr]
            maccess.execs += 1

            return True

        except Exception as e:
            logger.exception("Exception during code hook (tracing)")
            error = self.get_error_info(str(e), self.get_pc(), traceback=traceback.format_exc())
            self.curr_run.error = error  # type: ignore[union-attr]
            self.on_emu_complete()
            return False

    def _hook_code_debug(self, emu, addr, size):
        """
        Persistent code hook that prints disassembly and register state
        for every instruction when debug mode is enabled.
        """
        x = self.get_disasm(addr, size)[2]
        if self.get_arch() == _arch.ARCH_AMD64:
            regs = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9")
        else:
            regs = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        vals = " : ".join(f"{r}=0x{self.reg_read(r):x}" for r in regs)
        print(f"0x{addr:x}: {x}, {vals}")
        return True

    def get_native_module_path(self, mod_name=""):
        """
        Get the full filesystem path of a default decoy that is supplied by
        speakeasy
        """

        def get_fp(path, mod_name):
            path = common.normalize_package_path(path)
            files = [os.path.join(path, fn) for fn in os.listdir(path)]
            for fp in files:
                bn = os.path.basename(fp.lower())
                bn = os.path.splitext(bn)[0]
                if mod_name == bn:
                    return fp

        mod_name = mod_name.lower()
        decoy_arch_dir = {
            _arch.ARCH_X86: ("module_directory_x86", "x86"),
            _arch.ARCH_AMD64: ("module_directory_x64", "amd64"),
        }
        dirs = decoy_arch_dir[self.get_arch()]
        mod_dir = dirs[0]

        path = getattr(self.config.modules, mod_dir, "") or ""

        fp = get_fp(path, mod_name)
        if not fp:
            path = os.path.join(os.path.dirname(__file__), os.pardir, "winenv", "decoys", dirs[1])
            fp = get_fp(path, mod_name)

        return fp

    def _attach_module_to_current_process(self, module):
        if self.kernel_mode or not module.visible_in_peb or module.is_driver():
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
        original_attachments = self._snapshot_peb_attachments()
        name = winemu.normalize_dll_name(module_name(mod_name))
        module = self.get_mod_by_name(name)
        if module is None:
            known = self.get_native_module_path(name) or self.api.load_api_handler(name)
            known = known or next(
                iter(self.get_signature_db().iter_functions(name, "x86" if self.ptr_size == 4 else "x64")), None
            )
            if not known and not self.config.modules.modules_always_exist:
                return 0
            module = self.load_module_by_name(name)
        self._attach_module_to_current_process(module)
        frame = self._active_api_frame
        if frame is not None and not self.kernel_mode:
            # Keep the earliest snapshot for each process across reentrant loads.
            tracked = {process.id for process, _ in frame.loader_attachments}
            frame.loader_attachments.extend(item for item in original_attachments if item[0].id not in tracked)
            frame.created_modules.extend(module for module in self.modules if module not in original_modules)
            initializers = self._collect_guest_initializers()
            handler = self.api.load_api_handler("kernel32")
            for dependency, function, last, is_dll, pid in initializers:
                handler.setup_callback(function, (dependency.base, 1, 0))
                frame.initializers[function] = (dependency, last, is_dll, pid)
        return module.base

    def _make_image_at_free_base(self, make_loader: Callable[[int | None], Any], base: int | None):
        """
        Build a module image at the requested base, or at the next free range when
        another mapping already occupies part of it.
        """
        image = make_loader(base).make_image()
        if not image.image_base:
            return image
        free_base, _ = self.get_valid_ranges(image.image_size, addr=image.image_base)
        if free_base != image.image_base:
            logger.debug("module %s: base %#x is in use, loading at %#x", image.name, image.image_base, free_base)
            image = make_loader(free_base).make_image()
        return image

    def load_module_by_name(self, name, emu_path=None, base=None, native_path=None):
        """Load one coherent native or catalog-generated module instance."""
        from speakeasy.windows.loaders import ApiModuleLoader, PeLoader

        name = module_name(name)
        existing = self.get_mod_by_name(name)
        if existing is not None:
            self._attach_module_to_current_process(existing)
            return existing
        if not emu_path:
            emu_path = (self.config.current_dir or r"C:\Windows\system32") + "\\" + name + ".dll"
        native_path = native_path or self.get_native_module_path(mod_name=name)
        if base is None and not native_path:
            base = 0x6F000000
        handler = self.api.load_api_handler(name) if self.api else None
        if handler and name == "ntdll":
            nt_handler = self.api.load_api_handler("ntoskrnl")
            if nt_handler:
                handler._nt_handler = nt_handler

        def make_loader(address):
            if native_path:
                return PeLoader(
                    path=native_path,
                    base_override=address,
                    emu_path=emu_path,
                    strict=self.config.modules.strict_loading,
                )
            return ApiModuleLoader(
                name=name,
                api=handler,
                arch=self.get_arch(),
                base=address or 0,
                emu_path=emu_path,
                signature_db=self.get_signature_db(),
            )

        image = self._make_image_at_free_base(make_loader, base)
        image.name = name
        image.module_type = _module_type_from_path(emu_path)
        module = self.load_image(image)
        if image.source == "guest_pe" and module.is_dll() and not self.kernel_mode:
            module._initialization = {}
            self._guest_dependencies.append(module)
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
        return mod_file.data.getvalue()

    def init_environment(self, system_modules=None, user_modules=None):
        if system_modules is None:
            system_modules = self.config.modules.system_modules
        if user_modules is None:
            user_modules = self.config.modules.user_modules

        sys_mods = self._init_module_group(system_modules)
        self._init_module_group(user_modules, default_base=0x6F000000)
        return sys_mods

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
        else:
            ctx = self.wintypes.CONTEXT(self.get_ptr_size())
            if self.get_arch() == _arch.ARCH_X86:
                ctx.Edi = self.reg_read(_arch.X86_REG_EDI)
                ctx.Esi = self.reg_read(_arch.X86_REG_ESI)
                ctx.Eax = self.reg_read(_arch.X86_REG_EAX)
                ctx.Ebp = self.reg_read(_arch.X86_REG_EBP)
                ctx.Edx = self.reg_read(_arch.X86_REG_EDX)
                ctx.Ecx = self.reg_read(_arch.X86_REG_ECX)
                ctx.Ebx = self.reg_read(_arch.X86_REG_EBX)
                ctx.Esp = self.reg_read(_arch.X86_REG_ESP)
                ctx.Eip = self.reg_read(_arch.X86_REG_EIP)

                ctx.EFlags = self.reg_read(_arch.X86_REG_EFLAGS)
                ctx.SegCs = self.reg_read(_arch.X86_REG_CS)
                ctx.SegSs = self.reg_read(_arch.X86_REG_SS)
                ctx.SegDs = self.reg_read(_arch.X86_REG_DS)
                ctx.SegFs = self.reg_read(_arch.X86_REG_FS)
                ctx.SegGs = self.reg_read(_arch.X86_REG_GS)
                ctx.SegEs = self.reg_read(_arch.X86_REG_ES)
            elif self.get_arch() == _arch.ARCH_AMD64:
                ctx = self.wintypes.CONTEXT64(self.get_ptr_size())
                ctx.Rax = self.reg_read(_arch.AMD64_REG_RAX)
                ctx.Rbx = self.reg_read(_arch.AMD64_REG_RBX)
                ctx.Rcx = self.reg_read(_arch.AMD64_REG_RCX)
                ctx.Rdx = self.reg_read(_arch.AMD64_REG_RDX)
                ctx.Rsi = self.reg_read(_arch.AMD64_REG_RSI)
                ctx.Rdi = self.reg_read(_arch.AMD64_REG_RDI)
                ctx.Rbp = self.reg_read(_arch.AMD64_REG_RBP)
                ctx.Rsp = self.reg_read(_arch.AMD64_REG_RSP)
                ctx.Rip = self.reg_read(_arch.AMD64_REG_RIP)
                ctx.R8 = self.reg_read(_arch.AMD64_REG_R8)
                ctx.R9 = self.reg_read(_arch.AMD64_REG_R9)
                ctx.R10 = self.reg_read(_arch.AMD64_REG_R10)
                ctx.R11 = self.reg_read(_arch.AMD64_REG_R11)
                ctx.R12 = self.reg_read(_arch.AMD64_REG_R12)
                ctx.R13 = self.reg_read(_arch.AMD64_REG_R13)
                ctx.R14 = self.reg_read(_arch.AMD64_REG_R14)
                ctx.R15 = self.reg_read(_arch.AMD64_REG_R15)
                ctx.EFlags = self.reg_read(_arch.X86_REG_EFLAGS)
                ctx.SegCs = self.reg_read(_arch.X86_REG_CS)
                ctx.SegSs = self.reg_read(_arch.X86_REG_SS)
                ctx.SegDs = self.reg_read(_arch.X86_REG_DS)
                ctx.SegFs = self.reg_read(_arch.X86_REG_FS)
                ctx.SegGs = self.reg_read(_arch.X86_REG_GS)
                ctx.SegEs = self.reg_read(_arch.X86_REG_ES)
        return ctx

    def load_thread_context(self, ctx, thread=None):
        """
        Set the current thread CPU context
        """
        if self.get_arch() == _arch.ARCH_X86:
            self.reg_write(_arch.X86_REG_EDI, ctx.Edi)
            self.reg_write(_arch.X86_REG_ESI, ctx.Esi)
            self.reg_write(_arch.X86_REG_EAX, ctx.Eax)
            self.reg_write(_arch.X86_REG_EBP, ctx.Ebp)
            self.reg_write(_arch.X86_REG_EDX, ctx.Edx)
            self.reg_write(_arch.X86_REG_ECX, ctx.Ecx)
            self.reg_write(_arch.X86_REG_EBX, ctx.Ebx)
            self.reg_write(_arch.X86_REG_ESP, ctx.Esp)
            self.reg_write(_arch.X86_REG_EIP, ctx.Eip)

            self.reg_write(_arch.X86_REG_EFLAGS, ctx.EFlags)
            self.reg_write(_arch.X86_REG_CS, ctx.SegCs)
            self.reg_write(_arch.X86_REG_SS, ctx.SegSs)
            self.reg_write(_arch.X86_REG_DS, ctx.SegDs)
            self.reg_write(_arch.X86_REG_FS, ctx.SegFs)
            self.reg_write(_arch.X86_REG_GS, ctx.SegGs)
            self.reg_write(_arch.X86_REG_ES, ctx.SegEs)

        elif self.get_arch() == _arch.ARCH_AMD64:
            self.reg_write(_arch.AMD64_REG_RAX, ctx.Rax)
            self.reg_write(_arch.AMD64_REG_RBX, ctx.Rbx)
            self.reg_write(_arch.AMD64_REG_RCX, ctx.Rcx)
            self.reg_write(_arch.AMD64_REG_RDX, ctx.Rdx)
            self.reg_write(_arch.AMD64_REG_RSI, ctx.Rsi)
            self.reg_write(_arch.AMD64_REG_RDI, ctx.Rdi)
            self.reg_write(_arch.AMD64_REG_RBP, ctx.Rbp)
            self.reg_write(_arch.AMD64_REG_RSP, ctx.Rsp)
            self.reg_write(_arch.AMD64_REG_RIP, ctx.Rip)
            self.reg_write(_arch.AMD64_REG_R8, ctx.R8)
            self.reg_write(_arch.AMD64_REG_R9, ctx.R9)
            self.reg_write(_arch.AMD64_REG_R10, ctx.R10)
            self.reg_write(_arch.AMD64_REG_R11, ctx.R11)
            self.reg_write(_arch.AMD64_REG_R12, ctx.R12)
            self.reg_write(_arch.AMD64_REG_R13, ctx.R13)
            self.reg_write(_arch.AMD64_REG_R14, ctx.R14)
            self.reg_write(_arch.AMD64_REG_R15, ctx.R15)
            self.reg_write(_arch.X86_REG_EFLAGS, ctx.EFlags)
            self.reg_write(_arch.X86_REG_CS, ctx.SegCs)
            self.reg_write(_arch.X86_REG_SS, ctx.SegSs)
            self.reg_write(_arch.X86_REG_DS, ctx.SegDs)
            self.reg_write(_arch.X86_REG_FS, ctx.SegFs)
            self.reg_write(_arch.X86_REG_GS, ctx.SegGs)
            self.reg_write(_arch.X86_REG_ES, ctx.SegEs)

    def _get_exception_list(self):
        """
        Retrieves the exception handler list for the current thread
        """
        thread = self.get_current_thread()
        if not thread:
            return 0
        teb = thread.get_teb()
        teb = teb.read_back()
        return teb.object.NtTib.ExceptionList

    def _dispatch_seh_x86(self, except_code):
        """
        Get the initial SEH handler when dispatching a CPU exception
        that occurs during emulation
        """

        thread = self.get_current_thread()
        if not thread:
            return False
        seh = thread.seh
        exception_list = self._get_exception_list()
        ptr_size = self.get_ptr_size()

        seh.last_exception_code = except_code
        # Create the _EXCEPTION_RECORD
        record = self.wintypes.EXCEPTION_RECORD(self.get_ptr_size())
        record.ExceptionCode = except_code
        record.ExceptionFlags = 0
        record.ExceptionAddress = self.get_pc()
        record.NumberParameters = 0

        ereg = self.wintypes.EXCEPTION_REGISTRATION(self.get_ptr_size())
        if exception_list:
            entry = self.mem_cast(ereg, exception_list)
            sp = self.get_stack_ptr()

            exp_ptrs = self.wintypes.EXCEPTION_POINTERS(self.get_ptr_size())

            p_exp_ptrs = self.mem_map(exp_ptrs.sizeof(), tag="emu.struct.EXCEPTION_POINTERS")
            prec = self.mem_map(record.sizeof(), tag="emu.struct.EXCEPTION_RECORD")
            _ctx = self.get_thread_context()
            pctx = self.mem_map(_ctx.sizeof(), tag="emu.struct.EXCEPTION_CONTEXT")

            exp_ptrs.ExceptionRecord = prec
            exp_ptrs.ContextRecord = pctx

            self.mem_write(pctx, _ctx.get_bytes())
            seh.set_context(_ctx, address=pctx)

            p_exp_ptrs_bytes = (p_exp_ptrs).to_bytes(ptr_size, "little")

            self.mem_write(p_exp_ptrs, exp_ptrs.get_bytes())
            self.mem_write(prec, record.get_bytes())

            # Write the record to the ms_exc.exc_ptr offset
            self.mem_write(exception_list - ptr_size, p_exp_ptrs_bytes)

            args = [prec, exception_list, pctx, 0]
            self.set_func_args(sp, winemu.SEH_RETURN_ADDR, *args, conv=_arch.CALL_CONV_STDCALL)

            run = self.get_current_run()
            regs = self.get_register_state()

            pc = self.prev_pc
            try:
                mnem, op, instr = self.get_disasm(pc, DISASM_SIZE)
            except Exception as e:
                logger.error(str(e))
                instr = "disasm_failed"

            pc_module = self._resolve_module_offset(pc)
            stack_trace = self.get_stack_trace()
            handler_module = self._resolve_module_offset(entry.Handler)

            pc_desc = pc_module or f"0x{pc:x}"
            handler_desc = f"0x{entry.Handler:x}"
            if handler_module:
                handler_desc = f"{handler_desc} ({handler_module})"
            logger.info(
                '0x%x: Exception caught: code=0x%x handler=%s instr="%s"\n  pc: %s\n  regs: %s',
                pc,
                except_code,
                handler_desc,
                instr,
                pc_desc,
                "  ".join(f"{k}={v}" for k, v in regs.items()),
            )

            faulting_addr_hex = None
            if except_code == ddk.STATUS_ACCESS_VIOLATION:
                faulting_addr_hex = hex(self.prev_pc) if hasattr(self, "prev_pc") else None

            if self.profiler:
                tick = run.instr_cnt if run else 0
                tid = self.curr_thread.tid if self.curr_thread else 0
                pid = self.curr_process.id if self.curr_process else 0
                pos = TracePosition(tick=tick, tid=tid, pid=pid, pc=pc)
                self.profiler.record_exception_event(
                    run,
                    pos,
                    instr,
                    except_code,
                    entry.Handler,
                    regs,
                    faulting_address=faulting_addr_hex,
                    pc_module=pc_module,
                    stack_trace=stack_trace,
                )

            # EBX clobber, -1 is what I observed inside a VM
            self.reg_write(_arch.X86_REG_EBX, 0xFFFFFFFF)
            self.set_pc(entry.Handler)
            return True
        return False

    def get_reserved_ranges(self):
        """
        Get the allocated memory ranges that the emulator reserves
        """
        return (winemu.EMU_RESERVED, winemu.EMU_RESERVED_END)

    def _continue_seh_x86(self) -> bool:
        """
        Get the next exception handler while processing SEH
        Return True only when restoring the faulting guest context. Transfers
        to a filter or handler, and completion, return False.
        """
        thread = self.get_current_thread()
        seh = thread.seh
        sp = self.get_stack_ptr()
        ret_val = self.get_return_val()

        if seh.handler_ret_val is None:
            seh.handler_ret_val = ret_val

        ctx = seh.context

        if seh.context_address:
            ctx = self.mem_cast(ctx, seh.context_address)

        # Always restore thread context, is it correct to always
        # do this?
        self.load_thread_context(ctx)

        for frame in seh.frames:
            if not frame.searched:
                seh.frame = frame
                scope_record = frame.scope_records[0]
                if not scope_record.filter_called and scope_record.record.FilterFunc:
                    self.set_func_args(sp, winemu.SEH_RETURN_ADDR, conv=_arch.CALL_CONV_STDCALL)
                    self.set_pc(scope_record.record.FilterFunc)
                    seh.last_func = scope_record.record.FilterFunc
                    scope_record.filter_called = True
                    return False

                if (
                    windef.EXCEPTION_EXECUTE_HANDLER == ret_val
                    or scope_record.record.FilterFunc == 0
                    or scope_record.record.FilterFunc == 0xFFFFFFFF
                ):
                    if not scope_record.handler_called:
                        # If no filter was provided, this is a finally block
                        self.set_pc(scope_record.record.HandlerAddress)
                        seh.last_func = scope_record.record.HandlerAddress
                        scope_record.handler_called = True
                        return False
                elif windef.EXCEPTION_CONTINUE_EXECUTION == ret_val:
                    ctx = seh.context
                    if seh.context_address:
                        _ctx = self.mem_cast(ctx, seh.context_address)
                    self.load_thread_context(_ctx)
                    self.set_pc(ctx.Eip)
                    return True

                elif windef.EXCEPTION_CONTINUE_SEARCH == ret_val:
                    pass

                frame.searched = True

        if windef.EXCEPTION_CONTINUE_SEARCH == ret_val and not len(seh.frames):
            ctx = seh.context
            self.set_pc(ctx.Eip)
            return True

        self.run_complete = True
        return False

    def _map_faulting_page_for_exception(self, faulting_address):
        fakeout = faulting_address & 0xFFFFFFFFFFFFF000
        if self.api_registry.overlaps_traps(fakeout, self.page_size):
            return
        for base, end, _ in self.get_mem_regions():
            if base <= fakeout <= end:
                return
        self.mem_map(self.page_size, base=fakeout)
        self.tmp_maps.append((fakeout, self.page_size))

    _SEH_MAX_REPEAT = 4

    def dispatch_seh(self, except_code, faulting_address=None):
        self._seh_resume_pc = None
        fault_key = (self.get_pc(), faulting_address)
        if fault_key == self._seh_last_fault:
            self._seh_repeat_count += 1
            if self._seh_repeat_count >= self._SEH_MAX_REPEAT:
                return False
        else:
            self._seh_last_fault = fault_key
            self._seh_repeat_count = 1

        rv = False
        if self.get_arch() == _arch.ARCH_X86:
            rv = self._dispatch_seh_x86(except_code)
        if not rv and self.unhandled_exception_filter:
            record = self.wintypes.EXCEPTION_RECORD(self.get_ptr_size())
            record.ExceptionCode = except_code
            record.ExceptionFlags = 0
            record.ExceptionAddress = self.get_pc()
            record.NumberParameters = 0

            exp_ptrs = self.wintypes.EXCEPTION_POINTERS(self.get_ptr_size())
            p_exp_ptrs = self.mem_map(exp_ptrs.sizeof(), tag="emu.struct.EXCEPTION_POINTERS")
            prec = self.mem_map(record.sizeof(), tag="emu.struct.EXCEPTION_RECORD")
            ctx = self.get_thread_context()
            pctx = self.mem_map(ctx.sizeof(), tag="emu.struct.EXCEPTION_CONTEXT")

            exp_ptrs.ExceptionRecord = prec
            exp_ptrs.ContextRecord = pctx

            self.mem_write(p_exp_ptrs, exp_ptrs.get_bytes())
            self.mem_write(prec, record.get_bytes())
            self.mem_write(pctx, ctx.get_bytes())

            sp = self.get_stack_ptr()
            args = [p_exp_ptrs]
            self.set_func_args(sp, winemu.EMU_RETURN_ADDR, *args, conv=_arch.CALL_CONV_STDCALL)
            self.set_pc(self.unhandled_exception_filter)
            self.unhandled_exception_filter = 0
            rv = True

        if rv and faulting_address is not None:
            self._map_faulting_page_for_exception(faulting_address)

        return rv

    def continue_seh(self):
        if self.get_arch() == _arch.ARCH_X86:
            resumed = self._continue_seh_x86()
            if resumed and not self.run_complete and self._seh_last_fault is not None:
                if self.get_pc() == self._seh_last_fault[0]:
                    self._seh_resume_pc = self.get_pc()
                    self.enable_code_hook()
                else:
                    self._seh_last_fault = None
                    self._seh_repeat_count = 0
                    self._seh_resume_pc = None

    def create_event(self, name=""):
        """
        Create a kernel event object
        """
        self.validate_object_services("event creation")
        evt = self.new_object(objman.Event)
        evt.name = name
        hnd = self.om.get_handle(evt)  # type: ignore[union-attr]
        return hnd, evt

    def dec_ref(self, obj):
        """
        Dereference an object
        """
        self.validate_object_services("object dereference")
        return self.om.dec_ref(obj)  # type: ignore[union-attr]

    def create_mutant(self, name=""):
        """
        Create a kernel mutant object
        """
        self.validate_object_services("mutant creation")
        if name == 0:
            name = ""
        mtx = self.new_object(objman.Mutant)
        mtx.name = name
        hnd = self.om.get_handle(mtx)  # type: ignore[union-attr]
        return hnd, mtx

    def _hook_interrupt(self, emu, intnum):
        """
        Called when software interrupts occur
        """
        exception_list = self._get_exception_list()
        if exception_list and self.config.exceptions.dispatch_handlers:
            # Catch software breakpoint interrupts
            if intnum == 3 or intnum == 0x2D:
                self.curr_exception_code = ddk.STATUS_BREAKPOINT
                self.prev_pc = self.get_pc()
                self.enable_code_hook()
                return True
            # Catch divide-by-zero exceptions
            elif intnum == 0:
                self.curr_exception_code = ddk.STATUS_INTEGER_DIVIDE_BY_ZERO
                self.enable_code_hook()
                self.prev_pc = self.get_pc()
                return True
            # Catch single step exceptions
            elif intnum == 1:
                self.curr_exception_code = ddk.STATUS_SINGLE_STEP
                self.enable_code_hook()
                self.prev_pc = self.get_pc()
                eflags = self.reg_read(_arch.X86_REG_EFLAGS)
                # Remove the trap flag
                eflags &= 0xFFFFFEFF
                self.reg_write(_arch.X86_REG_EFLAGS, eflags)
                return True

        # Handle __fastfail interrupt introduced in Windows 8
        if intnum == 0x29:
            ecx = self.reg_read(_arch.X86_REG_ECX)
            # Cookie security init failed, just return since we are in __security_init_cookie
            if ecx == 6:
                hook_ref = [None]

                def _tmp_hook(emu, addr, size):
                    ret = self.pop_stack()
                    self.set_pc(ret)
                    hook_ref[0].disable()

                hook_ref[0] = self.add_code_hook(cb=_tmp_hook)
                return True

        pc = self.get_pc()
        logger.debug("interrupt: intnum=0x%x", intnum)
        logger.error("0x%x: Unhandled interrupt: intnum=0x%x", pc, intnum)
        error = self.get_error_info("unhandled_interrupt", pc)
        error.interrupt_num = intnum
        self.curr_run.error = error  # type: ignore[union-attr]

        self.restart_curr_run = True
        self.on_run_complete()
        return False
