# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import logging
import multiprocessing.synchronize
import ntpath
import os
import threading
import warnings
import zipfile
from collections.abc import Callable, Generator
from functools import wraps
from io import BytesIO
from pathlib import Path, PureWindowsPath
from types import TracebackType
from typing import Any, Concatenate, ParamSpec, TypeVar

from capstone import CsInsn
from pefile import MACHINE_TYPE, PEFormatError
from pydantic import ValidationError
from unicorn.x86_const import UC_X86_INS_IN, UC_X86_INS_SYSCALL, UC_X86_INS_SYSENTER

from speakeasy import common
from speakeasy.cli_config import output_active_config
from speakeasy.config import SpeakeasyConfig
from speakeasy.errors import ConfigError, InputError, NotSupportedError, SpeakeasyError
from speakeasy.hooks import (
    ApiHookCallback,
    CodeHookCallback,
    DynCodeHookCallback,
    InHookCallback,
    InterruptHookCallback,
    InvalidInstructionHookCallback,
    MemAccessHookCallback,
    MemMapHookCallback,
    SyscallHookCallback,
)
from speakeasy.memmgr import MemMap
from speakeasy.report import FileManifestEntry, Report
from speakeasy.struct import EmuStruct
from speakeasy.volumes import apply_volumes
from speakeasy.windows.common import _PeParser
from speakeasy.windows.fileman import File
from speakeasy.windows.kernel import WinKernelEmulator
from speakeasy.windows.loaders import LoadedImage, RuntimeModule
from speakeasy.windows.regman import RegKey
from speakeasy.windows.win32 import Win32Emulator
from speakeasy.windows.winemu import WindowsEmulator, execution_scope
from speakeasy.winenv import arch as _arch

logger = logging.getLogger(__name__)

P = ParamSpec("P")
R = TypeVar("R")
HookT = TypeVar("HookT", bound=common.Hook)

SHELLCODE_ARCH = {
    "x86": _arch.ARCH_X86,
    "x64": _arch.ARCH_AMD64,
    "amd64": _arch.ARCH_AMD64,
    _arch.ARCH_X86: _arch.ARCH_X86,
    _arch.ARCH_AMD64: _arch.ARCH_AMD64,
}


class Speakeasy:
    """
    Emulate a Windows PE file or shellcode.

    ``load_module``, ``load_shellcode`` or ``load_image`` creates the emulator for the input:
    ``WinKernelEmulator`` for a driver, else ``Win32Emulator``. Use the object as a context
    manager, or call ``shutdown`` at the end.
    """

    config: SpeakeasyConfig

    @staticmethod
    def check_init(func: Callable[Concatenate["Speakeasy", P], R]) -> Callable[Concatenate["Speakeasy", P], R]:
        """Wrap a method so that it raises ``SpeakeasyError`` while the emulator does not exist."""

        @wraps(func)
        def wrap(self: "Speakeasy", *args: P.args, **kwargs: P.kwargs) -> R:
            if self._emu is None:
                raise SpeakeasyError("Emulator not initialized")
            return func(self, *args, **kwargs)

        return wrap

    def __init__(
        self,
        config: dict | SpeakeasyConfig | None = None,
        argv: list[str] | None = None,
        *,
        debug: bool = False,
        exit_event: threading.Event | multiprocessing.synchronize.Event | None = None,
        gdb_port: int | None = None,
        volumes: list[str] | None = None,
        gdb_host: str = "127.0.0.1",
    ) -> None:
        """
        Validate the configuration. The emulator does not exist until a load creates it.

        Args:
            config: Configuration as a dict or a ``SpeakeasyConfig``. ``None`` selects the
                default configuration.
            argv: Command line arguments for the emulated program.
            debug: If true, log each instruction and the general-purpose registers at the DEBUG level.
            exit_event: Event that stops the emulation when it is set.
            gdb_port: Port on which to listen for a GDB client. The first run waits for the client.
                ``None`` disables the GDB server.
            volumes: Host paths to mount into the emulated file system, in the ``--volume`` format.
            gdb_host: Address on which the GDB server listens.

        Raises:
            ConfigError: if ``volumes`` is set and ``config`` is a ``SpeakeasyConfig``, if a volume
                is malformed or its host path does not exist, or if the configuration is not valid.
        """
        if volumes and isinstance(config, SpeakeasyConfig):
            raise ConfigError(
                "Cannot apply --volume to an already-validated SpeakeasyConfig; pass a raw dict or None instead"
            )

        self._init_config(config)
        if volumes:
            # Mount the volumes on the validated config, so that a partial dict keeps the default files.
            data = self.config.model_dump()
            try:
                apply_volumes(data, volumes)
            except (ValueError, FileNotFoundError) as err:
                raise ConfigError(f"Invalid volume: {err}") from err
            self._init_config(data)
        self._emu: Win32Emulator | WinKernelEmulator | None = None
        self.pending_hooks: list[common.Hook] = []
        self.argv: list[str] = argv if argv is not None else []
        self.exit_event: threading.Event | multiprocessing.synchronize.Event | None = exit_event
        self.debug: bool = debug
        self.gdb_port: int | None = gdb_port
        self.gdb_host: str = gdb_host
        self.loaded_bins: list[str | None] = []

    @property
    def has_emulator(self) -> bool:
        """Whether a load created the emulator, so that ``emu`` is available."""
        return self._emu is not None

    @property
    def emu(self) -> Win32Emulator | WinKernelEmulator:
        """
        The emulator for the loaded input.

        Raises:
            SpeakeasyError: if no input is loaded yet.
        """
        if self._emu is None:
            raise SpeakeasyError("Emulator not initialized")
        return self._emu

    def __enter__(self) -> "Speakeasy":
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: TracebackType | None
    ) -> None:
        self.shutdown()

    def _init_config(self, config: dict | SpeakeasyConfig | None) -> None:
        """
        Validate the configuration and store it. ``None`` selects the default configuration.

        Raises:
            ConfigError: if the configuration is not valid.
        """
        if config is None:
            config = {}

        if isinstance(config, SpeakeasyConfig):
            self.config = config
        else:
            try:
                self.config = SpeakeasyConfig.model_validate(config)
            except ValidationError as err:
                logger.exception("Invalid config: %s", str(err))
                raise ConfigError(f"Invalid config: {err}") from err

    def _init_pe_emulator(self, path: str | None = None, data: bytes | None = None) -> None:
        """
        Create the kernel mode emulator for a driver, else the user mode emulator, and its machine.

        For a user mode input that is not an EXE, also load the container image.

        Raises:
            InputError: if the PE is not valid, or its architecture is not x86 or x64.
            NotSupportedError: if the PE is a .NET assembly.
        """
        try:
            pe = _PeParser(path=path, data=data)
        except (PEFormatError, ValueError) as err:
            raise InputError(f"Target file is not a valid PE: {err}") from err
        machine = pe.FILE_HEADER.Machine
        mach = MACHINE_TYPE.get(machine, f"0x{machine:x}").split("_")[-1].lower()
        if mach not in ("amd64", "i386"):
            raise InputError(f"Unsupported architecture: {mach}")

        if pe.is_dotnet():
            raise NotSupportedError(".NET assemblies are not currently supported")

        if pe.is_driver():
            emu = WinKernelEmulator(
                config=self.config,
                debug=self.debug,
                exit_event=self.exit_event,
                gdb_port=self.gdb_port,
                gdb_host=self.gdb_host,
            )
            self._emu = emu
            self._init_machine(emu, pe.arch)
        else:
            user_emu = self._init_user_emulator()
            self._init_machine(user_emu, pe.arch)
            if not pe.is_exe():
                user_emu.load_container()

    def _init_user_emulator(self) -> Win32Emulator:
        emu = Win32Emulator(
            config=self.config,
            argv=self.argv,
            debug=self.debug,
            exit_event=self.exit_event,
            gdb_port=self.gdb_port,
            gdb_host=self.gdb_host,
        )
        self._emu = emu
        return emu

    def _init_machine(self, emu: WindowsEmulator, arch: int) -> None:
        """
        Create the machine of the emulator, then add the pending hooks.

        The engine does not exist before ``init_machine``, and the hooks must see the maps of the load.
        """
        emu.init_machine(arch)
        self._init_hooks()

    def _init_hooks(self) -> None:
        """Add the hooks that the user registered before the emulator existed."""
        while self.pending_hooks:
            self.emu.add_hook(self.pending_hooks.pop(0))

    def _add_hook(self, hook: HookT) -> HookT:
        # Append to the pending hooks, so that the emulator adds the hooks in the order that the caller added them.
        self.pending_hooks.append(hook)
        if self._emu is not None:
            self._init_hooks()
        return hook

    def remove_hook(self, hook: common.Hook) -> None:
        """
        Remove a hook that an ``add_*_hook`` method returned, so that its callback is not called again.

        Raises:
            ValueError: if the hook is not added, for example because it is already removed.
        """
        if hook in self.pending_hooks:
            self.pending_hooks.remove(hook)
        elif self._emu is not None:
            self._emu.remove_hook(hook)
        else:
            raise ValueError("Speakeasy does not have this hook")

    def disasm(self, addr: int, size: int, *, fast: bool = True) -> tuple[str, str, str] | list[CsInsn]:
        """
        Disassemble the code at an address.

        Args:
            addr: Address at which to begin the disassembly.
            size: Number of bytes to read.
            fast: If true, disassemble only the first instruction, with capstone's lite mode.

        Returns:
            If ``fast`` is true, a tuple of the mnemonic, the operands, and the full instruction.
            If ``fast`` is false, a list of the capstone instructions in the bytes.

        Raises:
            SpeakeasyError: if the disassembly fails or the emulator does not exist.
        """
        try:
            return self.emu.get_disasm(addr, size, fast=fast)
        except Exception as e:
            raise SpeakeasyError(f"Failed to disassemble at address: 0x{addr:x}") from e

    def is_pe(self, data: bytes) -> bool:
        """Check whether the data starts with the PE ``MZ`` header."""
        if data[:2] == b"MZ":
            return True
        return False

    def _auto_mount_target_directory(self, path: str) -> None:
        """
        Mount the files of the host directory of the input into the emulated current directory.

        Then the emulated program finds the files next to it, for example data files that it
        reads from its working directory. The method does not mount subdirectories.
        """
        target_dir = Path(path).resolve().parent
        if not target_dir.is_dir():
            return

        guest_cd = PureWindowsPath(self.config.current_dir)
        entries: list[dict] = []
        for child in sorted(target_dir.iterdir()):
            if not child.is_file():
                continue
            emu_path = guest_cd / child.name
            entries.append(
                {
                    "mode": "full_path",
                    "emu_path": str(emu_path),
                    "path": str(child),
                }
            )
        if not entries:
            return

        config_dict = self.config.model_dump()
        config_dict["filesystem"]["files"] = entries + config_dict["filesystem"]["files"]
        self.config = SpeakeasyConfig.model_validate(config_dict)

        logger.info("Auto-mounted %d file(s) from target directory %s into %s", len(entries), target_dir, guest_cd)
        for e in entries:
            logger.debug("  %s -> %s", e["emu_path"], e["path"])

    def load_module(
        self, path: str | None = None, data: bytes | None = None, filename: str | None = None
    ) -> RuntimeModule:
        """
        Create the emulator for a PE file and load the file as the input image.

        A driver gets the kernel mode emulator. Other PE files get the user mode emulator, and a
        DLL loads into the container process. If ``path`` is given, the emulator also mounts the
        files of its directory into the emulated current directory.

        Args:
            path: File path of the PE file.
            data: Bytes of the PE file.
            filename: File name of the module that the emulated program sees. Use it when you
                load from bytes and the sample checks its own file name, for example with
                ``GetModuleFileName``.

        Returns:
            The module of the input image.

        Raises:
            InputError: if neither ``path`` nor ``data`` is given, the file does not exist,
                the input is not a valid PE, or its architecture is not x86 or x64.
            NotSupportedError: if the PE is a .NET assembly.
        """
        if not path and not data:
            raise InputError("No emulation target supplied")

        if path and not os.path.exists(path):
            raise InputError(f"Target file not found: {path}")

        if data:
            test = data
        else:
            assert path is not None
            with open(path, "rb") as f:
                test = f.read(4)

        self.loaded_bins.append(path)

        if not self.is_pe(test):
            raise InputError("Target file is not a PE")

        if path:
            self._auto_mount_target_directory(path)

        self._init_pe_emulator(path=path, data=data)

        try:
            return self.emu.load_module(path=path, data=data, filename=filename)
        except ValueError as err:
            # PeLoader raises ValueError for a PE that pefile parses but that cannot be mapped.
            raise InputError(f"Target file is not a valid PE: {err}") from err

    def load_image(self, image: LoadedImage) -> RuntimeModule:
        """
        Load a ``LoadedImage`` into the emulator.

        If there is no emulator yet, ``load_image`` creates the user mode emulator, and the image is
        the input image. An image that is not an EXE then loads into the container process.
        """
        is_input = self._emu is None
        if is_input:
            emu = self._init_user_emulator()
            arch = image.arch if image.arch in (_arch.ARCH_X86, _arch.ARCH_AMD64) else _arch.ARCH_X86
            self._init_machine(emu, arch)
            if image.module_type != "exe":
                emu.load_container()
        return self.emu.load_image(image, is_input=is_input)

    @check_init
    @execution_scope
    def run_module(
        self,
        module: RuntimeModule,
        *,
        all_entrypoints: bool = False,
        emulate_children: bool = False,
        entry_point: int | None = None,
    ) -> None:
        """
        Add the runs of a loaded module to the run queue, and run the queue.

        The runs are the TLS callbacks and the entry point of the module, and its exports if
        ``all_entrypoints`` is true.

        Args:
            module: The module that ``load_module`` returned.
            all_entrypoints: If true, also run the exports. For a driver, also send IRPs to its
                dispatch functions and run its unload routine.
            emulate_children: If true, run the child processes that the module creates, after
                the module. The kernel mode emulator ignores this argument.
            entry_point: RVA at which to start, in place of the entry point of the PE.

        Raises:
            SpeakeasyError: if no module is loaded yet.
        """
        output_active_config(self.config, logger)

        if isinstance(self.emu, Win32Emulator):
            return self.emu.run_module(
                module=module,
                all_entrypoints=all_entrypoints,
                emulate_children=emulate_children,
                entry_point=entry_point,
            )
        return self.emu.run_module(module=module, all_entrypoints=all_entrypoints, entry_point=entry_point)

    def load_shellcode(
        self,
        fpath: str | None = None,
        arch: str | int | None = None,
        data: bytes | None = None,
        filename: str | None = None,
    ) -> int:
        """
        Create the user mode emulator and load shellcode into the container process.

        Args:
            fpath: File path of the shellcode blob.
            arch: Architecture to load the shellcode as: ``x86``, ``x64`` or ``amd64`` in any case,
                or ``ARCH_X86`` or ``ARCH_AMD64`` from ``speakeasy.winenv.arch``.
            data: Bytes of the shellcode blob.
            filename: Override for the module filename that the emulated program sees.

        Returns:
            Address of the loaded shellcode in the emulation space.

        Raises:
            InputError: if neither ``fpath`` nor ``data`` is given, the file does not exist,
                or ``arch`` is not one of the values above.
        """
        sc_arch = SHELLCODE_ARCH.get(arch.lower() if isinstance(arch, str) else arch)
        if sc_arch is None:
            raise InputError(f"Unsupported shellcode architecture: {arch!r}")
        if fpath is None and data is None:
            raise InputError("No emulation target supplied")
        if data is None and fpath is not None and not os.path.exists(fpath):
            raise InputError(f"Target file not found: {fpath}")

        emu = self._init_user_emulator()
        self._init_machine(emu, sc_arch)
        emu.load_container()
        self.loaded_bins.append(fpath)

        return emu.load_shellcode(fpath, sc_arch, data=data, filename=filename)

    @check_init
    @execution_scope
    def run_shellcode(self, sc_addr: int, stack_commit: int = 0x4000, offset: int = 0) -> None:
        """
        Run shellcode that ``load_shellcode`` loaded.

        Args:
            sc_addr: Address that ``load_shellcode`` returned.
            stack_commit: Size of the stack in bytes, if the ``stack_size`` of the config is not set.
            offset: Offset in the shellcode at which to start.

        Raises:
            SpeakeasyError: if no shellcode is loaded or the emulator is the kernel mode emulator.
        """
        emu = self.emu
        if not isinstance(emu, Win32Emulator):
            raise SpeakeasyError("Shellcode runs only in the user mode emulator")
        output_active_config(self.config, logger)
        return emu.run_shellcode(sc_addr, stack_commit=stack_commit, offset=offset)

    @check_init
    def get_report(self) -> Report:
        """
        Get the emulation report.

        Returns:
            The emulation report as a Pydantic ``Report`` model.

        Raises:
            SpeakeasyError: if the emulator does not exist.
        """
        return self.emu.get_report()

    @check_init
    def get_json_report(self) -> str:
        """
        Get the emulation report as a JSON string.

        Raises:
            SpeakeasyError: if the emulator does not exist.
        """
        return self.emu.get_json_report()

    def add_api_hook(
        self, cb: ApiHookCallback, module: str = "", api_name: str = "", argc: int = 0, call_conv: int | None = None
    ) -> common.ApiHook:
        """
        Set a callback to fire when the emulated program calls an API.

        The emulator calls ``cb(emu, api_name, func, argv)`` in place of the API handler.
        ``argv`` holds the raw arguments, and ``func(argv)`` runs the handler. ``func`` is
        ``None`` when the API has no handler. The callback returns the return value of the API.

        If more than one hook matches an API that has a handler, all of them run in the order
        that you added them, and the API returns the value of the last hook. If the API has no
        handler, only the hook that you added last runs.

        Args:
            cb: Python function to call.
            module: Name of the module, for example ``kernel32``. Wildcards such as ``*`` are supported.
            api_name: Name of the API. Wildcards such as ``*`` are supported.
            argc: Number of arguments of an API that has no handler. The emulator reads this
                number of arguments and removes them from the stack.
            call_conv: Calling convention of an API that has no handler. The default is stdcall.

        Returns:
            The hook object. Pass it to ``remove_hook`` to remove the hook.
        """
        return self._add_hook(common.ApiHook(cb, module, api_name, argc, call_conv))

    @execution_scope
    def resume(self, addr: int, count: int = -1) -> None:
        """
        Start emulation at an address in the current run.

        Args:
            addr: Address at which to start.
            count: Number of instructions to emulate. ``-1`` means no limit.
        """
        output_active_config(self.config, logger)
        self._init_hooks()
        self.emu.resume(addr, count=count)

    def stop(self) -> None:
        """Stop emulation."""
        return self.emu.stop()

    def shutdown(self) -> None:
        """
        Remove the hooks that the engine added through the Unicorn C API.

        Then Unicorn does not call a hook after Python frees its callback. ``shutdown`` does not
        call ``uc_close``, because ``uc_close`` changes state that the other Unicorn instances in
        the process use. The garbage collector releases the Unicorn instance.
        """
        if self._emu is not None:
            self._emu.emu_eng.close()

    @execution_scope
    def call(self, addr: int, params: list[int] | None = None) -> None:
        """
        Run the function at an address as a new run.

        If the run queue is empty, the run starts at once. Otherwise, the emulator adds the run
        to the end of the queue and does not start it.

        Args:
            addr: Address of the function.
            params: Arguments of the call, with the stdcall convention on x86 and the Microsoft
                x64 convention on x64.
        """
        output_active_config(self.config, logger)
        self._init_hooks()
        return self.emu.call(addr, params=params)

    def add_code_hook(self, cb: CodeHookCallback, begin: int = 1, end: int = 0) -> common.CodeHook:
        """
        Set a callback to fire for each instruction in an address range.

        The emulator calls ``cb(emu, address, size)`` before the instruction at ``address`` runs.
        The return value is not used.

        Args:
            cb: Python function to call.
            begin: Start of the address range to hook.
            end: Last address of the range to hook. If ``begin`` is greater than ``end``,
                the hook covers all addresses.

        Returns:
            The hook object. Pass it to ``remove_hook`` to remove the hook.
        """
        return self._add_hook(common.CodeHook(cb, begin, end))

    def add_dyn_code_hook(self, cb: DynCodeHookCallback) -> common.DynCodeHook:
        """
        Set a callback to fire when the guest runs code in memory that ``VirtualAlloc`` or a similar API allocated.

        The hook fires the first time that the start of the region runs, and each time that code
        in the region calls an API. The emulator calls ``cb(emu, region)`` with the ``MemMap`` of
        the code. The return value is not used.

        Args:
            cb: Python function to call.

        Returns:
            The hook object. Pass it to ``remove_hook`` to remove the hook.
        """
        return self._add_hook(common.DynCodeHook(cb))

    def add_mem_read_hook(self, cb: MemAccessHookCallback, begin: int = 1, end: int = 0) -> common.ReadMemHook:
        """
        Set a callback to fire when the guest reads mapped memory.

        The emulator calls ``cb(emu, access, address, size, value)``. The return value is not used.

        Args:
            cb: Python function to call.
            begin: Start of the address range to hook.
            end: End of the address range to hook.

        Returns:
            The hook object. Pass it to ``remove_hook`` to remove the hook.
        """
        return self._add_hook(common.ReadMemHook(cb, begin, end))

    def add_mem_write_hook(self, cb: MemAccessHookCallback, begin: int = 1, end: int = 0) -> common.WriteMemHook:
        """
        Set a callback to fire when the guest writes mapped memory.

        The emulator calls ``cb(emu, access, address, size, value)``, where ``value`` is the
        value that the instruction writes. The return value is not used.

        Args:
            cb: Python function to call.
            begin: Start of the address range to hook.
            end: End of the address range to hook.

        Returns:
            The hook object. Pass it to ``remove_hook`` to remove the hook.
        """
        return self._add_hook(common.WriteMemHook(cb, begin, end))

    def add_in_instruction_hook(self, cb: InHookCallback, begin: int = 1, end: int = 0) -> common.InstructionHook:
        """
        Set a callback to fire when an IN instruction executes.

        The emulator calls ``cb(emu, port, size)``. The callback returns the value that the
        instruction reads from ``port``. Only one IN hook runs for an instruction: the first
        hook that is enabled and covers the address.

        In user mode, when ``exceptions.dispatch_handlers`` is set, the emulator adds its own
        IN hook when the first run starts. That hook raises a privileged instruction exception,
        as Windows does. A hook that you add before the run comes first, so it replaces the
        exception.

        Args:
            cb: Python function to call.
            begin: Start of the address range to hook.
            end: End of the address range to hook.

        Returns:
            The hook object. Pass it to ``remove_hook`` to remove the hook.
        """
        return self._add_hook(common.InstructionHook(cb, begin, end, insns=(UC_X86_INS_IN,)))

    def add_IN_instruction_hook(self, cb: InHookCallback, begin: int = 1, end: int = 0) -> common.InstructionHook:
        """Deprecated alias of ``add_in_instruction_hook``."""
        warnings.warn(
            "add_IN_instruction_hook is deprecated, use add_in_instruction_hook", DeprecationWarning, stacklevel=2
        )
        return self.add_in_instruction_hook(cb, begin, end)

    def add_syscall_instruction_hook(
        self, cb: SyscallHookCallback, begin: int = 1, end: int = 0
    ) -> common.InstructionHook:
        """
        Set a callback to fire when a SYSCALL or SYSENTER instruction executes.

        The emulator calls ``cb(emu)``. The return value is not used. Unicorn does not
        emulate the system call, so the emulation continues at the next instruction.

        Args:
            cb: Python function to call.
            begin: Start of the address range to hook.
            end: End of the address range to hook.

        Returns:
            The hook object. Pass it to ``remove_hook`` to remove the hook.
        """
        return self._add_hook(common.InstructionHook(cb, begin, end, insns=(UC_X86_INS_SYSCALL, UC_X86_INS_SYSENTER)))

    def add_SYSCALL_instruction_hook(
        self, cb: SyscallHookCallback, begin: int = 1, end: int = 0
    ) -> common.InstructionHook:
        """Deprecated alias of ``add_syscall_instruction_hook``."""
        warnings.warn(
            "add_SYSCALL_instruction_hook is deprecated, use add_syscall_instruction_hook",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.add_syscall_instruction_hook(cb, begin, end)

    def add_invalid_instruction_hook(self, cb: InvalidInstructionHookCallback) -> common.InvalidInstructionHook:
        """
        Set a callback to fire when the guest runs an invalid instruction.

        The emulator calls ``cb(emu)``. The callback returns ``True`` if it handled the
        instruction, so that the hooks after it do not run, or ``False`` to let the next hook
        handle it.

        Args:
            cb: Python function to call.

        Returns:
            The hook object. Pass it to ``remove_hook`` to remove the hook.
        """
        return self._add_hook(common.InvalidInstructionHook(cb))

    def add_mem_invalid_hook(self, cb: MemAccessHookCallback) -> common.InvalidMemHook:
        """
        Set a callback to fire when the guest accesses unmapped or protected memory.

        The emulator calls ``cb(emu, access, address, size, value)``. The callback returns
        ``False`` to stop the hooks after it and fail the access. Any other value lets the next
        hook handle the access.

        Args:
            cb: Python function to call.

        Returns:
            The hook object. Pass it to ``remove_hook`` to remove the hook.
        """
        return self._add_hook(common.InvalidMemHook(cb))

    def add_interrupt_hook(self, cb: InterruptHookCallback) -> common.InterruptHook:
        """
        Set a callback to fire for interrupts and CPU exceptions.

        The emulator calls ``cb(emu, number)`` with the interrupt number. The return value is not used.

        Args:
            cb: Python function to call.

        Returns:
            The hook object. Pass it to ``remove_hook`` to remove the hook.
        """
        return self._add_hook(common.InterruptHook(cb))

    def get_registry_key(self, handle: int = 0, path: str = "") -> RegKey | None:
        """
        Get a registry key by path, or by handle if ``path`` is empty.

        Returns:
            The registry key, or ``None`` if no key has the path or the handle.
        """
        return self.emu.reg_get_key(handle=handle, path=path)

    def get_address_map(self, addr: int) -> MemMap | None:
        """Get the memory map that holds an address, or ``None`` if the address is not mapped."""
        mm: MemMap | None = self.emu.get_address_map(addr)
        return mm

    def mem_alloc(self, size: int, base: int | None = None, tag: str = "speakeasy.None") -> int:
        """
        Allocate a block of memory in the emulation space.

        Args:
            size: Size of the block in bytes.
            base: Requested base address. If the range is not free, the emulator uses the next
                free range above it.
            tag: Tag of the new memory map.

        Returns:
            Address of the newly allocated memory block.

        Raises:
            OutOfMemoryError: if no free range below the address limit can hold the block.
            SpeakeasyError: if the emulator does not exist.
        """
        return self.emu.mem_map(size, base=base, tag=tag)

    def mem_free(self, base: int) -> None:
        """Free a block of memory in the emulation space."""
        return self.emu.mem_free(base)

    def mem_read(self, addr: int, size: int) -> bytes:
        """
        Read bytes from a memory address.

        Raises:
            SpeakeasyError: if the read fails or the emulator does not exist.
        """
        try:
            return self.emu.mem_read(addr, size)
        except Exception as e:
            raise SpeakeasyError(f"Failed to read {size} bytes at address: 0x{addr:x}") from e

    def mem_write(self, addr: int, data: bytes) -> None:
        """
        Write bytes to a memory address.

        Raises:
            SpeakeasyError: if the write fails or the emulator does not exist.
        """
        try:
            return self.emu.mem_write(addr, data)
        except Exception as e:
            raise SpeakeasyError(f"Failed to write {len(data)} bytes at address: 0x{addr:x}") from e

    def mem_cast(self, obj: EmuStruct, addr: int) -> Any:
        """
        Read a structure from memory.

        Returns:
            ``obj``, with its fields set from the bytes at ``addr``.
        """
        return self.emu.mem_cast(obj, addr)

    def reg_read(self, reg: str) -> int:
        """
        Read the value of a register by name.

        Raises:
            CpuError: if ``reg`` is not a register name.
            SpeakeasyError: if the emulator does not exist.
        """
        return self.emu.reg_read(reg)

    def reg_write(self, reg: str, val: int) -> None:
        """
        Write a value to a register by name.

        Raises:
            CpuError: if ``reg`` is not a register name.
            SpeakeasyError: if the emulator does not exist.
        """
        return self.emu.reg_write(reg, val)

    def get_dropped_files(self) -> list[File]:
        """Get the files that the sample wrote during emulation."""
        return self.emu.get_dropped_files()

    def create_file_archive(self) -> bytes:
        """
        Create a zip archive of the dropped files.

        The archive has ``speakeasy_manifest.json``, which gives the emulated path, the size and
        the SHA-256 of each file.

        Returns:
            The bytes of the zip archive, or empty bytes if the sample dropped no files.
        """
        manifest: list[FileManifestEntry] = []
        _zip = BytesIO()
        files = self.get_dropped_files()

        if not files:
            return b""

        with zipfile.ZipFile(_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for f in files:
                path = f.path
                file_name = ntpath.basename(path)
                entry = FileManifestEntry(
                    path=path,
                    file_name=file_name,
                    size=f.get_size(),
                    sha256=f.get_hash(),
                )
                manifest.append(entry)
                zf.writestr(file_name, f.get_contents())

            manifest_json = "[" + ",".join(e.model_dump_json(indent=4, exclude_none=True) for e in manifest) + "]"
            zf.writestr("speakeasy_manifest.json", manifest_json)

        return _zip.getvalue()

    def get_mem_maps(self) -> list[MemMap]:
        """Get all valid memory maps in the emulation space."""
        return self.emu.get_mem_maps()

    def get_memory_dumps(self) -> Generator[tuple[str | None, int, int, bool, Any, bytes], None, None]:
        """
        Yield the contents of the memory maps.

        Yields:
            Tuples of tag, base, size, free flag, process, and data. The method skips the maps
            that it cannot read.
        """
        for mm in self.emu.get_mem_maps():
            base = mm.base
            size = mm.size
            tag = mm.tag
            proc = mm.process
            is_free = mm.free
            try:
                data = self.emu.mem_read(base, size)
            except Exception:
                continue
            yield (tag, base, size, is_free, proc, data)

    def read_mem_string(self, address: int, width: int = 1, max_chars: int = 0) -> str:
        """
        Read a string from emulated memory.

        Args:
            address: Address of the string.
            width: Character width in bytes.
            max_chars: Maximum number of characters to read. 0 reads until the null terminator.

        Returns:
            The decoded string.
        """
        return self.emu.read_mem_string(address, width, max_chars)

    def get_symbols(self) -> dict[int, tuple[str, str]]:
        """
        Get a snapshot of the symbols, as ``(dll, name)`` tuples by address.

        The symbols are the exports of the emulated DLLs and the other labels that the emulator
        adds, such as ``KiSystemCall64``. API tokens and forwarder strings are not symbols. Get
        a new snapshot after the emulator loads a module or resolves a function.
        """
        return self.emu.get_symbols()

    def get_ret_address(self) -> int:
        """Get the value at the top of the stack, which is the return address at the start of a call."""
        return self.emu.get_ret_address()

    def set_ret_address(self, addr: int) -> None:
        """Write a value at the top of the stack, which is the return address at the start of a call."""
        return self.emu.set_ret_address(addr)

    def push_stack(self, val: int) -> None:
        """Put a value on the stack and adjust the stack pointer."""
        self.emu.push_stack(val)

    def pop_stack(self) -> int:
        """
        Pop a value from the stack and adjust the stack pointer.

        Returns:
            The value that was at the top of the stack.
        """
        return self.emu.pop_stack()

    def get_stack_ptr(self) -> int:
        """Get the current address of the stack pointer."""
        return self.emu.get_stack_ptr()

    def set_stack_ptr(self, addr: int) -> None:
        """Set the current address of the stack pointer."""
        self.emu.set_stack_ptr(addr)

    def get_pc(self) -> int:
        """Get the value of the current program counter."""
        return self.emu.get_pc()

    def set_pc(self, addr: int) -> None:
        """Set the value of the current program counter."""
        self.emu.set_pc(addr)

    def reset_stack(self, base: int) -> tuple[int, int]:
        """
        Set the stack pointer and the frame pointer below ``base``, with room for stack arguments.

        Returns:
            A tuple of the stack base and the stack pointer.
        """
        return self.emu.reset_stack(base)

    def get_stack_base(self) -> int:
        """Get the base address of the stack."""
        return self.emu.stack_base

    def get_arch(self) -> int:
        """Get the architecture constant of the emulator."""
        return self.emu.get_arch()

    def get_ptr_size(self) -> int:
        """Get the size of a pointer in bytes."""
        return self.emu.ptr_size

    def get_all_registers(self) -> dict[str, str]:
        """Get the general-purpose registers and the instruction pointer as zero-padded hex strings."""
        width = 2 + self.get_ptr_size() * 2
        return {name: f"{value:#0{width}x}" for name, value in self.emu.get_register_state().items()}

    def get_symbol_from_address(self, address: int) -> str | None:
        """
        Look up the known symbol for an address.

        Returns:
            The symbol name, or ``None`` if the address has no known symbol.
        """
        return self.emu.get_symbol_from_address(address)

    def get_api_symbols(self) -> dict[int, str]:
        """Get a snapshot of the symbols of ``get_symbols``, as ``dll.name`` strings by address."""
        return self.emu.get_api_symbols()

    def is_address_valid(self, address: int) -> bool:
        """Check whether the memory manager mapped or reserved the address."""
        return self.emu.is_address_valid(address)

    def add_mem_map_hook(self, cb: MemMapHookCallback, begin: int = 1, end: int = 0) -> common.MapMemHook:
        """
        Set a callback to fire when the emulator maps memory.

        The emulator calls ``cb(emu, base, size, tag, perms, flags)`` for each new map with a base
        in the range. The return value is not used.

        Args:
            cb: Python function to call.
            begin: Start of the address range to hook.
            end: End of the address range to hook.

        Returns:
            The hook object. Pass it to ``remove_hook`` to remove the hook.
        """
        return self._add_hook(common.MapMemHook(cb, begin, end))
