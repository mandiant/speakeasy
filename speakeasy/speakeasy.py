# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import logging
import multiprocessing.synchronize
import ntpath
import os
import threading
import warnings
import zipfile
from collections.abc import Callable
from functools import wraps
from io import BytesIO
from pathlib import Path, PureWindowsPath
from typing import Concatenate, ParamSpec, TypeVar

from pefile import MACHINE_TYPE, PEFormatError
from pydantic import ValidationError

from speakeasy import Win32Emulator, WinKernelEmulator, common
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
from speakeasy.report import FileManifestEntry, Report
from speakeasy.volumes import apply_volumes
from speakeasy.windows.common import _PeParser
from speakeasy.windows.winemu import execution_scope
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
    """Wrapper class for invoking the speakeasy emulators."""

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
        config=None,
        argv=None,
        debug=False,
        exit_event=None,
        gdb_port=None,
        volumes=None,
        gdb_host="127.0.0.1",
    ):
        """
        Create a wrapper for the emulators.

        Args:
            config: Emulator configuration as a raw dict or a validated ``SpeakeasyConfig``.
                ``None`` selects the default configuration.
            argv: Command line arguments for the emulated program.
            debug: Whether to enable debug output in the emulator.
            exit_event: Event that stops the emulation when it is set.
            gdb_port: Port on which to listen for a GDB client. ``None`` disables the GDB server.
            volumes: Host paths to mount into the emulated file system.
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

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.shutdown()

    def _init_config(self, config: dict | SpeakeasyConfig | None) -> None:
        """
        Validate the configuration and store it.

        Args:
            config: The configuration data to set up the emulator environment.
                If ``None``, the default configuration is used.

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

    def _init_pe_emulator(self, path=None, data=None) -> None:
        """
        Create the emulator that fits the PE metadata and its machine.

        Picks the user mode emulator or the kernel mode emulator and creates the
        machine for the architecture of the PE.

        Raises:
            InputError: if the PE is not valid, or its architecture is not x86 or x64.
            NotSupportedError: if the PE is a .NET assembly.
        """
        try:
            pe = _PeParser(path=path, data=data)
        except (PEFormatError, ValueError) as err:
            raise InputError(f"Target file is not a valid PE: {err}") from err
        # Get the machine type we only support x86/x64 atm
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
            emu.init_machine(pe.arch)
        else:
            user_emu = self._init_user_emulator()
            user_emu.init_machine(pe.arch)
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

    def disasm(self, addr: int, size: int, fast=True):
        """
        Disassemble the code at an address.

        Args:
            addr: Address at which to begin the disassembly.
            size: Number of bytes to include.
            fast: Whether to use the fast disassembly path.

        Returns:
            A tuple of the mnemonic, the operands, and the full instruction.

        Raises:
            SpeakeasyError: if the disassembly fails or the emulator does not exist.
        """
        try:
            return self.emu.get_disasm(addr, size, fast)
        except Exception as e:
            raise SpeakeasyError(f"Failed to disassemble at address: 0x{addr:x}") from e

    def is_pe(self, data: bytes) -> bool:
        """Check whether the data starts with the PE ``MZ`` header."""
        # Check for the PE header
        if data[:2] == b"MZ":
            return True
        return False

    def _auto_mount_target_directory(self, path: str) -> None:
        """
        Mount direct-child files in the target's host directory into the emulated current directory.

        This makes sibling files (for example data files the sample expects to find
        in its working directory) available to the emulated program. Only
        immediate children are mounted, not subdirectories.
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

    def load_module(self, path=None, data=None, filename=None):
        """
        Load a PE module into the emulator.

        Args:
            path: File path of the PE module.
            data: Bytes of the PE module.
            filename: Override for the module filename that the emulated program sees.
                Useful when emulating from bytes and the malware checks its
                own filename (for example through ``GetModuleFileName``).

        Returns:
            The loaded module object from the emulator.

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

    def load_image(self, image):
        """
        Load a ``LoadedImage`` into the emulator.

        If there is no emulator yet, this method creates it and the image is the input image.
        """
        is_input = self._emu is None
        if is_input:
            emu = self._init_user_emulator()
            arch = image.arch if image.arch in (_arch.ARCH_X86, _arch.ARCH_AMD64) else _arch.ARCH_X86
            emu.init_machine(arch)
            if image.module_type != "exe":
                emu.load_container()
        self._init_hooks()
        return self.emu.load_image(image, is_input=is_input)

    @check_init
    @execution_scope
    def run_module(self, module, all_entrypoints=False, emulate_children=False, entry_point=None) -> None:
        """
        Run a previously loaded module through the configured emulator.

        Args:
            module: The module whose entry point to run.
            all_entrypoints: If true, emulate all exports. Otherwise, emulate
                only the main PE entry point.
            emulate_children: If true, emulate the child processes that this
                module creates. Otherwise, emulate only this module.
            entry_point: RVA to use as entry point instead of the
                default PE entry point.

        Raises:
            SpeakeasyError: if no module is loaded yet.
        """
        output_active_config(self.config, logger)
        self._init_hooks()

        if isinstance(self.emu, Win32Emulator):
            return self.emu.run_module(
                module=module,
                all_entrypoints=all_entrypoints,
                emulate_children=emulate_children,
                entry_point=entry_point,
            )
        return self.emu.run_module(module=module, all_entrypoints=all_entrypoints, entry_point=entry_point)

    def load_shellcode(self, fpath=None, arch=None, data=None, filename=None) -> int:
        """
        Load a shellcode blob into the emulation space.

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
        if data is None and not os.path.exists(fpath):
            raise InputError(f"Target file not found: {fpath}")

        emu = self._init_user_emulator()
        emu.init_machine(sc_arch)
        emu.load_container()
        self.loaded_bins.append(fpath)

        return emu.load_shellcode(fpath, sc_arch, data=data, filename=filename)

    @check_init
    @execution_scope
    def run_shellcode(self, sc_addr: int, stack_commit=0x4000, offset=0) -> None:
        """
        Run a previously loaded shellcode blob by address.

        Args:
            sc_addr: Address of the loaded shellcode to emulate.
            stack_commit: Number of bytes of stack to commit.
            offset: Offset within the blob at which to begin emulation.

        Raises:
            SpeakeasyError: if no shellcode is loaded or the emulator is the kernel mode emulator.
        """
        emu = self.emu
        if not isinstance(emu, Win32Emulator):
            raise SpeakeasyError("Shellcode runs only in the user mode emulator")
        output_active_config(self.config, logger)
        self._init_hooks()
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

    def add_api_hook(self, cb: ApiHookCallback, module="", api_name="", argc=0, call_conv=None) -> common.ApiHook:
        """
        Set a callback to fire when the emulated program calls a specified API.

        The emulator calls ``cb(emu, api_name, func, argv)`` in place of the API handler.
        ``argv`` holds the raw arguments, and ``func(argv)`` runs the handler. ``func`` is
        ``None`` when the API has no handler. The callback returns the return value of the API.

        Args:
            cb: Python function to call.
            module: Name of the module that contains the target API.
            api_name: Name of the API to hook. Wild cards (for example ``*``) are supported.
            argc: Force the emulator to account for this number of arguments (for stack cleanup).
            call_conv: Force the emulator to use this calling convention for the hook.

        Returns:
            The hook object. Pass it to ``remove_hook`` to remove the hook.
        """
        return self._add_hook(common.ApiHook(cb, module, api_name, argc, call_conv))

    @execution_scope
    def resume(self, addr: int, count: int = -1) -> None:
        """
        Resume emulating at the specified address.

        Args:
            addr: Address at which to begin emulation.
            count: Number of instructions to emulate. ``-1`` means no limit.
        """
        output_active_config(self.config, logger)
        self._init_hooks()
        self.emu.is_run_complete = False
        self.emu.resume(addr, count=count)

    def stop(self) -> None:
        """Stop emulation."""
        return self.emu.stop()

    def shutdown(self) -> None:
        """
        Close the emulation instance and release the underlying engine resources.

        Removes all Unicorn hooks so the garbage collector can finalize the native
        engine without it accessing stale callbacks. The Uc handle stays alive on
        purpose: Unicorn's ``uc_close`` has process-global side effects that can
        corrupt other live engine instances. The garbage collector and the weak-ref
        finalizer release it when the object graph is unreachable.
        """
        if self._emu is not None:
            self._emu.emu_eng.close()

    @execution_scope
    def call(self, addr: int, params: list[int] | None = None) -> None:
        """
        Call the function at the specified address.

        Args:
            addr: Address of the function.
            params: Arguments to push onto the stack for the call.
        """
        output_active_config(self.config, logger)
        self._init_hooks()
        return self.emu.call(addr, params=params)

    def add_code_hook(self, cb: CodeHookCallback, begin=1, end=0) -> common.CodeHook:
        """
        Set a callback to fire for every CPU instruction that is emulated.

        The emulator calls ``cb(emu, address, size)`` before the instruction at ``address`` runs.
        The return value is not used.

        Args:
            cb: Python function to call.
            begin: Start of the address range to hook.
            end: End of the address range to hook.

        Returns:
            The hook object. Pass it to ``remove_hook`` to remove the hook.
        """
        return self._add_hook(common.CodeHook(cb, begin, end))

    def add_dyn_code_hook(self, cb: DynCodeHookCallback) -> common.DynCodeHook:
        """
        Set a callback to fire when dynamically generated or copied code runs.

        The emulator calls ``cb(emu, region)`` with the ``MemMap`` of the code.
        The return value is not used.

        Args:
            cb: Python function to call.

        Returns:
            The hook object. Pass it to ``remove_hook`` to remove the hook.
        """
        return self._add_hook(common.DynCodeHook(cb))

    def add_mem_read_hook(self, cb: MemAccessHookCallback, begin=1, end=0) -> common.ReadMemHook:
        """
        Set a callback to fire when a memory address is read from.

        The emulator calls ``cb(emu, access, address, size, value)``. The return value is not used.

        Args:
            cb: Python function to call.
            begin: Start of the address range to hook.
            end: End of the address range to hook.

        Returns:
            The hook object. Pass it to ``remove_hook`` to remove the hook.
        """
        return self._add_hook(common.ReadMemHook(cb, begin, end))

    def add_mem_write_hook(self, cb: MemAccessHookCallback, begin=1, end=0) -> common.WriteMemHook:
        """
        Set a callback to fire when a memory address is written to.

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

    def add_in_instruction_hook(self, cb: InHookCallback, begin=1, end=0) -> common.InstructionHook:
        """
        Set a callback to fire when an IN instruction executes.

        The emulator calls ``cb(emu, port, size)``. The callback returns the value that the
        instruction reads from ``port``.

        Args:
            cb: Python function to call.
            begin: Start of the address range to hook.
            end: End of the address range to hook.

        Returns:
            The hook object. Pass it to ``remove_hook`` to remove the hook.
        """
        return self._add_hook(common.InstructionHook(cb, insn=218))

    def add_IN_instruction_hook(self, cb: InHookCallback, begin=1, end=0) -> common.InstructionHook:
        """Deprecated alias of ``add_in_instruction_hook``."""
        warnings.warn(
            "add_IN_instruction_hook is deprecated, use add_in_instruction_hook", DeprecationWarning, stacklevel=2
        )
        return self.add_in_instruction_hook(cb, begin, end)

    def add_syscall_instruction_hook(self, cb: SyscallHookCallback, begin=1, end=0) -> common.InstructionHook:
        """
        Set a callback to fire when a SYSCALL / SYSENTER instruction executes.

        The emulator calls ``cb(emu)``. The return value is not used.

        Args:
            cb: Python function to call.
            begin: Start of the address range to hook.
            end: End of the address range to hook.

        Returns:
            The hook object. Pass it to ``remove_hook`` to remove the hook.
        """
        return self._add_hook(common.InstructionHook(cb, insn=700))

    def add_SYSCALL_instruction_hook(self, cb: SyscallHookCallback, begin=1, end=0) -> common.InstructionHook:
        """Deprecated alias of ``add_syscall_instruction_hook``."""
        warnings.warn(
            "add_SYSCALL_instruction_hook is deprecated, use add_syscall_instruction_hook",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.add_syscall_instruction_hook(cb, begin, end)

    def add_invalid_instruction_hook(self, cb: InvalidInstructionHookCallback) -> common.InvalidInstructionHook:
        """
        Set a callback to fire when the emulator hits an invalid instruction.

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
        Set a callback to fire when a memory access violation occurs.

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
        Set a callback to fire for software interrupts.

        The emulator calls ``cb(emu, number)`` with the interrupt number. The return value is not used.

        Args:
            cb: Python function to call.

        Returns:
            The hook object. Pass it to ``remove_hook`` to remove the hook.
        """
        return self._add_hook(common.InterruptHook(cb))

    def get_registry_key(self, handle=0, path=""):
        """
        Get a registry key by path or handle.

        Args:
            handle: Handle of the registry key.
            path: Path of the registry key.

        Returns:
            The registry key object, if the handle or path is valid.
        """
        return self.emu.reg_get_key(handle=handle, path=path)

    def get_address_map(self, addr: int):
        """
        Get the memory map that holds the specified address.

        Args:
            addr: Address in the emulation space.
        """
        return self.emu.get_address_map(addr)

    def mem_alloc(self, size, base=None, tag="speakeasy.None") -> int:
        """
        Allocate a block of memory in the emulation space.

        Args:
            size: Size of the requested memory block.
            base: Requested base address. If it is in use, the emulator picks
                the next nearest address.
            tag: Tag to assign to the new memory mapping.

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

    def mem_cast(self, obj, addr: int):
        """
        Cast an address as an object for easy access.

        Args:
            obj: Object type to cast into.
            addr: Address of the data to cast into ``obj``.

        Returns:
            Python object based on the data at ``addr``.
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

    def get_dropped_files(self) -> list:
        """Get the files that the sample wrote during emulation."""
        return self.emu.get_dropped_files()

    def create_file_archive(self) -> bytes:
        """
        Create a zip archive of the dropped files.

        The archive contains a manifest that matches the metadata of the dropped
        files with the acquired files.

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

    def get_mem_maps(self) -> list:
        """Get all valid memory maps in the emulation space."""
        return self.emu.get_mem_maps()

    def get_memory_dumps(self):
        """
        Yield the contents of all readable memory maps with context information.

        Yields:
            Tuples of tag, base, size, free flag, process, and data. Maps that cannot be read
            are skipped.
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

    def read_mem_string(self, address: int, width=1, max_chars=0) -> str:
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
        Get a snapshot of public addresses mapped to ``(dll, name)`` tuples.

        Includes mapped API entries and auxiliary symbols. Take a new snapshot after
        the emulator resolves new modules or functions. Private dispatch tokens are excluded.
        """
        return self.emu.get_symbols()

    def get_ret_address(self) -> int:
        """Get the value stored at the top of the stack."""
        return self.emu.get_ret_address()

    def set_ret_address(self, addr) -> None:
        """Set the return address on the stack."""
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
        Reset the stack to the supplied base address.

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

    def get_ptr_size(self):
        """Get the size of a pointer in bytes."""
        return self.emu.ptr_size

    def get_all_registers(self) -> dict[str, str]:
        """Get the state of all registers as a dict of zero-padded hex strings."""
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
        """
        Get public addresses mapped to ``dll.name`` labels, including auxiliary symbols.

        Take a new snapshot after the emulator resolves new modules or functions. Private
        dispatch tokens and export-directory forwarder strings are excluded.
        """
        return self.emu.get_api_symbols()

    def is_address_valid(self, address: int) -> bool:
        """Check whether the address is reserved or mapped."""
        return self.emu.is_address_valid(address)

    def add_mem_map_hook(self, cb: MemMapHookCallback, begin=1, end=0) -> common.MapMemHook:
        """
        Set a callback to fire when a memory address is mapped.

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
