"""
Call API handlers directly, with the context that dispatch builds.
"""

import struct
from collections.abc import Iterator
from typing import Any

import pytest

from speakeasy import Speakeasy
from speakeasy.profiler import Run
from speakeasy.windows import objman
from speakeasy.windows.win32 import Win32Emulator
from speakeasy.winenv import arch as e_arch
from speakeasy.winenv.api import sigdb
from speakeasy.winenv.api.api import ApiContext, HandlerArgs


def load_emu(config: dict[str, Any], data: bytes) -> Iterator[Speakeasy]:
    if not sigdb.get_default_database().available:
        pytest.skip("bundled signature database not generated")
    se = Speakeasy(config=config)
    try:
        se.load_module(data=data)
        assert se.emu is not None
        se.emu.curr_run = Run()
        yield se
    finally:
        se.shutdown()


def alloc(se: Speakeasy, data: bytes) -> int:
    addr = se.mem_alloc(len(data), base=0x20000000)
    se.mem_write(addr, data)
    return addr


def unicode_string(se: Speakeasy, text: str) -> int:
    """Build an x86 UNICODE_STRING for ``text`` and return its address."""
    buf = text.encode("utf-16le")
    buf_addr = alloc(se, buf + b"\x00\x00")
    return alloc(se, struct.pack("<HHI", len(buf), len(buf) + 2, buf_addr))


def object_attributes(se: Speakeasy, name: str) -> int:
    """Build an x86 OBJECT_ATTRIBUTES for ``name`` and return its address."""
    return alloc(se, struct.pack("<IIIIII", 24, 0, unicode_string(se, name), 0, 0, 0))


def call(se: Speakeasy, dll: str, name: str, argv: list[int]) -> tuple[int, dict[str | int, str]]:
    """
    Call a handler with the context dispatch builds. A variadic handler reads
    ``argv`` from the stack. Return the handler result and the displays, by
    parameter name, or by slot index for a call without a signature.
    """
    emu = se.emu
    assert emu is not None and emu.api is not None
    mod, func_attrs = emu.api.get_export_func_handler(dll, name)
    if not func_attrs:
        mod, func_attrs = emu.normalize_import_miss(dll, name)
    _, func, argc, conv, _ = func_attrs
    if argc == e_arch.VAR_ARGS:
        emu.set_func_args(emu.stack_base, 0, *argv, conv=conv)
        argv = []
    assert argc in (e_arch.VAR_ARGS, len(argv))
    sig = emu.get_handler_signature(dll, name, argc)
    if sig is None:
        args = HandlerArgs.from_slots(argv)
    else:
        args = HandlerArgs.from_signature(sig, emu.get_ptr_size(), emu._render_signature_args(sig, argv), argv)
    ctx = ApiContext(func_name=f"{dll}.{name}", args=args)
    rv = func(mod, emu, list(argv), ctx)
    return rv, {i if a.name is None else a.name: a.display for i, a in enumerate(args.get_report_args())}


def start_process(se: Speakeasy) -> None:
    """
    Create the process and thread that ``run_module`` creates, for handlers
    that use the current process, thread, or module.
    """
    emu = se.emu
    assert isinstance(emu, Win32Emulator)
    module = emu.modules[0]
    emu.prepare_module_for_emulation(module, False)
    if not emu.processes:
        p = objman.Process(emu, path=module.emu_path, base=module.base, pe=module, cmdline=emu.command_line)
        emu.processes.append(p)
        emu.curr_process = p
        emu.om.objects.update({p.address: p})  # type: ignore[union-attr]
    t = objman.Thread(emu, stack_base=emu.stack_base, stack_commit=module.stack_commit)
    emu.om.objects.update({t.address: t})  # type: ignore[union-attr]
    emu.curr_process.threads.append(t)  # type: ignore[union-attr]
    emu.curr_thread = t
    emu.curr_mod = module
