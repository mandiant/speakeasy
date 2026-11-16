"""Test that a process without DEP can run code from every readable page, and a process with DEP cannot."""

from collections.abc import Iterator
from contextlib import contextmanager

import pytest
import unicorn

from speakeasy import Speakeasy
from speakeasy.config import get_default_config_dict
from speakeasy.profiler import Run
from speakeasy.winenv.defs.enums import PAGE_PROTECTION_FLAGS as PAGE
from speakeasy.winenv.defs.windows import windows as windefs
from tests.handler_harness import call, start_process
from tests.pe_builder import build_pe

READ_ONLY = unicorn.UC_PROT_READ
READ_WRITE = unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE
EXEC = unicorn.UC_PROT_EXEC


@contextmanager
def load(arch: int, nxcompat: bool) -> Iterator[Speakeasy]:
    data, _ = build_pe(arch, nxcompat=nxcompat)
    with Speakeasy(config=get_default_config_dict()) as se:
        se.load_module(data=data)
        se.emu.curr_run = Run()
        start_process(se)
        yield se


def native_perms(se: Speakeasy, address: int) -> int:
    return next(perms for start, end, perms in se.emu.get_mem_regions() if start <= address <= end)


@pytest.mark.parametrize(
    "arch, nxcompat, dep", [(32, False, False), (32, True, True), (64, False, True), (64, True, True)]
)
def test_the_input_exe_decides_if_the_header_and_a_data_section_can_run_code(
    arch: int, nxcompat: bool, dep: bool
) -> None:
    exec_perm = 0 if dep else EXEC
    with load(arch, nxcompat) as se:
        base = se.emu.modules[0].base
        assert native_perms(se, base) == READ_ONLY | exec_perm
        assert native_perms(se, base + 0x2000) == READ_WRITE | exec_perm


@pytest.mark.parametrize("nxcompat, expected", [(False, READ_WRITE | EXEC), (True, READ_WRITE)])
def test_virtual_alloc_read_write_can_run_code_only_without_dep(nxcompat: bool, expected: int) -> None:
    with load(32, nxcompat) as se:
        address = call(
            se,
            "kernel32",
            "VirtualAlloc",
            [0, 0x1000, windefs.MEM_COMMIT | windefs.MEM_RESERVE, PAGE.PAGE_READWRITE],
        )[0]
        assert native_perms(se, address) == expected


def test_without_dep_a_synthetic_module_keeps_its_protection() -> None:
    with load(32, nxcompat=False) as se:
        kernel32 = next(m for m in se.emu.modules if m.get_base_name().lower() == "kernel32.dll")
        data = next(s for s in kernel32.sections if s.name == ".data")
        assert native_perms(se, kernel32.base) == READ_ONLY
        assert native_perms(se, kernel32.base + data.virtual_address) == READ_WRITE
