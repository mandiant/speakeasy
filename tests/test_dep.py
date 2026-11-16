"""Test that a process without DEP can run code from every readable page, and a process with DEP cannot."""

import struct
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
    data, _ = build_pe(arch, data=b"\xc3", nxcompat=nxcompat)
    with Speakeasy(config=get_default_config_dict()) as se:
        se.load_module(data=data)
        se.emu.curr_run = Run()
        start_process(se)
        yield se


@pytest.fixture
def no_dep() -> Iterator[Speakeasy]:
    with load(32, nxcompat=False) as se:
        yield se


@pytest.fixture
def dep() -> Iterator[Speakeasy]:
    with load(32, nxcompat=True) as se:
        yield se


def native_perms(se: Speakeasy, address: int) -> int:
    return next(perms for start, end, perms in se.emu.get_mem_regions() if start <= address <= end)


@pytest.mark.parametrize(
    "arch, nxcompat, dep_enabled", [(32, False, False), (32, True, True), (64, False, True), (64, True, True)]
)
def test_the_input_exe_decides_dep(arch: int, nxcompat: bool, dep_enabled: bool) -> None:
    with load(arch, nxcompat) as se:
        assert se.emu.dep_enabled is dep_enabled


def test_without_dep_the_header_and_a_data_section_can_run_code(no_dep: Speakeasy) -> None:
    base = no_dep.emu.modules[0].base
    assert native_perms(no_dep, base) == READ_ONLY | EXEC
    assert native_perms(no_dep, base + 0x2000) == READ_WRITE | EXEC


def test_with_dep_the_header_and_a_data_section_cannot_run_code(dep: Speakeasy) -> None:
    base = dep.emu.modules[0].base
    assert native_perms(dep, base) == READ_ONLY
    assert native_perms(dep, base + 0x2000) == READ_WRITE


@pytest.mark.parametrize("fixture, expected", [("no_dep", READ_WRITE | EXEC), ("dep", READ_WRITE)])
def test_virtual_alloc_read_write_can_run_code_only_without_dep(
    request: pytest.FixtureRequest, fixture: str, expected: int
) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    address = call(
        se,
        "kernel32",
        "VirtualAlloc",
        [0, 0x1000, windefs.MEM_COMMIT | windefs.MEM_RESERVE, PAGE.PAGE_READWRITE],
    )[0]
    assert native_perms(se, address) == expected


@pytest.mark.parametrize("fixture, expected", [("no_dep", READ_ONLY | EXEC), ("dep", READ_ONLY)])
def test_virtual_protect_read_only_can_run_code_only_without_dep(
    request: pytest.FixtureRequest, fixture: str, expected: int
) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    address = call(
        se,
        "kernel32",
        "VirtualAlloc",
        [0, 0x1000, windefs.MEM_COMMIT | windefs.MEM_RESERVE, PAGE.PAGE_EXECUTE_READWRITE],
    )[0]
    old = se.mem_alloc(4)
    assert call(se, "kernel32", "VirtualProtect", [address, 0x1000, PAGE.PAGE_READONLY, old])[0] == 1
    assert native_perms(se, address) == expected


def test_without_dep_a_synthetic_module_keeps_its_protection(no_dep: Speakeasy) -> None:
    kernel32 = next(m for m in no_dep.emu.modules if m.get_base_name().lower() == "kernel32.dll")
    data = next(s for s in kernel32.sections if s.name == ".data")
    assert native_perms(no_dep, kernel32.base) == READ_ONLY
    assert native_perms(no_dep, kernel32.base + data.virtual_address) == READ_WRITE


def test_without_dep_virtual_query_gives_the_execute_variant(no_dep: Speakeasy) -> None:
    base = no_dep.emu.modules[0].base
    info = no_dep.mem_alloc(0x40)
    assert call(no_dep, "kernel32", "VirtualQuery", [base + 0x2000, info, 0x1C])[0] == 0x1C
    protect = struct.unpack_from("<I", no_dep.mem_read(info + 0x14, 4))[0]
    assert protect == PAGE.PAGE_EXECUTE_READWRITE
