"""ntoskrnl spinlock, pool allocation, current-pid and image header APIs."""

from collections.abc import Iterator
from typing import Any

import pefile
import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.defs.nt import ddk
from tests.handler_harness import alloc, call, get_kernel_emu, load_emu


@pytest.fixture(params=["wdm_test_x86.sys.xz", "wdm_test_x64.sys.xz"], ids=["x86", "x64"])
def any_driver_emu(request: pytest.FixtureRequest, config: dict[str, Any], load_test_bin: Any) -> Iterator[Speakeasy]:
    yield from load_emu(config, load_test_bin(request.param))


def test_ke_initialize_spin_lock_zeroes_the_lock(any_driver_emu: Speakeasy) -> None:
    ptr_size = any_driver_emu.get_ptr_size()
    lock = alloc(any_driver_emu, b"\xaa" * (ptr_size + 1))
    call(any_driver_emu, "ntoskrnl", "KeInitializeSpinLock", [lock])
    assert any_driver_emu.mem_read(lock, ptr_size + 1) == b"\x00" * ptr_size + b"\xaa"


@pytest.mark.parametrize("irql", [ddk.PASSIVE_LEVEL, ddk.DISPATCH_LEVEL])
def test_ke_acquire_spin_lock_saves_old_irql_and_raises_to_dispatch(driver_emu: Speakeasy, irql: int) -> None:
    emu = get_kernel_emu(driver_emu)
    old_irql = alloc(driver_emu, b"\xcc")
    emu.set_current_irql(irql)
    call(driver_emu, "ntoskrnl", "KeAcquireSpinLock", [alloc(driver_emu, b"\x00" * 4), old_irql])
    assert driver_emu.mem_read(old_irql, 1) == bytes([irql])
    assert emu.get_current_irql() == ddk.DISPATCH_LEVEL


def test_ke_release_spin_lock_restores_new_irql(driver_emu: Speakeasy) -> None:
    emu = get_kernel_emu(driver_emu)
    lock = alloc(driver_emu, b"\x00" * 4)
    emu.set_current_irql(ddk.DISPATCH_LEVEL)
    call(driver_emu, "ntoskrnl", "KeReleaseSpinLock", [lock, ddk.DISPATCH_LEVEL])
    assert emu.get_current_irql() == ddk.DISPATCH_LEVEL
    call(driver_emu, "ntoskrnl", "KeReleaseSpinLock", [lock, ddk.PASSIVE_LEVEL])
    assert emu.get_current_irql() == ddk.PASSIVE_LEVEL


def test_ex_allocate_pool2_zero_size_allocates_nothing(driver_emu: Speakeasy) -> None:
    emu = get_kernel_emu(driver_emu)
    before = list(emu.pool_allocs)
    assert call(driver_emu, "ntoskrnl", "ExAllocatePool2", [0x100, 0, 0, 0])[0] == 0
    assert emu.pool_allocs == before


def test_ps_get_current_process_id_returns_active_pid(driver_emu: Speakeasy) -> None:
    emu = get_kernel_emu(driver_emu)
    assert call(driver_emu, "ntoskrnl", "PsGetCurrentProcessId", [])[0] == 4
    proc = next(p for p in emu.processes if p.pid != 4)
    emu.set_current_process(proc)
    assert call(driver_emu, "ntoskrnl", "PsGetCurrentProcessId", [])[0] == proc.pid


@pytest.mark.parametrize("mapped", [1, 0x1E100], ids=["image", "file"])
def test_rtl_image_directory_entry_to_data_finds_the_import_directory(any_driver_emu: Speakeasy, mapped: int) -> None:
    se = any_driver_emu
    module = get_kernel_emu(se).modules[0]
    pe = pefile.PE(data=se.mem_read(module.base, 0x1000), fast_load=True)
    imports = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    size = alloc(se, b"\xcc" * 4)

    rv, _ = call(se, "ntoskrnl", "RtlImageDirectoryEntryToData", [module.base, mapped, 1, size])

    offset = imports.VirtualAddress if mapped & 0xFF else pe.get_offset_from_rva(imports.VirtualAddress)
    assert rv == module.base + offset
    assert int.from_bytes(se.mem_read(size, 4), "little") == imports.Size


@pytest.mark.parametrize(
    ("flags", "size", "status"),
    [
        (0, 0x1000, ddk.STATUS_SUCCESS),
        (0, 0x40, ddk.STATUS_INVALID_IMAGE_FORMAT),
        (ddk.RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK, 0, ddk.STATUS_SUCCESS),
    ],
    ids=["in-range", "out-of-range", "no-range-check"],
)
def test_rtl_image_nt_header_ex_checks_the_size(any_driver_emu: Speakeasy, flags: int, size: int, status: int) -> None:
    se = any_driver_emu
    module = get_kernel_emu(se).modules[0]
    out = alloc(se, b"\xcc" * se.get_ptr_size())
    # The x86 ULONG64 Size takes two stack slots
    argv = [flags, module.base, size, 0, out] if se.get_ptr_size() == 4 else [flags, module.base, size, out, 0]

    rv, _ = call(se, "ntoskrnl", "RtlImageNtHeaderEx", argv)

    nt = module.base + pefile.PE(data=se.mem_read(module.base, 0x1000), fast_load=True).DOS_HEADER.e_lfanew
    assert rv == status
    assert int.from_bytes(se.mem_read(out, se.get_ptr_size()), "little") == (nt if status == ddk.STATUS_SUCCESS else 0)
