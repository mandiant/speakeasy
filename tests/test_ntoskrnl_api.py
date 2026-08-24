"""Unit tests for ntoskrnl spinlock, pool allocation and current-pid APIs."""

import pytest

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.nt.ddk as ddk
from speakeasy.winenv.api.kernelmode.ntoskrnl import Ntoskrnl

TEST_POOL_BASE = 0x1000000


class FakeProcess:
    def __init__(self, pid):
        self.pid = pid


class FakeKernelEmu:
    """
    Minimal emulator seam exposing only what the Ntoskrnl handlers under test
    reach through self.emu.
    """

    def __init__(self, ptr_size=8):
        if ptr_size == 8:
            self._arch = _arch.ARCH_AMD64
        elif ptr_size == 4:
            self._arch = _arch.ARCH_X86
        else:
            raise ValueError(f"Unsupported pointer size: {ptr_size}")
        self.ptr_size = ptr_size
        self.mem: dict[int, int] = {}
        self.irql = ddk.PASSIVE_LEVEL
        self.process = None
        self.pool_allocs: list[tuple[int, int, str]] = []

    def get_arch(self):
        return self._arch

    def get_ptr_size(self):
        return self.ptr_size

    def get_current_irql(self):
        return self.irql

    def set_current_irql(self, irql):
        self.irql = irql

    def get_current_process(self):
        return self.process

    def get_address_map(self, addr):
        # No bookkeeping maps in the fake: mem_write takes the direct path.
        return None

    def mem_write(self, addr, data):
        for i, byte in enumerate(data):
            self.mem[addr + i] = byte

    def mem_read(self, addr, size):
        return bytes(self.mem.get(addr + i, 0) for i in range(size))

    def pool_alloc(self, pool_type, size, tag):
        chunk = TEST_POOL_BASE + len(self.pool_allocs) * 0x1000
        self.pool_allocs.append((pool_type, size, tag))
        return chunk


@pytest.fixture(params=[8, 4], ids=["x64", "x86"])
def emu(request):
    return FakeKernelEmu(ptr_size=request.param)


def make_api(emu):
    return Ntoskrnl(emu)


@pytest.mark.parametrize("ptr_size", [8, 4], ids=["x64", "x86"])
def test_ke_initialize_spin_lock_zeroes_the_lock(ptr_size):
    emu = FakeKernelEmu(ptr_size=ptr_size)
    api = make_api(emu)
    lock = 0x4000
    emu.mem_write(lock, b"\xaa" * emu.get_ptr_size())

    api.KeInitializeSpinLock(emu, [lock])

    assert emu.mem_read(lock, emu.get_ptr_size()) == b"\x00" * emu.get_ptr_size()


def test_ke_acquire_spin_lock_saves_old_irql_and_raises_to_dispatch(emu):
    api = make_api(emu)
    lock = 0x4000
    old_irql = 0x5000
    emu.set_current_irql(ddk.PASSIVE_LEVEL)

    api.KeAcquireSpinLock(emu, [lock, old_irql])

    assert emu.mem_read(old_irql, 1) == bytes([ddk.PASSIVE_LEVEL])
    assert emu.get_current_irql() == ddk.DISPATCH_LEVEL


def test_ke_acquire_spin_lock_at_dispatch_stays_at_dispatch(emu):
    # Documented simplification: acquisition always raises to DISPATCH_LEVEL,
    # even when starting there (matches the existing Kf* hook behavior).
    api = make_api(emu)
    lock = 0x4000
    old_irql = 0x5000
    emu.set_current_irql(ddk.DISPATCH_LEVEL)

    api.KeAcquireSpinLock(emu, [lock, old_irql])

    assert emu.mem_read(old_irql, 1) == bytes([ddk.DISPATCH_LEVEL])
    assert emu.get_current_irql() == ddk.DISPATCH_LEVEL


def test_ke_release_spin_lock_restores_new_irql(emu):
    api = make_api(emu)
    lock = 0x4000
    emu.set_current_irql(ddk.DISPATCH_LEVEL)

    api.KeReleaseSpinLock(emu, [lock, ddk.DISPATCH_LEVEL])
    assert emu.get_current_irql() == ddk.DISPATCH_LEVEL

    api.KeReleaseSpinLock(emu, [lock, 0])
    assert emu.get_current_irql() == ddk.PASSIVE_LEVEL


def test_ex_allocate_pool2_decodes_tag_and_paged_flag(emu):
    api = make_api(emu)
    tag = int.from_bytes(b"Face", "little")

    chunk = api.ExAllocatePool2(emu, [0x100, 0x50, tag])

    assert chunk != 0
    pool_type, size, decoded_tag = emu.pool_allocs[-1]
    assert pool_type == ddk.POOL_TYPE.PagedPool
    assert size == 0x50
    assert decoded_tag == "Face"


def test_ex_allocate_pool2_defaults_to_nonpaged(emu):
    api = make_api(emu)
    tag = int.from_bytes(b"tada", "little")

    chunk = api.ExAllocatePool2(emu, [0x0, 0x30, tag])

    assert chunk != 0
    pool_type, size, decoded_tag = emu.pool_allocs[-1]
    assert pool_type == ddk.POOL_TYPE.NonPagedPool
    assert size == 0x30
    assert decoded_tag == "tada"


def test_ex_allocate_pool2_zero_size_allocates_nothing(emu):
    api = make_api(emu)

    chunk = api.ExAllocatePool2(emu, [0x100, 0, 0])

    assert chunk == 0
    assert not emu.pool_allocs


def test_ps_get_current_process_id_returns_active_pid(emu):
    api = make_api(emu)
    emu.process = FakeProcess(pid=0x1234)

    assert api.PsGetCurrentProcessId(emu, []) == 0x1234


def test_ps_get_current_process_id_defaults_to_system_pid(emu):
    api = make_api(emu)
    emu.process = None

    assert api.PsGetCurrentProcessId(emu, []) == 4
