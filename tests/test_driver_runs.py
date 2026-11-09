"""The runs that the kernel emulator gives a driver, and the IRPs that it sends to the dispatch routines."""

from types import SimpleNamespace
from typing import Any

import pytest

import speakeasy.winenv.defs.nt.ntoskrnl as ntdefs
from speakeasy import Speakeasy
from speakeasy.profiler import Run
from speakeasy.report import EntryPointType
from speakeasy.windows.kernel import DISPATCH_IOCTL
from speakeasy.winenv.defs.nt import ddk


@pytest.fixture(params=["x86", "x64"])
def any_driver_emu(request: pytest.FixtureRequest) -> Speakeasy:
    se: Speakeasy = request.getfixturevalue("driver_emu" if request.param == "x86" else "driver64_emu")
    return se


def current_stack_location(se: Speakeasy, irp_addr: int) -> Any:
    """Read the stack location that IoGetCurrentIrpStackLocation gives the driver."""
    size = se.emu.get_ptr_size()
    irp: Any = ntdefs.IRP(size)
    irp.cast(se.mem_read(irp_addr, irp.sizeof()))
    ios: Any = ntdefs.IO_STACK_LOCATION(size)
    ios.cast(se.mem_read(irp.Tail.Overlay.CurrentStackLocation, ios.sizeof()))
    return ios


@pytest.mark.parametrize(
    "major",
    [
        ddk.IRP_MJ_CREATE,
        ddk.IRP_MJ_DEVICE_CONTROL,
        ddk.IRP_MJ_READ,
        ddk.IRP_MJ_WRITE,
        ddk.IRP_MJ_CLOSE,
        ddk.IRP_MJ_CLEANUP,
    ],
)
def test_the_current_stack_location_of_a_dispatch_irp_has_the_request(any_driver_emu: Speakeasy, major: int) -> None:
    dev = SimpleNamespace(address=0x7000)
    irp = any_driver_emu.emu.new_dispatch_irp(major, dev)

    ios = current_stack_location(any_driver_emu, irp.address)

    assert (ios.MajorFunction, ios.DeviceObject) == (major, dev.address)
    if major == ddk.IRP_MJ_DEVICE_CONTROL:
        assert ios.Parameters.DeviceIoControl.IoControlCode == DISPATCH_IOCTL


def test_each_run_starts_at_passive_level(any_driver_emu: Speakeasy) -> None:
    emu = any_driver_emu.emu
    address = emu.mem_map(0x1000, tag="driver_runs.code")
    emu.mem_write(address, b"\xc3")
    run = Run()
    run.type = EntryPointType.CALL
    run.start_addr = address
    run.args = []
    emu.add_run(run)
    emu.set_current_irql(ddk.DISPATCH_LEVEL)
    seen = []
    any_driver_emu.add_code_hook(lambda e, a, s: seen.append(emu.get_current_irql()), begin=address, end=address)

    emu.start()

    assert seen == [ddk.PASSIVE_LEVEL]
