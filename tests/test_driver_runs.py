"""The runs that the kernel emulator gives a driver, and the IRPs that it sends to the dispatch routines."""

from types import SimpleNamespace
from typing import Any

import pytest

import speakeasy.winenv.defs.nt.ntoskrnl as ntdefs
from speakeasy import Speakeasy
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
