"""The runs that the kernel emulator gives a driver, and the IRPs that it sends to the dispatch routines."""

from types import SimpleNamespace
from typing import Any

import pytest

import speakeasy.winenv.defs.nt.ntoskrnl as ntdefs
from speakeasy import Speakeasy
from speakeasy.profiler import Run
from speakeasy.report import EntryPointType, ErrorInfo, ErrorType
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


def fake_driver(*, exports=(), majors=(), unload=0):
    """A driver object with ``exports`` (names), handlers for ``majors``, one device, and an unload routine."""
    mj_funcs = [0] * (ddk.IRP_MJ_MAXIMUM_FUNCTION + 1)
    for i, major in enumerate(majors):
        mj_funcs[major] = 0x5000 + i
    pe = SimpleNamespace(
        get_exports=lambda: [SimpleNamespace(name=name, address=0x4000 + i) for i, name in enumerate(exports)]
    )
    return SimpleNamespace(
        address=0x3000, pe=pe, devices=[SimpleNamespace(address=0x7000)], mj_funcs=mj_funcs, on_unload=unload
    )


def driver_entry(return_value: int, error: str | None = None) -> Run:
    run = Run()
    run.type = EntryPointType.DRIVER_ENTRY
    run.return_value = return_value
    if error is not None:
        run.error = ErrorInfo(type=ErrorType(error))
    return run


def planned(emu) -> list[tuple[str, str | None]]:
    return [(run.type.value, run.name) for run in emu.run_queue]


@pytest.fixture
def plan_emu(driver_emu: Speakeasy):
    emu = driver_emu.emu
    emu.all_entrypoints = True
    emu.run_queue.clear()
    return emu


def test_after_driver_entry_the_exports_then_the_irp_handlers_then_unload_run(plan_emu) -> None:
    drv = fake_driver(exports=["a", "b"], majors=[ddk.IRP_MJ_CLOSE, ddk.IRP_MJ_CREATE], unload=0x6000)

    plan_emu._queue_driver_routines(drv, driver_entry(0))

    assert planned(plan_emu) == [
        ("export", "a"),
        ("export", "b"),
        ("irp", "IRP_MJ_CREATE"),
        ("irp", "IRP_MJ_CLOSE"),
        ("driver_unload", None),
    ]


def test_the_exports_run_when_the_driver_has_no_irp_handler_and_no_unload_routine(plan_emu) -> None:
    plan_emu._queue_driver_routines(fake_driver(exports=["a"]), driver_entry(0))

    assert planned(plan_emu) == [("export", "a")]


def test_a_driver_entry_that_returns_an_error_status_ends_the_driver(plan_emu) -> None:
    drv = fake_driver(exports=["a"], majors=[ddk.IRP_MJ_CREATE], unload=0x6000)

    plan_emu._queue_driver_routines(drv, driver_entry(0xC0000001))

    assert planned(plan_emu) == []


def test_a_driver_entry_that_ends_with_an_emulator_error_does_not_end_the_driver(plan_emu) -> None:
    drv = fake_driver(majors=[ddk.IRP_MJ_CREATE], unload=0x6000)

    plan_emu._queue_driver_routines(drv, driver_entry(0xC0000001, error="unsupported_api"))

    assert planned(plan_emu) == [("irp", "IRP_MJ_CREATE"), ("driver_unload", None)]


def test_without_all_entrypoints_only_driver_entry_runs(plan_emu) -> None:
    plan_emu.all_entrypoints = False

    plan_emu._queue_driver_routines(fake_driver(exports=["a"], unload=0x6000), driver_entry(0))

    assert planned(plan_emu) == []
