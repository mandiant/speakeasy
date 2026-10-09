"""Faults, non-executable fetch policy and API events stay with the queued run that caused them."""

import pytest
import unicorn as uc

from speakeasy import common
from speakeasy.profiler import Run


@pytest.fixture(params=["dll_emu", "dll64_emu"])
def api_emu(request):
    se = request.getfixturevalue(request.param)
    # The handler fixture loads an image; queued execution also needs its
    # normal DLL container process, without running the fixture's DllMain.
    se.emu.prepare_module_for_emulation(se.emu.modules[0], all_entrypoints=False)
    se.emu.run_queue.clear()
    return se


def queue_run(emu, address, name):
    run = Run()
    run.start_addr = address
    run.type = name
    run.args = []
    emu.add_run(run)
    return run


def return_code(emu, value, *, perms=None):
    address = emu.mem_map(0x1000, tag="fault_regression.anonymous")
    emu.mem_write(address, b"\xb8" + value.to_bytes(4, "little") + b"\xc3")
    if perms is not None:
        emu.mem_protect(address, 0x1000, perms)
    return address


def permissions_at(emu, address):
    return next(perms for start, end, perms in emu.get_mem_regions() if start <= address <= end)


@pytest.mark.parametrize("api_emu", ["dll_emu"], indirect=True)
def test_synthetic_api_nx_fault_never_dispatches_handler(api_emu):
    emu = api_emu.emu
    address = emu.get_proc("kernel32", "GetTickCount")
    hits = []
    api_emu.add_api_hook(lambda e, api, original, args: hits.append(api) or 77, "kernel32", "GetTickCount", argc=0)
    emu.mem_protect(address & ~0xFFF, 0x1000, common.PERM_MEM_READ)
    failed = queue_run(emu, address, "fault_regression.api_nx")
    following = queue_run(emu, return_code(emu, 43), "fault_regression.following")

    emu.start()

    assert hits == []
    assert failed.error is not None
    assert failed.error.type == "invalid_protect_fetch"
    assert failed.error.pc == address
    assert following.error is None
    assert following.ret_val == 43
    assert not permissions_at(emu, address) & uc.UC_PROT_EXEC


@pytest.mark.parametrize("api_emu", ["dll_emu"], indirect=True)
def test_anonymous_nx_is_recovered_by_default(api_emu):
    emu = api_emu.emu
    address = return_code(emu, 77, perms=common.PERM_MEM_READ | common.PERM_MEM_WRITE)
    recovered = queue_run(emu, address, "fault_regression.anonymous_nx")
    following = queue_run(emu, return_code(emu, 44), "fault_regression.following")

    emu.start()

    assert recovered.error is None
    assert recovered.ret_val == 77
    assert following.error is None
    assert following.ret_val == 44
    assert not permissions_at(emu, address) & uc.UC_PROT_EXEC


def api_events(run):
    return [event for event in (run.events or []) if event.event == "api"]


def guest_call(emu, target):
    """A guest caller, including Win64 shadow space, followed by RET."""
    width = emu.get_ptr_size()
    mov = b"\xb8" if width == 4 else b"\x48\xb8"
    code = mov + target.to_bytes(width, "little") + b"\xff\xd0"
    if width == 8:
        code = b"\x48\x83\xec\x28" + code + b"\x48\x83\xc4\x28"
    address = return_code(emu, 0)
    emu.mem_write(address, code + b"\xc3")
    return address


@pytest.mark.parametrize("api_emu", ["dll_emu"], indirect=True)
def test_sp_changing_exit_hook_ends_run_and_successor_owns_its_events(api_emu):
    se = api_emu
    emu = se.emu
    emu.config = emu.config.model_copy(update={"max_instructions": 100})

    def exit_thread(e, api, original, args):
        width = e.get_ptr_size()
        ret = e.get_ret_address()
        sp = e.get_stack_ptr() - width
        e.set_stack_ptr(sp)
        e.mem_write(sp, ret.to_bytes(width, "little"))
        original(args)
        return 77

    se.add_api_hook(exit_thread, "kernel32", "ExitThread", argc=1)
    se.add_api_hook(lambda e, api, original, args: 43, "run_boundary", "Next", argc=0)
    exiting = queue_run(emu, guest_call(emu, emu.get_proc("kernel32", "ExitThread")), "run_boundary.exit")
    following = queue_run(emu, guest_call(emu, emu.get_proc("run_boundary", "Next")), "run_boundary.next")

    emu.start()

    assert exiting.error is None
    assert following.error is None and following.ret_val == 43
    assert [(event.api_name, event.ret_val) for event in api_events(exiting)] == [("kernel32.ExitThread", "0x4d")]
    assert [(event.api_name, event.ret_val) for event in api_events(following)] == [("run_boundary.Next", "0x2b")]
    assert not emu.run_queue
