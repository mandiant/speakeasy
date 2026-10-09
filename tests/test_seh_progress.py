"""SEH replay guards distinguish handler execution from resumed guest progress."""

import struct
from types import SimpleNamespace

import pytest

from speakeasy.profiler import Run
from speakeasy.winenv import arch


@pytest.fixture
def seh_emu(dll_emu):
    emu = dll_emu.emu
    emu.prepare_module_for_emulation(emu.modules[0], all_entrypoints=False)
    emu.run_queue.clear()
    return emu


def dword(value):
    return struct.pack("<I", value)


def guest(seh_emu, *, repair=False, skip=False, change_address=False, iterations=8):
    emu = seh_emu
    code = emu.mem_map(0x1000, tag="seh_progress.code")
    data = emu.mem_map(0x1000, tag="seh_progress.data")
    handler = code + 0x100
    bad = 0x60000000
    assert emu.get_address_map(bad) is None
    # Install an independent registration, then repeatedly read an unmapped page.
    registration = data + 0x100
    emu.mem_write(registration, dword(0xFFFFFFFF) + dword(handler))
    setup = b"\xc7\x05" + dword(emu.fs_addr) + dword(registration) + b"\xb9" + dword(iterations)
    loop = code + len(setup)
    fault_pc = loop + 5
    body = b"\xb8" + dword(bad) + b"\x8b\x00\xe2\xf7"
    # Clear the registration and return a recognizable value.
    finish = b"\xc7\x05" + dword(emu.fs_addr) + dword(0) + b"\xb8" + dword(42) + b"\xc3"
    emu.mem_write(code, setup + body + finish)
    # Handler instructions must not count as progress at the fault site.
    handler_code = b"\xff\x05" + dword(data) + b"\x90" * 16
    if repair or skip:
        # Third handler argument is CONTEXT*. EAX=0xb0, EIP=0xb8 on x86.
        context = emu.wintypes.CONTEXT(4)
        offset = 0xB8 if skip else 0xB0
        assert context.get_field_name(offset) == ("Eip" if skip else "Eax")
        value = fault_pc + 2 if skip else data + 4
        handler_code += b"\x8b\x4c\x24\x0c\xc7\x81" + dword(offset) + dword(value)
    if change_address:
        # Change the fault address on the first three continuations, without
        # allowing the faulting instruction to complete at any point.
        handler_code += b"\x8b\x4c\x24\x0c\x83\x3d" + dword(data) + b"\x03\x77\x0a"
        handler_code += b"\x81\xb1" + dword(0xB0) + dword(0x1000)
    handler_code += b"\x31\xc0\xc3"
    emu.mem_write(handler, handler_code)
    return code, data, fault_pc, bad


def queue(emu, code, name):
    run = Run()
    run.start_addr = code
    run.type = name
    run.args = []
    run.thread = emu.curr_thread
    emu.add_run(run)
    return run


def observe_faults(emu, monkeypatch):
    faults = []
    dispatch = emu.dispatch_seh

    def observed(code, faulting_address=None):
        result = dispatch(code, faulting_address)
        faults.append((emu.curr_run, emu._seh_last_fault, emu._seh_repeat_count, result))
        return result

    monkeypatch.setattr(emu, "dispatch_seh", observed)
    return faults


def test_same_fault_stops_after_three_guest_handlers(seh_emu, monkeypatch):
    code, counter, pc, bad = guest(seh_emu)
    faults = observe_faults(seh_emu, monkeypatch)
    run = queue(seh_emu, code, "seh_progress.no_progress")

    seh_emu.start()

    assert run.error.type == "invalid_read"
    assert run.error.pc == pc
    assert int.from_bytes(seh_emu.mem_read(counter, 4), "little") == 3
    assert [(key, count, handled) for _, key, count, handled in faults] == [
        ((pc, bad), count, count < 4) for count in range(1, 5)
    ]


@pytest.mark.parametrize("skip", [False, True], ids=["repair_register", "change_pc"])
def test_guest_progress_allows_repeated_fault_site(seh_emu, monkeypatch, skip):
    code, counter, pc, bad = guest(seh_emu, repair=True, skip=skip)
    faults = observe_faults(seh_emu, monkeypatch)
    run = queue(seh_emu, code, "seh_progress.repaired")

    seh_emu.start()

    assert run.error is None
    assert run.ret_val == 42
    assert int.from_bytes(seh_emu.mem_read(counter, 4), "little") == 8
    assert [(key, count, handled) for _, key, count, handled in faults] == [((pc, bad), 1, True)] * 8
    assert seh_emu._seh_last_fault is None
    assert seh_emu._seh_repeat_count == 0
    assert seh_emu._seh_resume_pc is None


def test_queued_runs_reset_replay_guard(seh_emu, monkeypatch):
    code, counter, pc, bad = guest(seh_emu)
    faults = observe_faults(seh_emu, monkeypatch)
    runs = [queue(seh_emu, code, f"seh_progress.queued_{index}") for index in range(2)]

    seh_emu.start()

    assert int.from_bytes(seh_emu.mem_read(counter, 4), "little") == 6
    for run in runs:
        assert run.error.type == "invalid_read"
        assert run.error.pc == pc
        assert [(key, count, handled) for owner, key, count, handled in faults if owner is run] == [
            ((pc, bad), count, count < 4) for count in range(1, 5)
        ]
    assert not seh_emu.run_queue


def test_fresh_public_calls_reset_terminal_guard(seh_emu, monkeypatch):
    code, counter, pc, bad = guest(seh_emu)
    faults = observe_faults(seh_emu, monkeypatch)

    for _ in range(2):
        seh_emu.call(code)
        assert seh_emu.curr_run.error.type == "invalid_read"
        assert seh_emu.curr_run.error.pc == pc

    assert int.from_bytes(seh_emu.mem_read(counter, 4), "little") == 6
    assert [(key, count, handled) for _, key, count, handled in faults] == [
        ((pc, bad), count, count < 4) for count in range(1, 5)
    ] * 2


def test_changed_fault_address_resets_guard_without_guest_progress(seh_emu, monkeypatch):
    code, counter, pc, bad = guest(seh_emu, change_address=True)
    faults = observe_faults(seh_emu, monkeypatch)
    run = queue(seh_emu, code, "seh_progress.changed_address")

    seh_emu.start()

    assert run.error.type == "invalid_read"
    assert run.error.pc == pc
    assert int.from_bytes(seh_emu.mem_read(counter, 4), "little") == 6
    assert [(key, count, handled) for _, key, count, handled in faults] == [
        ((pc, bad), 1, True),
        ((pc, bad ^ 0x1000), 1, True),
        ((pc, bad), 1, True),
        *[((pc, bad ^ 0x1000), count, count < 4) for count in range(1, 5)],
    ]


def test_filter_and_handler_transfers_preserve_guard(seh_emu):
    code, _, pc, bad = guest(seh_emu)
    run = queue(seh_emu, code, "seh_progress.scope_transfers")
    seh_emu._prepare_run_context(run)
    seh_emu._seh_last_fault = (pc, bad)
    seh_emu._seh_repeat_count = 3
    seh = seh_emu.curr_thread.seh
    seh.set_context(seh_emu.get_thread_context())
    scope = SimpleNamespace(
        record=SimpleNamespace(FilterFunc=code + 0x200, HandlerAddress=code + 0x300),
        filter_called=False,
        handler_called=False,
    )
    seh.frames = [SimpleNamespace(searched=False, scope_records=[scope])]
    for target in (scope.record.FilterFunc, scope.record.HandlerAddress):
        seh_emu.reg_write(arch.X86_REG_EAX, 1)
        seh_emu.continue_seh()
        assert seh_emu.get_pc() == target
        assert seh_emu._seh_resume_pc is None
        assert seh_emu._hook_code_core(seh_emu, target, 1)
        assert seh_emu._seh_last_fault == (pc, bad)
        assert seh_emu._seh_repeat_count == 3


def test_cleanup_failure_keeps_resumed_instruction_hook(seh_emu, monkeypatch):
    code, _, pc, bad = guest(seh_emu)
    seh_emu._prepare_run_context(queue(seh_emu, code, "seh_progress.cleanup"))
    seh_emu._seh_last_fault = (pc, bad)
    seh_emu._seh_repeat_count = 3
    seh_emu._seh_resume_pc = pc
    seh_emu.tmp_maps = [(bad, 0x1000)]
    seh_emu.enable_code_hook()

    def failed_unmap(base, size):
        raise RuntimeError("injected cleanup failure")

    monkeypatch.setattr(seh_emu, "mem_unmap", failed_unmap)
    assert seh_emu._hook_code_core(seh_emu, pc, 2)
    assert seh_emu.tmp_code_hook.enabled
    assert seh_emu._seh_repeat_count == 3
    assert seh_emu._seh_resume_pc == pc
    assert seh_emu._hook_code_core(seh_emu, pc + 2, 2)
    assert seh_emu._seh_last_fault is None
    assert seh_emu._seh_repeat_count == 0
    assert seh_emu._seh_resume_pc is None
