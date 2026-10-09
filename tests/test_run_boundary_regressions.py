"""Queued execution and legitimate hook continuations retain their run owner."""

import time
from types import SimpleNamespace

import pytest

from speakeasy.windows import winemu
from tests.test_fault_run_ownership import api_emu as api_emu
from tests.test_fault_run_ownership import queue_run, return_code
from tests.test_public_api_regressions import api_events
from tests.test_public_api_regressions import public_session as public_session


def guest_call(emu, target, *, result=None):
    """A real guest caller, including Win64 shadow space, followed by RET."""
    width = emu.get_ptr_size()
    mov = b"\xb8" if width == 4 else b"\x48\xb8"
    code = mov + target.to_bytes(width, "little") + b"\xff\xd0"
    if width == 8:
        code = b"\x48\x83\xec\x28" + code + b"\x48\x83\xc4\x28"
    if result is not None:
        code += b"\xb8" + result.to_bytes(4, "little")
    address = return_code(emu, 0)
    emu.mem_write(address, code + b"\xc3")
    return address


def shift_hook_stack(emu):
    """Keep a valid return address while a terminating hook changes SP."""
    width = emu.get_ptr_size()
    ret = emu.get_ret_address()
    sp = emu.get_stack_ptr() - width
    emu.set_stack_ptr(sp)
    emu.mem_write(sp, ret.to_bytes(width, "little"))


def test_queued_run_elapsed_is_charged_to_origin_after_replacement(api_emu, monkeypatch):
    se = api_emu
    emu = se.emu
    emu.config = emu.config.model_copy(update={"timeout": 1, "max_instructions": 100})
    clock = [0.0]
    hits = []

    def tick(e, api, original, args):
        assert original is None and args == []
        # This handler is reached through guest CALL and a private API yield.
        # A previous run's finally must not consume this run's fresh budget.
        assert e.curr_run.execution_elapsed == 0.0
        hits.append(e.curr_run)
        clock[0] += 0.6
        return 77

    se.add_api_hook(tick, "run_boundary", "Tick", argc=0)
    target = emu.get_proc("run_boundary", "Tick")
    first = queue_run(emu, guest_call(emu, target), "run_boundary.first")
    following = queue_run(emu, guest_call(emu, target), "run_boundary.following")
    starts = []

    def observe_start(e, address, size):
        starts.append(e.curr_run)
        assert e.curr_run is following
        assert following.execution_elapsed == 0.0
        # The preceding engine invocation has already left its finally.
        assert first.execution_elapsed == pytest.approx(0.6)

    emu.add_code_hook(observe_start, begin=following.start_addr, end=following.start_addr)
    # Patch this module binding only, leaving pytest and Unicorn clocks alone.
    monkeypatch.setattr(winemu, "time", SimpleNamespace(monotonic=lambda: clock[0], time=time.time))

    emu.start()

    assert hits == [first, following]
    assert starts == [following]
    assert clock[0] == pytest.approx(1.2)
    assert sum(run.execution_elapsed for run in (first, following)) > emu.config.timeout
    for run in (first, following):
        assert run.error is None
        assert run.ret_val == 77
        assert run.execution_elapsed == pytest.approx(0.6)
        events = api_events(run)
        assert len(events) == 1
        assert events[0].api_name == "run_boundary.Tick"
        assert events[0].ret_val == "0x4d"
    assert not emu.run_queue


def test_sp_changing_exit_hook_completes_public_run(public_session):
    se = public_session
    hits = []

    def terminate(e, api, original, args):
        hits.append(api)
        assert args == [0] and original is not None
        shift_hook_stack(e)
        # Exercise the real ExitThread lifecycle without changing PC or
        # fabricating guard state. Completion must exempt this changed SP.
        original(args)
        return 77

    se.add_api_hook(terminate, "kernel32", "ExitThread", argc=1)
    se.call(se.emu.get_proc("kernel32", "ExitThread"), params=[0])

    run = se.get_report().entry_points[-1]
    assert hits == ["kernel32.ExitThread"]
    assert run.error is None
    events = api_events(run)
    assert len(events) == 1
    assert events[0].api_name == "kernel32.ExitThread"
    assert events[0].ret_val == "0x4d"


def test_sp_changing_hook_run_replacement_preserves_api_ownership(api_emu):
    se = api_emu
    emu = se.emu
    emu.config = emu.config.model_copy(update={"max_instructions": 100})
    hits = []

    def finish(e, api, original, args):
        hits.append(e.curr_run)
        assert original is not None and args == []
        shift_hook_stack(e)
        e.reg_write("eax", 77)
        # A terminating hook advances the actual queue during dispatch; the
        # event recorded after it returns still belongs to the completed run.
        e.on_run_complete()
        return 88

    def next_api(e, api, original, args):
        hits.append(e.curr_run)
        return 43

    se.add_api_hook(finish, "kernel32", "GetTickCount", argc=0)
    se.add_api_hook(next_api, "run_boundary", "Next", argc=0)
    first_address = guest_call(emu, emu.get_proc("kernel32", "GetTickCount"), result=0xDEAD)
    next_address = guest_call(emu, emu.get_proc("run_boundary", "Next"))
    first = queue_run(emu, first_address, "run_boundary.terminated")
    following = queue_run(emu, next_address, "run_boundary.replacement")

    emu.start()

    assert hits == [first, following]
    assert first.error is None and first.ret_val == 77  # Caller tail was abandoned.
    assert following.error is None and following.ret_val == 43
    first_events = api_events(first)
    next_events = api_events(following)
    assert len(first_events) == len(next_events) == 1
    assert first_events[0].api_name == "kernel32.GetTickCount"
    assert first_events[0].ret_val == "0x58"
    assert next_events[0].api_name == "run_boundary.Next"
    assert next_events[0].ret_val == "0x2b"
    assert not emu.run_queue


def test_sp_changing_hook_runs_deferred_guest_callbacks(public_session):
    se = public_session
    emu = se.emu
    width = emu.get_ptr_size()
    counter = se.mem_alloc(0x1000)
    callback = se.mem_alloc(0x1000)
    # Each actual callback adds its argument to guest memory. Its return 99
    # must be replaced with the outer API result after both callbacks finish.
    if width == 4:
        code = b"\x8b\x4c\x24\x04\xb8" + counter.to_bytes(width, "little")
        code += b"\x01\x08\xb8\x63\0\0\0\xc2\x04\0"
    else:
        code = b"\x48\xb8" + counter.to_bytes(width, "little")
        code += b"\x01\x08\xb8\x63\0\0\0\xc3"
    se.mem_write(counter, b"\0" * 4)
    se.mem_write(callback, code)
    handler = emu.api.load_api_handler("user32")
    hits = []
    owners = []

    def outer(e, api, original, args):
        hits.append(api)
        sp = e.get_stack_ptr()
        handler.setup_callback(callback, [3], caller_argv=args)
        handler.setup_callback(callback, [5], caller_argv=args)
        assert e.get_stack_ptr() != sp
        owners.append(e.curr_run)
        return 77

    se.add_api_hook(outer, "run_boundary", "Callbacks", argc=0)
    caller = guest_call(emu, emu.get_proc("run_boundary", "Callbacks"))
    se.call(caller)

    run = owners[0]
    assert hits == ["run_boundary.Callbacks"]
    assert run.error is None and run.ret_val == 77
    assert se.mem_read(counter, 4) == (8).to_bytes(4, "little")
    assert run.api_callbacks == []
    events = api_events(run)
    assert len(events) == 1
    assert events[0].api_name == "run_boundary.Callbacks"
    assert events[0].ret_val == "0x4d"
