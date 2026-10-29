"""The max_instructions limit applies to each queued run; the exit event stops all runs."""

import threading
import time

import pytest
import unicorn as uc

import speakeasy.winenv.arch as arch
from speakeasy import Speakeasy
from speakeasy.engines.start_timer import StartTimer
from speakeasy.engines.unicorn_eng import EmuEngine, get_exception_state_offset, get_tsc_offset_location
from speakeasy.profiler import Run
from speakeasy.windows.winemu import RunLimits, _ExecutionBudget


def test_instruction_limit_stops_spinning_run_and_next_run_executes(config):
    config.update({"timeout": 3, "max_instructions": 1000})
    se = Speakeasy(config=config)
    try:
        # CreateThread(NULL, 0, thread, NULL, 0, NULL); JMP $; thread: MOV EAX,0x2a; RET
        code = b"\x6a\0\x6a\0\x6a\0\x68" + b"\0" * 4 + b"\x6a\0\x6a\0\xb8" + b"\0" * 4 + b"\xff\xd0\xeb\xfe"
        thread = len(code)
        code += b"\xb8\x2a\0\0\0\xc3"
        base = se.load_shellcode(data=code, arch="x86")
        se.mem_write(base + 7, (base + thread).to_bytes(4, "little"))
        se.mem_write(base + 16, se.emu.get_proc("kernel32", "CreateThread").to_bytes(4, "little"))

        se.run_shellcode(base)

        spinning, created = se.get_report().entry_points
        assert spinning.error is not None
        assert spinning.error.type == "max_instructions"
        assert int(spinning.error.pc) == base + thread - 2
        assert created.error is None
        assert created.ret_val == 0x2A
    finally:
        se.shutdown()


def test_exit_event_stops_an_api_loop_as_a_timeout(config, load_test_bin):
    config.update({"timeout": 60, "max_api_count": 10_000_000})
    exit_event = threading.Event()
    se = Speakeasy(config=config, exit_event=exit_event)
    try:
        module = se.load_module(data=load_test_bin("api_loop_x86.exe.xz"))
        calls = []

        def count_ticks(emu, api_name, func, params):
            calls.append(api_name)
            if len(calls) == 100:
                exit_event.set()
            return len(calls)

        se.add_api_hook(count_ticks, "kernel32", "GetTickCount", argc=0)

        se.run_module(module)

        assert exit_event.is_set()
        (entry,) = se.get_report().entry_points
        assert entry.error is not None
        assert entry.error.type == "timeout"
        assert module.base <= int(entry.error.pc) < module.base + module.image_size
    finally:
        se.shutdown()


def test_engine_timeout_stops_a_native_loop():
    eng = EmuEngine()
    eng.init_engine(arch.ARCH_X86, arch.BITS_32)
    eng.mem_map(0x1000, 0x1000)
    eng.mem_write(0x1000, b"\xeb\xfe\xf4")  # jmp $; hlt

    started = time.monotonic()
    eng.start(0x1000, timeout=0.05)
    assert 0.05 <= time.monotonic() - started < 1
    assert eng.reg_read(arch.X86_REG_EIP) == 0x1000

    started = time.monotonic()
    eng.start(0x1002, timeout=10)
    assert time.monotonic() - started < 1


def test_engine_probes_the_cpu_context_before_it_starts():
    # Unicorn stops an instance that runs with a timeout, as timed out, when another
    # instance initializes, so the probes cannot run from a hook.
    get_exception_state_offset.cache_clear()
    get_tsc_offset_location.cache_clear()
    eng = EmuEngine()
    eng.init_engine(arch.ARCH_X86, arch.BITS_64)

    assert get_exception_state_offset.cache_info().currsize == 1
    assert get_tsc_offset_location.cache_info().currsize == 1


def test_start_timer_repeats_a_stop_that_is_lost():
    stopped = threading.Event()
    calls = []

    def lose_the_first_stop():
        calls.append(time.monotonic())
        if len(calls) == 2:
            stopped.set()

    timer = StartTimer(lose_the_first_stop)
    timer.arm(0.01)
    try:
        assert stopped.wait(1)
    finally:
        timer.disarm()


def test_engine_stops_every_start_with_a_short_timeout():
    eng = EmuEngine()
    eng.init_engine(arch.ARCH_X86, arch.BITS_32)
    eng.mem_map(0x1000, 0x1000)
    eng.mem_write(0x1000, b"\xb8\x00\x00\x00\xf0\xff\xd0\xeb\xfe")  # call 0xf0000000; jmp $

    for _ in range(100):
        with pytest.raises(uc.UcError):
            eng.start(0x1000, timeout=0.01)
        eng.start(0x1007, timeout=0.0001)
        assert eng.reg_read(arch.X86_REG_EIP) == 0x1007


def _run_with(elapsed: float = 0.0, instructions: int = 0) -> Run:
    run = Run()
    run.execution_elapsed = elapsed
    run.budget_instructions = instructions
    return run


def test_run_limits_stop_at_the_total_time_when_it_comes_first():
    total = _ExecutionBudget(limit=5, elapsed=5)
    limits = RunLimits.from_run(_run_with(elapsed=1), timeout=60, budget=0, total_budget=total)

    assert limits.deadline_kind == "max_total_time"
    assert limits.is_total_time_reached()
    assert limits.get_reached_limit() == "max_total_time"


def test_run_limits_stop_at_the_run_timeout_when_it_comes_first():
    total = _ExecutionBudget(limit=100)
    limits = RunLimits.from_run(_run_with(elapsed=10), timeout=10, budget=0, total_budget=total)

    assert limits.deadline_kind == "timeout"
    assert not limits.is_total_time_reached()
    assert limits.get_reached_limit() == "timeout"


def test_run_limits_count_the_instructions_that_the_run_already_used():
    limits = RunLimits.from_run(_run_with(instructions=7), timeout=0, budget=10, total_budget=None)

    assert limits.deadline is None
    assert limits.get_native_timeout() == 0
    assert limits.get_native_count() == 3
    assert limits.get_reached_limit() is None
    limits.remaining = 0
    assert limits.get_reached_limit() == "max_instructions"

    unlimited = RunLimits.from_run(_run_with(instructions=7), timeout=0, budget=0, total_budget=None)
    assert unlimited.get_native_count() == 0
    assert unlimited.get_reached_limit() is None
