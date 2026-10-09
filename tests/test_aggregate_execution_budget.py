"""Public aggregate active-time limits, independent of per-Run limits."""

import json
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from speakeasy import Speakeasy
from speakeasy.config import SpeakeasyConfig
from speakeasy.gdb import GdbServer, ResumeAction
from speakeasy.windows import winemu
from speakeasy.windows.api_image import ApiExportSpec
from tests.test_api_image import build, image_bytes


@pytest.fixture
def clock(monkeypatch):
    value = [0.0]
    monkeypatch.setattr(winemu, "time", SimpleNamespace(monotonic=lambda: value[0], time=time.time))
    return value


@pytest.fixture(params=["x86", "amd64"])
def session(request, config):
    config["timeout"] = 10
    config["max_total_time"] = 1
    se = Speakeasy(config=config)
    base = se.load_shellcode(data=b"\xc3", arch=request.param)
    yield se, base
    se.shutdown()


def ticking_api(se, clock, amount):
    def tick(e, api, original, args):
        clock[0] += amount[0]
        return 1

    se.add_api_hook(tick, "aggregate_test", "Tick", argc=0)
    return se.emu.get_proc("aggregate_test", "Tick")


def test_config_policy(config):
    cfg = SpeakeasyConfig.model_validate(config)
    assert cfg.max_total_time == 60
    assert SpeakeasyConfig.model_validate({**config, "timeout": 4}).max_total_time == 60
    assert SpeakeasyConfig.model_validate({**config, "max_total_time": 0}).max_total_time == 0
    for invalid in (-1, float("inf"), float("nan")):
        with pytest.raises(ValidationError):
            SpeakeasyConfig.model_validate({**config, "max_total_time": invalid})
    assert winemu.WindowsEmulator.__doc__


def test_fresh_public_call_after_success_and_exhaustion(session, clock):
    se, base = session
    se.run_shellcode(base)
    amount = [0.6]
    target = ticking_api(se, clock, amount)
    for _ in range(3):
        se.call(target)
        assert se.emu.curr_run.error is None
        assert se.emu.curr_run.execution_elapsed == pytest.approx(0.6)
        assert se.emu._execution_budget is None
    amount[0] = 1.2
    se.call(target)
    assert se.emu.curr_run.error.type == "max_total_time"
    assert not se.emu.run_queue
    assert se.emu._execution_budget is None
    amount[0] = 0.6
    se.call(target)
    assert se.emu.curr_run.error is None


@pytest.mark.parametrize("cap,expected", [(2.5, 3), (0, 11)])
@pytest.mark.parametrize("architecture", [32, 64])
def test_eleven_spinning_exports_share_aggregate(config, clock, cap, expected, architecture, monkeypatch):
    config.update(timeout=1, max_total_time=cap)
    image = build([ApiExportSpec(f"Spin{i:02}") for i in range(11)], architecture)
    raw = bytearray(image_bytes(image))
    for export in image.exports:
        offset = export.address - image.image_base
        raw[offset : offset + 2] = b"\xeb\xfe"
    se = Speakeasy(config=config)
    try:
        module = se.load_module(data=bytes(raw))
        native_start = se.emu.emu_eng.start
        timeouts = []

        def advance(address, timeout=0, count=0):
            timeouts.append(timeout)
            native_start(address, timeout=0.001, count=count)
            clock[0] += timeout

        monkeypatch.setattr(se.emu.emu_eng, "start", advance)
        se.run_module(module, all_entrypoints=True, entry_point=image.exports[0].address - image.image_base)
        runs = se.get_report().entry_points
        assert len(runs) == expected
        assert timeouts == ([1, 1, 0.5] if cap else [1] * 11)
        assert [run.error.type for run in runs] == ["timeout"] * (expected - 1) + [
            "max_total_time" if cap else "timeout"
        ]
        assert not se.emu.run_queue
        assert se.emu._execution_budget is None
    finally:
        se.shutdown()


def test_completion_overhead_does_not_report_unexecuted_successor(config, clock, monkeypatch):
    config.update(timeout=10, max_total_time=1)
    image = build([ApiExportSpec("First"), ApiExportSpec("Second")])
    raw = bytearray(image_bytes(image))
    for export in image.exports:
        raw[export.address - image.image_base] = 0xC3
    se = Speakeasy(config=config)
    try:
        module = se.load_module(data=bytes(raw))
        prepare = se.emu._prepare_run_context

        def prepare_with_overhead(run):
            prepare(run)
            if run.type == "export.Second":
                clock[0] += 1.1

        monkeypatch.setattr(se.emu, "_prepare_run_context", prepare_with_overhead)
        se.run_module(module, all_entrypoints=True, entry_point=image.exports[0].address - image.image_base)
        runs = se.get_report().entry_points
        assert len(runs) == 2
        assert runs[-1].ep_type == "export.First"
        assert runs[-1].error.type == "max_total_time"
        assert len(se.emu.runs) == len(se.emu.profiler.runs) == 2
        assert not se.emu.run_queue
    finally:
        se.shutdown()


@pytest.mark.parametrize("action", [ResumeAction(), ResumeAction(step=True), ResumeAction(detach=True)])
def test_gdb_aggregate_stop_is_terminal_and_pause_is_excluded(session, clock, monkeypatch, action):
    se, base = session
    se.run_shellcode(base)
    target = ticking_api(se, clock, [1.1])
    stops = []
    exits = []
    # Keep the actual debugger stop/begin/finish machinery, replace only transport.
    monkeypatch.setattr(GdbServer, "__enter__", lambda self: self)
    monkeypatch.setattr(GdbServer, "__exit__", lambda self, *args: self.close())

    def commands(debugger, reason=None):
        clock[0] += 50  # Time waiting at a debugger stop must not consume either cap.
        if reason is not None:
            stops.append(reason.kind)
            assert len(stops) == 1, "repeated exhausted T05 stop"
        debugger._stop_pending = False
        return action if reason is not None else ResumeAction()

    monkeypatch.setattr(GdbServer, "command_loop", commands)
    monkeypatch.setattr(GdbServer, "notify_exit", lambda self, code: exits.append(code))
    se.emu.gdb_port = 12345
    se.emu.gdb_host = "127.0.0.1"
    se.call(target)
    assert stops == ["max_total_time"]
    assert exits == ([] if action.detach else [0])
    assert se.emu.curr_run.execution_elapsed == pytest.approx(1.1)
    assert se.emu.curr_run.error.type == "max_total_time"
    assert se.emu._execution_budget is None
    assert not se.emu.run_queue
    se.emu.gdb_port = None
    se.call(base)
    assert se.emu.curr_run.error is None


def test_multiple_backend_starts_share_public_invocation(session, clock, monkeypatch):
    se, base = session
    se.run_shellcode(base)
    target = ticking_api(se, clock, [0.6])
    budgets = []

    def children(**kwargs):
        for _ in range(3):
            budgets.append(se.emu._execution_budget)
            se.emu.call(target)

    monkeypatch.setattr(se.emu, "run_module", children)
    se.run_module(None, emulate_children=True)
    assert all(budget is budgets[0] for budget in budgets)
    assert budgets[0].elapsed == pytest.approx(1.2)
    assert budgets[0].exhausted
    assert se.emu.curr_run.error.type == "max_total_time"
    assert not se.emu.run_queue
    assert se.emu._execution_budget is None
    se.call(base)
    assert se.emu.curr_run.error is None


def test_self_respawning_threads_are_bounded(config, clock):
    config.update(timeout=10, max_total_time=0.75)
    se = Speakeasy(config=config)
    try:
        # CreateThread(NULL,0,this_function,NULL,0,NULL); return.
        code = b"\x6a\0\x6a\0\x6a\0\x68" + b"\0" * 4 + b"\x6a\0\x6a\0\xb8" + b"\0" * 4 + b"\xff\xd0\xc3"
        base = se.load_shellcode(data=code, arch="x86")
        calls = []

        def spawn(e, api, original, args):
            result = original(args)
            calls.append(api)
            clock[0] += 0.25
            return result

        se.add_api_hook(spawn, "kernel32", "CreateThread")
        target = se.emu.get_proc("kernel32", "CreateThread")
        se.mem_write(base + 7, base.to_bytes(4, "little"))
        se.mem_write(base + 16, target.to_bytes(4, "little"))
        se.run_shellcode(base)
        assert calls == ["kernel32.CreateThread"] * 3
        runs = se.get_report().entry_points
        assert len(runs) == 3
        assert [run.error for run in runs[:-1]] == [None, None]
        assert runs[-1].error.type == "max_total_time"
        assert not se.emu.run_queue
        assert not se.emu.suspended_runs
    finally:
        se.shutdown()


def test_public_scope_is_cleared_on_exception(session, monkeypatch):
    se, base = session

    def fail(*args, **kwargs):
        raise RuntimeError("test failure")

    with monkeypatch.context() as patch:
        patch.setattr(se.emu, "run_shellcode", fail)
        with pytest.raises(RuntimeError, match="test failure"):
            se.run_shellcode(base)
    assert se.emu._execution_budget is None
    se.run_shellcode(base)
    assert se.emu.curr_run.error is None


@pytest.mark.parametrize("architecture", ["x86", "amd64"])
def test_native_clock_cap_without_per_run_timeout(config, architecture):
    config.update(timeout=0, max_total_time=0.05)
    # Separate process guard catches an unbounded JIT loop without imposing a
    # fragile elapsed-time assertion on machines running the full suite.
    script = """
import json
import sys
from speakeasy import Speakeasy
se = Speakeasy(config=json.loads(sys.argv[1]))
try:
    base = se.load_shellcode(data=bytes.fromhex("c3ebfe"), arch=sys.argv[2])
    se.run_shellcode(base)
    se.call(base + 1)
    assert se.emu.curr_run.error.type == "max_total_time"
    assert not se.emu.run_queue
    assert se.emu._execution_budget is None
    se.call(base)
    assert se.emu.curr_run.error is None
    assert se.emu._execution_budget is None
finally:
    se.shutdown()
"""
    result = subprocess.run(
        [sys.executable, "-c", script, json.dumps(config), architecture],
        capture_output=True,
        text=True,
        timeout=8,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("debug", [False, True])
@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("after_prepare", [False, True])
def test_canceled_native_dependency_can_initialize_on_fresh_call(
    session, clock, tmp_path, monkeypatch, debug, strict, after_prepare
):
    from tests.test_guest_dependency_loading import make_native_dll

    se, base = session
    se.run_shellcode(base)
    emu = se.emu
    emu.config = emu.config.model_copy(
        update={"modules": emu.config.modules.model_copy(update={"strict_pe_parsing": strict})}
    )
    emu.alloc_peb(emu.curr_process)
    first_path = tmp_path / "first.dll"
    first_exports = make_native_dll(emu, first_path)
    first = emu.load_module_by_name("first", native_path=str(first_path))
    second_path = tmp_path / "second.dll"
    second_exports = make_native_dll(emu, second_path)
    second = emu.load_module_by_name("second", native_path=str(second_path))
    pid = emu.curr_process.id
    exceeded = []

    def expire(e, address, size):
        if address == first_exports["Initializer"] and not exceeded:
            clock[0] += 1.1
            exceeded.append(True)

    if after_prepare:
        prepare = emu._prepare_run_context

        def prepare_with_overhead(run):
            prepare(run)
            if run.start_addr == second_exports["TlsCallback"] and not exceeded:
                clock[0] += 1.1
                exceeded.append(True)

        monkeypatch.setattr(emu, "_prepare_run_context", prepare_with_overhead)
    else:
        se.add_code_hook(expire)
    if debug:
        monkeypatch.setattr(GdbServer, "__enter__", lambda self: self)
        monkeypatch.setattr(GdbServer, "__exit__", lambda self, *args: self.close())

        def commands(debugger, reason=None):
            debugger._stop_pending = False
            return ResumeAction()

        monkeypatch.setattr(GdbServer, "command_loop", commands)
        monkeypatch.setattr(GdbServer, "notify_exit", lambda self, code: None)
        emu.gdb_port, emu.gdb_host = 12345, "127.0.0.1"
    se.call(base)
    assert exceeded
    assert emu.curr_run.error.type == "max_total_time"
    assert first._initialization.get(pid) == (None if strict else "failed")
    assert pid not in second._initialization
    assert all(run.start_addr != second_exports["TlsCallback"] for run in emu.runs)
    assert int.from_bytes(se.mem_read(second_exports["Flag"], 4), "little") == 0
    assert not emu.curr_run.api_callbacks
    emu.gdb_port = None
    se.call(second_exports["GetTickCount"])
    assert emu.curr_run.error is None
    assert emu.curr_run.ret_val == 2
    assert second._initialization[pid] == "ready"
    assert not emu.run_queue


@pytest.mark.parametrize("debug", [False, True])
def test_terminal_cap_rolls_back_runtime_loader_callbacks(session, clock, tmp_path, monkeypatch, debug):
    from tests.test_guest_dependency_loading import make_native_dll

    se, base = session
    se.run_shellcode(base)
    emu = se.emu
    emu.alloc_peb(emu.curr_process)
    path = tmp_path / "guest_dependency.dll"
    exports = make_native_dll(emu, path)
    original = emu.get_native_module_path
    monkeypatch.setattr(
        emu,
        "get_native_module_path",
        lambda mod_name: str(path) if mod_name == "guest_dependency" else original(mod_name),
    )

    def expire(e, address, size):
        if address == exports["Initializer"]:
            clock[0] += 1.1

    se.add_code_hook(expire)
    if debug:
        monkeypatch.setattr(GdbServer, "__enter__", lambda self: self)
        monkeypatch.setattr(GdbServer, "__exit__", lambda self, *args: self.close())

        def commands(debugger, reason=None):
            debugger._stop_pending = False
            return ResumeAction()

        monkeypatch.setattr(GdbServer, "command_loop", commands)
        monkeypatch.setattr(GdbServer, "notify_exit", lambda self, code: None)
        emu.gdb_port, emu.gdb_host = 12345, "127.0.0.1"
    name = se.mem_alloc(0x1000)
    se.mem_write(name, b"guest_dependency.dll\0")
    target = emu.get_proc("kernel32", "LoadLibraryA")
    se.call(target, [name])
    assert emu.curr_run.error.type == "max_total_time"
    assert not emu.curr_run.api_callbacks
    assert emu.get_address_map(exports["Initializer"]) is None
    assert all(module.name != "guest_dependency" for module in emu.modules)
    assert not emu.run_queue
