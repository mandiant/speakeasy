"""Public call budgets, unknown API policy, and malformed user-hook returns."""

import time
from types import SimpleNamespace

import pytest

from speakeasy import Speakeasy
from speakeasy.windows import winemu
from speakeasy.winenv.api import sigdb


@pytest.fixture(params=["x86", "amd64"])
def public_session(request, config):
    config["timeout"] = 1
    config["modules"]["functions_always_exist"] = (
        request.getfixturevalue("always_exist") if "always_exist" in request.fixturenames else True
    )
    # Bound a broken hook redispatch loop without making runner time a test input.
    config["max_instructions"] = 100
    se = Speakeasy(config=config)
    try:
        base = se.load_shellcode(data=b"\xc3", arch=request.param)
        se.run_shellcode(base)
        assert se.get_report().entry_points[0].error is None
        assert se.emu.get_current_process() is not None
        yield se
    finally:
        se.shutdown()


def api_events(run):
    return [event for event in (run.events or []) if event.event == "api"]


def test_public_call_timeout_is_per_fresh_run(public_session, monkeypatch):
    se = public_session
    emu = se.emu
    clock = [0.0]
    runs = []

    def handler(e, api, original, args):
        assert api == "public_timeout.Tick"
        assert original is None and args == []
        assert e.curr_run.execution_elapsed == 0.0
        runs.append(e.curr_run)
        clock[0] += 0.6
        return 77

    se.add_api_hook(handler, "public_timeout", "Tick", argc=0)
    target = emu.get_proc("public_timeout", "Tick")
    # Replace only winemu's binding; patching time.monotonic globally breaks
    # pytest/Unicorn clocks and would make this regression runner-dependent.
    monkeypatch.setattr(winemu, "time", SimpleNamespace(monotonic=lambda: clock[0], time=time.time))
    for _ in range(3):
        se.call(target)
        assert se.reg_read("eax") == 77
        assert emu.curr_run.error is None
        assert emu.curr_run.execution_elapsed == pytest.approx(0.6)
    assert len(runs) == 3 and len({id(run) for run in runs}) == 3
    assert clock[0] == pytest.approx(1.8)
    assert sum(run.execution_elapsed for run in runs) > emu.config.timeout
    entries = se.get_report().entry_points
    assert len(entries) == 4  # shellcode bootstrap plus three public calls
    for entry in entries[1:]:
        assert entry.error is None
        events = api_events(entry)
        assert len(events) == 1
        assert events[0].api_name == "public_timeout.Tick"
        assert events[0].ret_val == "0x4d"


@pytest.mark.parametrize("always_exist", [False, True])
def test_unknown_api_scalar_fallback_is_win64_only(public_session, always_exist):
    se = public_session
    emu = se.emu
    dll, name = "public_unknown", "OpaqueFunction"
    assert emu.get_signature_db().lookup_exact(dll, name, emu._get_signature_arch()) is None
    target = emu.get_proc(dll, name)
    before = se.get_symbols()[target]
    # Opaque arguments must not require guessing argc or decoding guest memory.
    se.call(target, params=[0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
    run = se.get_report().entry_points[-1]
    events = api_events(run)
    assert len(events) == 1 and events[0].api_name == f"{dll}.{name}"
    assert events[0].args == []
    assert se.get_symbols()[target] == before == (dll, name)
    if emu.get_ptr_size() == 8 and always_exist:
        assert run.error is None
        assert events[0].ret_val == "0x1"
        assert se.reg_read("eax") == 1
        assert emu.get_pc() == emu.return_hook
    else:
        assert run.error is not None and run.error.type == "unsupported_api"
        assert run.error.api_name == f"{dll}.{name}"
        assert events[0].ret_val is None


class UnsafeDeclarationSource(sigdb.SignatureSource):
    name = "regression"

    def __init__(self, declaration):
        self.declaration = declaration

    @property
    def available(self):
        return True

    def lookup(self, dll, func, architecture):
        declaration = self.declaration
        if dll == declaration.dll and func == declaration.name and declaration.supports_arch(architecture):
            return declaration
        return None


@pytest.mark.parametrize(
    "return_type, parameter_type",
    [("f64", None), ("u32", "f32"), ("st:PAIR:16", None), ("u32", "st:PAIR:16")],
    ids=["float-return", "float-argument", "aggregate-return", "aggregate-argument"],
)
def test_known_unsafe_declaration_cannot_be_stubbed(public_session, monkeypatch, return_type, parameter_type):
    se = public_session
    emu = se.emu
    dll, name = "public_unsafe", "RequiresExplicitHandler"
    declaration = sigdb.FuncSig(
        dll=dll,
        name=name,
        ret=return_type,
        params=() if parameter_type is None else (sigdb.ParamSig("value", parameter_type),),
    )
    database = sigdb.SignatureDatabase([UnsafeDeclarationSource(declaration)])
    monkeypatch.setattr(emu, "get_signature_db", lambda: database)
    assert database.lookup_exact(dll, name, emu._get_signature_arch()) is declaration
    assert not declaration.supports_emulation(emu.get_ptr_size())
    target = emu.get_proc(dll, name)
    se.call(target, params=[] if parameter_type is None else [0])
    run = se.get_report().entry_points[-1]
    assert run.error is not None and run.error.type == "unsupported_api"
    assert run.error.api_name == f"{dll}.{name}"
    events = api_events(run)
    assert len(events) == 1 and events[0].api_name == f"{dll}.{name}"
    assert events[0].ret_val is None


@pytest.mark.parametrize("handled", [False, True], ids=["hook-only", "handled-api"])
def test_sp_changing_hook_faults_once_without_redispatch(public_session, handled):
    se = public_session
    emu = se.emu
    dll, name = ("kernel32", "GetTickCount") if handled else ("public_sp_hook", "BadReturn")
    hits = []

    def handler(e, api, original, args):
        hits.append(api)
        assert bool(original) == handled
        assert args == []
        original_return = e.get_ret_address()
        new_sp = e.get_stack_ptr() - e.get_ptr_size()
        e.set_stack_ptr(new_sp)
        # Keep the return target valid: this must report the malformed handler,
        # rather than merely falling through to an unrelated memory fault.
        e.mem_write(new_sp, original_return.to_bytes(e.get_ptr_size(), "little"))
        return 77

    se.add_api_hook(handler, dll, name, argc=0)
    target = emu.get_proc(dll, name)
    se.call(target)
    run = se.get_report().entry_points[-1]
    assert hits == [f"{dll}.{name}"]
    assert run.error is not None and run.error.type == "api_handler_did_not_return"
    events = api_events(run)
    assert len(events) == 1
    assert events[0].api_name == f"{dll}.{name}"
    assert events[0].ret_val == "0x4d"
