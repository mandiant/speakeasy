"""Guest callbacks and execution budgets survive deferred API dispatch."""

import struct

import pytest

from speakeasy.profiler import Run
from speakeasy.winenv import arch


@pytest.fixture(params=["dll_emu", "dll64_emu"])
def api_emu(request):
    return request.getfixturevalue(request.param)


def prepare(emu, argc=0):
    emu.curr_run = Run()
    emu.profiler.add_run(emu.curr_run)
    emu.emu_complete = False
    emu.run_complete = False
    emu.set_hooks()
    caller = emu.mem_map(0x1000, tag="test.api.caller")
    emu.mem_write(caller, b"\x90")
    emu.set_func_args(emu.stack_base, caller, *range(argc), conv=arch.CALL_CONV_STDCALL)
    return caller, emu.get_stack_ptr()


@pytest.mark.parametrize("nested", [False, True])
def test_callbacks_restore_original_api_frame(api_emu, nested):
    emu = api_emu.emu
    caller, sp = prepare(emu, argc=2)
    handler = emu.api.load_api_handler("user32")
    callback = emu.mem_map(0x1000, tag="test.callback")
    leaf = callback + 0x100
    emu.mem_write(leaf, b"\xb8\x63\x00\x00\x00" + (b"\xc2\x04\x00" if emu.ptr_size == 4 else b"\xc3"))
    calls = []

    def inner(e, api, original, args):
        calls.append("inner")
        handler.setup_callback(leaf, [3], caller_argv=args)
        return 88

    def outer(e, api, original, args):
        calls.append("outer")
        handler.setup_callback(callback, [1], caller_argv=args)
        handler.setup_callback(leaf, [2], caller_argv=args)
        return 77

    api_emu.add_api_hook(inner, "test_callbacks", "Inner", argc=1)
    api_emu.add_api_hook(outer, "test_callbacks", "Outer", argc=2)
    inner_address = emu.get_proc("test_callbacks", "Inner")
    if not nested:
        code = b"\xb8\x63\x00\x00\x00" + (b"\xc2\x04\x00" if emu.ptr_size == 4 else b"\xc3")
    elif emu.ptr_size == 4:
        code = b"\x6a\x01\xb8" + struct.pack("<I", inner_address) + b"\xff\xd0\xc2\x04\x00"
    else:
        code = b"\x48\x83\xec\x28\xb9\x01\x00\x00\x00\x48\xb8" + struct.pack("<Q", inner_address)
        code += b"\xff\xd0\x48\x83\xc4\x28\xc3"
    emu.mem_write(callback, code)
    stop = emu.add_code_hook(lambda e, a, n: e.emu_eng.stop(), begin=caller, end=caller)
    emu._run_api_engine(emu.get_proc("test_callbacks", "Outer"), timeout=3)
    assert emu.get_pc() == caller
    assert calls == (["outer", "inner"] if nested else ["outer"])
    assert emu.get_return_val() == 77
    assert emu.get_stack_ptr() == sp + emu.ptr_size + (8 if emu.ptr_size == 4 else 0)
    assert emu.curr_run.api_callbacks == []
    stop.disable()


def test_instruction_limit_is_shared_across_api_yields(api_emu):
    emu = api_emu.emu
    caller, _ = prepare(emu)
    hits = []
    api_emu.add_api_hook(lambda e, api, original, args: hits.append(api) or 1, "test_budget", "Tick", argc=0)
    entry = emu.get_proc("test_budget", "Tick")
    code = (b"\xb8" + struct.pack("<I", entry)) if emu.ptr_size == 4 else (b"\x48\xb8" + struct.pack("<Q", entry))
    code += b"\xff\xd0\xeb" + bytes([(-len(code) - 4) & 0xFF])
    emu.mem_write(caller, code)
    emu._run_api_engine(caller, timeout=3, count=17)
    assert len(hits) == 3
    assert emu.curr_run.instr_cnt == 17
    assert emu.curr_run.error.type == "max_instructions"
