"""Instruction caps through the public execution and report interfaces."""

import struct

import pytest

from speakeasy import Speakeasy


@pytest.fixture(params=[("x86", False), ("amd64", False), ("x86", True), ("amd64", True)])
def budget_target(request, config):
    architecture, memory_tracing = request.param
    config["analysis"]["memory_tracing"] = memory_tracing
    config["timeout"] = 3
    sessions = []

    def create(budget):
        config["max_instructions"] = budget
        se = Speakeasy(config=config)
        sessions.append(se)
        return se, architecture

    yield create
    for se in sessions:
        se.shutdown()


def assert_limit(se, budget):
    run = se.get_report().entry_points[0]
    assert run.error.type == "max_instructions"
    assert run.error.count == budget
    assert run.instr_count == budget
    return run


@pytest.mark.parametrize("budget", [1, 7, 8, 9, 17])
def test_cap_within_block_and_at_back_edge(budget_target, budget):
    se, architecture = budget_target(budget)
    # Seven NOPs then a jump to the first NOP: eight instructions per cycle.
    base = se.load_shellcode(data=b"\x90" * 7 + b"\xeb\xf7", arch=architecture)
    se.run_shellcode(base)
    run = assert_limit(se, budget)
    assert int(run.error.pc) == base + budget % 8


@pytest.mark.parametrize("budget", [3, 4, 5, 6, 17])
def test_cap_is_shared_across_public_api_yields(budget_target, budget):
    se, architecture = budget_target(budget)
    hits = []
    # MOV target; CALL target; public stub (three x86/two x64 instructions); JMP caller.
    width = 4 if architecture == "x86" else 8
    mov = b"\xb8" if width == 4 else b"\x48\xb8"
    code = mov + b"\0" * width + b"\xff\xd0"
    code += b"\xeb" + bytes([(-len(code) - 2) & 0xFF])
    base = se.load_shellcode(data=code, arch=architecture)
    se.add_api_hook(lambda e, api, original, args: hits.append(api) or 1, "budget_test", "Tick", argc=0)
    target = se.emu.get_proc("budget_test", "Tick")
    se.mem_write(base + len(mov), target.to_bytes(width, "little"))
    se.run_shellcode(base)
    run = assert_limit(se, budget)
    if width == 4:
        calls, pc = {
            3: (0, target + 2),
            4: (0, target + 5),
            5: (0, target),
            6: (1, base),
            17: (2, target),
        }[budget]
    else:
        calls, pc = {
            3: (0, target + 2),
            4: (0, target),
            5: (1, base),
            6: (1, base + len(mov) + width),
            17: (3, target),
        }[budget]
    assert hits == ["budget_test.Tick"] * calls
    events = [event for event in (run.events or []) if event.event == "api"]
    # The report coalesces consecutive identical API events.
    assert bool(events) == bool(calls)
    assert int(run.error.pc) == pc


@pytest.mark.parametrize("budget", [4, 5, 7, 8, 9, 10])
def test_rep_iterations_use_unicorn_instruction_count_semantics(budget_target, budget):
    se, architecture = budget_target(budget)
    # MOV ECX,5; MOV EDI,destination; REP STOSB; NOP; infinite JMP.
    # Unicorn counts each of five writes and the final zero-ECX REP visit.
    code = b"\xb9\x05\0\0\0\xbf\0\0\0\0\xf3\xaa\x90\xeb\xfe"
    base = se.load_shellcode(data=code, arch=architecture)
    destination = se.mem_alloc(0x1000)
    se.mem_write(base + 6, struct.pack("<I", destination))
    se.run_shellcode(base)
    run = assert_limit(se, budget)
    written = min(max(budget - 2, 0), 5)
    assert se.reg_read("ecx") == 5 - written
    assert se.reg_read("edi") == destination + written
    expected_offset = 10 if budget < 8 else (12 if budget == 8 else 13)
    assert int(run.error.pc) == base + expected_offset


def test_each_public_run_has_a_fresh_run_budget(budget_target):
    se, architecture = budget_target(1)
    base = se.load_shellcode(data=b"\x90\xc3", arch=architecture)
    se.run_shellcode(base)
    se.run_shellcode(base)
    runs = se.get_report().entry_points
    assert len(runs) == 2
    for run in runs:
        assert run.error.type == "max_instructions"
        assert run.error.count == run.instr_count == 1
        assert int(run.error.pc) == base + 1


@pytest.mark.parametrize("budget", [5, 6, 7])
def test_callback_return_is_finalized_at_exact_cap(budget_target, budget):
    se, architecture = budget_target(budget)
    width = 4 if architecture == "x86" else 8
    mov = b"\xb8" if width == 4 else b"\x48\xb8"
    code = mov + b"\0" * width + b"\xff\xd0\xeb\xfe"
    base = se.load_shellcode(data=code, arch=architecture)
    callback = se.mem_alloc(0x1000)
    se.mem_write(callback, b"\xb8\x2a\0\0\0\xc3")
    handler = se.emu.api.load_api_handler("user32")
    hits = []

    def outer(e, api, original, args):
        hits.append(api)
        handler.setup_callback(callback, [], caller_argv=args)
        return 77

    se.add_api_hook(outer, "budget_test", "Outer", argc=0)
    target = se.emu.get_proc("budget_test", "Outer")
    se.mem_write(base + len(mov), target.to_bytes(width, "little"))
    se.run_shellcode(base)
    run = assert_limit(se, budget)
    dispatch_count = 5 if width == 4 else 4
    if budget == dispatch_count:
        assert hits == []
        assert se.reg_read("eax") == target
        expected_pc = target
    else:
        assert hits == ["budget_test.Outer"]
        before_return = budget == dispatch_count + 1
        assert se.reg_read("eax") == (42 if before_return else 77)
        expected_pc = callback + 5 if before_return else base + len(mov) + width + 2
    assert int(run.error.pc) == expected_pc
