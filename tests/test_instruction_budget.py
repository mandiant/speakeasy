"""The max_instructions cap through the public execution and report interfaces."""

import struct

import pytest

from speakeasy import Speakeasy


@pytest.fixture
def capped_session(config):
    config["timeout"] = 3
    sessions = []

    def create(budget, memory_tracing=False):
        config["max_instructions"] = budget
        config["analysis"]["memory_tracing"] = memory_tracing
        se = Speakeasy(config=config)
        sessions.append(se)
        return se

    yield create
    for se in sessions:
        se.shutdown()


def assert_limit(run, budget):
    assert run.error.type == "max_instructions"
    assert run.error.count == budget
    assert run.instr_count == budget


@pytest.mark.parametrize("memory_tracing", [False, True])
@pytest.mark.parametrize("budget", [8, 17])
def test_cap_stops_loop_at_exact_instruction(capped_session, budget, memory_tracing):
    se = capped_session(budget, memory_tracing)
    # Seven NOPs then a jump to the first NOP: eight instructions per cycle.
    base = se.load_shellcode(data=b"\x90" * 7 + b"\xeb\xf7", arch="x86")
    se.run_shellcode(base)
    run = se.get_report().entry_points[0]
    assert_limit(run, budget)
    assert int(run.error.pc) == base + budget % 8


def test_cap_counts_each_rep_iteration(capped_session):
    se = capped_session(4)
    # MOV ECX,5; MOV EDI,destination; REP STOSB; NOP; JMP $
    code = b"\xb9\x05\0\0\0\xbf\0\0\0\0\xf3\xaa\x90\xeb\xfe"
    base = se.load_shellcode(data=code, arch="x86")
    destination = se.mem_alloc(0x1000)
    se.mem_write(base + 6, struct.pack("<I", destination))
    se.run_shellcode(base)
    run = se.get_report().entry_points[0]
    assert_limit(run, 4)
    assert se.reg_read("ecx") == 3
    assert se.reg_read("edi") == destination + 2
    assert int(run.error.pc) == base + 10


def test_cap_is_shared_across_api_calls(capped_session):
    se = capped_session(40)
    hits = []
    # MOV EAX,target; CALL EAX; JMP back to MOV
    code = b"\xb8\0\0\0\0\xff\xd0\xeb\xf7"
    base = se.load_shellcode(data=code, arch="x86")
    se.add_api_hook(lambda e, api, original, args: hits.append(api) or 1, "budget_test", "Tick", argc=0)
    se.mem_write(base + 1, se.emu.get_proc("budget_test", "Tick").to_bytes(4, "little"))
    se.run_shellcode(base)
    run = se.get_report().entry_points[0]
    assert_limit(run, 40)
    assert 1 < len(hits) < 40


def test_each_public_run_has_a_fresh_budget(capped_session):
    se = capped_session(1)
    base = se.load_shellcode(data=b"\x90\xc3", arch="x86")
    se.run_shellcode(base)
    se.run_shellcode(base)
    runs = se.get_report().entry_points
    assert len(runs) == 2
    for run in runs:
        assert_limit(run, 1)
        assert int(run.error.pc) == base + 1
