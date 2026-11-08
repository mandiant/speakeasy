"""How a run ends, and which run the loop starts next."""

import pytest

from speakeasy import Speakeasy
from speakeasy.profiler import Run
from speakeasy.report import EntryPointType

# mov eax, 2; ret
RETURN_2 = b"\xb8\x02\x00\x00\x00\xc3"
# jmp $
LOOP = b"\xeb\xfe"
# mov eax, [0]; ret
READ_NULL = b"\xa1\x00\x00\x00\x00\xc3"


@pytest.fixture
def emu(dll_emu):
    """An x86 user mode emulator with a process and an empty run queue."""
    dll_emu.emu.prepare_module_for_emulation(dll_emu.emu.modules[0], all_entrypoints=False)
    dll_emu.emu.run_queue.clear()
    return dll_emu


def queue(emu, code: bytes, name: str) -> Run:
    address = emu.mem_map(0x1000, tag=f"run_lifecycle.{name}")
    emu.mem_write(address, code)
    run = Run()
    run.start_addr = address
    run.type = EntryPointType.CALL
    run.name = name
    run.args = []
    emu.add_run(run)
    return run


def call(api: int, arg: int | None = None) -> bytes:
    """Push ``arg``, call ``api``, then return 99 if the call returns."""
    push = b"" if arg is None else b"\x6a" + bytes([arg])
    return push + b"\xb8" + api.to_bytes(4, "little") + b"\xff\xd0" + b"\xb8\x63\x00\x00\x00\xc3"


def ran(emu) -> list[tuple[str, str | None, int | None]]:
    """The queued runs that the emulator started, with the error type and the return value of each."""
    return [
        (run.name, run.error.type.value if run.error else None, run.return_value)
        for run in emu.runs
        if run.type == EntryPointType.CALL
    ]


def test_runs_run_in_queue_order(emu):
    queue(emu.emu, b"\xb8\x01\x00\x00\x00\xc3", "a")
    queue(emu.emu, RETURN_2, "b")

    emu.emu.start()

    assert ran(emu.emu) == [("a", None, 1), ("b", None, 2)]
    assert emu.emu.is_emu_complete
    assert not emu.emu.run_queue


def test_exit_process_ends_only_the_current_run(emu):
    queue(emu.emu, call(emu.emu.get_proc("kernel32", "ExitProcess"), 7), "a")
    queue(emu.emu, RETURN_2, "b")

    emu.emu.start()

    (a, b) = ran(emu.emu)
    assert a[:2] == ("a", None) and a[2] != 99
    assert b == ("b", None, 2)


def test_a_fault_ends_the_run_and_the_next_run_starts(emu):
    queue(emu.emu, READ_NULL, "a")
    queue(emu.emu, RETURN_2, "b")

    emu.emu.start()

    assert [(name, error) for name, error, _ in ran(emu.emu)] == [("a", "invalid_read"), ("b", None)]


def test_the_api_limit_ends_the_run_and_the_next_run_starts(emu):
    emu.emu.config = emu.emu.config.model_copy(update={"max_api_calls": 2})
    tick = emu.emu.get_proc("kernel32", "GetTickCount")
    queue(emu.emu, (b"\xb8" + tick.to_bytes(4, "little") + b"\xff\xd0") * 4 + RETURN_2, "a")
    queue(emu.emu, RETURN_2, "b")

    emu.emu.start()

    assert [(name, error) for name, error, _ in ran(emu.emu)] == [("a", "max_api_count"), ("b", None)]
    assert emu.emu.runs[-2].get_api_count() == 3


def test_the_instruction_limit_ends_the_run_and_the_next_run_starts(emu):
    emu.emu.config = emu.emu.config.model_copy(update={"max_instructions": 1000})
    queue(emu.emu, LOOP, "a")
    queue(emu.emu, RETURN_2, "b")

    emu.emu.start()

    assert [(name, error) for name, error, _ in ran(emu.emu)] == [("a", "max_instructions"), ("b", None)]


def test_an_unsupported_api_ends_the_run_and_the_next_run_starts(emu):
    queue(emu.emu, call(emu.emu.get_proc("run_lifecycle", "Missing")), "a")
    queue(emu.emu, RETURN_2, "b")

    emu.emu.start()

    assert [(name, error) for name, error, _ in ran(emu.emu)] == [("a", "unsupported_api"), ("b", None)]


def test_an_api_hook_that_raises_ends_the_run_and_the_next_run_starts(emu):
    def fail(e, api, original, args):
        raise ValueError("hook failed")

    emu.add_api_hook(fail, "kernel32", "GetTickCount", argc=0)
    queue(emu.emu, call(emu.emu.get_proc("kernel32", "GetTickCount")), "a")
    queue(emu.emu, RETURN_2, "b")

    emu.emu.start()

    assert [(name, error) for name, error, _ in ran(emu.emu)] == [("a", "internal_error"), ("b", None)]


def test_stop_in_a_code_hook_ends_the_emulation(emu):
    a = queue(emu.emu, LOOP, "a")
    queue(emu.emu, RETURN_2, "b")
    emu.add_code_hook(lambda e, address, size: emu.stop(), begin=a.start_addr, end=a.start_addr)

    emu.emu.start()

    assert [name for name, _, _ in ran(emu.emu)] == ["a"]
    assert emu.emu.is_emu_complete


def test_stop_in_an_api_hook_ends_the_current_run(emu):
    def stop(e, api, original, args):
        emu.stop()
        return 5

    emu.add_api_hook(stop, "kernel32", "GetTickCount", argc=0)
    queue(emu.emu, call(emu.emu.get_proc("kernel32", "GetTickCount")), "a")
    queue(emu.emu, RETURN_2, "b")

    emu.emu.start()

    assert [(name, error) for name, error, _ in ran(emu.emu)] == [("a", None), ("b", None)]


def test_stop_in_a_code_hook_in_kernel_mode(config, load_test_bin):
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin("wdm_test_x86.sys.xz"))
        entry = module.base + module.ep
        se.add_code_hook(lambda e, address, size: se.stop(), begin=entry, end=entry)
        se.run_module(module, all_entrypoints=True)
        eps = se.get_report().entry_points

    assert [(ep.type, ep.error.type if ep.error else None) for ep in eps] == [("driver_entry", "engine_stopped")]
