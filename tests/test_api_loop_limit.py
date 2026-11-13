"""A run that makes max_api_loop_calls API calls with no call from a new call site ends with ``api_loop``."""

import pytest

from speakeasy.profiler import ApiLoopTracker
from speakeasy.profiler_events import TracePosition
from speakeasy.report import ApiLoopSite
from tests.test_run_lifecycle import RETURN_2, queue, ran

LIMIT = 20


def at(tick: int) -> TracePosition:
    return TracePosition(tick=tick, tid=1, pid=1, pc=0x401000 + tick)


def record(tracker: ApiLoopTracker, sites: list[tuple[str, int]]) -> ApiLoopTracker:
    for tick, site in enumerate(sites):
        tracker.record(site, at(tick))
    return tracker


A = ("kernel32.GetTickCount", 0x401005)
B = ("kernel32.Sleep", 0x40100C)
C = ("kernel32.GetTickCount", 0x401020)


def test_calls_from_known_sites_count_and_a_new_site_resets_the_count():
    tracker = record(ApiLoopTracker(), [A, A, A, B, A, B, B])
    assert tracker.calls == 3
    assert tracker.site_calls == {A: 1, B: 2}

    tracker.record(C, at(7))
    assert tracker.calls == 0
    assert tracker.get_loop() is None

    tracker.record(A, at(8))
    assert tracker.calls == 1
    assert tracker.site_calls == {A: 1}


def test_the_loop_starts_at_the_first_call_after_the_last_new_site():
    tracker = record(ApiLoopTracker(), [A, A, A, B, B, A, B])

    loop = tracker.get_loop()

    assert loop is not None
    assert loop.start == at(4)
    assert loop.calls == 3
    assert loop.sites == [
        ApiLoopSite(api_name=B[0], return_address=B[1], calls=2),
        ApiLoopSite(api_name=A[0], return_address=A[1], calls=1),
    ]


def test_the_loop_has_at_most_16_sites_with_the_most_calls_first():
    sites = [(f"mod.f{i}", 0x1000 + i) for i in range(20)]
    tracker = record(ApiLoopTracker(), sites)
    for i, site in enumerate(sites):
        for _ in range(i + 1):
            tracker.record(site, at(100))

    loop = tracker.get_loop()

    assert loop is not None
    assert loop.calls == sum(range(1, 21))
    assert [site.calls for site in loop.sites] == list(range(20, 4, -1))


@pytest.fixture
def emu(dll_emu):
    """An x86 user mode emulator with a process, an empty run queue and an API loop limit of 20."""
    dll_emu.emu.prepare_module_for_emulation(dll_emu.emu.modules[0], all_entrypoints=False)
    dll_emu.emu.run_queue.clear()
    dll_emu.emu.config = dll_emu.emu.config.model_copy(update={"max_api_loop_calls": LIMIT})
    return dll_emu


def call_api(address: int) -> bytes:
    """Call the API at ``address`` through eax."""
    return b"\xb8" + address.to_bytes(4, "little") + b"\xff\xd0"


def loop_forever(body: bytes) -> bytes:
    """Run ``body`` again and again with a ``jmp`` back to its start."""
    return body + b"\xeb" + (-(len(body) + 2) & 0xFF).to_bytes(1, "little")


def loop_times(count: int, body: bytes) -> bytes:
    """Run ``body`` ``count`` times, with the counter in ecx saved on the stack around ``body``."""
    body = b"\x51" + body + b"\x59\x49"
    return b"\xb9" + count.to_bytes(4, "little") + body + b"\x75" + (-(len(body) + 2) & 0xFF).to_bytes(1, "little")


def test_an_endless_loop_on_one_api_ends_with_api_loop_and_the_next_run_starts(emu):
    tick = emu.emu.get_proc("kernel32", "GetTickCount")
    base = queue(emu.emu, loop_forever(call_api(tick)), "a").start_addr
    queue(emu.emu, RETURN_2, "b")
    assert base is not None

    emu.emu.start()

    assert [(name, error) for name, error, _ in ran(emu.emu)] == [("a", "api_loop"), ("b", None)]
    error = emu.emu.runs[-2].error
    assert error.count == LIMIT
    assert error.last_api == "kernel32.GetTickCount"
    assert error.loop.calls == LIMIT
    assert error.loop.start.pc == base + 5
    assert error.loop.sites == [ApiLoopSite(api_name="kernel32.GetTickCount", return_address=base + 7, calls=LIMIT)]
    assert emu.emu.runs[-2].get_api_count() == LIMIT + 1


def test_a_loop_of_two_apis_ends_with_api_loop_and_names_both_sites(emu):
    tick = emu.emu.get_proc("kernel32", "GetTickCount")
    thread_id = emu.emu.get_proc("kernel32", "GetCurrentThreadId")
    base = queue(emu.emu, loop_forever(call_api(tick) + call_api(thread_id)), "a").start_addr
    assert base is not None

    emu.emu.start()

    assert ran(emu.emu)[0][1] == "api_loop"
    loop = emu.emu.runs[-1].error.loop
    assert loop.calls == LIMIT
    assert {(site.api_name, site.return_address, site.calls) for site in loop.sites} == {
        ("kernel32.GetTickCount", base + 7, LIMIT // 2),
        ("kernel32.GetCurrentThreadId", base + 14, LIMIT // 2),
    }


def test_a_loop_limit_of_0_leaves_the_loop_to_the_api_call_limit(emu):
    emu.emu.config = emu.emu.config.model_copy(update={"max_api_loop_calls": 0, "max_api_calls": 3 * LIMIT})
    tick = emu.emu.get_proc("kernel32", "GetTickCount")
    queue(emu.emu, loop_forever(call_api(tick)), "a")

    emu.emu.start()

    assert [(name, error) for name, error, _ in ran(emu.emu)] == [("a", "max_api_count")]


@pytest.mark.parametrize("count, error", [(LIMIT, None), (LIMIT + 1, "api_loop")])
def test_a_finite_loop_ends_with_api_loop_only_above_the_limit(emu, count, error):
    tick = emu.emu.get_proc("kernel32", "GetTickCount")
    queue(emu.emu, loop_times(count, call_api(tick)) + RETURN_2, "a")

    emu.emu.start()

    assert [(name, err) for name, err, _ in ran(emu.emu)] == [("a", error)]
