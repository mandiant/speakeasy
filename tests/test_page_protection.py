import struct

import pytest

from speakeasy import Speakeasy, common
from speakeasy.profiler_events import EventType
from speakeasy.windows.winemu import get_page_protection_runs
from speakeasy.winenv.defs.enums import PAGE_PROTECTION_FLAGS
from speakeasy.winenv.defs.nt import ddk
from speakeasy.winenv.defs.windows import windows as windefs
from tests.guest_harness import Deref, get_api, guest_call
from tests.handler_harness import alloc, call, start_process

PAGE = 0x1000
RX = common.PERM_MEM_RX
RW = common.PERM_MEM_RW


def test_runs_merge_contiguous_pages_with_equal_perms():
    page_perms = {0x1000: RX, 0x2000: RX, 0x3000: RX, 0x4000: RW, 0x5000: RW}
    assert get_page_protection_runs(page_perms, PAGE) == [
        (0x1000, 0x3000, RX),
        (0x4000, 0x2000, RW),
    ]


def test_runs_split_at_gaps_and_ignore_insertion_order():
    page_perms = {0x5000: RX, 0x1000: RX, 0x2000: RX}
    assert get_page_protection_runs(page_perms, PAGE) == [
        (0x1000, 0x2000, RX),
        (0x5000, 0x1000, RX),
    ]


def test_runs_keep_perm_changes_separate():
    page_perms = {0x1000: RX, 0x2000: RW, 0x3000: RX}
    assert get_page_protection_runs(page_perms, PAGE) == [
        (0x1000, 0x1000, RX),
        (0x2000, 0x1000, RW),
        (0x3000, 0x1000, RX),
    ]


def test_protecting_an_empty_range_changes_nothing(dll_emu: Speakeasy) -> None:
    emu = dll_emu.emu
    base = emu.mem_map(PAGE, perms=RW, tag="test.empty_protect")
    before = list(emu.get_mem_regions())

    emu.mem_protect(base, 0, RX)
    assert list(emu.get_mem_regions()) == before


@pytest.mark.parametrize("bin_name", ["dll_test_x86.dll.xz", "dll_test_x64.dll.xz"])
def test_loaded_sections_have_expected_page_protections(config, load_test_bin, bin_name):
    se = Speakeasy(config=config)
    try:
        module = se.load_module(data=load_test_bin(bin_name))
        emu = se.emu
        page_size = emu.page_size

        expected: dict[int, int] = {}
        for sect in module.sections:
            start = (module.base + sect.virtual_address) & ~(page_size - 1)
            end = (module.base + sect.virtual_address + sect.virtual_size + page_size - 1) & ~(page_size - 1)
            for page in range(start, end, page_size):
                expected[page] = expected.get(page, 0) | sect.perms

        regions = list(emu.get_mem_regions())
        for page, perms in expected.items():
            region = next(r for r in regions if r[0] <= page <= r[1])
            assert region[2] == emu.emu_eng.perms[perms], hex(page)

        image_regions = [r for r in regions if module.base <= r[0] < module.base + module.image_size]
        assert len(image_regions) <= len(get_page_protection_runs(expected, page_size)) + 1
    finally:
        se.shutdown()


def get_rx_page(se: Speakeasy) -> int:
    module = se.emu.modules[0]
    sect = next(s for s in module.sections if s.perms == RX)
    return module.base + sect.virtual_address


def get_perms(se: Speakeasy, address: int) -> int:
    return next(p for start, end, p in se.emu.get_mem_regions() if start <= address <= end)


def protect(se: Speakeasy, address: int, size: int, new: int) -> tuple[int, int, int, int]:
    """Call ntdll!NtProtectVirtualMemory on the current process, and return the status and the three outputs."""
    ptr = "<I" if se.get_ptr_size() == 4 else "<Q"
    p_base = alloc(se, struct.pack(ptr, address))
    p_size = alloc(se, struct.pack(ptr, size))
    p_old = alloc(se, b"\xff" * 4)
    current_process = (1 << 8 * se.get_ptr_size()) - 1
    rv, _ = call(se, "ntdll", "NtProtectVirtualMemory", [current_process, p_base, p_size, new, p_old])
    base = struct.unpack(ptr, se.mem_read(p_base, se.get_ptr_size()))[0]
    size = struct.unpack(ptr, se.mem_read(p_size, se.get_ptr_size()))[0]
    old = struct.unpack("<I", se.mem_read(p_old, 4))[0]
    return rv, base, size, old


def test_commit_changes_the_perms_of_the_region_in_the_memory_layout(config) -> None:
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=bytes(0x1000), arch="x86")
        data = se.mem_alloc(0x100)
        reserved, committed = data, data + 4
        virtual_alloc = get_api(se, "kernel32", "VirtualAlloc")
        body = guest_call(
            4, virtual_alloc, 0, 4 * PAGE, windefs.MEM_RESERVE, PAGE_PROTECTION_FLAGS.PAGE_NOACCESS, store=reserved
        )
        args = (Deref(reserved), PAGE, windefs.MEM_COMMIT, PAGE_PROTECTION_FLAGS.PAGE_READWRITE)
        body += guest_call(4, virtual_alloc, *args, store=committed)
        se.mem_write(code, body + b"\xc3")
        se.run_shellcode(code)
        base, commit_base = struct.unpack("<2I", se.mem_read(data, 8))
        report = se.get_report()

    assert commit_base == base
    run = report.runs[0]
    assert run.memory is not None
    [region] = [r for r in run.memory.layout if r.tag == "api.VirtualAlloc"]
    assert (region.base, region.size, region.perms) == (base, 4 * PAGE, "rw-")


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
def test_ntdll_protect_virtual_memory_changes_page_protection(request, fixture: str) -> None:
    se = request.getfixturevalue(fixture)
    start_process(se)
    page = get_rx_page(se)
    next_perms = get_perms(se, page + PAGE)

    rv, base, size, old = protect(se, page + 0x10, 0x10, PAGE_PROTECTION_FLAGS.PAGE_READWRITE)
    assert (rv, base, size, old) == (ddk.STATUS_SUCCESS, page, PAGE, PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READ)
    assert get_perms(se, page) == se.emu.emu_eng.perms[RW]
    assert get_perms(se, page + PAGE) == next_perms

    rv, _, _, old = protect(se, page, PAGE, PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READ)
    assert (rv, old) == (ddk.STATUS_SUCCESS, PAGE_PROTECTION_FLAGS.PAGE_READWRITE)
    assert get_perms(se, page) == se.emu.emu_eng.perms[RX]


def test_ntdll_protect_virtual_memory_spans_pages(dll64_emu: Speakeasy) -> None:
    se = dll64_emu
    start_process(se)
    page = get_rx_page(se)

    rv, base, size, _ = protect(se, page + 0xFF0, 0x20, PAGE_PROTECTION_FLAGS.PAGE_READWRITE)
    assert (rv, base, size) == (ddk.STATUS_SUCCESS, page, 2 * PAGE)
    assert get_perms(se, page + PAGE) == se.emu.emu_eng.perms[RW]


def test_ntdll_protect_virtual_memory_records_a_mem_protect_event(dll64_emu: Speakeasy) -> None:
    se = dll64_emu
    start_process(se)
    page = get_rx_page(se)

    protect(se, page + 0x10, 0x10, PAGE_PROTECTION_FLAGS.PAGE_READWRITE)
    events = [e for e in se.emu.get_current_run().events if e.event == EventType.MEM_PROTECT]
    assert [(e.base, e.size, e.protect, e.pid) for e in events] == [(page + 0x10, 0x10, ["PAGE_READWRITE"], None)]


def test_ntdll_protect_virtual_memory_fails_for_an_empty_or_unmapped_range(dll64_emu: Speakeasy) -> None:
    se = dll64_emu
    start_process(se)
    page = get_rx_page(se)
    rw = PAGE_PROTECTION_FLAGS.PAGE_READWRITE

    assert protect(se, page, 0, rw) == (ddk.STATUS_INVALID_PARAMETER, page, 0, 0xFFFFFFFF)
    assert protect(se, 0, PAGE, rw)[0] == ddk.STATUS_CONFLICTING_ADDRESSES
    assert get_perms(se, page) == se.emu.emu_eng.perms[RX]
