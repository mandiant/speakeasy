import pytest

import speakeasy.common as common
from speakeasy import Speakeasy
from speakeasy.windows.winemu import get_page_protection_runs

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
