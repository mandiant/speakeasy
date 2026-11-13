import copy
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from speakeasy import Speakeasy
from tests.handler_harness import alloc, call, load_emu, start_process


def test_map_view_of_file_uses_readable_protections(base_config, tmp_path):
    src = Path(__file__).resolve().parent / "capa-testfiles"
    exe_src = src / "Practical Malware Analysis Lab 01-01.exe_"
    dll_src = src / "Practical Malware Analysis Lab 01-01.dll_"
    k32_src = src / "kernel32.dll_"

    exe_path = tmp_path / exe_src.name
    shutil.copy2(exe_src, exe_path)
    shutil.copy2(dll_src, tmp_path / "Lab01-01.dll")
    shutil.copy2(k32_src, tmp_path / "Kernel32.dll")

    cfg = copy.deepcopy(base_config)
    se = Speakeasy(config=cfg, argv=["WARNING_THIS_WILL_DESTROY_YOUR_MACHINE"])
    try:
        module = se.load_module(path=str(exe_path))
        se.run_module(module)
        report = se.get_report()
    finally:
        se.shutdown()

    ep = report.runs[0]
    assert ep.memory is not None

    map_views = [region for region in ep.memory.layout if (region.tag or "").startswith("api.MapViewOfFile")]
    assert len(map_views) >= 2

    for region in map_views:
        assert region.perms in {"r--", "rw-", "r-x", "rwx"}

    if ep.error is not None:
        assert ep.error.type != "internal_error"


FILE_MAP_READ = 0x04
GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
PAGE_READONLY = 0x02


@pytest.fixture
def split_file_emu(config, load_test_bin, tmp_path) -> Iterator[Speakeasy]:
    host = tmp_path / "data.bin"
    host.write_bytes(b"A" * 0x10000 + b"B" * 0x10000)
    config["filesystem"]["files"].insert(0, {"mode": "full_path", "emu_path": "c:\\data.bin", "path": str(host)})
    yield from load_emu(config, load_test_bin("dll_test_x86.dll.xz"))


@pytest.mark.parametrize("part_first", [False, True], ids=["whole_first", "part_first"])
def test_views_at_different_file_offsets_keep_their_own_bytes(split_file_emu: Speakeasy, part_first: bool) -> None:
    se = split_file_emu
    start_process(se)
    name = alloc(se, b"c:\\data.bin\x00")
    hfile, _ = call(se, "kernel32", "CreateFileA", [name, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0])
    hmap, _ = call(se, "kernel32", "CreateFileMappingA", [hfile, 0, PAGE_READONLY, 0, 0, 0])

    def map_whole() -> int:
        view, _ = call(se, "kernel32", "MapViewOfFile", [hmap, FILE_MAP_READ, 0, 0, 0])
        return view

    def map_part() -> int:
        view, _ = call(se, "kernel32", "MapViewOfFile", [hmap, FILE_MAP_READ, 0, 0x10000, 0x1000])
        return view

    if part_first:
        part = map_part()
        whole = map_whole()
    else:
        whole = map_whole()
        part = map_part()
    assert whole and part

    assert se.mem_read(whole, 0x1000) == b"A" * 0x1000
    assert se.mem_read(whole + 0x10000, 0x1000) == b"B" * 0x1000
    assert se.mem_read(part, 0x1000) == b"B" * 0x1000
