"""Child processes run after the parent when emulate_children is set."""

import hashlib
import logging

from speakeasy import Speakeasy

CHILD_PATH = "c:\\child.exe"
CHILD_BASE = 0x10000000
# parent.c starts c:\child.exe. child.c returns the base of the first image in its loader
# list; child_x86 has the image base of the parent, child_at_10000000_x86 has CHILD_BASE.
PARENT = "parent_x86.exe.xz"
CHILD = "child_x86.exe.xz"
CHILD_AT_CHILD_BASE = "child_at_10000000_x86.exe.xz"


def test_child_exe_runs_at_the_base_of_the_parent_exe(config, load_test_bin):
    parent = load_test_bin(PARENT)
    with Speakeasy(config=config) as se:
        module = se.load_module(data=parent)
        se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin(CHILD))
        se.run_module(module, emulate_children=True)
        child = se.emu.get_mod_from_addr(module.base)
        pids = [se.emu.processes[0].pid, se.emu.get_current_process().pid]
        report = se.get_report()
        entries = report.entry_points

    assert (child.name, child.emu_path) == ("child", CHILD_PATH)
    assert report.sha256 == hashlib.sha256(parent).hexdigest()

    assert [(ep.ep_type, ep.error) for ep in entries] == [("module_entry", None), ("module_entry", None)]
    assert entries[0].ret_val == 1
    assert entries[1].ret_val == module.base
    assert len(set(pids)) == 2
    assert [ep.pid for ep in entries] == pids


def test_child_without_relocations_whose_base_is_in_use_is_skipped(config, load_test_bin, caplog):
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(PARENT))
        se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin(CHILD_AT_CHILD_BASE))
        se.emu.mem_map(0x1000, base=CHILD_BASE, tag="test.block")
        with caplog.at_level(logging.WARNING):
            se.run_module(module, emulate_children=True)
        report = se.get_report()

    assert [(ep.ep_type, ep.error) for ep in report.entry_points] == [("module_entry", None)]
    assert f"skipping child process {CHILD_PATH}" in caplog.text
    assert "Cannot rebase a guest PE without valid relocation data" in caplog.text


def test_child_finds_its_own_image_first_in_its_loader_list(config, load_test_bin):
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(PARENT))
        se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin(CHILD_AT_CHILD_BASE))
        se.run_module(module, emulate_children=True)
        child = se.emu.get_current_process()
        entries = se.get_report().entry_points

    assert [(ep.ep_type, ep.error) for ep in entries] == [("module_entry", None), ("module_entry", None)]
    assert entries[1].ret_val == CHILD_BASE
    assert [entry.object.DllBase for entry in child.ldr_entries][:4] == [
        CHILD_BASE,
        se.emu.get_mod_by_name("ntdll").base,
        se.emu.get_mod_by_name("kernel32").base,
        se.emu.get_mod_by_name("kernelbase").base,
    ]


def test_finished_parent_gives_up_its_image_peb_and_heap(config, load_test_bin):
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(PARENT))
        se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin(CHILD_AT_CHILD_BASE))
        se.run_module(module, emulate_children=True)
        parent = se.emu.processes[0]
        maps = se.emu.get_mem_maps()
        heap = [address for address, _, name in se.emu.heap_allocs if name == "LocalAlloc"]

    assert parent.pe is module
    assert module not in se.emu.modules
    assert all(not m.base <= module.base < m.base + m.size for m in maps)
    assert all(m.free for m in maps if m.base <= parent.peb.address < m.base + m.size)
    assert len(heap) == 1
    assert all(m.free for m in maps if m.base <= heap[0] < m.base + m.size)
