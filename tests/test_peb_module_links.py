"""Guest code walks the PEB loader lists of its own process."""

import struct

import pytest

from speakeasy import Speakeasy
from tests.guest_harness import (
    Deref,
    assert_process_rings,
    assert_rings,
    get_api,
    guest_call,
    loader_bases,
    make_list_walker,
    read_pointer,
    read_walk,
)


@pytest.mark.parametrize("arch", ["x86", "amd64"])
def test_guest_walks_loader_lists_of_its_own_process(config, arch):
    config["modules"]["modules_always_exist"] = True
    se = Speakeasy(config=config)
    try:
        code = se.load_shellcode(data=b"\xc3" * 0x1000, arch=arch)
        ptr = se.get_ptr_size()
        data = se.mem_alloc(0x2000, base=0x20000000)
        dll_name, child_path, startup_info, process_info, results = (data + offset for offset in range(0, 0x280, 0x80))
        parent_walk, child_walk = data + 0x400, data + 0x1000
        se.mem_write(dll_name, b"peb_walk.dll\0")
        se.mem_write(child_path, b"C:\\Windows\\notepad.exe\0")
        se.mem_write(startup_info, struct.pack("<I", 0x44 if ptr == 4 else 0x68))
        walker = code + 0x800
        load_library = get_api(se, "kernel32", "LoadLibraryA")
        program = guest_call(ptr, load_library, dll_name, store=results)
        program += guest_call(ptr, load_library, dll_name, store=results + 8)
        program += guest_call(ptr, walker, parent_walk)
        create_suspended = 4
        program += guest_call(
            ptr,
            get_api(se, "kernel32", "CreateProcessA"),
            child_path,
            0,
            0,
            0,
            0,
            create_suspended,
            0,
            0,
            startup_info,
            process_info,
        )
        program += guest_call(
            ptr, get_api(se, "kernel32", "CreateRemoteThread"), Deref(process_info), 0, 0, walker, child_walk, 0, 0
        )
        se.mem_write(code, program + b"\xc3")
        se.mem_write(walker, make_list_walker(ptr))

        se.run_shellcode(code)

        report = se.get_report()
        assert [ep.error for ep in report.entry_points] == [None, None]
        dll = read_pointer(se, results)
        assert dll and read_pointer(se, results + 8) == dll
        emu = se.emu
        ntdll, kernel32 = (emu.get_mod_by_name(name).base for name in ("ntdll", "kernel32"))
        kernel = emu.get_mod_by_name("ntoskrnl").base
        child = emu.get_mod_by_name("notepad").base

        load, memory, init = read_walk(se, parent_walk)
        assert memory == load
        assert load[1:3] == [ntdll, kernel32]
        assert init == load[1:]
        assert load.count(dll) == 1 and load[-1] == dll
        assert child not in load and kernel not in load

        load, memory, init = read_walk(se, child_walk)
        assert memory == load
        assert load.count(child) == 1
        assert init == [base for base in load if base != child]
        assert kernel not in load

        for proc in emu.processes:
            if proc.is_peb_active:
                assert_process_rings(proc)
        for proc in emu.child_processes:
            bases = loader_bases(proc)
            assert child in bases
            assert_rings(proc, bases, [base for base in bases if base != proc.pe.base])
    finally:
        se.shutdown()
