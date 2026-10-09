"""Guest code walks the PEB loader lists of its own process."""

import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.defs.nt import ntoskrnl

LISTS = (
    ("InLoadOrderModuleList", "InLoadOrderLinks"),
    ("InMemoryOrderModuleList", "InMemoryOrderLinks"),
    ("InInitializationOrderModuleList", "InInitializationOrderLinks"),
)


def assert_rings(proc, bases, init_bases=None):
    emu = proc.emu
    ptr_size = emu.get_ptr_size()
    assert proc.peb.read_back().object.Ldr == proc.peb_ldr_data.address
    for head_field, link_field in LISTS:
        head = proc.peb_ldr_data.address + getattr(proc.peb_ldr_data.object.get_cstruct(), head_field).offset
        link_offset = getattr(ntoskrnl.LDR_DATA_TABLE_ENTRY(ptr_size).get_cstruct(), link_field).offset
        expected = init_bases if init_bases is not None and link_field == "InInitializationOrderLinks" else bases

        def links(address):
            raw = emu.mem_read(address, ptr_size * 2)
            return int.from_bytes(raw[:ptr_size], "little"), int.from_bytes(raw[ptr_size:], "little")

        for direction in (0, 1):
            seen = []
            node = links(head)[direction]
            while node != head:
                assert node not in seen, "Ring cycled without returning to its PEB head"
                assert len(seen) < len(proc.ldr_entries), "Ring contains extra nodes"
                seen.append(node)
                flink, blink = links(node)
                assert links(flink)[1] == node
                assert links(blink)[0] == node
                node = (flink, blink)[direction]
            observed = []
            for node in seen:
                entry = ntoskrnl.LDR_DATA_TABLE_ENTRY(ptr_size)
                entry.cast(emu.mem_read(node - link_offset, entry.sizeof()))
                observed.append(entry.DllBase)
            assert observed == (expected if direction == 0 else list(reversed(expected)))
        flink, blink = links(head)
        assert links(flink)[1] == head
        assert links(blink)[0] == head


def loader_bases(proc):
    return [entry.object.DllBase for entry in proc.ldr_entries]


def assert_process_rings(proc):
    main_base = proc.pe.base if proc.pe is not None else proc.base
    bases = loader_bases(proc)
    if main_base in proc._peb_modules and proc._peb_modules[main_base].is_exe():
        assert bases[0] == main_base, "Process main executable must lead the loader lists"
    assert all(base == main_base or not proc._peb_modules[base].is_exe() for base in bases), (
        "Process loader lists contain a foreign executable"
    )
    init_bases = [base for base in bases if base != main_base or not proc._peb_modules[base].is_exe()]
    assert_rings(proc, bases, init_bases)
    for base in bases:
        assert proc.emu.mem_read(base, 2) == b"MZ"


class Deref(int):
    """A guest call argument read from this address when the call executes."""


_X64_ARG_REGS = (b"\x48\x89\xc1", b"\x48\x89\xc2", b"\x49\x89\xc0", b"\x49\x89\xc1")


def guest_call(ptr_size, target, *args, store=None):
    """
    Assemble a call to ``target`` with the native calling convention, optionally
    storing the return value at ``store``.
    """
    if ptr_size == 4:
        code = b"".join(
            (b"\xff\x35" if isinstance(arg, Deref) else b"\x68") + struct.pack("<I", arg) for arg in reversed(args)
        )
        code += b"\xb8" + struct.pack("<I", target) + b"\xff\xd0"
        if store is not None:
            code += b"\xa3" + struct.pack("<I", store)
        return code
    code = b"\x48\x83\xec\x58"
    for index, arg in enumerate(args):
        code += (b"\x48\xa1" if isinstance(arg, Deref) else b"\x48\xb8") + struct.pack("<Q", arg)
        code += _X64_ARG_REGS[index] if index < 4 else b"\x48\x89\x44\x24" + bytes([0x20 + 8 * (index - 4)])
    code += b"\x48\xb8" + struct.pack("<Q", target) + b"\xff\xd0\x48\x83\xc4\x58"
    if store is not None:
        code += b"\x48\xa3" + struct.pack("<Q", store)
    return code


def get_api(se, dll, name):
    return next(address for address, symbol in se.get_symbols().items() if symbol == (dll, name))


def read_pointer(se, address):
    return int.from_bytes(se.mem_read(address, se.get_ptr_size()), "little")


def make_list_walker(ptr_size):
    """
    Assemble a thread procedure that takes an output buffer and writes the
    DllBase of every entry in the load, memory and initialization order lists
    of its own PEB, each list terminated by zero.
    """
    if ptr_size == 4:
        code = b"\x56\x57\x53\x8b\x7c\x24\x10\x64\xa1\x30\x00\x00\x00\x8b\x40\x0c"
        for head, dll_base in ((0x0C, 0x18), (0x14, 0x10), (0x1C, 0x08)):
            code += b"\x8d\x70" + bytes([head]) + b"\x8b\x0e"
            code += b"\x39\xf1\x74\x0c\x8b\x51" + bytes([dll_base]) + b"\x89\x17\x83\xc7\x04\x8b\x09\xeb\xf0"
            code += b"\xc7\x07\x00\x00\x00\x00\x83\xc7\x04"
        return code + b"\x5b\x5f\x5e\x31\xc0\xc2\x04\x00"
    code = b"\x49\x89\xc8\x65\x48\x8b\x04\x25\x60\x00\x00\x00\x48\x8b\x40\x18"
    for head, dll_base in ((0x10, 0x30), (0x20, 0x20), (0x30, 0x10)):
        code += b"\x4c\x8d\x48" + bytes([head]) + b"\x49\x8b\x09"
        code += b"\x4c\x39\xc9\x74\x10\x48\x8b\x51" + bytes([dll_base])
        code += b"\x49\x89\x10\x49\x83\xc0\x08\x48\x8b\x09\xeb\xeb"
        code += b"\x49\xc7\x00\x00\x00\x00\x00\x49\x83\xc0\x08"
    return code + b"\x31\xc0\xc3"


def read_walk(se, address):
    lists, current = [], []
    while len(lists) < 3:
        value = read_pointer(se, address)
        address += se.get_ptr_size()
        if value:
            current.append(value)
        else:
            lists.append(current)
            current = []
    return lists


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
        main = load[0]
        assert memory == load
        assert load[1:3] == [ntdll, kernel32]
        assert init == load[1:]
        assert load.count(dll) == 1 and load[-1] == dll
        assert child not in load and kernel not in load

        load, memory, init = read_walk(se, child_walk)
        assert memory == load
        assert load[0] == child
        assert load[1:3] == [ntdll, kernel32]
        assert init == load[1:]
        assert dll not in load and main not in load and kernel not in load

        for proc in emu.processes:
            if proc.is_peb_active:
                assert_process_rings(proc)
    finally:
        se.shutdown()
