"""Walk the serialized loader rings as a guest would, on both architectures."""

from types import SimpleNamespace

import pytest

from speakeasy.windows.objman import HandleAllocator, LdrDataTableEntry, Process
from speakeasy.winenv import arch
from speakeasy.winenv.defs.nt import ntoskrnl


class MemoryEmulator:
    """Strict mapped memory without a native execution engine."""

    def __init__(self, ptr_size):
        self.ptr_size = ptr_size
        self.handle_allocator = HandleAllocator()
        self.next_address = 0x100000000 if ptr_size == 8 else 0x100000
        self.maps = {}

    def get_arch(self):
        return arch.ARCH_AMD64 if self.ptr_size == 8 else arch.ARCH_X86

    def get_ptr_size(self):
        return self.ptr_size

    def add_object(self, obj):
        pass

    def mem_map(self, size, tag=None, perms=None, base=0):
        address = base or self.next_address
        if not base:
            self.next_address += (size + 0xFFF) & ~0xFFF
        self.maps[address] = bytearray(size)
        return address

    def _region(self, address, size):
        for base, data in self.maps.items():
            if base <= address and address + size <= base + len(data):
                return data, address - base
        raise AssertionError(f"Unmapped access: {address:#x} + {size:#x}")

    def mem_read(self, address, size):
        data, offset = self._region(address, size)
        return bytes(data[offset : offset + size])

    def mem_write(self, address, value):
        data, offset = self._region(address, len(value))
        data[offset : offset + len(value)] = value


def module(base, name="test.dll", exe=False):
    return SimpleNamespace(base=base, emu_path="C:\\test\\" + name, ep=0x1000, image_size=0x5000, is_exe=lambda: exe)


@pytest.fixture(params=[4, 8], ids=["x86", "x64"])
def emu(request):
    return MemoryEmulator(request.param)


def process(emu, main=None, base=0):
    proc = Process(emu, pe=main, base=base)
    address = emu.mem_map(proc.peb_ldr_data.sizeof())
    proc.set_peb_ldr_address(address)
    return proc


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


def test_empty_loader_heads_self_link(emu):
    proc = process(emu)
    proc.init_peb([])
    assert_rings(proc, [])
    proc.init_peb([])
    assert_rings(proc, [])


@pytest.mark.parametrize("count", [1, 4])
def test_one_and_many_dlls(emu, count):
    proc = process(emu)
    mods = [module(0x400000 + i * 0x10000) for i in range(count)]
    for i, mod in enumerate(mods):
        proc.add_module_to_peb(mod)
        assert_rings(proc, [m.base for m in mods[: i + 1]])
    assert all(isinstance(entry, LdrDataTableEntry) for entry in proc.ldr_entries)
    for entry, mod in zip(proc.ldr_entries, mods):
        serialized = entry.object.get_cstruct().from_buffer_copy(emu.mem_read(entry.address, entry.sizeof()))
        assert serialized.EntryPoint == mod.base + mod.ep
        assert serialized.SizeOfImage == mod.image_size
        name = serialized.FullDllName
        assert emu.mem_read(name.Buffer, name.MaximumLength) == (mod.emu_path + "\0").encode("utf-16le")


@pytest.mark.parametrize("main_index", [0, 1, 2])
def test_initialization_ring_excludes_main_by_identity(emu, main_index):
    main = module(0x400000, "main.exe", exe=True)
    mods = [module(0x500000), module(0x600000)]
    mods.insert(main_index, main)
    proc = process(emu, main)
    proc.init_peb([main])
    assert_rings(proc, [main.base], [])
    # Use a new process to exercise insertion of the main image at any position.
    proc = process(MemoryEmulator(emu.ptr_size), main)
    proc.init_peb(mods)
    assert_rings(proc, [m.base for m in mods], [m.base for m in mods if m is not main])


def test_main_base_without_pe_and_dll_primary_image(emu):
    main = module(0x400000, "main.exe", exe=True)
    proc = process(emu, base=main.base)
    proc.init_peb([main])
    assert_rings(proc, [main.base], [])
    dll = module(0x500000)
    proc.pe = dll
    proc.init_peb([dll])
    assert_rings(proc, [main.base, dll.base])


def test_repeated_init_and_attachment_reuse_entries(emu):
    main = module(0x400000, "main.exe", exe=True)
    dll = module(0x500000)
    proc = process(emu, main)
    proc.init_peb([main, dll, main])
    original_entries = list(proc.ldr_entries)
    original_maps = len(emu.maps)
    proc.init_peb([dll, main, dll])
    proc.add_module_to_peb(main)
    proc.add_module_to_peb(module(dll.base, "alias.dll"))
    proc.init_peb([])
    assert proc.ldr_entries == original_entries
    assert len(emu.maps) == original_maps
    assert_rings(proc, [main.base, dll.base], [dll.base])
    extra = module(0x600000)
    proc.add_module_to_peb(extra)
    proc.init_peb([main, dll])
    assert proc.ldr_entries[:2] == original_entries
    assert_rings(proc, [main.base, dll.base, extra.base], [dll.base, extra.base])


def test_processes_have_separate_entries_for_shared_dll(emu):
    first_main = module(0x400000, "first.exe", exe=True)
    second_main = module(0x500000, "second.exe", exe=True)
    dll = module(0x600000)
    first = process(emu, first_main)
    # EPROCESS uses a fixed preferred address; the rings/PEBs still allocate independently.
    second = process(emu, second_main)
    first.init_peb([first_main, dll])
    second.init_peb([second_main, dll])
    first.init_peb([first_main, dll])
    assert first.ldr_entries[1].address != second.ldr_entries[1].address
    assert_rings(first, [first_main.base, dll.base], [dll.base])
    assert_rings(second, [second_main.base, dll.base], [dll.base])


@pytest.mark.parametrize("main_index", [0, 1, 2])
@pytest.mark.parametrize("remove_index", [0, 1, 2], ids=["first", "middle", "last"])
def test_remove_module_preserves_survivors_and_initialization_membership(emu, main_index, remove_index):
    main = module(0x400000, "main.exe", exe=True)
    mods = [module(0x500000), module(0x600000)]
    mods.insert(main_index, main)
    proc = process(emu, main)
    proc.init_peb(mods)
    entries = list(proc.ldr_entries)
    entries_list = proc.ldr_entries
    mappings = dict(emu.maps)
    removed = mods[remove_index]
    # Mapped base is the attachment identity, including for alias objects.
    proc.remove_module_from_peb(module(removed.base, "alias.dll"))
    survivors = [mod for mod in mods if mod is not removed]
    assert proc.ldr_entries is entries_list
    assert proc.ldr_entries == [entry for i, entry in enumerate(entries) if i != remove_index]
    assert proc._peb_modules == {mod.base: mod for mod in survivors}
    assert emu.maps.keys() == mappings.keys()
    assert len(emu.mem_read(entries[remove_index].address, entries[remove_index].sizeof()))
    assert_rings(proc, [mod.base for mod in survivors], [mod.base for mod in survivors if mod is not main])
    proc.remove_module_from_peb(removed)
    proc.remove_module_from_peb(module(0x700000))
    proc.init_peb(survivors)
    assert proc.ldr_entries == [entry for i, entry in enumerate(entries) if i != remove_index]
    assert_rings(proc, [mod.base for mod in survivors], [mod.base for mod in survivors if mod is not main])


@pytest.mark.parametrize("exe", [False, True], ids=["dll", "main-exe"])
def test_remove_only_module_restores_empty_heads(emu, exe):
    mod = module(0x400000, "main.exe" if exe else "test.dll", exe=exe)
    proc = process(emu, mod)
    proc.init_peb([mod])
    proc.remove_module_from_peb(mod)
    assert proc.ldr_entries == []
    assert proc._peb_modules == {}
    assert_rings(proc, [])
    proc.remove_module_from_peb(mod)
    assert_rings(proc, [])


def test_removed_module_can_be_reattached_without_duplicating_survivors(emu):
    main = module(0x400000, "main.exe", exe=True)
    dll = module(0x500000)
    proc = process(emu, main)
    proc.init_peb([main, dll])
    main_entry = proc.ldr_entries[0]
    proc.remove_module_from_peb(dll)
    assert dll.base not in proc._peb_modules
    proc.add_module_to_peb(dll)
    proc.add_module_to_peb(dll)
    assert proc.ldr_entries[0] is main_entry
    assert len(proc.ldr_entries) == 2
    assert proc._peb_modules[dll.base] is dll
    assert_rings(proc, [main.base, dll.base], [dll.base])


def test_remove_unattached_module_before_loader_allocation_is_noop(emu):
    proc = Process(emu)
    proc.remove_module_from_peb(module(0x400000))
    assert proc.ldr_entries == []
    assert proc._peb_modules == {}


@pytest.fixture(params=["x86", "amd64"])
def real_peb_emu(request, config):
    from speakeasy import Speakeasy

    config["max_instructions"] = 1
    config["modules"]["modules_always_exist"] = True
    se = Speakeasy(config=config)
    try:
        address = se.load_shellcode(data=b"\x90\x90", arch=request.param)
        se.run_shellcode(address)
        yield se.emu
    finally:
        se.shutdown()


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


def secondary_process(emu):
    # A real mapped image/registry record, rather than a fabricated module.
    main = emu.load_module_by_name("peb_child", emu_path=r"C:\test\peb_child.exe")
    proc = Process(emu, pe=main, base=main.base, path=main.emu_path)
    emu.processes.append(proc)
    return proc


def test_real_load_library_preserves_current_process_rings(real_peb_emu):
    emu = real_peb_emu
    proc = emu.get_current_process()
    assert_process_rings(proc)
    entries = list(proc.ldr_entries)
    dll_base = emu.load_library("peb_regression.dll")
    dll = emu.get_mod_by_name("peb_regression")
    assert dll_base == dll.base
    assert proc.ldr_entries[:-1] == entries
    assert loader_bases(proc).count(dll_base) == 1
    assert_process_rings(proc)
    after_load = list(proc.ldr_entries)
    assert emu.load_library(r"C:\test\PEB_REGRESSION.DLL") == dll_base
    emu.init_peb(emu._ordered_peb_modules(), proc=proc)
    assert proc.ldr_entries == after_load
    assert_process_rings(proc)
    # The loader entry and exported address registry describe the same image.
    assert emu.api_registry.names[id(dll)] == {}
    assert dll in emu.modules
    assert dll.visible_in_peb


def test_real_cached_library_attaches_only_to_selected_process(real_peb_emu):
    emu = real_peb_emu
    first = emu.get_current_process()
    shared_base = emu.load_library("peb_shared.dll")
    first_entries = list(first.ldr_entries)
    second = secondary_process(emu)
    # Allocate the secondary loader storage explicitly to isolate load_library
    # from the independently tested alloc_peb process-selection defect.
    second.set_peb_ldr_address(emu.mem_map(second.peb_ldr_data.sizeof()))
    second.init_peb([second.pe])
    try:
        emu.set_current_process(second)
        assert emu.load_library("peb_shared.dll") == shared_base
        assert loader_bases(second) == [second.base, shared_base]
        assert first.ldr_entries == first_entries
        assert first.ldr_entries[-1].address != second.ldr_entries[-1].address
        assert_process_rings(first)
        assert_process_rings(second)
        second_entries = list(second.ldr_entries)
        assert emu.load_library("peb_shared.dll") == shared_base
        assert second.ldr_entries == second_entries
        private_base = emu.load_library("peb_child_private.dll")
        assert private_base in loader_bases(second)
        assert private_base not in loader_bases(first)
        assert_process_rings(first)
        assert_process_rings(second)
    finally:
        emu.set_current_process(first)


def test_real_alloc_peb_initializes_requested_process(real_peb_emu):
    emu = real_peb_emu
    current = emu.get_current_process()
    second = secondary_process(emu)
    original_entries = list(current.ldr_entries)
    original_slot = emu.mem_read(emu.peb_addr, emu.get_ptr_size())
    peb = emu.alloc_peb(second)
    assert peb is second.peb
    assert emu.get_current_process() is current
    assert current.ldr_entries == original_entries, "alloc_peb(other) modified the current process"
    assert second.base in loader_bases(second), "Requested process PEB was never initialized"
    assert current.base not in loader_bases(second)
    assert emu.mem_read(emu.peb_addr, emu.get_ptr_size()) == original_slot
    assert_process_rings(current)
    assert_process_rings(second)


def test_real_peb_order_excludes_other_process_images(real_peb_emu):
    emu = real_peb_emu
    current = emu.get_current_process()
    second = secondary_process(emu)
    assert second.base not in [mod.base for mod in emu._ordered_peb_modules()], (
        "Current process ordering includes another process's executable"
    )
    assert current.base in [mod.base for mod in emu._ordered_peb_modules()]


def test_real_init_other_peb_preserves_current_segment_slot(real_peb_emu):
    emu = real_peb_emu
    current = emu.get_current_process()
    second = secondary_process(emu)
    second.set_peb_ldr_address(emu.mem_map(second.peb_ldr_data.sizeof()))
    original_slot = emu.mem_read(emu.peb_addr, emu.get_ptr_size())
    assert emu.init_peb([second.pe], proc=second) is second.peb
    assert emu.get_current_process() is current
    assert_process_rings(second)
    assert emu.mem_read(emu.peb_addr, emu.get_ptr_size()) == original_slot, (
        "Initializing another PEB replaced the running thread's PEB pointer"
    )


def test_real_load_module_by_name_attaches_active_process(real_peb_emu):
    emu = real_peb_emu
    proc = emu.get_current_process()
    dll = emu.load_module_by_name("peb_direct")
    assert dll in emu.modules
    assert id(dll) in emu.api_registry.names
    assert dll.visible_in_peb
    assert loader_bases(proc).count(dll.base) == 1, "Mapped/registered module is absent from the active PEB"
    original_entries = list(proc.ldr_entries)
    assert emu.load_module_by_name("peb_direct") is dll
    assert proc.ldr_entries == original_entries
    assert_process_rings(proc)


def test_real_reinit_does_not_import_other_process_private_dll(real_peb_emu):
    emu = real_peb_emu
    first = emu.get_current_process()
    second = secondary_process(emu)
    second.set_peb_ldr_address(emu.mem_map(second.peb_ldr_data.sizeof()))
    second.init_peb([second.pe])
    try:
        emu.set_current_process(second)
        private_base = emu.load_library("peb_private.dll")
    finally:
        emu.set_current_process(first)
    assert private_base not in loader_bases(first)
    emu.init_peb(emu._ordered_peb_modules(), proc=first)
    assert private_base not in loader_bases(first), "PEB reinitialization imported another process's private DLL"
    assert_process_rings(first)
    assert_process_rings(second)


def test_real_load_library_respects_peb_visibility(real_peb_emu):
    emu = real_peb_emu
    proc = emu.get_current_process()
    hidden = next(mod for mod in emu.modules if mod.is_driver() and not mod.visible_in_peb)
    assert hidden.base not in loader_bases(proc)
    entries = list(proc.ldr_entries)
    assert emu.load_library(hidden.name) == hidden.base
    assert proc.ldr_entries == entries, "load_library attached a PEB-invisible kernel module"
    assert_process_rings(proc)


def test_real_remove_module_leaves_image_and_registry_for_caller_rollback(real_peb_emu):
    emu = real_peb_emu
    proc = emu.get_current_process()
    original_entries = list(proc.ldr_entries)
    base = emu.load_library("peb_rollback.dll")
    dll = emu.get_mod_by_name("peb_rollback")
    address = emu.get_proc("peb_rollback", "RollbackExport")
    registry_entry = emu.api_registry.entries[address]
    proc.remove_module_from_peb(dll)
    assert proc.ldr_entries == original_entries
    assert base not in proc._peb_modules
    assert base not in loader_bases(proc)
    assert_process_rings(proc)
    # This helper owns PEB detachment; the caller owns global registry/mapping rollback.
    assert emu.mem_read(base, 2) == b"MZ"
    assert dll in emu.modules
    assert emu.api_registry.entries[address] is registry_entry
    assert registry_entry.module is dll
    assert emu.get_address_map(address) is not None
    assert emu.load_library("peb_rollback.dll") == base
    assert proc.ldr_entries[:-1] == original_entries
    assert loader_bases(proc).count(base) == 1
    assert_process_rings(proc)


def test_real_foreign_executable_never_attaches_to_current_process(real_peb_emu):
    emu = real_peb_emu
    current = emu.get_current_process()
    original_entries = list(current.ldr_entries)
    second = secondary_process(emu)
    assert current.ldr_entries == original_entries, "Loading another executable attached it to the running process"
    assert second.base not in current._peb_modules
    assert second.pe in emu.modules
    assert emu.mem_read(second.base, 2) == b"MZ"
    assert emu.load_library(second.pe.name) == second.base
    assert current.ldr_entries == original_entries, "Cached executable load bypassed process-image ownership"
    assert_process_rings(current)


def test_real_private_dll_membership_isolated_in_both_directions(real_peb_emu):
    emu = real_peb_emu
    first = emu.get_current_process()
    first_private = emu.load_library("peb_first_only")
    shared = emu.load_library("peb_both_processes")
    first_entries = list(first.ldr_entries)
    second = secondary_process(emu)
    original_slot = emu.mem_read(emu.peb_addr, emu.get_ptr_size())
    emu.alloc_peb(second)
    assert emu.mem_read(emu.peb_addr, emu.get_ptr_size()) == original_slot
    assert first.ldr_entries == first_entries
    assert loader_bases(second)[0] == second.base
    assert first.base not in loader_bases(second)
    assert first_private not in loader_bases(second)
    assert shared not in loader_bases(second), "A globally cached DLL became owned without attachment"
    try:
        emu.set_current_process(second)
        second_private = emu.load_library("peb_second_only")
        assert emu.load_library("peb_both_processes") == shared
        second_entries = list(second.ldr_entries)
        for _ in range(2):
            emu.init_peb(emu._ordered_peb_modules(second), proc=second)
            assert second.ldr_entries == second_entries
        assert first_private not in loader_bases(second)
        assert shared in loader_bases(second)
        assert_process_rings(second)
    finally:
        emu.set_current_process(first)
    for _ in range(2):
        emu.init_peb(emu._ordered_peb_modules(first), proc=first)
        assert first.ldr_entries == first_entries
    assert second.base not in loader_bases(first)
    assert second_private not in loader_bases(first)
    assert shared in loader_bases(first)
    first_shared = next(entry for entry in first.ldr_entries if entry.object.DllBase == shared)
    second_shared = next(entry for entry in second.ldr_entries if entry.object.DllBase == shared)
    assert first_shared.address != second_shared.address
    assert_process_rings(first)
    assert_process_rings(second)


def test_real_cached_load_module_by_name_records_process_attachment(real_peb_emu):
    emu = real_peb_emu
    first = emu.get_current_process()
    base = emu.load_library("peb_cached_direct")
    dll = emu.get_mod_by_name("peb_cached_direct")
    original_entries = list(first.ldr_entries)
    second = secondary_process(emu)
    second.set_peb_ldr_address(emu.mem_map(second.peb_ldr_data.sizeof()))
    second.init_peb([second.pe])
    try:
        emu.set_current_process(second)
        assert emu.load_module_by_name(dll.name) is dll
        assert loader_bases(second) == [second.base, base]
        attached = list(second.ldr_entries)
        assert emu.load_module_by_name(dll.name) is dll
        emu.init_peb(emu._ordered_peb_modules(second), proc=second)
        assert second.ldr_entries == attached
        assert first.ldr_entries == original_entries
        assert_process_rings(second)
    finally:
        emu.set_current_process(first)


def test_real_repeated_alloc_peb_returns_existing_peb(real_peb_emu):
    emu = real_peb_emu
    current = emu.get_current_process()
    original_entries = list(current.ldr_entries)
    original_ldr = current.peb_ldr_data.address
    original_maps = {id(mapping) for mapping in emu.maps}
    for _ in range(2):
        assert emu.alloc_peb(current) is current.peb
    assert current.peb_ldr_data.address == original_ldr
    assert current.ldr_entries == original_entries
    assert {id(mapping) for mapping in emu.maps} == original_maps
    assert_process_rings(current)


def test_real_cached_invisible_dll_stays_out_of_peb(real_peb_emu):
    from speakeasy.windows.loaders import ApiModuleLoader

    emu = real_peb_emu
    current = emu.get_current_process()
    original_entries = list(current.ldr_entries)
    image = emu._make_image_at_free_base(
        lambda base: ApiModuleLoader(
            name="peb_invisible", arch=emu.get_arch(), base=base, emu_path=r"C:\test\peb_invisible.dll"
        ),
        0x6D000000,
    )
    image.visible_in_peb = False
    image.module_type = "dll"
    dll = emu.load_image(image)
    assert current.ldr_entries == original_entries
    assert emu.load_library(dll.name) == dll.base
    assert current.ldr_entries == original_entries, "Cached invisible DLL bypassed PEB visibility"
    assert_process_rings(current)


def test_real_module_publication_observes_coherent_peb(real_peb_emu):
    emu = real_peb_emu
    current = emu.get_current_process()
    published = []

    def on_module_change():
        dll = emu.get_mod_by_name("peb_publication")
        if dll is not None:
            assert loader_bases(current).count(dll.base) == 1
            assert id(dll) in emu.api_registry.names
            assert_process_rings(current)
            published.append(dll)

    emu.module_change_listeners.append(on_module_change)
    try:
        dll = emu.load_module_by_name("peb_publication")
    finally:
        emu.module_change_listeners.remove(on_module_change)
    assert published == [dll]


def test_real_prepare_run_context_switches_segment_peb_both_directions(real_peb_emu):
    from speakeasy.profiler import Run

    emu = real_peb_emu
    first = emu.get_current_process()
    first_thread = emu.get_current_thread()
    second = secondary_process(emu)
    start_address = emu.modules[0].base

    def prepare(proc, thread=None):
        run = Run()
        run.type = "shellcode"
        run.start_addr = start_address
        run.args = []
        run.process_context = proc
        run.thread = thread
        emu._prepare_run_context(run)
        assert emu.get_current_process() is proc
        assert emu.get_current_thread() is run.thread
        expected = proc.peb.address.to_bytes(emu.get_ptr_size(), "little")
        assert emu.mem_read(emu.peb_addr, emu.get_ptr_size()) == expected
        teb = emu.get_current_thread().teb
        assert teb.address == (emu.fs_addr if emu.get_ptr_size() == 4 else emu.gs_addr)
        serialized = teb.object.get_cstruct().from_buffer_copy(emu.mem_read(teb.address, teb.sizeof()))
        assert serialized.ProcessEnvironmentBlock == proc.peb.address
        return run.thread

    second_thread = prepare(second)
    prepare(first, first_thread)
    # Repeat with an already allocated PEB and an existing target thread.
    prepare(second, second_thread)
    prepare(first, first_thread)
