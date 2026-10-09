"""Resolution and execution invariants across the public mapped API boundary."""

import struct

import pefile
import pytest
import unicorn as uc

from speakeasy.errors import WindowsEmuError
from speakeasy.profiler import Run
from speakeasy.winenv import arch
from tests.handler_harness import alloc, call


@pytest.fixture(params=["dll_emu", "dll64_emu"])
def api_emu(request):
    return request.getfixturevalue(request.param)


def export_bytes(emu, module):
    return emu.mem_read(module.base, module.image_size)


def test_iats_and_lookup_share_public_entries(api_emu):
    emu = api_emu.emu
    primary = emu.modules[0]
    for imp in primary._image.imports:
        address = int.from_bytes(emu.mem_read(imp.iat_address, emu.get_ptr_size()), "little")
        assert address == emu.get_proc(imp.dll_name, imp.func_name)
        assert emu.get_address_map(address) is not None
        assert emu.get_symbol_from_address(address)
        entry = emu.api_registry.entries[address]
        if entry.export.kind == "function":
            assert entry.trap in emu.api_registry.traps
            assert emu.get_address_map(entry.trap) is None


def test_metadata_export_eat_getproc_and_ordinal_agree(api_emu):
    emu = api_emu.emu
    address = emu.get_proc("kernel32", "MoveFileExW")
    module = emu.get_mod_by_name("kernel32")
    export = module.get_export_by_name("MoveFileExW")
    parsed = pefile.PE(data=export_bytes(emu, module))
    pe_export = next(e for e in parsed.DIRECTORY_ENTRY_EXPORT.symbols if e.name == b"MoveFileExW")
    assert address == module.base + pe_export.address == export.address
    name = alloc(api_emu, b"MoveFileExW\0")
    rv, _ = call(api_emu, "kernel32", "GetProcAddress", [module.base, name])
    assert rv == address
    rv, _ = call(api_emu, "kernel32", "GetProcAddress", [module.base, export.ordinal])
    assert rv == address
    ptr = emu.get_ptr_size()
    ansi = alloc(api_emu, struct.pack("<HH", 11, 12) + (b"\0" * 4 if ptr == 8 else b"") + name.to_bytes(ptr, "little"))
    output = alloc(api_emu, b"\0" * ptr)
    status, _ = call(api_emu, "ntdll", "LdrGetProcedureAddress", [module.base, ansi, 0, output])
    assert status == 0
    assert int.from_bytes(emu.mem_read(output, ptr), "little") == address
    assert emu.mem_read(address, 2) == (b"\x8b\xff" if ptr == 4 else b"\x66\x90")
    assert emu.get_symbol_from_address(address + 2).endswith("MoveFileExW+0x2")


def test_missing_known_export_fails_both_resolvers(api_emu):
    emu = api_emu.emu
    module = emu.get_mod_by_name("kernel32")
    name = alloc(api_emu, b"NotARealKernel32Export\0")
    result, _ = call(api_emu, "kernel32", "GetProcAddress", [module.base, name])
    assert result == 0
    output = alloc(api_emu, b"\0" * emu.get_ptr_size())
    status, _ = call(api_emu, "ntdll", "LdrGetProcedureAddress", [module.base, 0, 65535, output])
    assert status != 0
    assert emu.mem_read(output, emu.get_ptr_size()) == b"\0" * emu.get_ptr_size()


def test_unknown_dynamic_entries_leave_eat_unchanged(api_emu):
    emu = api_emu.emu
    module = emu.load_module_by_name("unknown_vendor")
    original = module.get_exports().copy()
    parsed_before = pefile.PE(data=export_bytes(emu, module))
    directory = parsed_before.OPTIONAL_HEADER.DATA_DIRECTORY[0]
    address = emu.resolve_export(module, "UnknownFunction")
    assert address == emu.resolve_export(module, "UnknownFunction")
    assert address != emu.resolve_export(module, "AnotherFunction")
    assert module.get_exports() == original == []
    parsed_after = pefile.PE(data=export_bytes(emu, module))
    assert parsed_after.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress == directory.VirtualAddress
    assert parsed_after.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size == directory.Size
    assert module.base <= address < module.base + module.image_size
    assert emu.get_symbol_from_address(address) == "unknown_vendor.UnknownFunction"
    symbols = api_emu.get_api_symbols()
    assert symbols[address] == "unknown_vendor.UnknownFunction"
    assert set(emu.api_registry.traps).isdisjoint(symbols)
    region = next(r for r in emu.get_mem_regions() if r[0] <= address <= r[1])
    assert region[2] & uc.UC_PROT_EXEC
    assert not region[2] & uc.UC_PROT_WRITE
    assert emu.mem_map(0x1000, base=emu.api_registry.trap_base, tag="guest.attempt") != emu.api_registry.trap_base


def test_dynamic_arena_exhaustion_does_not_move_entries(api_emu):
    emu = api_emu.emu
    module = emu.load_module_by_name("unknown_vendor")
    address = emu.resolve_export(module, "First")
    arena = next(section for section in module.sections if section.name == ".dyn")
    emu.api_registry.dynamic_offsets[id(module)] = arena.virtual_size
    with pytest.raises(WindowsEmuError, match="exhausted"):
        emu.api_registry.dynamic(module, "Last")
    assert emu.resolve_export(module, "First") == address


def test_exported_variable_is_shared_storage(api_emu):
    emu = api_emu.emu
    address = emu.get_proc("msvcrt", "_acmdln")
    module = emu.get_mod_by_name("msvcrt")
    assert module.get_export_by_name("_acmdln").address == address
    assert address == emu.get_proc("msvcrt", "_acmdln")
    assert emu.api_registry.entries[address].export.kind == "data"
    assert emu.api_registry.entries[address].trap is None
    pointer = int.from_bytes(emu.mem_read(address, emu.get_ptr_size()), "little")
    assert pointer and emu.mem_read(pointer, 1)
    result, _ = call(api_emu, "msvcrt", "__p__acmdln", [])
    assert result == address


@pytest.mark.parametrize("tracing", [False, True])
def test_breakpoint_precedes_dispatch_and_patches_execute(api_emu, tracing):
    emu = api_emu.emu
    # Tracing is configured at construction; exercise its actual observer hook.
    if tracing:
        emu.add_code_hook(emu._hook_code_tracing)
    emu.curr_run = Run()
    emu.profiler.add_run(emu.curr_run)
    emu.set_hooks()
    entry = emu.get_proc("kernel32", "GetTickCount")
    caller = emu.mem_map(0x1000, tag="research.caller")
    emu.mem_write(caller, b"\x90")
    hits = []
    api_emu.add_api_hook(lambda e, api, original, args: hits.append(api) or 77, "kernel32", "GetTickCount", argc=0)
    emu.set_func_args(emu.stack_base, caller, conv=arch.CALL_CONV_STDCALL)
    sp = emu.get_stack_ptr()
    bp = emu.add_code_hook(lambda e, a, n: e.emu_eng.stop(), begin=entry, end=entry)
    emu._run_api_engine(entry)
    assert emu.get_pc() == entry and emu.get_stack_ptr() == sp
    assert hits == []
    bp.disable()
    stop = emu.add_code_hook(lambda e, a, n: e.emu_eng.stop(), begin=caller, end=caller)
    emu._run_api_engine(entry)
    assert hits == ["kernel32.GetTickCount"]
    assert emu.get_pc() == caller
    assert emu.get_stack_ptr() == sp + emu.get_ptr_size()
    # A guest patch replaces the trampoline rather than being intercepted by name.
    emu.mem_write(entry, b"\xb8\x2a\0\0\0\xc3")
    emu.set_func_args(emu.stack_base, caller, conv=arch.CALL_CONV_STDCALL)
    emu._run_api_engine(entry)
    assert hits == ["kernel32.GetTickCount"]
    assert emu.get_return_val() == 42
    stop.disable()


def test_forwarders_share_target_and_preserve_export_strings(api_emu):
    from speakeasy.windows.api_image import ApiExportSpec, build_api_image

    emu = api_emu.emu
    base, _ = emu.get_valid_ranges(0x20000, addr=0x63000000)
    image = build_api_image(
        name="forwarding_test",
        arch=emu.arch,
        base=base,
        emu_path="forwarding_test.dll",
        exports=[
            ApiExportSpec("Tick", forwarder="kernel32.GetTickCount"),
            ApiExportSpec("Variable", forwarder="msvcrt._acmdln"),
            ApiExportSpec("Cycle", forwarder="forwarding_test.Cycle"),
            ApiExportSpec("Missing", forwarder="kernel32.NotARealExport"),
        ],
    )
    module = emu.load_image(image)
    before = export_bytes(emu, module)
    assert emu.resolve_export(module, "Tick") == emu.get_proc("kernel32", "GetTickCount")
    assert emu.resolve_export(module, "Variable") == emu.get_proc("msvcrt", "_acmdln")
    assert emu.resolve_export(module, "Cycle") == 0
    assert emu.resolve_export(module, "Missing") == 0
    assert export_bytes(emu, module) == before
    assert all(emu.api_registry.entries[e.address].trap is None for e in module.get_exports())


def test_private_traps_never_reach_user_fault_hooks(api_emu):
    emu = api_emu.emu
    emu.curr_run = Run()
    emu.profiler.add_run(emu.curr_run)
    emu.set_hooks()
    target = emu.get_proc("kernel32", "GetTickCount")
    trap = emu.api_registry.entries[target].trap
    observed = []
    api_emu.add_mem_invalid_hook(lambda *args: observed.append(args) or True)
    # An unregistered token is a genuine control-target error, never fake memory.
    invalid = emu.api_registry.trap_base + emu.api_registry.TRAP_SIZE - 1
    emu._run_api_engine(invalid)
    assert emu.curr_run.error.type == "invalid_fetch"
    assert observed == []
    assert emu.get_address_map(invalid) is None
    assert emu.get_address_map(trap) is None


@pytest.mark.parametrize("copied_pointer", [False, True])
def test_same_address_alias_hooks_merge_once_with_canonical_telemetry(api_emu, copied_pointer):
    from speakeasy.windows.api_image import ApiExportSpec, build_api_image

    emu = api_emu.emu
    base, _ = emu.get_valid_ranges(0x20000, addr=0x63000000)
    module = emu.load_image(
        build_api_image(
            name="alias_hooks",
            arch=emu.arch,
            base=base,
            emu_path="alias_hooks.dll",
            exports=[ApiExportSpec("GetTickCount", 7), ApiExportSpec("TickAlias", 7)],
        )
    )
    # Supply an implemented canonical handler so the ordinary hook chain runs.
    emu.api.mods["alias_hooks"] = emu.api.load_api_handler("kernel32")
    secondary = emu.resolve_export(module, "TickAlias")
    canonical = emu.resolve_export(module, "GetTickCount")
    assert secondary == canonical
    parsed = pefile.PE(data=export_bytes(emu, module))
    assert {e.address for e in parsed.DIRECTORY_ENTRY_EXPORT.symbols} == {canonical - module.base}
    observed = []

    def register(label, module_pattern, name_pattern, result):
        def callback(e, api, original, args):
            observed.append((label, api))
            assert original is not None and args == []
            return result

        return api_emu.add_api_hook(callback, module_pattern, name_pattern, argc=0)

    wildcard_first = register("wildcard-first", "alias_hooks", "*", 11)
    secondary_first = register("secondary-first", "alias_hooks", "TickAlias", 22)
    canonical_second = register("canonical-second", "alias_hooks", "GetTickCount", 33)
    module_wildcard = register("module-wildcard-exact-name", "alias_*", "TickAlias", 44)
    secondary_last = register("secondary-last", "alias_hooks", "TickAlias", 55)
    wildcard_last = register("wildcard-last", "alias_*", "*", 66)
    expected = [secondary_first, canonical_second, module_wildcard, secondary_last, wildcard_first, wildcard_last]
    assert emu.get_api_hooks("alias_hooks", "GetTickCount") == expected
    assert emu.get_api_hooks("alias_hooks", "TickAlias") == expected
    emu.curr_run = Run()
    emu.profiler.add_run(emu.curr_run)
    emu.set_hooks()
    caller = emu.mem_map(0x1000, tag="test.alias.caller")
    return_address = caller + 0x40
    if copied_pointer:
        pointer = caller + 0x100
        emu.mem_write(pointer, secondary.to_bytes(emu.ptr_size, "little"))
        operand = pointer if emu.ptr_size == 4 else pointer - caller - 6
        emu.mem_write(caller, b"\xff\x15" + struct.pack("<I", operand) + b"\x90")
        return_address = caller + 6
        start = caller
    else:
        start = secondary
    emu.set_func_args(emu.stack_base, return_address, conv=arch.CALL_CONV_STDCALL)
    stop = emu.add_code_hook(lambda e, a, n: e.emu_eng.stop(), begin=return_address, end=return_address)
    try:
        emu._run_api_engine(start)
    finally:
        stop.disable()
    assert [label for label, _ in observed] == [
        "secondary-first",
        "canonical-second",
        "module-wildcard-exact-name",
        "secondary-last",
        "wildcard-first",
        "wildcard-last",
    ]
    assert {api for _, api in observed} == {"alias_hooks.GetTickCount"}
    assert emu.get_return_val() == 66
    assert [event.api_name for event in emu.curr_run.events if event.event == "api"] == ["alias_hooks.GetTickCount"]


def test_unaliased_hook_lookup_preserves_base_order(api_emu):
    from speakeasy.binemu import BinaryEmulator

    emu = api_emu.emu

    def callback(*args):
        return 0

    api_emu.add_api_hook(callback, "kernel*", "*", argc=0)
    api_emu.add_api_hook(callback, "kernel32", "GetTickCount", argc=0)
    api_emu.add_api_hook(callback, "kernel32", "Get*", argc=0)
    assert emu.get_api_hooks("kernel32", "GetTickCount") == BinaryEmulator.get_api_hooks(
        emu, "kernel32", "GetTickCount"
    )
