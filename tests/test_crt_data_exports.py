"""Explicit CRT data exports share writable storage with pointer accessors."""

import pefile
import pytest
import unicorn as uc

from speakeasy import Speakeasy


@pytest.fixture(params=["x86", "amd64"])
def crt_session(request, config):
    config["timeout"] = 2
    config["max_api_count"] = 200
    se = Speakeasy(config=config)
    try:
        base = se.load_shellcode(data=b"\xc3", arch=request.param)
        se.run_shellcode(base)
        assert se.get_report().entry_points[0].error is None
        yield se
    finally:
        se.shutdown()


def region_permissions(se, address):
    return next(perms for start, end, perms in se.emu.get_mem_regions() if start <= address <= end)


@pytest.mark.parametrize(
    "name, accessor, initial",
    [("_fmode", "__p__fmode", 0x4000), ("_commode", "__p__commode", 0x4000), ("__initenv", "__p___initenv", 0)],
)
@pytest.mark.parametrize("accessor_first", [False, True], ids=["export-first", "accessor-first"])
def test_public_crt_data_export_and_accessor_share_guest_writable_storage(
    crt_session, name, accessor, initial, accessor_first
):
    se = crt_session
    emu = se.emu
    ptr_size = emu.get_ptr_size()
    function = emu.get_proc("msvcrt", accessor)
    first_pointer = None
    if accessor_first:
        se.call(function)
        assert se.get_report().entry_points[-1].error is None
        first_pointer = se.reg_read("rax" if ptr_size == 8 else "eax")
    address = emu.get_proc("msvcrt", name)
    if accessor_first:
        assert first_pointer == address
    entry = emu.api_registry.entries[address]
    module = emu.get_mod_by_name("msvcrt")
    assert entry.export.kind == "data"
    assert entry.export.visibility != "dynamic"
    assert entry.trap is None
    assert module.get_export_by_name(name).address == address
    assert module.get_section_for_addr(address).name == ".data"
    assert region_permissions(se, address) == uc.UC_PROT_READ | uc.UC_PROT_WRITE
    assert region_permissions(se, function) == uc.UC_PROT_READ | uc.UC_PROT_EXEC
    assert se.get_symbols()[address] == ("msvcrt", name)
    assert se.get_api_symbols()[address] == f"msvcrt.{name}"
    assert se.get_symbol_from_address(address) == f"msvcrt.{name}"
    assert set(emu.api_registry.traps).isdisjoint(se.get_symbols())
    parsed = pefile.PE(data=se.mem_read(module.base, module.image_size))
    export = next(e for e in parsed.DIRECTORY_ENTRY_EXPORT.symbols if e.name == name.encode())
    assert module.base + export.address == address
    width = ptr_size if name == "__initenv" else 4
    assert int.from_bytes(se.mem_read(address, width), "little") == initial

    if name == "__initenv":
        # A 64-bit pointer above 4 GB catches accidental DWORD storage writes.
        value = se.mem_alloc(0x1000, base=0x180000000 if ptr_size == 8 else 0x20000000)
        se.mem_write(value, b"\x00" * ptr_size)
    else:
        value = 0x8000
    # Execute an actual guest store: host mem_write alone bypasses page protection.
    code = (b"\xb8" if ptr_size == 4 else b"\x48\xb8") + address.to_bytes(ptr_size, "little")
    if width == 8:
        code += b"\x48\xb9" + value.to_bytes(8, "little") + b"\x48\x89\x08"
    else:
        code += b"\xc7\x00" + value.to_bytes(4, "little")
    writer = se.mem_alloc(0x1000)
    se.mem_write(writer, code + b"\xc3")
    se.call(writer)
    assert se.get_report().entry_points[-1].error is None
    assert int.from_bytes(se.mem_read(address, width), "little") == value

    # Existing CRT aliases normalize to the same module and actual storage.
    assert emu.get_proc("msvcr90", name) == address
    assert emu.get_proc("msvcr90", accessor) == function
    for _ in range(2):
        se.call(function)
        assert se.get_report().entry_points[-1].error is None
        assert se.reg_read("rax" if ptr_size == 8 else "eax") == address
        assert int.from_bytes(se.mem_read(address, width), "little") == value
    assert region_permissions(se, function) == uc.UC_PROT_READ | uc.UC_PROT_EXEC
