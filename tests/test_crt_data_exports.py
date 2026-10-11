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
    [("_fmode", "__p__fmode", 0x4000), ("__initenv", "__p___initenv", 0)],
)
def test_crt_data_export_and_accessor_share_guest_writable_storage(crt_session, name, accessor, initial):
    se = crt_session
    emu = se.emu
    ptr_size = emu.get_ptr_size()
    result = "rax" if ptr_size == 8 else "eax"
    function = emu.get_proc("msvcrt", accessor)
    se.call(function)
    assert se.get_report().entry_points[-1].error is None
    address = se.reg_read(result)
    assert emu.get_proc("msvcrt", name) == address
    module = emu.get_mod_by_name("msvcrt")
    assert module.get_export_by_name(name).address == address
    assert module.get_section_for_addr(address).name == ".data"
    assert region_permissions(se, address) == uc.UC_PROT_READ | uc.UC_PROT_WRITE
    assert se.get_symbols()[address] == ("msvcrt", name)
    parsed = pefile.PE(data=se.mem_read(module.base, module.image_size))
    export = next(e for e in parsed.DIRECTORY_ENTRY_EXPORT.symbols if e.name == name.encode())
    assert module.base + export.address == address
    width = ptr_size if name == "__initenv" else 4
    assert int.from_bytes(se.mem_read(address, width), "little") == initial

    # A pointer above 4 GB on x64 catches DWORD-sized storage.
    value = 0x8000
    if name == "__initenv":
        value = se.mem_alloc(0x1000, base=0x180000000 if ptr_size == 8 else 0x20000000)
    # A guest store checks page protection; a host mem_write would bypass it.
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

    assert emu.get_proc("msvcr90", name) == address
    assert emu.get_proc("msvcr90", accessor) == function
    se.call(function)
    assert se.get_report().entry_points[-1].error is None
    assert se.reg_read(result) == address
    assert int.from_bytes(se.mem_read(address, width), "little") == value
