"""Injected PE import repair shares addresses and preserves guest IAT patches."""

import struct

import pytest

from speakeasy.windows.api_image import build_api_image


@pytest.fixture(params=["dll_emu", "dll64_emu"])
def api_emu(request):
    return request.getfixturevalue(request.param)


@pytest.mark.parametrize("zero_oft", [False, True])
def test_injected_import_repair_reuses_entry_and_preserves_hook(api_emu, zero_oft):
    emu = api_emu.emu
    base, _ = emu.get_valid_ranges(0x20000, addr=0x61000000)
    image = build_api_image(name="injected", arch=emu.arch, base=base, emu_path="injected.dll", exports=[])
    data = bytearray(image.image_size)
    for region in image.regions:
        offset = region.base - base
        data[offset : offset + len(region.data)] = region.data
    ptr = emu.ptr_size
    section = next(section for section in image.sections if section.name == ".data")
    descriptor = section.virtual_address
    ilt, iat, dll, symbol = [descriptor + offset for offset in (0x80, 0xA0, 0xC0, 0xE0)]
    opt = 0x98
    struct.pack_into("<II", data, opt + (112 if ptr == 8 else 96) + 8, descriptor, 40)
    struct.pack_into("<5I", data, descriptor, 0 if zero_oft else ilt, 0, 0, dll, iat)
    data[ilt : ilt + ptr] = symbol.to_bytes(ptr, "little")
    data[iat : iat + ptr] = symbol.to_bytes(ptr, "little")
    data[dll : dll + 13] = b"kernel32.dll\0"
    data[symbol : symbol + 15] = b"\0\0GetTickCount\0"
    assert emu.mem_map(len(data), base=base, tag="test.injected") == base
    emu.mem_write(base, bytes(data))
    emu.ensure_pe_import_hooks(base)
    entry = emu.get_proc("kernel32", "GetTickCount")
    assert int.from_bytes(emu.mem_read(base + iat, ptr), "little") == entry
    before = len(emu.api_registry.entries)
    emu.ensure_pe_import_hooks(base)
    assert len(emu.api_registry.entries) == before
    patch = emu.mem_map(0x1000, tag="test.guest_iat_hook")
    emu.mem_write(patch, b"\xc3")
    emu.mem_write(base + iat, patch.to_bytes(ptr, "little"))
    emu.ensure_pe_import_hooks(base)
    assert int.from_bytes(emu.mem_read(base + iat, ptr), "little") == patch
    assert emu._import_bindings[base + iat] == entry
    # A valid name-table lookup cannot read a symbol outside SizeOfImage.
    if not zero_oft:
        emu.mem_write(base + ilt, (image.image_size + 0x100).to_bytes(ptr, "little"))
        emu.mem_write(base + iat, (image.image_size + 0x100).to_bytes(ptr, "little"))
        emu.ensure_pe_import_hooks(base)
        assert len(emu.api_registry.entries) == before
