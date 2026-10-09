"""Injected PE import repair shares addresses and preserves guest IAT patches."""

import struct

import pytest
import unicorn as uc

from speakeasy.errors import WindowsEmuError
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


def _map_two_imports(emu, zero_oft, bad_second=False):
    base, _ = emu.get_valid_ranges(0x20000, addr=0x62000000)
    image = build_api_image(name="atomic_imports", arch=emu.arch, base=base, emu_path="atomic.dll", exports=[])
    data = bytearray(image.image_size)
    for region in image.regions:
        offset = region.base - base
        data[offset : offset + len(region.data)] = region.data
    ptr = emu.ptr_size
    descriptor = next(section.virtual_address for section in image.sections if section.name == ".data")
    ilt, iat, dll, first, second = [descriptor + offset for offset in (0x80, 0xA0, 0xC0, 0xE0, 0x100)]
    struct.pack_into("<II", data, 0x98 + (112 if ptr == 8 else 96) + 8, descriptor, 40)
    struct.pack_into("<5I", data, descriptor, 0 if zero_oft else ilt, 0, 0, dll, iat)
    thunks = first.to_bytes(ptr, "little") + (image.image_size - 1 if bad_second else second).to_bytes(ptr, "little")
    data[ilt : ilt + len(thunks)] = thunks
    data[iat : iat + len(thunks)] = thunks
    data[dll : dll + 13] = b"kernel32.dll\0"
    for rva, name in ((first, "GetTickCount"), (second, "GetCurrentProcess")):
        encoded = b"\0\0" + name.encode("ascii") + b"\0"
        data[rva : rva + len(encoded)] = encoded
    assert emu.mem_map(len(data), base=base, tag="test.atomic_imports") == base
    emu.mem_write(base, bytes(data))
    return base, base + iat, thunks


@pytest.mark.parametrize("zero_oft", [False, True])
@pytest.mark.parametrize("failure", ["missing", "resolution_error", "bad_rva"])
def test_second_import_failure_leaves_original_iat_intact(api_emu, monkeypatch, zero_oft, failure):
    emu = api_emu.emu
    address = emu.get_proc("kernel32", "GetTickCount")
    assert address
    base, iat, original = _map_two_imports(emu, zero_oft, bad_second=failure == "bad_rva")
    bindings = dict(emu._import_bindings)
    resolutions = []
    writes = []
    write = emu.mem_write

    def resolve(dll, reference):
        resolutions.append(reference)
        assert emu.mem_read(iat, len(original)) == original
        if reference == "GetTickCount":
            return address
        if failure == "resolution_error":
            raise WindowsEmuError("second import resolution failed")
        return 0

    def record_write(slot, data):
        if iat <= slot < iat + len(original):
            writes.append(slot)
        return write(slot, data)

    monkeypatch.setattr(emu, "get_proc", resolve)
    monkeypatch.setattr(emu, "mem_write", record_write)
    emu.ensure_pe_import_hooks(base)
    assert resolutions == (["GetTickCount"] if failure == "bad_rva" else ["GetTickCount", "GetCurrentProcess"])
    assert writes == []
    assert emu.mem_read(iat, len(original)) == original
    assert emu._import_bindings == bindings


@pytest.mark.parametrize("zero_oft", [False, True])
def test_commit_fault_restores_all_attempted_iat_writes(api_emu, monkeypatch, zero_oft):
    emu = api_emu.emu
    targets = {name: emu.get_proc("kernel32", name) for name in ("GetTickCount", "GetCurrentProcess")}
    assert all(targets.values())
    base, iat, original = _map_two_imports(emu, zero_oft)
    bindings = dict(emu._import_bindings)
    write = emu.mem_write
    faulted = []

    def fail_second_write(slot, data):
        if slot == iat + emu.ptr_size and not faulted:
            # Simulate a backend that modifies memory before reporting failure.
            write(slot, data)
            assert emu.mem_read(slot, emu.ptr_size) != original[emu.ptr_size :]
            faulted.append(slot)
            raise uc.UcError(uc.UC_ERR_WRITE_UNMAPPED)
        return write(slot, data)

    monkeypatch.setattr(emu, "get_proc", lambda dll, reference: targets[reference])
    monkeypatch.setattr(emu, "mem_write", fail_second_write)
    emu.ensure_pe_import_hooks(base)
    assert faulted == [iat + emu.ptr_size]
    assert emu.mem_read(iat, len(original)) == original
    assert emu._import_bindings == bindings
    # A restored zero-OFT table must remain resolvable on the next attempt.
    emu.ensure_pe_import_hooks(base)
    assert emu.mem_read(iat, len(original)) == b"".join(
        targets[name].to_bytes(emu.ptr_size, "little") for name in ("GetTickCount", "GetCurrentProcess")
    )
    assert emu._import_bindings[iat] == targets["GetTickCount"]
    assert emu._import_bindings[iat + emu.ptr_size] == targets["GetCurrentProcess"]
