"""Import repair of an injected PE binds registry addresses and skips invalid slots."""

import struct

import pytest

from speakeasy.windows.api_image import build_api_image


@pytest.fixture(params=["dll_emu", "dll64_emu"])
def api_emu(request):
    return request.getfixturevalue(request.param)


def map_injected_pe(emu, names, zero_oft=False, bad_index=None):
    """Map a PE that imports `names` from kernel32 into memory outside the loader.

    The thunk at `bad_index` points past SizeOfImage. Returns the image base
    and the IAT address.
    """
    base, _ = emu.get_valid_ranges(0x20000, addr=0x61000000)
    image = build_api_image(name="injected", arch=emu.arch, base=base, emu_path="injected.dll", exports=[])
    data = bytearray(image.image_size)
    for region in image.regions:
        data[region.base - base : region.base - base + len(region.data)] = region.data
    ptr = emu.ptr_size
    descriptor = next(section.virtual_address for section in image.sections if section.name == ".data")
    ilt, iat, dll, strings = (descriptor + offset for offset in (0x80, 0xC0, 0x100, 0x120))
    optional_header = 0x98
    struct.pack_into("<II", data, optional_header + (112 if ptr == 8 else 96) + 8, descriptor, 40)
    struct.pack_into("<5I", data, descriptor, 0 if zero_oft else ilt, 0, 0, dll, iat)
    data[dll : dll + 13] = b"kernel32.dll\0"
    thunks = []
    for index, name in enumerate(names):
        encoded = b"\0\0" + name.encode("ascii") + b"\0"
        data[strings : strings + len(encoded)] = encoded
        thunks.append(image.image_size - 1 if index == bad_index else strings)
        strings += len(encoded)
    table = b"".join(thunk.to_bytes(ptr, "little") for thunk in thunks)
    data[ilt : ilt + len(table)] = table
    data[iat : iat + len(table)] = table
    assert emu.mem_map(len(data), base=base, tag="test.injected") == base
    emu.mem_write(base, bytes(data))
    return base, base + iat


def read_slots(emu, iat, count):
    return [int.from_bytes(emu.mem_read(iat + index * emu.ptr_size, emu.ptr_size), "little") for index in range(count)]


@pytest.mark.parametrize("zero_oft", [False, True])
def test_injected_import_repair_binds_registry_address_and_keeps_guest_patch(api_emu, zero_oft):
    emu = api_emu.emu
    base, iat = map_injected_pe(emu, ["GetTickCount"], zero_oft)

    emu.ensure_pe_import_hooks(base)
    entry = emu.get_proc("kernel32", "GetTickCount")
    assert read_slots(emu, iat, 1) == [entry]

    emu.ensure_pe_import_hooks(base)
    assert read_slots(emu, iat, 1) == [entry]

    patch = emu.mem_map(0x1000, tag="test.guest_iat_hook")
    emu.mem_write(iat, patch.to_bytes(emu.ptr_size, "little"))
    emu.ensure_pe_import_hooks(base)
    assert read_slots(emu, iat, 1) == [patch]


def test_malformed_injected_import_slot_follows_parsing_policy(dll_emu):
    emu = dll_emu.emu
    names = ["GetTickCount", "GetCurrentProcess", "GetCurrentThread"]
    base, iat = map_injected_pe(emu, names, bad_index=1)
    thunks = read_slots(emu, iat, 3)

    emu.ensure_pe_import_hooks(base)

    assert read_slots(emu, iat, 3) == [
        emu.get_proc("kernel32", "GetTickCount"),
        thunks[1],
        emu.get_proc("kernel32", "GetCurrentThread"),
    ]
