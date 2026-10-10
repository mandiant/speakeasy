"""Native guest DLLs: import binding against their exports."""

import struct

import pefile

from speakeasy import Speakeasy, common
from speakeasy.windows.api_image import ApiExportSpec, build_api_image
from speakeasy.windows.loaders import ImportEntry, LoadedImage, MemoryRegion
from tests.guest_harness import read_pointer


def make_native_dll(emu, path):
    base, _ = emu.get_valid_ranges(0x20000, addr=0x62000000)
    image = build_api_image(
        name="guest_dependency",
        arch=emu.arch,
        base=base,
        emu_path="guest_dependency.dll",
        exports=[
            ApiExportSpec("Initializer"),
            ApiExportSpec("TlsCallback"),
            ApiExportSpec("GetTickCount"),
            ApiExportSpec("Flag", kind="data"),
        ],
    )
    exports = {entry.name: entry.address for entry in image.exports}
    flag = exports["Flag"]
    data = bytearray(image.image_size)
    for region in image.regions:
        offset = region.base - base
        data[offset : offset + len(region.data)] = region.data
    ret = b"\xc2\x0c\x00" if emu.ptr_size == 4 else b"\xc3"
    for name, value in [("TlsCallback", 1), ("Initializer", 1)]:
        address = exports[name]
        increment = b"\xff\x05" + (
            struct.pack("<I", flag) if emu.ptr_size == 4 else struct.pack("<i", flag - address - 6)
        )
        code = increment + b"\xb8" + struct.pack("<I", value) + ret
        data[address - base : address - base + len(code)] = code
    address = exports["GetTickCount"]
    code = (
        (b"\xa1" + struct.pack("<I", flag))
        if emu.ptr_size == 4
        else (b"\x8b\x05" + struct.pack("<i", flag - address - 6))
    )
    data[address - base : address - base + len(code) + 1] = code + b"\xc3"
    tls_rva = flag - base + 0x40
    callbacks_rva = tls_rva + 0x40
    if emu.ptr_size == 4:
        tls = struct.pack("<6I", 0, 0, flag + 0x20, base + callbacks_rva, 0, 0)
    else:
        tls = struct.pack("<4Q2I", 0, 0, flag + 0x20, base + callbacks_rva, 0, 0)
    data[tls_rva : tls_rva + len(tls)] = tls
    data[callbacks_rva : callbacks_rva + emu.ptr_size * 2] = (
        exports["TlsCallback"].to_bytes(emu.ptr_size, "little") + b"\0" * emu.ptr_size
    )
    pe = pefile.PE(data=bytes(data))
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = exports["Initializer"] - base
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress = tls_rva
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size = len(tls)
    path.write_bytes(pe.write())
    return exports


def native_config(config, tmp_path):
    config["modules"]["module_directory_x86"] = str(tmp_path)
    config["modules"]["module_directory_x64"] = str(tmp_path)
    return config


def test_guest_image_imports_cannot_invent_native_exports(config, tmp_path):
    se = Speakeasy(config=native_config(config, tmp_path))
    try:
        se.load_shellcode(data=b"\xc3", arch="x86")
        exports = make_native_dll(se.emu, tmp_path / "guest_dependency.dll")
        base, _ = se.emu.get_valid_ranges(0x1000, addr=0x64000000)
        image = LoadedImage(
            arch=se.get_arch(),
            module_type="dll",
            name="import_policy",
            emu_path="import_policy.dll",
            image_base=base,
            image_size=0x1000,
            regions=[MemoryRegion(base, b"\x41" * 0x1000, ".data", common.PERM_MEM_RWX)],
            imports=[
                ImportEntry(base, "guest_dependency", "GetTickCount"),
                ImportEntry(base + 4, "guest_dependency", "MissingExport"),
                ImportEntry(base + 8, "guest_dependency", "Flag"),
            ],
            exports=[],
            default_export_mode="native",
            entry_points=[],
        )

        se.load_image(image)
        assert read_pointer(se, base) == exports["GetTickCount"]
        assert se.mem_read(base + 4, 4) == b"\x41" * 4
        assert read_pointer(se, base + 8) == exports["Flag"]
        assert "MissingExport" not in {name for _, name in se.get_symbols().values()}
    finally:
        se.shutdown()
