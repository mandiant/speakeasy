"""Native guest DLLs: TLS callback and DllMain order, failure policy, and import binding."""

import struct

import pefile
import pytest

from speakeasy import Speakeasy, common
from speakeasy.errors import WindowsEmuError
from speakeasy.windows.api_image import ApiExportSpec, build_api_image
from speakeasy.windows.loaders import ImportEntry, LoadedImage, MemoryRegion
from tests.guest_harness import Deref, get_api, guest_call, read_pointer


def make_native_dll(emu, path, result=1):
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
    for name, value in [("TlsCallback", 1), ("Initializer", result)]:
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


def image_base(path):
    return pefile.PE(str(path), fast_load=True).OPTIONAL_HEADER.ImageBase


def native_config(config, tmp_path, strict=False):
    config["modules"]["module_directory_x86"] = str(tmp_path)
    config["modules"]["module_directory_x64"] = str(tmp_path)
    config["modules"]["strict_loading"] = strict
    return config


@pytest.mark.parametrize("arch", ["x86", "amd64"])
def test_runtime_load_runs_tls_callback_and_dllmain_once(config, tmp_path, arch):
    se = Speakeasy(config=native_config(config, tmp_path))
    try:
        code = se.load_shellcode(data=b"\xc3" * 0x400, arch=arch)
        ptr = se.get_ptr_size()
        exports = make_native_dll(se.emu, tmp_path / "guest_dependency.dll")
        data = se.mem_alloc(0x1000, base=0x20000000)
        dll_name, export_name, results = data, data + 0x40, data + 0x80
        se.mem_write(dll_name, b"guest_dependency.dll\0")
        se.mem_write(export_name, b"GetTickCount\0")
        load_library = get_api(se, "kernel32", "LoadLibraryA")
        program = guest_call(ptr, load_library, dll_name, store=results)
        program += guest_call(ptr, load_library, dll_name, store=results + 8)
        program += guest_call(
            ptr, get_api(se, "kernel32", "GetProcAddress"), Deref(results), export_name, store=results + 16
        )
        program += guest_call(ptr, exports["GetTickCount"], store=results + 24)
        se.mem_write(code, program + b"\xc3")

        se.run_shellcode(code)

        report = se.get_report()
        assert [ep.error for ep in report.entry_points] == [None]
        base = se.emu.get_mod_by_name("guest_dependency").base
        assert read_pointer(se, results) == base
        assert read_pointer(se, results + 8) == base
        assert read_pointer(se, results + 16) == exports["GetTickCount"]
        # The export reads a counter that the TLS callback and DllMain each increment.
        assert read_pointer(se, results + 24) & 0xFFFFFFFF == 2
        apis = [event.api_name for event in report.entry_points[0].events if event.event == "api"]
        assert not any(api.endswith("GetTickCount") for api in apis)
    finally:
        se.shutdown()


@pytest.mark.parametrize("result", [0, 0x100], ids=["false", "low-byte-false"])
@pytest.mark.parametrize("arch", ["x86", "amd64"])
def test_failed_dllmain_fails_runtime_load_and_unmaps_dll(config, tmp_path, arch, result):
    se = Speakeasy(config=native_config(config, tmp_path))
    try:
        code = se.load_shellcode(data=b"\xc3" * 0x400, arch=arch)
        ptr = se.get_ptr_size()
        exports = make_native_dll(se.emu, tmp_path / "guest_dependency.dll", result=result)
        data = se.mem_alloc(0x1000, base=0x20000000)
        dll_name, wide_name, unicode, handle, results = (data + offset for offset in range(0, 0x140, 0x40))
        text = "guest_dependency.dll".encode("utf-16le")
        se.mem_write(dll_name, b"guest_dependency.dll\0")
        se.mem_write(wide_name, text + b"\0\0")
        padding = b"\0" * 4 if ptr == 8 else b""
        se.mem_write(
            unicode, struct.pack("<HH", len(text), len(text) + 2) + padding + wide_name.to_bytes(ptr, "little")
        )
        se.mem_write(handle, b"\xcc" * ptr)
        program = guest_call(ptr, get_api(se, "kernel32", "LoadLibraryA"), dll_name, store=results)
        program += guest_call(ptr, get_api(se, "ntdll", "LdrLoadDll"), 0, 0, unicode, handle, store=results + 8)
        se.mem_write(code, program + b"\xc3")

        se.run_shellcode(code)

        assert [ep.error for ep in se.get_report().entry_points] == [None]
        assert read_pointer(se, results) == 0
        assert read_pointer(se, results + 8) & 0xFFFFFFFF == 0xC0000142
        assert read_pointer(se, handle) == 0
        assert se.get_address_map(exports["Flag"]) is None
    finally:
        se.shutdown()


@pytest.mark.parametrize("strict", [False, True], ids=["lenient", "strict"])
def test_startup_dllmain_failure_policy(config, tmp_path, strict):
    builder = Speakeasy(config=config)
    try:
        builder.load_shellcode(data=b"\xc3", arch="x86")
        first = make_native_dll(builder.emu, tmp_path / "first.dll", result=0)
        builder.mem_alloc(0x20000, base=image_base(tmp_path / "first.dll"))
        second = make_native_dll(builder.emu, tmp_path / "second.dll")
    finally:
        builder.shutdown()
    config["modules"]["user_modules"] += [
        {"name": name, "base_addr": hex(image_base(tmp_path / f"{name}.dll")), "path": f"C:\\Windows\\{name}.dll"}
        for name in ("first", "second")
    ]
    se = Speakeasy(config=native_config(config, tmp_path, strict))
    try:
        code = se.load_shellcode(data=b"\xc3" * 0x100, arch="x86")
        kernel32 = se.mem_alloc(0x100, base=0x20000000)
        se.mem_write(kernel32, b"kernel32.dll\0")
        program = guest_call(4, get_api(se, "kernel32", "LoadLibraryA"), kernel32)
        program += guest_call(4, second["GetTickCount"])
        se.mem_write(code, program + b"\xc3")

        se.run_shellcode(code)

        runs = [(ep.ep_type, ep.error.type if ep.error else None) for ep in se.get_report().entry_points]
        failed_startup = [
            ("dependency.first.tls_callback", None),
            ("dependency.first.dll_entry", "dll_initialization_failed"),
        ]
        if strict:
            assert runs == failed_startup
            assert se.get_address_map(first["Flag"]) is None
        else:
            assert runs == failed_startup + [
                ("dependency.second.tls_callback", None),
                ("dependency.second.dll_entry", None),
                ("shellcode", None),
            ]
            assert se.get_report().entry_points[-1].ret_val == 2
            assert int.from_bytes(se.mem_read(first["Flag"], 4), "little") == 2
    finally:
        se.shutdown()


@pytest.mark.parametrize("strict", [False, True], ids=["lenient", "strict"])
def test_guest_image_imports_cannot_invent_native_exports(config, tmp_path, strict):
    se = Speakeasy(config=native_config(config, tmp_path, strict))
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

        if strict:
            with pytest.raises(WindowsEmuError):
                se.load_image(image)
            assert se.get_address_map(base) is None
        else:
            se.load_image(image)
            assert read_pointer(se, base) == exports["GetTickCount"]
            assert se.mem_read(base + 4, 4) == b"\x41" * 4
            assert read_pointer(se, base + 8) == exports["Flag"]
        assert "MissingExport" not in {name for _, name in se.get_symbols().values()}
    finally:
        se.shutdown()
