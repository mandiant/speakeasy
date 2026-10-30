"""Native guest DLLs: TLS callback and DllMain order, failure policy, and import binding."""

import struct

import pefile
import pytest

from speakeasy import Speakeasy, common
from speakeasy.windows.api_image import ApiExportSpec, build_api_image
from speakeasy.windows.loaders import ImportEntry, LoadedImage, MemoryRegion
from tests.guest_harness import Deref, get_api, guest_call, read_pointer

NSIS_INSTALLER = "0ef34c5d595dc3d165d54bf14cc994de39d4009d4ea5762e3e74385437d2a178.exe.xz"


def make_native_dll(emu, path, result=1, entry_point=True, forwarder=False, fault=None, fault_body=None):
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
            *([ApiExportSpec("Forwarded", forwarder="kernel32.GetTickCount")] if forwarder else []),
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
        if name == fault:
            body = fault_body or (b"\xa1\0\0\0\0" if emu.ptr_size == 4 else b"\x8b\x04\x25\0\0\0\0")
        else:
            body = b"\xb8" + struct.pack("<I", value)
        code = increment + body + ret
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
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = exports["Initializer"] - base if entry_point else 0
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress = tls_rva
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size = len(tls)
    path.write_bytes(pe.write())
    return exports


def image_base(path):
    return pefile.PE(str(path), fast_load=True).OPTIONAL_HEADER.ImageBase


def native_config(config, tmp_path):
    config["modules"]["module_directory_x86"] = str(tmp_path)
    config["modules"]["module_directory_x64"] = str(tmp_path)
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


def test_runtime_load_of_a_dll_that_the_program_wrote(config, load_test_bin):
    """
    0ef34c5d is an NSIS installer. Before it shows its first page, it writes its nsDialogs
    plugin to a new folder under %TEMP% with CreateFileW and WriteFile, then loads it from
    that path with LoadLibraryExW. The third letter of the temp folder name comes from
    GetTickCount.
    """
    config["max_api_count"] = 300000  # NSIS calls CharNextW for each path character
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(NSIS_INSTALLER))
        loaded = []

        def after_load_library(emu, address, size):
            loaded.append(se.reg_read("eax"))
            se.stop()

        se.add_code_hook(after_load_library, begin=0x40211F, end=0x40211F)
        se.run_module(module)
        plugin = se.emu.get_mod_by_name("nsDialogs")
        events = [e for ep in se.get_report().entry_points for e in ep.events or [] if e.event == "api"]

    path = [e for e in events if e.api_name == "kernel32.LoadLibraryExW"][-1].args[0].display
    assert path.lower().startswith("c:\\windows\\temp\\ns") and path.endswith("\\nsDialogs.dll")
    create = next(e for e in events if e.api_name == "kernel32.CreateFileW" and e.args[0].display == path)
    assert any(e.api_name == "kernel32.WriteFile" and e.args[0].value == int(create.ret_val, 16) for e in events)
    assert plugin is not None
    assert loaded == [plugin.base]


@pytest.mark.parametrize(
    "arch, dll_path",
    [("amd64", b"C:\\Windows\\Temp\\nsu1.tmp\\plugin.dll"), ("x86", b"plugin.dll"), ("amd64", b"plugin.dll")],
)
def test_runtime_load_of_a_dll_that_shellcode_wrote(config, tmp_path, arch, dll_path):
    se = Speakeasy(config=config)
    try:
        code = se.load_shellcode(data=b"\xc3" * 0x800, arch=arch)
        ptr = se.get_ptr_size()
        exports = make_native_dll(se.emu, tmp_path / "plugin.dll")
        dll = (tmp_path / "plugin.dll").read_bytes()
        data = se.mem_alloc(0x1000, base=0x20000000)
        path, export_name, results = data, data + 0x40, data + 0x80
        image = se.mem_alloc(len(dll))
        se.mem_write(image, dll)
        se.mem_write(path, dll_path + b"\0")
        se.mem_write(export_name, b"GetTickCount\0")
        program = guest_call(
            ptr, get_api(se, "kernel32", "CreateFileA"), path, 0x40000000, 0, 0, 2, 0, 0, store=results
        )
        program += guest_call(
            ptr, get_api(se, "kernel32", "WriteFile"), Deref(results), image, len(dll), results + 8, 0
        )
        program += guest_call(ptr, get_api(se, "kernel32", "CloseHandle"), Deref(results))
        program += guest_call(ptr, get_api(se, "kernel32", "LoadLibraryA"), path, store=results + 16)
        program += guest_call(
            ptr, get_api(se, "kernel32", "GetProcAddress"), Deref(results + 16), export_name, store=results + 24
        )
        program += guest_call(ptr, exports["GetTickCount"], store=results + 32)
        se.mem_write(code, program + b"\xc3")

        se.run_shellcode(code)

        assert [ep.error for ep in se.get_report().entry_points] == [None]
        module = se.emu.get_mod_by_name("plugin")
        assert module is not None
        assert read_pointer(se, results + 16) == module.base
        assert read_pointer(se, results + 24) == exports["GetTickCount"]
        assert read_pointer(se, results + 32) & 0xFFFFFFFF == 2
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


@pytest.mark.parametrize(
    "fault_body, error",
    [(None, "invalid_read"), (b"\x0f\x0b", "Invalid instruction (UC_ERR_INSN_INVALID)")],
    ids=["read", "ud2"],
)
@pytest.mark.parametrize("arch", ["x86", "amd64"])
def test_faulting_dllmain_ends_run_and_unmaps_dll(config, tmp_path, arch, fault_body, error):
    se = Speakeasy(config=native_config(config, tmp_path))
    try:
        code = se.load_shellcode(data=b"\xc3" * 0x400, arch=arch)
        exports = make_native_dll(se.emu, tmp_path / "guest_dependency.dll", fault="Initializer", fault_body=fault_body)
        dll_name = se.mem_alloc(0x100, base=0x20000000)
        se.mem_write(dll_name, b"guest_dependency.dll\0")
        program = guest_call(se.get_ptr_size(), get_api(se, "kernel32", "LoadLibraryA"), dll_name)
        se.mem_write(code, program + b"\xc3")

        se.run_shellcode(code)

        errors = [ep.error.type if ep.error else None for ep in se.get_report().entry_points]
        assert errors == [error]
        assert se.emu.get_mod_by_name("guest_dependency") is None
        assert se.get_address_map(exports["Flag"]) is None
    finally:
        se.shutdown()


def test_faulting_dllmain_with_declining_handler_unmaps_dll(config, tmp_path):
    se = Speakeasy(config=native_config(config, tmp_path))
    try:
        code = se.load_shellcode(data=b"\xc3" * 0x400, arch="x86")
        # The handler returns ExceptionContinueSearch
        handler = code + 0x300
        se.mem_write(handler, b"\xb8\x01\0\0\0\xc3")
        # push handler; push fs:[0]; mov fs:[0], esp; mov eax, [0]
        body = b"\x68" + struct.pack("<I", handler) + b"\x64\xff\x35\0\0\0\0\x64\x89\x25\0\0\0\0\xa1\0\0\0\0"
        exports = make_native_dll(se.emu, tmp_path / "guest_dependency.dll", fault="Initializer", fault_body=body)
        dll_name = se.mem_alloc(0x100, base=0x20000000)
        se.mem_write(dll_name, b"guest_dependency.dll\0")
        program = guest_call(se.get_ptr_size(), get_api(se, "kernel32", "LoadLibraryA"), dll_name)
        se.mem_write(code, program + b"\xc3")

        se.run_shellcode(code)

        errors = [ep.error.type if ep.error else None for ep in se.get_report().entry_points]
        assert errors == ["invalid_read"]
        assert se.emu.get_mod_by_name("guest_dependency") is None
        assert se.get_address_map(exports["Flag"]) is None
    finally:
        se.shutdown()


@pytest.mark.parametrize(
    "result, fault, first_runs, flag",
    [
        (0, None, [("tls_callback", None), ("dll_entry", "dll_initialization_failed")], 2),
        (1, "Initializer", [("tls_callback", None), ("dll_entry", "invalid_read")], 2),
        (1, "TlsCallback", [("tls_callback", "invalid_read")], 1),
    ],
    ids=["dllmain-false", "dllmain-fault", "tls-callback-fault"],
)
def test_startup_initializer_failure_continues_startup(config, tmp_path, result, fault, first_runs, flag):
    builder = Speakeasy(config=config)
    try:
        builder.load_shellcode(data=b"\xc3", arch="x86")
        first = make_native_dll(builder.emu, tmp_path / "first.dll", result=result, fault=fault)
        builder.mem_alloc(0x20000, base=image_base(tmp_path / "first.dll"))
        second = make_native_dll(builder.emu, tmp_path / "second.dll")
    finally:
        builder.shutdown()
    config["modules"]["user_modules"] += [
        {"name": name, "base_addr": hex(image_base(tmp_path / f"{name}.dll")), "path": f"C:\\Windows\\{name}.dll"}
        for name in ("first", "second")
    ]
    se = Speakeasy(config=native_config(config, tmp_path))
    try:
        code = se.load_shellcode(data=b"\xc3" * 0x100, arch="x86")
        kernel32 = se.mem_alloc(0x100, base=0x20000000)
        se.mem_write(kernel32, b"kernel32.dll\0")
        program = guest_call(4, get_api(se, "kernel32", "LoadLibraryA"), kernel32)
        program += guest_call(4, second["GetTickCount"])
        se.mem_write(code, program + b"\xc3")

        se.run_shellcode(code)

        runs = [(ep.ep_type, ep.error.type if ep.error else None) for ep in se.get_report().entry_points]
        assert runs == [
            *((f"dependency.first.{kind}", error) for kind, error in first_runs),
            ("dependency.second.tls_callback", None),
            ("dependency.second.dll_entry", None),
            ("shellcode", None),
        ]
        assert se.get_report().entry_points[-1].ret_val == 2
        assert int.from_bytes(se.mem_read(first["Flag"], 4), "little") == flag
    finally:
        se.shutdown()


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
            entry_points=[],
        )

        se.load_image(image)
        assert read_pointer(se, base) == exports["GetTickCount"]
        assert se.mem_read(base + 4, 4) == b"\x41" * 4
        assert read_pointer(se, base + 8) == exports["Flag"]
        assert "MissingExport" not in {name for _, name in se.get_symbols().values()}
    finally:
        se.shutdown()


def jump_to(ptr_size, target):
    if ptr_size == 4:
        return b"\xb8" + struct.pack("<I", target) + b"\xff\xe0"
    return b"\x48\xb8" + struct.pack("<Q", target) + b"\xff\xe0"


@pytest.mark.parametrize("module_type", ["dll", "exe"])
@pytest.mark.parametrize("arch", ["x86", "amd64"])
def test_entry_point_sees_tls_slots_that_the_tls_callback_set(config, tmp_path, arch, module_type):
    path = tmp_path / "guest_dependency.dll"
    se = Speakeasy(config=config)
    try:
        se.load_shellcode(data=b"\xc3", arch=arch)
        exports = make_native_dll(se.emu, path)
    finally:
        se.shutdown()
    if module_type == "exe":
        pe = pefile.PE(str(path))
        pe.FILE_HEADER.Characteristics &= ~pefile.IMAGE_CHARACTERISTICS["IMAGE_FILE_DLL"]
        path.write_bytes(pe.write())

    with Speakeasy(config=config) as se:
        module = se.load_module(path=str(path))
        ptr = se.get_ptr_size()
        ret = b"\xc2\x0c\x00" if ptr == 4 else b"\xc3"
        data = se.mem_alloc(0x1000, base=0x20000000)
        index, result, callback, entry = data, data + 8, data + 0x100, data + 0x400
        se.mem_write(result, b"\xcc" * ptr)
        program = guest_call(ptr, get_api(se, "kernel32", "TlsAlloc"), store=index)
        program += guest_call(ptr, get_api(se, "kernel32", "TlsSetValue"), Deref(index), 0x1234)
        se.mem_write(callback, program + ret)
        program = guest_call(ptr, get_api(se, "kernel32", "TlsGetValue"), Deref(index), store=result)
        se.mem_write(entry, program + b"\xb8\x01\x00\x00\x00" + ret)
        se.mem_write(exports["TlsCallback"], jump_to(ptr, callback))
        se.mem_write(exports["Initializer"], jump_to(ptr, entry))

        se.run_module(module)

        assert [ep.error for ep in se.get_report().entry_points] == [None, None]
        assert read_pointer(se, result) == 0x1234


@pytest.mark.parametrize("arch", ["x86", "amd64"])
def test_entry_point_sees_static_tls_data_that_the_tls_callback_wrote(config, tmp_path, arch):
    path = tmp_path / "guest_dependency.dll"
    se = Speakeasy(config=config)
    try:
        se.load_shellcode(data=b"\xc3", arch=arch)
        exports = make_native_dll(se.emu, path)
    finally:
        se.shutdown()

    with Speakeasy(config=config) as se:
        module = se.load_module(path=str(path))
        result = se.mem_alloc(0x100, base=0x20000000)
        if se.get_ptr_size() == 4:
            block = b"\x64\xa1\x2c\x00\x00\x00\x8b\x00"
            callback = block + b"\xc7\x00\x34\x12\x00\x00\xc2\x0c\x00"
            entry = block + b"\x8b\x00\xa3" + struct.pack("<I", result) + b"\xb8\x01\x00\x00\x00\xc2\x0c\x00"
        else:
            block = b"\x65\x48\x8b\x04\x25\x58\x00\x00\x00\x48\x8b\x00"
            callback = block + b"\xc7\x00\x34\x12\x00\x00\xc3"
            entry = block + b"\x8b\x00\xa3" + struct.pack("<Q", result) + b"\xb8\x01\x00\x00\x00\xc3"
        se.mem_write(result + 0x40, callback)
        se.mem_write(result + 0x80, entry)
        se.mem_write(exports["TlsCallback"], jump_to(se.get_ptr_size(), result + 0x40))
        se.mem_write(exports["Initializer"], jump_to(se.get_ptr_size(), result + 0x80))

        se.run_module(module)

        assert [ep.error for ep in se.get_report().entry_points] == [None, None]
        assert int.from_bytes(se.mem_read(result, 4), "little") == 0x1234


def test_all_entrypoints_skips_data_exports(config, tmp_path):
    se = Speakeasy(config=config)
    try:
        se.load_shellcode(data=b"\xc3", arch="x86")
        make_native_dll(se.emu, tmp_path / "guest_dependency.dll")
    finally:
        se.shutdown()

    with Speakeasy(config=config) as se:
        module = se.load_module(path=str(tmp_path / "guest_dependency.dll"))
        se.run_module(module, all_entrypoints=True)
        runs = [ep.ep_type for ep in se.get_report().entry_points]

    assert "export.GetTickCount" in runs
    assert "export.Flag" not in runs


def test_all_entrypoints_skips_forwarded_exports(config, tmp_path):
    se = Speakeasy(config=config)
    try:
        se.load_shellcode(data=b"\xc3", arch="x86")
        make_native_dll(se.emu, tmp_path / "guest_dependency.dll", forwarder=True)
    finally:
        se.shutdown()

    with Speakeasy(config=config) as se:
        module = se.load_module(path=str(tmp_path / "guest_dependency.dll"))
        se.run_module(module, all_entrypoints=True)
        runs = [ep.ep_type for ep in se.get_report().entry_points]

    assert "export.GetTickCount" in runs
    assert "export.Forwarded" not in runs


def test_dll_without_an_entry_point_runs_only_its_exports(config, tmp_path):
    se = Speakeasy(config=config)
    try:
        se.load_shellcode(data=b"\xc3", arch="x86")
        make_native_dll(se.emu, tmp_path / "guest_dependency.dll", entry_point=False)
    finally:
        se.shutdown()

    with Speakeasy(config=config) as se:
        module = se.load_module(path=str(tmp_path / "guest_dependency.dll"))
        se.run_module(module, all_entrypoints=True)
        entries = se.get_report().entry_points

    assert [ep.ep_type for ep in entries if not ep.ep_type.startswith("export.")] == ["tls_callback_0"]
    assert "export.GetTickCount" in [ep.ep_type for ep in entries]
    assert all(ep.error is None for ep in entries)
