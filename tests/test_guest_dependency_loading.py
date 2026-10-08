"""Native DLL bytes, initialization order, and failed load ownership."""

import struct

import pefile
import pytest

from speakeasy.profiler import Run
from speakeasy.windows.api_image import ApiExportSpec, build_api_image
from tests.handler_harness import alloc, start_process


@pytest.fixture(params=["dll_emu", "dll64_emu"])
def api_emu(request):
    return request.getfixturevalue(request.param)


def make_native_dll(emu, path, success=True):
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
    for name, result in [("TlsCallback", 1), ("Initializer", int(success))]:
        address = exports[name]
        increment = b"\xff\x05" + (
            struct.pack("<I", flag) if emu.ptr_size == 4 else struct.pack("<i", flag - address - 6)
        )
        code = increment + b"\xb8" + struct.pack("<I", result) + ret
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


@pytest.mark.parametrize("startup", [True, False, "native"])
@pytest.mark.parametrize("success", [True, False])
def test_native_dll_initializes_once_before_guest_call(api_emu, tmp_path, monkeypatch, startup, success):
    emu = api_emu.emu
    start_process(api_emu)
    emu.alloc_peb(emu.curr_process)
    path = tmp_path / "guest_dependency.dll"
    exports = make_native_dll(emu, path, success)
    original = emu.get_native_module_path
    monkeypatch.setattr(
        emu,
        "get_native_module_path",
        lambda mod_name: str(path) if mod_name == "guest_dependency" else original(mod_name),
    )
    emu.run_queue.clear()
    if startup is True:
        module = emu.load_module_by_name("guest_dependency")
        run = Run()
        run.type = "test.guest_export"
        run.start_addr = exports["GetTickCount"]
        run.args = ()
        run.thread = emu.curr_thread
        emu.add_run(run)
        emu.start()
        if success:
            assert run.ret_val == 2
            assert module._initialization[emu.curr_process.id] == "ready"
            assert all(entry.trap is None for entry in emu.api_registry.entries.values() if entry.module is module)
        else:
            assert run not in emu.runs
    else:
        name = alloc(api_emu, b"guest_dependency.dll\0")
        return_site = emu.mem_map(0x1000, tag="test.loadlibrary.return")
        emu.mem_write(return_site, b"\x90")
        emu.curr_run = Run()
        emu.profiler.add_run(emu.curr_run)
        emu.set_hooks()
        from speakeasy.winenv import arch

        output = None
        if startup == "native":
            text = alloc(api_emu, "guest_dependency.dll\0".encode("utf-16le"))
            unicode = alloc(
                api_emu,
                struct.pack("<HH", 40, 42)
                + (b"\0" * 4 if emu.ptr_size == 8 else b"")
                + text.to_bytes(emu.ptr_size, "little"),
            )
            output = alloc(api_emu, b"\xcc" * emu.ptr_size)
            arguments = [0, 0, unicode, output]
            target = emu.get_proc("ntdll", "LdrLoadDll")
        else:
            arguments = [name]
            target = emu.get_proc("kernel32", "LoadLibraryA")
        emu.set_func_args(emu.stack_base, return_site, *arguments, conv=arch.CALL_CONV_STDCALL)
        sp = emu.get_stack_ptr()
        stop = emu.add_code_hook(lambda e, a, n: e.emu_eng.stop(), begin=return_site, end=return_site)
        emu._run_api_engine(target, timeout=3)
        assert emu.get_pc() == return_site
        assert emu.get_stack_ptr() == sp + emu.ptr_size + (len(arguments) * 4 if emu.ptr_size == 4 else 0)
        if output is not None:
            assert emu.get_return_val() == (0 if success else 0xC0000142)
            assert bool(int.from_bytes(emu.mem_read(output, emu.ptr_size), "little")) == success
        else:
            assert bool(emu.get_return_val()) == success
        event = next(event for event in emu.curr_run.events if event.event == "api")
        assert event.ret_val == hex(emu.get_return_val())
        stop.disable()
    if success:
        module = emu.get_mod_by_name("guest_dependency")
        assert int.from_bytes(emu.mem_read(exports["Flag"], 4), "little") == 2
        assert emu.load_library("guest_dependency") == module.base
        assert emu._collect_guest_initializers() == []
    else:
        assert emu.get_mod_by_name("guest_dependency") is None
        assert emu.get_address_map(exports["Flag"]) is None
        assert all(entry.object.DllBase != exports["Flag"] & ~0xFFFF for entry in emu.curr_process.ldr_entries)


def switch_process(emu):
    from speakeasy.windows.objman import Process, Thread

    process = Process(emu, name="second")
    emu.processes.append(process)
    emu.alloc_peb(process)
    emu.set_current_process(process)
    thread = Thread(emu, stack_base=emu.stack_base)
    thread.process = process
    process.threads.append(thread)
    emu.set_current_thread(thread)
    emu.init_teb(thread, process.peb)
    return process


def runtime_load(se, name):
    from speakeasy.winenv import arch

    emu = se.emu
    name_address = alloc(se, name.encode() + b"\0")
    return_site = emu.mem_map(0x1000, tag="test.process_load.return")
    emu.mem_write(return_site, b"\x90")
    emu.curr_run = Run()
    emu.profiler.add_run(emu.curr_run)
    emu.set_hooks()
    target = emu.get_proc("kernel32", "LoadLibraryA")
    emu.set_func_args(emu.stack_base, return_site, name_address, conv=arch.CALL_CONV_STDCALL)
    stop = emu.add_code_hook(lambda e, a, n: e.emu_eng.stop(), begin=return_site, end=return_site)
    try:
        emu._run_api_engine(target, timeout=3)
        assert emu.get_pc() == return_site
        assert emu.curr_run.api_callbacks == []
        return emu.get_return_val()
    finally:
        stop.disable()


def native_path(emu, monkeypatch, path):
    original = emu.get_native_module_path
    monkeypatch.setattr(
        emu,
        "get_native_module_path",
        lambda mod_name: str(path) if mod_name == "guest_dependency" else original(mod_name),
    )


def test_foreign_private_native_dll_is_not_initialized(api_emu, tmp_path, monkeypatch):
    emu = api_emu.emu
    start_process(api_emu)
    emu.alloc_peb(emu.curr_process)
    first = emu.curr_process
    path = tmp_path / "guest_dependency.dll"
    exports = make_native_dll(emu, path)
    native_path(emu, monkeypatch, path)
    module = emu.load_module_by_name("guest_dependency")
    first_entries = list(first.ldr_entries)
    second = switch_process(emu)
    assert module.base not in second._peb_modules
    assert emu._collect_guest_initializers() == []
    assert runtime_load(api_emu, "kernel32.dll")
    assert module._initialization == {}
    assert int.from_bytes(emu.mem_read(exports["Flag"], 4), "little") == 0
    assert first.ldr_entries == first_entries
    assert module.base not in second._peb_modules


def test_cached_native_init_failure_preserves_other_owner_and_allows_retry(api_emu, tmp_path, monkeypatch):
    from tests.test_peb_module_links import assert_process_rings

    emu = api_emu.emu
    start_process(api_emu)
    emu.alloc_peb(emu.curr_process)
    first = emu.curr_process
    path = tmp_path / "guest_dependency.dll"
    exports = make_native_dll(emu, path)
    native_path(emu, monkeypatch, path)
    assert runtime_load(api_emu, "guest_dependency.dll")
    module = emu.get_mod_by_name("guest_dependency")
    first_entries = list(first.ldr_entries)
    registry_entries = dict(emu.api_registry.entries)
    traps = dict(emu.api_registry.traps)
    bindings = dict(emu._import_bindings)
    # Change only DllMain's result for the second process; mapping/addresses stay stable.
    emu.mem_write(exports["Initializer"] + 7, struct.pack("<I", 0))
    second = switch_process(emu)
    second_entries = list(second.ldr_entries)
    assert runtime_load(api_emu, "guest_dependency.dll") == 0
    assert emu.get_mod_by_name("guest_dependency") is module
    assert first.ldr_entries == first_entries
    assert second.ldr_entries == second_entries
    assert module._initialization == {first.id: "ready"}
    assert emu.api_registry.entries == registry_entries
    assert emu.api_registry.traps == traps
    assert emu._import_bindings == bindings
    assert emu.get_address_map(module.base) is not None
    assert int.from_bytes(emu.mem_read(exports["Flag"], 4), "little") == 4
    assert_process_rings(first)
    assert_process_rings(second)
    emu.mem_write(exports["Initializer"] + 7, struct.pack("<I", 1))
    assert runtime_load(api_emu, "guest_dependency.dll") == module.base
    assert module._initialization == {first.id: "ready", second.id: "ready"}
    assert int.from_bytes(emu.mem_read(exports["Flag"], 4), "little") == 6
    assert len([entry for entry in second.ldr_entries if entry.object.DllBase == module.base]) == 1


def test_cached_startup_init_failure_preserves_ready_owner(api_emu, tmp_path, monkeypatch):
    emu = api_emu.emu
    start_process(api_emu)
    emu.alloc_peb(emu.curr_process)
    first = emu.curr_process
    path = tmp_path / "guest_dependency.dll"
    exports = make_native_dll(emu, path)
    native_path(emu, monkeypatch, path)
    assert runtime_load(api_emu, "guest_dependency.dll")
    module = emu.get_mod_by_name("guest_dependency")
    entries = list(first.ldr_entries)
    emu.mem_write(exports["Initializer"] + 7, struct.pack("<I", 0))
    second = switch_process(emu)
    emu.load_module_by_name("guest_dependency")
    run = Run()
    run.type = "test.cached_startup"
    run.start_addr = exports["GetTickCount"]
    run.args = ()
    run.thread = emu.curr_thread
    emu.run_queue[:] = [run]
    emu.start()
    assert run not in emu.runs
    assert module in emu.modules
    assert first.ldr_entries == entries
    assert module.base not in second._peb_modules
    assert module._initialization == {first.id: "ready"}
    assert not any(getattr(queued, "_guest_initialization", None) for queued in emu.run_queue)
