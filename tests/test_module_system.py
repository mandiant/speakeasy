from speakeasy import Speakeasy
from speakeasy.windows.loaders import RuntimeModule


def test_static_import_dispatches_api_handler(config, load_test_bin):
    se = Speakeasy(config=config)
    try:
        module = se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
        se.run_module(module, all_entrypoints=True)
        report = se.get_report()
    finally:
        se.shutdown()

    events = report.entry_points[0].events or []
    msgbox_calls = [evt for evt in events if evt.event == "api" and "MessageBox" in evt.api_name]
    assert msgbox_calls


def test_getprocaddress_dynamic_resolution(config, load_test_bin):
    se = Speakeasy(config=config)
    try:
        module = se.load_module(data=load_test_bin("GetProcAddress.exe.xz"))
        se.run_module(module, all_entrypoints=True)
        report = se.get_report()
    finally:
        se.shutdown()

    events = report.entry_points[0].events or []
    gpa_calls = [evt for evt in events if evt.event == "api" and evt.api_name == "kernel32.GetProcAddress"]
    assert gpa_calls
    assert any(call.ret_val != "0x0" for call in gpa_calls)


def test_get_mod_from_addr_finds_primary_module(config, load_test_bin):
    se = Speakeasy(config=config)
    try:
        module = se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
        found = se.emu.get_mod_from_addr(module.base + 0x100)
    finally:
        se.shutdown()

    assert found is not None
    assert isinstance(found, RuntimeModule)


def test_get_mod_from_addr_excludes_the_end_of_the_current_module(config, load_test_bin):
    se = Speakeasy(config=config)
    try:
        module = se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
        se.emu.curr_mod = module
        end = module.base + module.image_size
        last = se.emu.get_mod_from_addr(end - 1)
        past_end = se.emu.get_mod_from_addr(end)
    finally:
        se.shutdown()

    assert last is module
    assert past_end is not module


def test_peb_modules_populated(config, load_test_bin):
    se = Speakeasy(config=config)
    try:
        module = se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
        se.run_module(module, all_entrypoints=True)
        peb_mods = se.emu.get_peb_modules()
    finally:
        se.shutdown()

    assert peb_mods
    assert all(isinstance(mod, RuntimeModule) for mod in peb_mods)


def test_win32_shellcode_peb_uses_mapped_user_modules(config):
    config["max_instructions"] = 1
    se = Speakeasy(config=config)
    try:
        sc_addr = se.load_shellcode(data=b"\x90\x90", arch="amd64")
        se.run_shellcode(sc_addr)
        peb_mods = se.emu.get_peb_modules()
        peb_names = {mod.name.lower() for mod in peb_mods}
        loaded_names = {mod.name.lower() for mod in se.emu.modules}
        ordered_names = [mod.name.lower() for mod in se.emu._ordered_peb_modules()]
        mapped_headers = [se.emu.mem_read(mod.base, 2) for mod in peb_mods]
    finally:
        se.shutdown()

    system_names = {mod["name"].lower() for mod in config["modules"]["system_modules"]}
    assert system_names <= loaded_names
    assert system_names.isdisjoint(peb_names)
    assert {"main", "ntdll", "kernel32", "kernelbase", "wininet"} <= peb_names
    assert ordered_names[:4] == ["main", "ntdll", "kernel32", "kernelbase"]
    assert all(header == b"MZ" for header in mapped_headers)


def test_runtime_modules_have_loader_provenance(config, load_test_bin):
    se = Speakeasy(config=config)
    try:
        se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
        runtime_modules = [m for m in se.emu.modules if isinstance(m, RuntimeModule)]
    finally:
        se.shutdown()

    assert runtime_modules
    assert all(mod.loader is not None for mod in runtime_modules)
