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
    gpa_calls = [evt for evt in events if evt.event == "api" and evt.api_name == "KERNEL32.GetProcAddress"]
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


def test_runtime_modules_have_loader_provenance(config, load_test_bin):
    se = Speakeasy(config=config)
    try:
        se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
        runtime_modules = [m for m in se.emu.modules if isinstance(m, RuntimeModule)]
    finally:
        se.shutdown()

    assert runtime_modules
    assert all(mod.loader is not None for mod in runtime_modules)
