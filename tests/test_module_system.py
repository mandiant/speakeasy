from speakeasy import Speakeasy


def test_get_mod_from_addr_finds_primary_module(config, load_test_bin):
    se = Speakeasy(config=config)
    try:
        module = se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
        found = se.emu.get_mod_from_addr(module.base + 0x100)
    finally:
        se.shutdown()

    assert found is module


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


def test_win32_shellcode_peb_uses_mapped_user_modules(config):
    config["max_instructions"] = 1
    se = Speakeasy(config=config)
    try:
        sc_addr = se.load_shellcode(data=b"\x90\x90", arch="amd64")
        se.run_shellcode(sc_addr)
        peb_mods = se.emu.get_peb_modules()
        peb_names = {mod.name.lower() for mod in peb_mods}
        loaded_names = {mod.name.lower() for mod in se.emu.modules}
        mapped_headers = [se.emu.mem_read(mod.base, 2) for mod in peb_mods]
    finally:
        se.shutdown()

    system_names = {mod["name"].lower() for mod in config["modules"]["system_modules"]}
    assert system_names <= loaded_names
    assert system_names.isdisjoint(peb_names)
    assert {"main", "ntdll", "kernel32", "kernelbase", "wininet"} <= peb_names
    assert all(header == b"MZ" for header in mapped_headers)
