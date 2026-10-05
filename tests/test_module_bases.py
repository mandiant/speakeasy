import pefile
import pytest

from speakeasy import Speakeasy


@pytest.fixture
def loaded_exe(config, load_test_bin):
    data = load_test_bin("argv_test_x86.exe.xz")
    se = Speakeasy(config=config)
    try:
        module = se.load_module(data=data)
        yield se.emu, module, data
    finally:
        se.shutdown()


def test_exe_at_main_process_base_keeps_its_headers(loaded_exe):
    emu, module, data = loaded_exe
    pe = pefile.PE(data=data, fast_load=True)
    assert module.base == pe.OPTIONAL_HEADER.ImageBase == 0x400000

    header_size = pe.OPTIONAL_HEADER.SizeOfHeaders
    assert emu.mem_read(module.base, header_size) == data[:header_size]


def test_loaded_modules_do_not_overlap(loaded_exe):
    emu, _module, _data = loaded_exe
    spans = sorted((mod.base, mod.base + mod.image_size, mod.name) for mod in emu.modules)
    for (_, prev_end, prev_name), (base, _, name) in zip(spans, spans[1:]):
        assert prev_end <= base, f"{prev_name} overlaps {name}"


def test_relocated_main_decoy_is_mapped_at_its_base(loaded_exe):
    emu, module, _data = loaded_exe
    decoy = emu.get_mod_by_name("main")
    assert decoy.base != module.base
    assert emu.mem_read(decoy.base, 2) == b"MZ"
    e_lfanew = int.from_bytes(emu.mem_read(decoy.base + 0x3C, 4), "little")
    assert emu.mem_read(decoy.base + e_lfanew, 4) == b"PE\0\0"
