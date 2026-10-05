import pefile
import pytest

from speakeasy import Speakeasy


@pytest.fixture
def emulator(config):
    se = Speakeasy(config=config)
    try:
        yield se
    finally:
        se.shutdown()


@pytest.fixture(scope="module")
def dll_at_container_base(load_test_bin):
    pe = pefile.PE(data=load_test_bin("dll_test_x86.dll.xz"))
    pe.relocate_image(0x400000)
    pe.OPTIONAL_HEADER.ImageBase = 0x400000
    return bytes(pe.write())


def test_exe_at_main_process_base_keeps_its_headers(emulator, load_test_bin):
    data = load_test_bin("argv_test_x86.exe.xz")
    module = emulator.load_module(data=data)
    pe = pefile.PE(data=data, fast_load=True)
    assert module.base == pe.OPTIONAL_HEADER.ImageBase == 0x400000

    header_size = pe.OPTIONAL_HEADER.SizeOfHeaders
    assert emulator.emu.mem_read(module.base, header_size) == data[:header_size]


def test_exe_input_is_the_only_exe_module(emulator, load_test_bin):
    module = emulator.load_module(data=load_test_bin("argv_test_x86.exe.xz"))
    emu = emulator.emu
    assert emu.container_image is None
    assert [mod for mod in emu.get_peb_modules() if mod.is_exe()] == [module]


def test_container_image_moves_when_dll_occupies_its_base(emulator, dll_at_container_base):
    module = emulator.load_module(data=dll_at_container_base)
    emu = emulator.emu
    assert module.base == 0x400000

    container = emu.container_image
    assert container is not None
    assert container.base != module.base
    assert emu.mem_read(container.base, 2) == b"MZ"
    e_lfanew = int.from_bytes(emu.mem_read(container.base + 0x3C, 4), "little")
    assert emu.mem_read(container.base + e_lfanew, 4) == b"PE\0\0"
    assert emu.init_container_process().base == container.base

    spans = sorted((mod.base, mod.base + mod.image_size, mod.name) for mod in emu.modules)
    for (_, prev_end, prev_name), (base, _, name) in zip(spans, spans[1:]):
        assert prev_end <= base, f"{prev_name} overlaps {name}"
