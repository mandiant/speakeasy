import contextlib
import struct

import pytest

import speakeasy.windows.common as winemu
from speakeasy import Speakeasy
from speakeasy.config import SpeakeasyConfig
from speakeasy.windows.win32 import Win32Emulator
from speakeasy.winenv import arch as _arch
from tests.pe_builder import build_pe


@pytest.fixture
def emulator(config):
    se = Speakeasy(config=config)
    try:
        yield se
    finally:
        se.shutdown()


@contextlib.contextmanager
def make_machine(config):
    emu = Win32Emulator(SpeakeasyConfig(**config))
    try:
        yield emu
    finally:
        emu.emu_eng.close()


@pytest.fixture
def machine(config):
    with make_machine(config) as emu:
        yield emu


def read_segment_pointers(arch, out):
    if arch == "x86":
        code = b"\x64\xa1\x18\x00\x00\x00" + b"\xa3" + struct.pack("<I", out)
        code += b"\x64\xa1\x30\x00\x00\x00" + b"\xa3" + struct.pack("<I", out + 8)
    else:
        code = b"\x65\x48\x8b\x04\x25\x30\x00\x00\x00" + b"\x48\xa3" + struct.pack("<Q", out)
        code += b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00" + b"\x48\xa3" + struct.pack("<Q", out + 8)
    return code + b"\xc3"


@pytest.mark.parametrize("arch", ["x86", "amd64"])
def test_teb_and_peb_are_at_the_fixed_addresses(emulator, arch):
    code = emulator.load_shellcode(data=b"\xc3" * 0x100, arch=arch)
    out = emulator.mem_alloc(0x1000, base=0x20000000)
    emulator.mem_write(code, read_segment_pointers(arch, out))
    emulator.run_shellcode(code)

    teb, peb = struct.unpack("<QQ", emulator.mem_read(out, 16))
    assert teb == winemu.TEB_ADDRESS
    assert peb == winemu.PEB_ADDRESS


@pytest.mark.parametrize("name", ["dll_test_x86.dll.xz", "argv_test_x86.exe.xz"])
def test_input_image_is_the_first_module(emulator, load_test_bin, name):
    module = emulator.load_module(data=load_test_bin(name))
    assert emulator.emu.modules[0] is module


def build_large_exe(image_size):
    relocations = struct.pack("<IIHH", 0x1000, 12, 0, 0)
    data, _ = build_pe(32, data=relocations, extra_dirs={5: (0x2000, len(relocations))})
    data = bytearray(data)
    struct.pack_into("<I", data, 0x98 + 56, image_size)
    return bytes(data)


def native_container_config(config, tmp_path, image_size):
    (tmp_path / "main.exe").write_bytes(build_large_exe(image_size))
    config["modules"]["module_directory_x86"] = str(tmp_path)
    return config


def test_large_native_container_fits_below_the_teb(config, tmp_path):
    se = Speakeasy(config=native_container_config(config, tmp_path, 0x1000000))
    try:
        code = se.load_shellcode(data=b"\xc3", arch="x86")
        emu = se.emu
        assert isinstance(emu, Win32Emulator)
        container = emu.container_image
        assert container is not None
        assert container.image_size == 0x1000000
        assert container.base + container.image_size <= winemu.TEB_ADDRESS
        se.run_shellcode(code)
        assert se.get_report().entry_points[0].error is None
    finally:
        se.shutdown()


@pytest.mark.parametrize("arch", [_arch.ARCH_X86, _arch.ARCH_AMD64])
def test_load_container_loads_the_container_in_the_machine_range(machine, arch):
    machine.init_machine(arch)
    first_free, _ = machine.get_valid_ranges(0x1000, addr=winemu.MACHINE_BASE)
    process = machine.load_container()

    container = machine.container_image
    assert container.base == first_free
    assert container.base + container.image_size <= winemu.TEB_ADDRESS
    assert machine.processes == [process]
    assert machine.get_current_process() is process
    assert process.base == container.base


def test_native_container_does_not_allocate_the_stack(config, tmp_path):
    with make_machine(native_container_config(config, tmp_path, 0x4000)) as emu:
        emu.init_machine(_arch.ARCH_X86)
        emu.load_container()
        assert emu.mem_read(emu.container_image.base, 2) == b"MZ"
        assert emu.stack_base == 0
