import struct

import pytest
import unicorn as uc
import unicorn.x86_const as ux

import speakeasy.windows.common as winemu
from speakeasy import Speakeasy
from speakeasy.windows.win32 import Win32Emulator
from tests.pe_builder import build_pe


@pytest.fixture
def emulator(config):
    se = Speakeasy(config=config)
    try:
        yield se
    finally:
        se.shutdown()


def read_teb_fields(arch, offsets, out):
    """Get code that copies the TEB fields at offsets to 8-byte slots at out."""
    code = b""
    for i, offset in enumerate(offsets):
        if arch == "x86":
            code += b"\x64\xa1" + struct.pack("<I", offset) + b"\xa3" + struct.pack("<I", out + 8 * i)
        else:
            code += b"\x65\x48\x8b\x04\x25" + struct.pack("<I", offset) + b"\x48\xa3" + struct.pack("<Q", out + 8 * i)
    return code + b"\xc3"


def run_teb_reads(emulator, arch, offsets):
    code = emulator.load_shellcode(data=b"\xc3" * 0x100, arch=arch)
    out = emulator.mem_alloc(0x1000, base=0x20000000)
    emulator.mem_write(code, read_teb_fields(arch, offsets, out))
    emulator.run_shellcode(code)
    return struct.unpack(f"<{len(offsets)}Q", emulator.mem_read(out, 8 * len(offsets)))


@pytest.mark.parametrize("arch", ["x86", "amd64"])
def test_teb_and_peb_are_at_the_fixed_addresses(emulator, arch):
    offsets = (0x18, 0x30) if arch == "x86" else (0x30, 0x60)
    teb, peb = run_teb_reads(emulator, arch, offsets)
    assert teb == winemu.TEB_ADDRESS
    assert peb == winemu.PEB_ADDRESS


@pytest.mark.parametrize("arch", ["x86", "amd64"])
def test_teb_client_id_has_the_process_and_thread_ids(emulator, arch):
    # TEB.ClientId.UniqueProcess and UniqueThread, which an inlined GetCurrentThreadId reads
    offsets = (0x20, 0x24) if arch == "x86" else (0x40, 0x48)
    pid, tid = run_teb_reads(emulator, arch, offsets)
    run = emulator.get_report().runs[0]
    assert tid != 0
    assert (pid, tid) == (run.pid, run.tid)


def get_unicorn_cpuid(arch, leaf):
    """Get the registers that cpuid gives for a leaf in Unicorn with no hooks."""
    probe = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32 if arch == "x86" else uc.UC_MODE_64)
    probe.mem_map(0x1000, 0x1000)
    probe.mem_write(0x1000, b"\x0f\xa2")
    probe.reg_write(ux.UC_X86_REG_EAX, leaf)
    probe.emu_start(0x1000, 0x1002)
    return tuple(
        probe.reg_read(r) for r in (ux.UC_X86_REG_EAX, ux.UC_X86_REG_EBX, ux.UC_X86_REG_ECX, ux.UC_X86_REG_EDX)
    )


def run_cpuid(emulator, arch, leaf):
    """Run cpuid for a leaf in the guest, and get the full registers that it gives."""
    code = emulator.load_shellcode(data=b"\xc3" * 0x100, arch=arch)
    out = emulator.mem_alloc(0x1000, base=0x20000000)
    if arch == "x86":
        cpuid = b"\xb8" + struct.pack("<I", leaf) + b"\x0f\xa2\xbf" + struct.pack("<I", out)
        cpuid += b"\x89\x07\x89\x5f\x04\x89\x4f\x08\x89\x57\x0c\xc3"
    else:
        # mov rbx, -1; mov rcx, -1; mov rdx, -1, so that a value with the high bits set shows up
        cpuid = b"\x48\xc7\xc3\xff\xff\xff\xff\x48\xc7\xc1\xff\xff\xff\xff\x48\xc7\xc2\xff\xff\xff\xff"
        cpuid += b"\xb8" + struct.pack("<I", leaf) + b"\x0f\xa2\x48\xbf" + struct.pack("<Q", out)
        cpuid += b"\x48\x89\x07\x48\x89\x5f\x08\x48\x89\x4f\x10\x48\x89\x57\x18\xc3"
    emulator.mem_write(code, cpuid)
    emulator.run_shellcode(code)
    assert emulator.get_report().runs[0].error is None
    fmt = "<4I" if arch == "x86" else "<4Q"
    return struct.unpack(fmt, emulator.mem_read(out, struct.calcsize(fmt)))


@pytest.mark.parametrize("arch", ["x86", "amd64"])
def test_cpuid_leaf_1_has_no_hypervisor_bit(emulator, arch):
    eax, ebx, ecx, edx = get_unicorn_cpuid(arch, 1)
    assert run_cpuid(emulator, arch, 1) == (eax, ebx, ecx & ~(1 << 31), edx)


@pytest.mark.parametrize("arch", ["x86", "amd64"])
def test_cpuid_hypervisor_leaf_is_empty(emulator, arch):
    assert run_cpuid(emulator, arch, 0x40000000) == (0, 0, 0, 0)


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
    config["modules"]["directory_x86"] = str(tmp_path)
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
        assert se.get_report().runs[0].error is None
    finally:
        se.shutdown()


def test_process_list_has_each_configured_process_one_time(emulator, config):
    emulator.load_shellcode(None, "x86", data=b"\xc3")
    emu = emulator.emu
    configured = [p["name"] for p in config["processes"] if not p.get("is_main_exe")]

    def get_names():
        return [p.name for p in emu.get_processes() if p is not emu.curr_process]

    assert get_names() == configured
    assert emu.get_processes().count(emu.curr_process) == 1

    child = emu.create_process(path="C:\\Windows\\system32\\notepad.exe")
    assert get_names() == [*configured, child.name]
    assert emu.get_processes().count(emu.curr_process) == 1


def test_no_other_object_has_the_id_of_a_configured_pid(config):
    # Speakeasy gives out object IDs from 0x400 up, so these pids are in the range of the object IDs.
    entries = [p for p in config["processes"] if p["name"] != "System" and not p.get("is_main_exe")]
    for i, p in enumerate(entries):
        p["pid"] = 0x400 + 4 * i
    se = Speakeasy(config=config)
    try:
        se.load_shellcode(None, "x86", data=b"\xc3")
        emu = se.emu
        assert emu.om is not None
        for proc in emu.get_processes():
            if proc is not emu.curr_process:
                assert emu.get_object_from_id(proc.pid) is proc
        ids = [obj.id for obj in emu.om.objects.values()]
        assert len(ids) == len(set(ids))
    finally:
        se.shutdown()
