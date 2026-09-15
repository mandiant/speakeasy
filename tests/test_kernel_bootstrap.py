import copy
from pathlib import Path

import pytest

import speakeasy.winenv.arch as _arch
from speakeasy import Speakeasy, WinKernelEmulator
from speakeasy.config import SpeakeasyConfig
from speakeasy.errors import WindowsEmuError

SAMPLE_PATH = Path(__file__).resolve().parent / "capa-testfiles" / "Practical Malware Analysis Lab 10-03.sys_"

KUSER_TAG_PREFIX = "emu.struct.KUSER_SHARED_DATA"
KUSER_LOW_BASE = 0x7FFE0000
KUSER_X86_ALIAS = 0xFFDF0000
KUSER_X64_CANONICAL_ALIAS = 0xFFFFF78000000000
KUSER_X64_EXEC_MIRROR = 0xFF78000000000


def test_kernel_current_process_requires_bootstrap_phase(config):
    emu = WinKernelEmulator(config=SpeakeasyConfig.model_validate(config))

    with pytest.raises(WindowsEmuError, match="bootstrap phase"):
        emu.get_current_process()


def test_kernel_import_data_allocation_uses_system_process_context(config):
    se = Speakeasy(config=config)

    try:
        se.load_module(str(SAMPLE_PATH))
        emu = se.emu
        maps = [mm for mm in emu.get_mem_maps() if mm.tag and mm.tag.startswith("api.ntoskrnl.KeTickCount.")]

        assert maps
        proc = maps[0].process
        assert proc is not None
        assert proc.pid == 4
    finally:
        se.shutdown()


@pytest.fixture(scope="module", params=["wdm_test_x86.sys.xz", "wdm_test_x64.sys.xz"], ids=["x86", "x64"])
def kernel_session(request, base_config, load_test_bin):
    data = load_test_bin(request.param)
    se = Speakeasy(config=copy.deepcopy(base_config))
    try:
        module = se.load_module(data=data)
        se.run_module(module, all_entrypoints=True)
        yield se
    finally:
        se.shutdown()


def kuser_expected_bases(emu):
    if emu.get_arch() == _arch.ARCH_AMD64:
        return {KUSER_LOW_BASE, KUSER_X64_CANONICAL_ALIAS, KUSER_X64_EXEC_MIRROR}
    return {KUSER_LOW_BASE, KUSER_X86_ALIAS}


def covering_kuser_map(maps, base):
    return next((mm for mm in maps if mm.base <= base < mm.base + mm.size), None)


def kuser_maps(emu):
    return [mm for mm in emu.get_mem_maps() if mm.tag and mm.tag.startswith(KUSER_TAG_PREFIX)]


def test_kuser_shared_data_mapped_and_populated_at_all_aliases(kernel_session):
    emu = kernel_session.emu
    expected = kuser_expected_bases(emu)
    maps = kuser_maps(emu)

    for base in expected:
        assert covering_kuser_map(maps, base) is not None, f"no KUSER_SHARED_DATA map covers {hex(base)}"

    chunks = {base: bytes(emu.mem_read(base, 0x400)) for base in expected}
    assert len(set(chunks.values())) == 1

    chunk = next(iter(chunks.values()))
    qpc_frequency = int.from_bytes(chunk[0x3B8:0x3C0], "little")
    assert qpc_frequency == 10_000_000


def test_setup_user_shared_data_skips_already_mapped_aliases(kernel_session):
    emu = kernel_session.emu
    count_before = len(kuser_maps(emu))

    emu.setup_user_shared_data()

    maps = kuser_maps(emu)
    assert len(maps) == count_before
    for base in kuser_expected_bases(emu):
        assert covering_kuser_map(maps, base) is not None, f"no KUSER_SHARED_DATA map covers {hex(base)}"

    # Mapping is skipped for pages we already own, but their contents must
    # still be rewritten: trash one page and expect re-setup to restore it.
    emu.mem_write(KUSER_LOW_BASE, b"\x00" * 0x400)
    emu.setup_user_shared_data()

    chunk = bytes(emu.mem_read(KUSER_LOW_BASE, 0x400))
    assert int.from_bytes(chunk[0x3B8:0x3C0], "little") == 10_000_000


@pytest.mark.parametrize(
    ("arch", "bits"),
    [(_arch.ARCH_X86, _arch.BITS_32), (_arch.ARCH_AMD64, _arch.BITS_64)],
    ids=["x86", "x64"],
)
def test_setup_user_shared_data_leaves_foreign_maps_untouched(config, arch, bits):
    emu = WinKernelEmulator(config=SpeakeasyConfig.model_validate(config))
    emu.arch = arch
    emu.emu_eng.init_engine(_arch.ARCH_X86, bits)

    foreign_tag = "emu.test.collision"
    sentinel = bytes(range(256)) * 16
    emu.mem_map(emu.page_size, base=KUSER_LOW_BASE, tag=foreign_tag)
    emu.mem_write(KUSER_LOW_BASE, sentinel)

    emu.setup_user_shared_data()

    mm = emu.get_address_map(KUSER_LOW_BASE)
    assert mm.tag.startswith(foreign_tag)
    assert bytes(emu.mem_read(KUSER_LOW_BASE, emu.page_size)) == sentinel
    assert covering_kuser_map(kuser_maps(emu), KUSER_LOW_BASE) is None

    served = kuser_expected_bases(emu) - {KUSER_LOW_BASE}
    chunks = {base: bytes(emu.mem_read(base, 0x400)) for base in served}
    assert len(set(chunks.values())) == 1
    chunk = next(iter(chunks.values()))
    assert int.from_bytes(chunk[0x3B8:0x3C0], "little") == 10_000_000
