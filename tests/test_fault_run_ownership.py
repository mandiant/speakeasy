"""Native fetch faults must retain run ownership across queued execution."""

import pytest
import unicorn as uc

from speakeasy import common
from speakeasy.profiler import Run


@pytest.fixture(params=["dll_emu", "dll64_emu"])
def api_emu(request):
    se = request.getfixturevalue(request.param)
    # The handler fixture loads an image; queued execution also needs its
    # normal DLL container process, without running the fixture's DllMain.
    se.emu.prepare_module_for_emulation(se.emu.modules[0], all_entrypoints=False)
    se.emu.run_queue.clear()
    return se


def queue_run(emu, address, name):
    run = Run()
    run.start_addr = address
    run.type = name
    run.args = []
    emu.add_run(run)
    return run


def return_code(emu, value, *, perms=None):
    address = emu.mem_map(0x1000, tag="fault_regression.anonymous")
    emu.mem_write(address, b"\xb8" + value.to_bytes(4, "little") + b"\xc3")
    if perms is not None:
        emu.mem_protect(address, 0x1000, perms)
    return address


def permissions_at(emu, address):
    return next(perms for start, end, perms in emu.get_mem_regions() if start <= address <= end)


def test_module_nx_fault_does_not_overwrite_next_queued_run(api_emu):
    emu = api_emu.emu
    emu.config = emu.config.model_copy(update={"analysis": emu.config.analysis.model_copy(update={"enforce_nx": True})})
    module = emu.modules[0]
    section = next(section for section in module.sections if section.perms & common.PERM_MEM_EXEC)
    address = module.base + section.virtual_address
    emu.mem_write(address, b"\xb8\x01\0\0\0\xc3")
    emu.mem_protect(address, 0x1000, common.PERM_MEM_READ)
    failed = queue_run(emu, address, "fault_regression.module_nx")
    following = queue_run(emu, return_code(emu, 42), "fault_regression.following")

    emu.start()

    assert failed.error is not None
    assert failed.error.type == "invalid_protect_fetch"
    assert failed.error.pc == address
    assert following.error is None
    assert following.ret_val == 42
    assert not emu.run_queue


def test_synthetic_api_nx_fault_never_dispatches_handler(api_emu):
    emu = api_emu.emu
    address = emu.get_proc("kernel32", "GetTickCount")
    assert emu.get_mod_from_addr(address)._image.source == "synthetic"
    hits = []
    api_emu.add_api_hook(lambda e, api, original, args: hits.append(api) or 77, "kernel32", "GetTickCount", argc=0)
    emu.mem_protect(address & ~0xFFF, 0x1000, common.PERM_MEM_READ)
    failed = queue_run(emu, address, "fault_regression.api_nx")
    following = queue_run(emu, return_code(emu, 43), "fault_regression.following")

    emu.start()

    assert hits == []
    assert failed.error is not None
    assert failed.error.type == "invalid_protect_fetch"
    assert failed.error.pc == address
    assert following.error is None
    assert following.ret_val == 43
    assert not permissions_at(emu, address) & uc.UC_PROT_EXEC


def test_anonymous_nx_preserves_legacy_nondebug_recovery(api_emu):
    emu = api_emu.emu
    address = return_code(emu, 77, perms=common.PERM_MEM_READ | common.PERM_MEM_WRITE)
    assert emu.get_mod_from_addr(address) is None
    assert not emu.api_registry.overlaps_traps(address)
    assert not permissions_at(emu, address) & uc.UC_PROT_EXEC
    recovered = queue_run(emu, address, "fault_regression.anonymous_nx")
    following = queue_run(emu, return_code(emu, 44), "fault_regression.following")

    emu.start()

    assert recovered.error is None
    assert recovered.ret_val == 77
    assert following.error is None
    assert following.ret_val == 44
    assert not permissions_at(emu, address) & uc.UC_PROT_EXEC


@pytest.mark.parametrize("architecture", [32, 64])
@pytest.mark.parametrize("nx_compat", [False, True])
@pytest.mark.parametrize("enforce_nx", [None, False, True], ids=["default", "recover", "enforce"])
def test_guest_module_nx_policy(architecture, nx_compat, enforce_nx, config):
    import pefile

    from speakeasy import Speakeasy
    from tests.test_api_image import build, image_bytes

    if enforce_nx is not None:
        config.setdefault("analysis", {})["enforce_nx"] = enforce_nx
    pe = pefile.PE(data=image_bytes(build([], architecture)))
    if nx_compat:
        pe.OPTIONAL_HEADER.DllCharacteristics |= 0x100  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    else:
        pe.OPTIONAL_HEADER.DllCharacteristics &= ~0x100
    section = next(s for s in pe.sections if s.Name.startswith(b".data"))
    address = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
    raw = bytearray(pe.write())
    raw[section.PointerToRawData : section.PointerToRawData + 6] = b"\xb8\x4d\0\0\0\xc3"
    se = Speakeasy(config=config)
    try:
        module = se.load_module(data=bytes(raw))
        emu = se.emu
        assert module._image.source == "guest_pe"
        assert emu.get_mod_from_addr(address) is module
        assert emu.config.analysis.enforce_nx is (enforce_nx is True)
        assert bool(module.loader._pe_obj.OPTIONAL_HEADER.DllCharacteristics & 0x100) is nx_compat
        assert not permissions_at(emu, address) & uc.UC_PROT_EXEC
        emu.prepare_module_for_emulation(module, all_entrypoints=False)
        emu.run_queue.clear()
        first = queue_run(emu, address, "fault_regression.guest_nx")
        following = queue_run(emu, return_code(emu, 44), "fault_regression.following")

        emu.start()

        if enforce_nx:
            assert first.error is not None
            assert first.error.type == "invalid_protect_fetch"
            assert first.error.pc == address
        else:
            assert first.error is None
            assert first.ret_val == 77
        assert following.error is None
        assert following.ret_val == 44
        assert not emu.run_queue
        assert bool(permissions_at(emu, address) & uc.UC_PROT_EXEC) is not (enforce_nx is True)
    finally:
        se.shutdown()
