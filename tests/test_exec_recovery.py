"""Guest PE execute recovery changes protection after native callbacks unwind."""

import pefile
import pytest
import unicorn as uc

from speakeasy import Speakeasy, common
from speakeasy.profiler import Run
from tests.test_api_image import build, image_bytes


def permissions_at(emu, address):
    return next(perms for start, end, perms in emu.get_mem_regions() if start <= address <= end)


@pytest.mark.parametrize("architecture", [32, 64])
@pytest.mark.parametrize(
    "perms", [common.PERM_MEM_RW, common.PERM_MEM_READ, common.PERM_MEM_WRITE, common.PERM_MEM_NONE]
)
@pytest.mark.parametrize("budget", [1, 2, 17])
def test_guest_fetch_recovers_outside_callback_preserving_permissions(config, monkeypatch, architecture, perms, budget):
    config["max_instructions"] = budget
    config["timeout"] = 3
    pe = pefile.PE(data=image_bytes(build([], architecture)))
    section = next(section for section in pe.sections if section.Name.startswith(b".data"))
    address = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
    raw = bytearray(pe.write())
    code = b"\x90" * 7 + b"\xeb\xf7" if budget == 17 else b"\xb8\x4d\0\0\0\xc3"
    raw[section.PointerToRawData : section.PointerToRawData + len(code)] = code
    with Speakeasy(config=config) as se:
        module = se.load_module(data=bytes(raw))
        emu = se.emu
        assert module._image.source == "guest_pe"
        emu.prepare_module_for_emulation(module, all_entrypoints=False)
        emu.run_queue.clear()
        emu.mem_protect(address, emu.page_size, perms)
        previous = permissions_at(emu, address)
        assert previous == emu.emu_eng.perms[perms]
        run = Run()
        run.start_addr = address
        run.type = "exec_recovery.guest_pe"
        run.args = []
        emu.add_run(run)
        in_callback = False
        fetches = []
        promotions = []
        original_fetch = emu._handle_prot_fetch
        original_protect = emu.mem_protect

        def fetch(engine, fault_address, size, value):
            nonlocal in_callback
            in_callback = True
            try:
                fetches.append((fault_address, emu.get_pc()))
                result = original_fetch(engine, fault_address, size, value)
                assert result is False
                assert emu._pending_control == "exec_recovery"
                return result
            finally:
                in_callback = False

        def protect(page, size, new_perms):
            assert not in_callback
            assert emu.get_pc() == address
            promotions.append((page, size, new_perms))
            return original_protect(page, size, new_perms)

        def unexpected_callback():
            pytest.fail("execute recovery must not advance API callbacks")

        monkeypatch.setattr(emu, "_handle_prot_fetch", fetch)
        monkeypatch.setattr(emu, "mem_protect", protect)
        monkeypatch.setattr(emu, "_continue_api_callback", unexpected_callback)
        emu.start()

        assert fetches == [(address, address)]
        assert promotions == [(address, emu.page_size, perms | common.PERM_MEM_EXEC)]
        assert permissions_at(emu, address) == previous | uc.UC_PROT_EXEC
        assert emu._pending_exec_recovery is None
        assert emu._pending_control is None
        assert run.instr_cnt == budget
        if budget != 2:
            assert run.error.type == "max_instructions"
            assert int(run.error.pc) == address + (1 if budget == 17 else 5)
        else:
            assert run.error is None
            assert run.ret_val == 77


def test_failed_recovery_clears_pending_state_before_next_run(dll_emu, monkeypatch):
    emu = dll_emu.emu
    module = emu.modules[0]
    emu.prepare_module_for_emulation(module, all_entrypoints=False)
    emu.run_queue.clear()
    section = next(section for section in module.sections if section.perms & common.PERM_MEM_EXEC)
    address = module.base + section.virtual_address
    emu.mem_write(address, b"\xb8\x4d\0\0\0\xc3")
    emu.mem_protect(address, emu.page_size, common.PERM_MEM_READ)
    following_address = emu.mem_map(emu.page_size, tag="exec_recovery.following")
    emu.mem_write(following_address, b"\xb8\x2a\0\0\0\xc3")
    failed, following = Run(), Run()
    for run, target in ((failed, address), (following, following_address)):
        run.start_addr = target
        run.type = "exec_recovery.failure_ownership"
        run.args = []
        emu.add_run(run)

    def fail_protection(page, size, perms):
        assert emu._pending_exec_recovery is None
        assert emu._pending_control is None
        raise uc.UcError(uc.UC_ERR_ARG)

    monkeypatch.setattr(emu, "mem_protect", fail_protection)
    emu.start()

    assert failed.error is not None
    assert following.error is None
    assert following.ret_val == 42
    assert emu._pending_exec_recovery is None
    assert emu._pending_control is None
    assert not permissions_at(emu, address) & uc.UC_PROT_EXEC
