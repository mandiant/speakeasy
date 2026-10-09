import copy

from speakeasy import Speakeasy

_SC = (
    b"\xe8\x0b\x00\x00\x00"  # 00: call func
    b"\x89\xc3"  # 05: mov ebx, eax
    b"\xe8\x04\x00\x00\x00"  # 07: call func
    b"\x90"  # 0c: nop
    b"\xc3"  # 0d: ret
    b"\x90\x90"
    b"\xb8\x01\x00\x00\x00"  # 10: func: mov eax, 1
    b"\xc3"  # 15: ret
)
_PATCH_SITE = 0x07
_END = 0x0C
_FUNC_IMM = 0x11


def _run(base_config, patch_in_hook):
    se = Speakeasy(config=copy.deepcopy(base_config))
    try:
        addr = se.load_shellcode(data=_SC, arch="x86")
        results = []

        def on_patch_site(emu, pc, size):
            emu.mem_write(addr + _FUNC_IMM, b"\x02")
            return True

        def on_end(emu, pc, size):
            results.append((emu.reg_read("ebx"), emu.reg_read("eax")))
            return True

        if patch_in_hook:
            se.add_code_hook(on_patch_site, begin=addr + _PATCH_SITE, end=addr + _PATCH_SITE)
        se.add_code_hook(on_end, begin=addr + _END, end=addr + _END)
        se.run_shellcode(addr)
        if not patch_in_hook:
            se.mem_write(addr + _FUNC_IMM, b"\x02")
            se.run_shellcode(addr)
        return results
    finally:
        se.shutdown()


def test_hook_patch_to_executed_code_takes_effect(base_config):
    assert _run(base_config, patch_in_hook=True) == [(1, 2)]


def test_patch_between_runs_takes_effect(base_config):
    assert _run(base_config, patch_in_hook=False) == [(1, 1), (2, 2)]
