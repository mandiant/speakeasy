"""Hooks added before an input is loaded fire once the emulator exists."""

from speakeasy import Speakeasy


def test_mem_map_hook_added_before_load_fires(config):
    tags = []
    with Speakeasy(config=config) as se:
        se.add_mem_map_hook(lambda emu, base, size, tag, prot, flags: tags.append(tag))
        se.run_shellcode(se.load_shellcode(data=b"\xc3", arch="x86"))

    assert any(tag.startswith("emu.stack.") for tag in tags)
