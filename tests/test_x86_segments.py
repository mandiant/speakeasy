"""x86 user-mode code sees the segment selectors of native 32-bit Windows."""

import struct

from speakeasy import Speakeasy

INJECTOR = "0be93fa8c17e75b9a3c01bd2d3ed153638c2e26d3724dafdd33eb6ba23389af1.exe.xz"


def dword(value):
    return struct.pack("<I", value)


def test_code_selector_is_the_native_x86_selector(config, load_test_bin):
    """
    0be93fa8 is a crypter stub that unpacks an injector to 0x41e000. Before it injects into
    a process, the injector reads CS and compares the low byte with 0x1B: on native 32-bit
    Windows it calls CreateRemoteThread (0x41ee84), else it asks IsWow64Process and can make
    a far call to the 64-bit selector 0x33.
    """
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(INJECTOR))
        cs = []
        path = []

        def skip_delay_loop(emu, address, size):
            # the stub runs 0x100000 rounds of AddAtomW and GetDeviceCaps before it unpacks
            se.mem_write(se.reg_read("ebp") - 0x90, dword(0x100000))

        def compare_cs(emu, address, size):
            cs.append(se.reg_read("eax") & 0xFFFF)  # mov ax, cs

        def branch(emu, address, size):
            path.append(address)
            se.stop()

        se.add_code_hook(skip_delay_loop, begin=0x405761, end=0x405761)
        se.add_code_hook(compare_cs, begin=0x41EE55, end=0x41EE55)
        se.add_code_hook(branch, begin=0x41EE84, end=0x41EE84)
        se.add_code_hook(branch, begin=0x41EE5E, end=0x41EE5E)
        se.run_module(module)

    assert cs == [0x1B]
    assert path == [0x41EE84]
