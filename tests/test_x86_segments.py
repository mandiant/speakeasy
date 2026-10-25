"""x86 user-mode code sees the segment selectors of native 32-bit Windows."""

import struct

from speakeasy import Speakeasy
from tests.guest_harness import get_api, guest_call

INJECTOR = "0be93fa8c17e75b9a3c01bd2d3ed153638c2e26d3724dafdd33eb6ba23389af1.exe.xz"


def dword(value):
    return struct.pack("<I", value)


def word(se, address):
    return struct.unpack("<H", se.mem_read(address, 2))[0]


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


def test_exception_context_has_the_selectors(config):
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="x86")
        data = se.mem_alloc(0x1000)
        done, handler = code + 0x80, code + 0x100

        main = b"\x68" + dword(handler)  # push handler
        main += b"\x64\xff\x35" + dword(0) + b"\x64\x89\x25" + dword(0)  # push fs:[0]; mov fs:[0], esp
        main += b"\xc7\x05" + dword(0) + dword(1)  # mov dword [0], 1
        finish = b"\x64\x8f\x05" + dword(0) + b"\x83\xc4\x04"  # pop fs:[0]; add esp, 4
        finish += b"\x31\xc0\xc3"  # xor eax, eax; ret

        handler_code = b"\x8b\x44\x24\x0c"  # mov eax, [esp + 0xc]  (context)
        for field, offset in ((0xBC, 0), (0x98, 4), (0x90, 8)):  # SegCs, SegDs, SegFs
            handler_code += b"\x8b\x88" + dword(field)  # mov ecx, [eax + field]
            handler_code += b"\x89\x0d" + dword(data + offset)  # mov [data + offset], ecx
        handler_code += b"\xc7\x80\xb8\x00\x00\x00" + dword(done)  # mov [eax + Eip], done
        handler_code += b"\x31\xc0\xc3"  # return ExceptionContinueExecution

        se.mem_write(code, main)
        se.mem_write(done, finish)
        se.mem_write(handler, handler_code)

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is None
        assert struct.unpack("<III", se.mem_read(data, 12)) == (0x1B, 0x23, 0x3B)


def test_nt_continue_restores_a_captured_context(config):
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="x86")
        data = se.mem_alloc(0x1000)
        context, counter = data, data + 0x800

        main = guest_call(4, get_api(se, "kernel32", "RtlCaptureContext"), context)
        main += b"\xff\x05" + dword(counter)  # inc dword [counter]
        main += b"\x83\x3d" + dword(counter) + b"\x02"  # cmp dword [counter], 2
        restore = guest_call(4, get_api(se, "ntdll", "NtContinue"), context, 0)
        main += b"\x74" + bytes([len(restore)]) + restore  # je past the restore
        main += b"\x8c\x0d" + dword(data + 0x900)  # mov [data + 0x900], cs
        main += b"\xa1" + dword(counter) + b"\xc3"  # return the count
        se.mem_write(code, main)

        se.run_shellcode(code)

        run = se.get_report().entry_points[0]
        assert run.error is None
        assert run.ret_val == 2
        assert struct.unpack("<I", se.mem_read(context + 0xBC, 4))[0] == 0x1B
        assert word(se, data + 0x900) == 0x1B
