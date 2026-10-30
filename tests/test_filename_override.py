"""Tests for the ``filename`` parameter on load_module / load_shellcode."""

from speakeasy import Speakeasy
from speakeasy.windows.win32 import Win32Emulator


def test_load_module_filename_override(load_test_bin):
    data = load_test_bin("dll_test_x86.dll.xz")
    se = Speakeasy()
    se.load_module(data=data, filename="malware.dll")

    emu = se.emu
    assert isinstance(emu, Win32Emulator)
    assert emu.file_name == "malware.dll"
    assert emu.mod_name == "malware"
