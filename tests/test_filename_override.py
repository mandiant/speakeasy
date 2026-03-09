"""Tests for the ``filename`` parameter on load_module / load_shellcode."""

from speakeasy import Speakeasy


def test_load_module_filename_override(load_test_bin):
    data = load_test_bin("dll_test_x86.dll.xz")
    se = Speakeasy()
    se.load_module(data=data, filename="malware.dll")

    assert se.emu.file_name == "malware.dll"
    assert se.emu.mod_name == "malware"
