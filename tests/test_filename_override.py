"""Tests for the ``filename`` parameter on load_module / load_shellcode."""

from speakeasy import Speakeasy


def test_load_module_filename_override(load_test_bin):
    data = load_test_bin("dll_test_x86.dll.xz")
    se = Speakeasy()
    mod = se.load_module(data=data, filename="malware.dll")

    assert se.emu.file_name == "malware.dll"
    assert se.emu.mod_name == "malware"


def test_load_module_filename_strips_directory(load_test_bin):
    data = load_test_bin("dll_test_x86.dll.xz")
    se = Speakeasy()
    se.load_module(data=data, filename="C:\\Users\\victim\\Desktop\\evil.dll")

    assert se.emu.file_name == "evil.dll"
    assert se.emu.mod_name == "evil"


def test_load_module_path_still_works(load_test_bin, tmp_path):
    data = load_test_bin("dll_test_x86.dll.xz")
    p = tmp_path / "sample.dll"
    p.write_bytes(data)
    se = Speakeasy()
    se.load_module(path=str(p))

    assert se.emu.file_name == "sample.dll"
    assert se.emu.mod_name == "sample"


def test_load_module_filename_overrides_path(load_test_bin, tmp_path):
    data = load_test_bin("dll_test_x86.dll.xz")
    p = tmp_path / "sample.dll"
    p.write_bytes(data)
    se = Speakeasy()
    se.load_module(path=str(p), filename="renamed.dll")

    assert se.emu.file_name == "renamed.dll"
    assert se.emu.mod_name == "renamed"


def test_load_module_kernel_filename_override(load_test_bin):
    data = load_test_bin("wdm_test_x86.sys.xz")
    se = Speakeasy()
    mod = se.load_module(data=data, filename="rootkit.sys")

    assert se.emu is not None
    from speakeasy import WinKernelEmulator

    assert isinstance(se.emu, WinKernelEmulator)
