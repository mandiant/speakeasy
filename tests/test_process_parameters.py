import ctypes as ct

import speakeasy.winenv.defs.nt.ntoskrnl as nt


def _get_offset(cstruct, field_name):
    return cstruct.__dict__[field_name].offset


def test_rtl_user_process_parameters_offsets_x86():
    params = nt.RTL_USER_PROCESS_PARAMETERS(ptr_size=4)
    cs = params.get_cstruct()
    assert _get_offset(cs, "MaximumLength") == 0x00
    assert _get_offset(cs, "Flags") == 0x08
    assert _get_offset(cs, "ConsoleHandle") == 0x10
    assert _get_offset(cs, "StandardInput") == 0x18
    assert _get_offset(cs, "StandardOutput") == 0x1C
    assert _get_offset(cs, "StandardError") == 0x20
    assert _get_offset(cs, "CurrentDirectory") == 0x24
    assert _get_offset(cs, "DllPath") == 0x30
    assert _get_offset(cs, "ImagePathName") == 0x38
    assert _get_offset(cs, "CommandLine") == 0x40
    assert _get_offset(cs, "Environment") == 0x48


def test_rtl_user_process_parameters_offsets_x64():
    params = nt.RTL_USER_PROCESS_PARAMETERS(ptr_size=8)
    cs = params.get_cstruct()
    assert _get_offset(cs, "MaximumLength") == 0x00
    assert _get_offset(cs, "Flags") == 0x08
    assert _get_offset(cs, "ConsoleHandle") == 0x10
    assert _get_offset(cs, "StandardInput") == 0x20
    assert _get_offset(cs, "StandardOutput") == 0x28
    assert _get_offset(cs, "StandardError") == 0x30
    assert _get_offset(cs, "CurrentDirectory") == 0x38
    assert _get_offset(cs, "DllPath") == 0x50
    assert _get_offset(cs, "ImagePathName") == 0x60
    assert _get_offset(cs, "CommandLine") == 0x70
    assert _get_offset(cs, "Environment") == 0x80


def test_curdir_struct_sizes():
    curdir32 = nt.CURDIR(ptr_size=4)
    curdir64 = nt.CURDIR(ptr_size=8)
    assert ct.sizeof(curdir32.__struct__) == 12
    assert ct.sizeof(curdir64.__struct__) == 24


def test_process_parameters_field_access():
    params = nt.RTL_USER_PROCESS_PARAMETERS(ptr_size=4)
    params.Flags = 1
    params.ConsoleHandle = 0xDEAD
    params.StandardInput = 0xF001
    params.ImagePathName.Length = 20
    params.ImagePathName.Buffer = 0x1000
    params.CurrentDirectory.DosPath.Length = 10
    params.CurrentDirectory.DosPath.Buffer = 0x2000

    data = params.get_bytes()
    assert len(data) == ct.sizeof(params.__struct__)
    assert int.from_bytes(data[0x08:0x0C], "little") == 1
    assert int.from_bytes(data[0x10:0x14], "little") == 0xDEAD
    assert int.from_bytes(data[0x18:0x1C], "little") == 0xF001
    assert int.from_bytes(data[0x38:0x3A], "little") == 20
    assert int.from_bytes(data[0x3C:0x40], "little") == 0x1000
    assert int.from_bytes(data[0x24:0x26], "little") == 10
    assert int.from_bytes(data[0x28:0x2C], "little") == 0x2000
