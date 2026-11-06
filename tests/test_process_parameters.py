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
