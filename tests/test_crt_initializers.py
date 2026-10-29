import struct

import pytest

from speakeasy import Speakeasy

ACTIVE_SETUP_DROPPER = "025bd4d05ca3557f429bf0a44f5f93745df2b70398ed80a19b7807cc472649df.exe.xz"


@pytest.mark.parametrize("bin_file", ["argv_test_x86.exe.xz", "argv_test_x64.exe.xz"])
def test_initterm_e_runs_the_crt_initializers_in_order(config, load_test_bin, run_test, bin_file):
    report = run_test(config, load_test_bin(bin_file))
    names = [evt.api_name for evt in report.entry_points[0].events or [] if evt.event == "api"]
    initializers = names[names.index("msvcrt._initterm_e") + 1 : names.index("msvcrt._initterm")]
    calls = [
        name
        for name in initializers
        if name in ("msvcrt._configure_narrow_argv", "msvcrt._initialize_narrow_environment")
    ]
    assert calls == ["msvcrt._configure_narrow_argv", "msvcrt._initialize_narrow_environment"]
    assert "msvcrt.__stdio_common_vfprintf" in names


def test_iostream_static_constructors_are_thiscall_on_x86(config, load_test_bin):
    """
    025bd4d0 is a VC6 program that includes <iostream>. Its second _initterm table has two
    static initializers that load ECX with a static object and jump to the MSVCP60
    std::ios_base::Init and std::_Winit constructors. These are thiscall with no stack
    arguments, so when _initterm returns (RVA 0x273E) the start-up code still has the 0x24
    bytes of call arguments above the stack pointer it saved at [ebp - 0x18].
    """
    with Speakeasy(config=config) as se:
        module = se.load_module(data=load_test_bin(ACTIVE_SETUP_DROPPER))
        stacks = []

        def after_initterm(emu, address, size):
            saved_esp = struct.unpack("<I", se.mem_read(se.reg_read("ebp") - 0x18, 4))[0]
            stacks.append((se.reg_read("esp") + 0x24, saved_esp))
            se.stop()

        se.add_code_hook(after_initterm, begin=module.base + 0x273E, end=module.base + 0x273E)
        se.run_module(module)
        run = se.get_report().entry_points[0]

    assert run.error is None
    ctors = [
        (e.api_name, e.ret_val) for e in run.events or [] if e.event == "api" and e.api_name.startswith("msvcrt.??0")
    ]
    assert ctors == [
        ("msvcrt.??0Init@ios_base@std@@QAE@XZ", hex(module.base + 0x44F9)),
        ("msvcrt.??0_Winit@std@@QAE@XZ", hex(module.base + 0x44F8)),
    ]
    [(esp, saved_esp)] = stacks
    assert esp == saved_esp
