import pytest

from speakeasy import Speakeasy
from speakeasy.windows import objman
from tests.handler_harness import call, start_process


@pytest.mark.parametrize("bin_file", ["argv_test_x86.exe.xz"])
def test_argv_exe(config, load_test_bin, run_test, bin_file):
    argv_len = 10
    argv = [f"argument_{i + 1}" for i in range(argv_len)]
    data = load_test_bin(bin_file)
    report = run_test(config, data, argv=argv)
    ep = report.runs
    printfs = []
    for evt in ep[0].events:
        if evt.event == "api" and "__stdio_common_vfprintf" in evt.api_name:
            printfs.append(evt)

    assert len(printfs) - 2 == argv_len
    for i, p in enumerate(printfs[2:]):
        i += 1
        fmt_str = p.args[2].display
        test_str = f"argv[{i}] = argument_{i}\n"
        assert test_str == fmt_str


def test_argv_zero_is_the_program_path(config, load_test_bin):
    with Speakeasy(config=config, argv=["x"]) as se:
        module = se.load_module(data=load_test_bin("argv_test_x86.exe.xz"))
        se.run_module(module)
        events = se.get_report().runs[0].events
    printfs = [evt.args[2].display for evt in events if evt.event == "api" and "vfprintf" in evt.api_name]
    assert printfs[1] == f"argv[0] = {module.emu_path}\n"


@pytest.mark.parametrize(("api", "width"), [("GetCommandLineA", 1), ("GetCommandLineW", 2)])
def test_argv_goes_into_the_command_line(config, load_test_bin, api, width):
    with Speakeasy(config=config, argv=["/run", "x y", 'a"b']) as se:
        module = se.load_module(data=load_test_bin("argv_test_x86.exe.xz"))
        se.run_module(module)
        rv, _ = call(se, "kernel32", api, [])
        assert se.read_mem_string(rv, width) == f'"{module.emu_path}" /run "x y" a\\"b'


@pytest.mark.parametrize(("api", "width"), [("GetCommandLineA", 1), ("GetCommandLineW", 2)])
def test_each_process_has_its_own_command_line_buffer(dll_emu, api, width):
    start_process(dll_emu)
    emu = dll_emu.emu
    parent = emu.get_current_process()
    parent.cmdline = "parent.exe a"
    first, _ = call(dll_emu, "kernel32", api, [])

    emu.set_current_process(objman.Process(emu, cmdline="child.exe " + "x" * 100))
    second, _ = call(dll_emu, "kernel32", api, [])
    emu.set_current_process(parent)

    assert dll_emu.read_mem_string(first, width) == "parent.exe a"
    assert dll_emu.read_mem_string(second, width) == "child.exe " + "x" * 100
    assert call(dll_emu, "kernel32", api, [])[0] == first
