import pytest

from speakeasy import Speakeasy
from speakeasy.config import SpeakeasyConfig
from speakeasy.errors import ConfigError
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


def read_command_line(se):
    rv, _ = call(se, "kernel32", "GetCommandLineA", [])
    return se.read_mem_string(rv, 1)


def get_printfs(se):
    events = se.get_report().runs[0].events
    return [evt.args[2].display for evt in events if evt.event == "api" and "vfprintf" in evt.api_name]


def test_default_command_line_is_the_quoted_image_path(load_test_bin):
    with Speakeasy() as se:
        module = se.load_module(data=load_test_bin("argv_test_x86.exe.xz"))
        se.run_module(module)
        assert read_command_line(se) == f'"{module.emu_path}"'
        assert get_printfs(se) == ["argc = 1\n", f"argv[0] = {module.emu_path}\n"]


def test_configured_command_line_gives_argv(load_test_bin):
    with Speakeasy(config={"process": {"command_line": 'lab.exe -x "a b"'}}) as se:
        se.run_module(se.load_module(data=load_test_bin("argv_test_x86.exe.xz")))
        assert get_printfs(se)[1:] == ["argv[0] = lab.exe\n", "argv[1] = -x\n", "argv[2] = a b\n"]


def test_argv_and_a_configured_command_line_are_an_error():
    with pytest.raises(ConfigError, match="argv"):
        Speakeasy(config={"process": {"command_line": "lab.exe"}}, argv=["x"])


def test_dll_runs_in_a_container_with_the_quoted_container_path_and_argv(load_test_bin):
    with Speakeasy(argv=["x"]) as se:
        se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
        start_process(se)
        assert read_command_line(se) == f'"{se.emu.get_current_process().path}" x'


def test_argv_and_a_container_command_line_are_an_error(load_test_bin):
    processes = SpeakeasyConfig().model_dump()["processes"]
    next(p for p in processes if p["is_main_exe"])["command_line"] = "svchost.exe -k netsvcs"
    with Speakeasy(config={"processes": processes}, argv=["x"]) as se, pytest.raises(ConfigError, match="argv"):
        se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))


def test_child_does_not_get_the_argv_of_the_parent(load_test_bin):
    with Speakeasy(argv=["x"]) as se:
        module = se.load_module(data=load_test_bin("parent_x86.exe.xz"))
        se.emu.fileman.add_existing_file("c:\\child.exe", load_test_bin("child_x86.exe.xz"))
        se.run_module(module)
        assert se.emu.get_current_process().path == "c:\\child.exe"
        assert "x" not in se.emu.get_argv()


@pytest.mark.parametrize(("name", "width"), [("_acmdln", 1), ("_wcmdln", 2)])
def test_crt_command_line_global_is_the_command_line_of_the_process(load_test_bin, name, width):
    with Speakeasy(argv=["a b"]) as se:
        module = se.load_module(data=load_test_bin("argv_test_x86.exe.xz"))
        se.run_module(module)
        ptr = int.from_bytes(se.mem_read(se.emu.get_proc("msvcrt", name), 4), "little")
        assert se.read_mem_string(ptr, width) == f'"{module.emu_path}" "a b"'
