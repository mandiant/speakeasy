"""The top-level pid of the report is the process that runs the input."""

import pytest

from speakeasy import Speakeasy


@pytest.mark.parametrize("kind", ["dll", "shellcode"])
def test_pid_is_the_container_process_for_a_dll_or_shellcode(config, load_test_bin, kind):
    container_path = next(p["path"] for p in config["processes"] if p.get("is_main_exe"))
    with Speakeasy(config=config) as se:
        if kind == "dll":
            se.run_module(se.load_module(data=load_test_bin("dll_test_x86.dll.xz")))
        else:
            se.run_shellcode(se.load_shellcode(None, "x86", data=b"\xc3"))
        report = se.get_report()

    assert [p.path for p in report.processes if p.pid == report.pid] == [container_path]
