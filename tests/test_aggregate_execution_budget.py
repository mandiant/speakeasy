"""The limits.total_time cap on active execution across one public invocation."""

import json
import subprocess
import sys
import time

import pytest
from pydantic import ValidationError

from speakeasy import Speakeasy
from speakeasy.config import SpeakeasyConfig
from tests.test_emulate_children import CHILD, CHILD_PATH, PARENT
from tests.test_guest_dependency_loading import make_native_dll


def last_error(se):
    error = se.get_report().entry_points[-1].error
    return error.type if error is not None else None


def test_limits_total_time_rejects_invalid_values(config):
    for invalid in (-1, float("inf"), float("nan")):
        with pytest.raises(ValidationError):
            SpeakeasyConfig.model_validate({**config, "limits": {"total_time": invalid}})


def test_spinning_call_stops_without_per_run_timeout(config):
    config["limits"].update(per_run_time=0, total_time=0.05)
    # A child process turns a missed native stop into a failure instead of a hung suite.
    script = """
import json
import sys
from speakeasy import Speakeasy
se = Speakeasy(config=json.loads(sys.argv[1]))
base = se.load_shellcode(data=bytes.fromhex("c3ebfe"), arch="x86")
se.run_shellcode(base)
se.call(base + 1)
error = se.get_report().entry_points[-1].error
assert error is not None and error.type == "max_total_time", error
se.call(base)
assert se.get_report().entry_points[-1].error is None
se.shutdown()
"""
    result = subprocess.run(
        [sys.executable, "-c", script, json.dumps(config)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_self_respawning_threads_stop_at_cap(config, caplog):
    total_time, delay = 0.25, 0.05
    config["limits"].update(per_run_time=5, total_time=total_time)
    se = Speakeasy(config=config)
    try:
        # CreateThread(NULL, 0, this_function, NULL, 0, NULL); RET
        code = b"\x6a\0\x6a\0\x6a\0\x68" + b"\0" * 4 + b"\x6a\0\x6a\0\xb8" + b"\0" * 4 + b"\xff\xd0\xc3"
        base = se.load_shellcode(data=code, arch="x86")
        create_thread = se.emu.get_proc("kernel32", "CreateThread")
        se.mem_write(base + 7, base.to_bytes(4, "little"))
        se.mem_write(base + 16, create_thread.to_bytes(4, "little"))

        def slow_create_thread(e, api, original, args):
            time.sleep(delay)
            return original(args)

        se.add_api_hook(slow_create_thread, "kernel32", "CreateThread")
        se.run_shellcode(base)

        errors = [run.error.type if run.error else None for run in se.get_report().entry_points]
        assert errors[:-1] == [None] * (len(errors) - 1)
        # The last run is complete if the cap is reached while its thread is prepared.
        assert errors[-1] in (None, "max_total_time")
        # Each run that starts a thread uses at least delay, so no run starts after the cap.
        assert len(errors) <= total_time / delay + 1
        assert sum("Total execution time" in record.message for record in caplog.records) == 1
    finally:
        se.shutdown()


def test_runtime_dll_main_stopped_by_cap_is_unloaded(config, tmp_path):
    config["limits"].update(per_run_time=5, total_time=0.05)
    config["modules"]["directory_x86"] = str(tmp_path)
    se = Speakeasy(config=config)
    try:
        base = se.load_shellcode(data=b"\xc3", arch="x86")
        se.run_shellcode(base)
        exports = make_native_dll(se.emu, tmp_path / "guest_dependency.dll")
        se.add_code_hook(
            lambda e, address, size: time.sleep(0.1), begin=exports["Initializer"], end=exports["Initializer"]
        )
        name = se.mem_alloc(0x1000)
        se.mem_write(name, b"guest_dependency.dll\0")

        se.call(se.emu.get_proc("kernel32", "LoadLibraryA"), [name])
        assert last_error(se) == "max_total_time"

        se.call(se.emu.get_proc("kernel32", "GetModuleHandleA"), [name])
        assert last_error(se) is None
        assert se.reg_read("eax") == 0
    finally:
        se.shutdown()


def test_exit_process_after_the_cap_ends_the_run_at_the_cap(config):
    config["limits"].update(per_run_time=5, total_time=0.05)
    with Speakeasy(config=config) as se:
        # PUSH 0; MOV EAX,ExitProcess; CALL EAX; RET
        base = se.load_shellcode(data=b"\x6a\x00\xb8\0\0\0\0\xff\xd0\xc3", arch="x86")
        se.mem_write(base + 3, se.emu.get_proc("kernel32", "ExitProcess").to_bytes(4, "little"))

        def slow_exit_process(e, api, original, args):
            time.sleep(0.1)
            return original(args)

        se.add_api_hook(slow_exit_process, "kernel32", "ExitProcess")
        se.run_shellcode(base)

        (run,) = se.get_report().entry_points
        assert run.error is not None and run.error.type == "max_total_time"
        assert [event.api_name for event in run.events if event.event == "api"] == ["kernel32.ExitProcess"]


def test_run_that_the_cap_prevents_from_starting_is_not_reported(config, caplog):
    config["limits"].update(per_run_time=5, total_time=0.05, api_calls=1)
    with Speakeasy(config=config) as se:
        # CreateThread(NULL, 0, thread, NULL, 0, NULL); MOV EAX,GetTickCount; CALL EAX; RET; thread: RET
        code = b"\x6a\0\x6a\0\x6a\0\x68" + b"\0" * 4 + b"\x6a\0\x6a\0\xb8" + b"\0" * 4 + b"\xff\xd0"
        code += b"\xb8\0\0\0\0\xff\xd0\xc3"
        thread = len(code)
        code += b"\xc3"
        base = se.load_shellcode(data=code, arch="x86")
        se.mem_write(base + 7, (base + thread).to_bytes(4, "little"))
        se.mem_write(base + 16, se.emu.get_proc("kernel32", "CreateThread").to_bytes(4, "little"))
        se.mem_write(base + 23, se.emu.get_proc("kernel32", "GetTickCount").to_bytes(4, "little"))

        def slow_tick_count(e, api, original, args):
            time.sleep(0.1)
            return 1

        # The second API call reaches limits.api_calls, so the run ends and the thread's run
        # is prepared. The time of the slow call then uses up limits.total_time.
        se.add_api_hook(slow_tick_count, "kernel32", "GetTickCount", argc=0)
        se.run_shellcode(base)

        (run,) = se.get_report().entry_points
        assert run.error is not None and run.error.type == "max_api_count"
        assert sum("Total execution time" in record.message for record in caplog.records) == 1


def run_parent_with_child(se, load_test_bin):
    module = se.load_module(data=load_test_bin(PARENT))
    se.emu.fileman.add_existing_file(CHILD_PATH, load_test_bin(CHILD))
    se.run_module(module)
    return module


def test_children_do_not_load_after_the_cap(config, load_test_bin):
    config["limits"].update(per_run_time=5, total_time=0.25)
    with Speakeasy(config=config) as se:

        def slow_create_process(e, api, original, args):
            rv = original(args)
            time.sleep(0.3)
            return rv

        se.add_api_hook(slow_create_process, "kernel32", "CreateProcessA")
        module = run_parent_with_child(se, load_test_bin)
        report = se.get_report()

        assert se.emu.get_current_process().path == module.emu_path
        assert [run.error.type if run.error else None for run in report.entry_points] == ["max_total_time"]
        assert [(error.type, error.context_summary) for error in report.errors] == [
            ("max_total_time", "1 child process did not run")
        ]


def test_load_of_a_child_counts_against_the_cap(config, load_test_bin):
    config["limits"].update(per_run_time=5, total_time=0.25)
    with Speakeasy(config=config) as se:

        def slow_child_image_map(e, base, size, tag, perms, flags):
            if tag.startswith("emu.module.child."):
                time.sleep(0.3)

        se.add_mem_map_hook(slow_child_image_map)
        run_parent_with_child(se, load_test_bin)
        report = se.get_report()

        assert [run.error for run in report.entry_points] == [None]
        assert [(error.type, error.context_summary) for error in report.errors] == [
            ("max_total_time", "1 child process did not run")
        ]
