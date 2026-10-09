"""The max_total_time cap on active execution across one public invocation."""

import json
import subprocess
import sys
import time

import pytest
from pydantic import ValidationError

from speakeasy import Speakeasy
from speakeasy.config import SpeakeasyConfig


def last_error(se):
    error = se.get_report().entry_points[-1].error
    return error.type if error is not None else None


def test_max_total_time_config(config):
    assert SpeakeasyConfig.model_validate(config).max_total_time == 60
    assert SpeakeasyConfig.model_validate({**config, "max_total_time": 0}).max_total_time == 0
    for invalid in (-1, float("inf"), float("nan")):
        with pytest.raises(ValidationError):
            SpeakeasyConfig.model_validate({**config, "max_total_time": invalid})


def test_spinning_call_stops_without_per_run_timeout(config):
    config.update(timeout=0, max_total_time=0.05)
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


def test_self_respawning_threads_stop_at_cap(config):
    config.update(timeout=5, max_total_time=0.06)
    se = Speakeasy(config=config)
    try:
        # CreateThread(NULL, 0, this_function, NULL, 0, NULL); RET
        code = b"\x6a\0\x6a\0\x6a\0\x68" + b"\0" * 4 + b"\x6a\0\x6a\0\xb8" + b"\0" * 4 + b"\xff\xd0\xc3"
        base = se.load_shellcode(data=code, arch="x86")
        create_thread = se.emu.get_proc("kernel32", "CreateThread")
        se.mem_write(base + 7, base.to_bytes(4, "little"))
        se.mem_write(base + 16, create_thread.to_bytes(4, "little"))

        def slow_create_thread(e, api, original, args):
            time.sleep(0.04)
            return original(args)

        se.add_api_hook(slow_create_thread, "kernel32", "CreateThread")
        se.run_shellcode(base)

        errors = [run.error.type if run.error else None for run in se.get_report().entry_points]
        assert errors == [None, "max_total_time"]
    finally:
        se.shutdown()


def test_runtime_dll_main_stopped_by_cap_is_unloaded(config, tmp_path):
    from tests.test_guest_dependency_loading import make_native_dll

    config.update(timeout=5, max_total_time=0.05)
    config["modules"]["module_directory_x86"] = str(tmp_path)
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
