import json
import multiprocessing as mp
import os
import struct
import subprocess
import sys

import pytest

from speakeasy.cli import wait_for_child
from tests.pe_builder import build_pe


def test_cli_rejects_removed_runtime_flags():
    legacy_arg_sets = [
        ["--capture-memory-dumps"],
        ["-p", "foo"],
    ]

    for legacy_args in legacy_arg_sets:
        result = subprocess.run(
            [sys.executable, "-m", "speakeasy.cli", "--dump-default-config", *legacy_args],
            check=False,
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0
        assert "unrecognized arguments" in result.stderr


@pytest.mark.parametrize("mode", [[], ["--no-mp"]])
def test_cli_reports_a_load_error_and_exits_nonzero(tmp_path, mode):
    image, _ = build_pe(data=b"\0" * 0x48, extra_dirs={14: (0x2000, 0x48)})
    target = tmp_path / "dotnet.exe"
    target.write_bytes(image)
    output = tmp_path / "report.json"

    result = subprocess.run(
        [sys.executable, "-m", "speakeasy.cli", "-t", str(target), "-o", str(output), *mode],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "error: .NET assemblies are not currently supported" in result.stderr
    assert "Traceback" not in result.stderr
    assert not output.exists()


def spinning_threads(base, iat):
    spin = base + 0x1000 + 21
    code = b"\x6a\x00" * 3 + b"\x68" + struct.pack("<I", spin) + b"\x6a\x00" * 2
    code += b"\xff\x15" + struct.pack("<I", base + iat["kernel32.dll", "CreateThread"])
    return code + b"\xeb\xfe"


def test_cli_waits_for_every_run_within_the_total_time(tmp_path):
    image, _ = build_pe(text=spinning_threads, imports={"kernel32.dll": ["CreateThread"]})
    target = tmp_path / "spin.exe"
    target.write_bytes(image)
    output = tmp_path / "report.json"

    subprocess.run(
        [sys.executable, "-m", "speakeasy.cli", "-t", str(target), "-o", str(output)]
        + ["--timeout", "1", "--max-total-time", "20"],
        check=False,
        capture_output=True,
        timeout=60,
    )

    report = json.loads(output.read_text())
    assert [(ep["ep_type"], ep["error"]["type"]) for ep in report["entry_points"]] == [
        ("module_entry", "timeout"),
        ("thread", "timeout"),
    ]


@pytest.mark.parametrize("code", [0, 3])
def test_a_child_that_exits_without_a_result_is_an_error(code):
    q: mp.Queue = mp.Queue()
    p = mp.Process(target=os._exit, args=(code,))
    p.start()

    report, error = wait_for_child(q, p, mp.Event(), wall_limit=0)

    assert report is None
    assert error == f"emulation process exited with code {code} and sent no report"


def test_the_result_of_a_child_is_returned():
    q: mp.Queue = mp.Queue()
    q.put(("{}", None))
    p = mp.Process(target=os._exit, args=(0,))
    p.start()

    assert wait_for_child(q, p, mp.Event(), wall_limit=0) == ("{}", None)
