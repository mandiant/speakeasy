import json
import multiprocessing as mp
import os
import struct
import subprocess
import sys

import pytest

from speakeasy.cli import wait_for_child
from speakeasy.version import __version__
from tests.pe_builder import build_pe


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


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "speakeasy.cli", *args], check=False, capture_output=True, text=True, timeout=60
    )


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--raw"], "--raw needs --arch"),
        (["-V", "/nonexistent:c:\\x"], "Volume host path does not exist: /nonexistent"),
    ],
)
def test_cli_rejects_bad_arguments(tmp_path, args, message):
    target = tmp_path / "sc.bin"
    target.write_bytes(b"\xc3")

    result = run_cli("-t", str(target), "--no-mp", *args)

    assert result.returncode == 2
    assert message in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("mode", [[], ["--no-mp"]])
def test_cli_logs_its_progress_when_run_as_a_module(tmp_path, mode):
    target = tmp_path / "sc.bin"
    target.write_bytes(b"\xc3")
    output = tmp_path / "report.json"
    dropped = tmp_path / "dropped.zip"

    result = run_cli(
        "-t", str(target), "--raw", "--arch", "x86", "-o", str(output), "--dropped-files-path", str(dropped), *mode
    )

    assert result.returncode == 0, result.stderr
    assert "* No dropped files found" in result.stderr
    assert "* Finished emulating" in result.stderr
    assert "* Saving emulation report to" in result.stderr


def test_cli_prints_its_version():
    result = run_cli("--version")

    assert result.returncode == 0
    assert result.stdout.strip() == f"speakeasy {__version__}"


# ud2 at offset 10, so that only a decimal start offset of 10 runs it.
UD2_AT_10 = b"\xc3" * 10 + b"\x0f\x0b" + b"\xc3" * 10


@pytest.mark.parametrize(
    ("name", "content", "args"),
    [
        ("sc.bin", UD2_AT_10, ["--raw", "--arch", "x86", "--raw-offset", "10"]),
        ("ep.exe", build_pe(text=UD2_AT_10)[0], ["--entry-point", str(0x1000 + 10)]),
    ],
)
def test_cli_writes_the_report_of_a_failed_run_to_stdout_and_exits_zero(tmp_path, name, content, args):
    target = tmp_path / name
    target.write_bytes(content)

    result = run_cli("-t", str(target), "--no-mp", *args)

    assert result.returncode == 0
    entry_point = json.loads(result.stdout)["runs"][0]
    assert entry_point["error"]["type"] == "invalid_instruction"
    assert entry_point["error"]["pc"] == entry_point["start_address"]


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
        + ["--limits-per-run-time", "1", "--limits-total-time", "20"],
        check=False,
        capture_output=True,
        timeout=60,
    )

    report = json.loads(output.read_text())
    assert [(ep["type"], ep["error"]["type"]) for ep in report["runs"]] == [
        ("module_entry", "per_run_time_limit"),
        ("thread", "per_run_time_limit"),
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


@pytest.mark.parametrize(("args", "count"), [([], 3), (["--no-runs-exports"], 1)])
def test_cli_runs_the_exports_unless_no_runs_exports(tmp_path, load_test_bin, args, count):
    target = tmp_path / "dll_test_x86.dll"
    target.write_bytes(load_test_bin("dll_test_x86.dll.xz"))
    config = os.path.join(os.path.dirname(__file__), "test.json")

    result = run_cli("-t", str(target), "-c", config, "--no-mp", *args)

    assert result.returncode == 0, result.stderr
    assert len(json.loads(result.stdout)["runs"]) == count
