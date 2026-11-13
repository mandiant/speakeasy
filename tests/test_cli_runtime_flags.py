import hashlib
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
        (["-o", "/nonexistent/r.json"], "cannot write --output /nonexistent/r.json: directory does not exist"),
        (["--dropped-files-path", "/nonexistent/d.zip"], "cannot write --dropped-files-path /nonexistent/d.zip"),
        (["--argv", "x", "--process-command-line", "a.exe"], "--argv conflicts with process.command_line"),
        (["--argv", "unterminated 'quote"], "Invalid --argv: No closing quotation"),
    ],
)
def test_cli_rejects_bad_arguments(tmp_path, args, message):
    target = tmp_path / "sc.bin"
    target.write_bytes(b"\xc3")

    result = run_cli("-t", str(target), "--no-mp", *args)

    assert result.returncode == 2
    assert message in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_logs_its_progress_when_run_as_a_module(tmp_path):
    target = tmp_path / "sc.bin"
    target.write_bytes(b"\xc3")
    dropped = tmp_path / "dropped.zip"

    result = run_cli("-t", str(target), "--raw", "--arch", "x86", "--dropped-files-path", str(dropped))

    assert result.returncode == 0, result.stderr
    # The child process logs the first line and the parent process logs the second.
    assert "No dropped files found" in result.stderr
    assert "Finished emulating" in result.stderr


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b'{"limits": {\n', "Config file is not valid JSON: {config}: line 2 column 1:"),
        (b"\x81", "Cannot read config file: {config}:"),
    ],
)
def test_cli_rejects_a_config_file_it_cannot_parse(tmp_path, data, message):
    target = tmp_path / "sc.bin"
    target.write_bytes(b"\xc3")
    config = tmp_path / "bad.json"
    config.write_bytes(data)

    result = run_cli("-t", str(target), "--no-mp", "-c", str(config))

    assert result.returncode == 2
    assert message.format(config=config) in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_rejects_a_directory_as_the_config_file(tmp_path):
    target = tmp_path / "sc.bin"
    target.write_bytes(b"\xc3")

    result = run_cli("-t", str(target), "--no-mp", "-c", str(tmp_path))

    assert result.returncode == 2
    assert f"Config file is a directory: {tmp_path}" in result.stderr


def test_cli_prints_its_version():
    result = run_cli("--version")

    assert result.returncode == 0
    assert result.stdout.strip() == f"speakeasy {__version__}"


def test_cli_writes_one_line_per_log_record_when_stderr_is_a_pipe(tmp_path):
    # The long directory name makes the auto-mount record longer than 80 columns.
    target_dir = tmp_path / ("x" * 100)
    target_dir.mkdir()
    target = target_dir / "sample.exe"
    target.write_bytes(build_pe(text=b"\xc3")[0])

    result = run_cli("-t", str(target), "-o", str(tmp_path / "report.json"))

    assert result.returncode == 0, result.stderr
    expected = f"Auto-mounted 1 file(s) from target directory {target_dir.resolve()} into C:\\Windows\\system32"
    assert expected in result.stderr.splitlines()


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


# CreateFileA("C:\\out.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL), then WriteFile of 4 bytes to the handle.
def drop_file(base, iat):
    data = base + 0x2000
    code = b"\x6a\x00" * 2 + b"\x6a\x02" + b"\x6a\x00" * 2 + b"\x68" + struct.pack("<I", 0x40000000)
    code += (
        b"\x68" + struct.pack("<I", data) + b"\xff\x15" + struct.pack("<I", base + iat["kernel32.dll", "CreateFileA"])
    )
    code += (
        b"\x6a\x00\x68" + struct.pack("<I", data + 0x20) + b"\x6a\x04\x68" + struct.pack("<I", data + 0x10) + b"\x50"
    )
    return code + b"\xff\x15" + struct.pack("<I", base + iat["kernel32.dll", "WriteFile"]) + b"\xc3"


# The directory exists, so the check before the run accepts the path, but the name is too long to create.
LONG_NAME = "x" * 300


@pytest.mark.parametrize("mode", [[], ["--no-mp"]])
def test_cli_writes_the_report_and_exits_nonzero_when_the_dropped_files_archive_write_fails(tmp_path, mode):
    data = b"C:\\out.txt".ljust(0x10, b"\0") + b"data".ljust(0x14, b"\0")
    image, _ = build_pe(text=drop_file, data=data, imports={"kernel32.dll": ["CreateFileA", "WriteFile"]})
    target = tmp_path / "dropper.exe"
    target.write_bytes(image)
    output = tmp_path / "report.json"

    result = run_cli("-t", str(target), "-o", str(output), "--dropped-files-path", str(tmp_path / LONG_NAME), *mode)

    assert result.returncode == 1
    assert "error: failed to write the dropped files archive:" in result.stderr
    assert "Traceback" not in result.stderr
    assert json.loads(output.read_text())["runs"][0]["dropped_files"]


def test_cli_exits_nonzero_when_the_report_write_fails(tmp_path):
    target = tmp_path / "ret.exe"
    target.write_bytes(build_pe(text=b"\xc3")[0])

    result = run_cli("-t", str(target), "-o", str(tmp_path / LONG_NAME), "--no-mp")

    assert result.returncode == 1
    assert "error: failed to write the report:" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(("args", "mounted"), [([], True), (["--no-auto-mount"], False)])
def test_cli_auto_mounts_the_target_directory_unless_no_auto_mount(tmp_path, load_test_bin, args, mounted):
    # The sample opens and reads c:\myfile.txt.
    target = tmp_path / "file_access_test_x86.exe"
    target.write_bytes(load_test_bin("file_access_test_x86.exe.xz"))
    content = b"next to the input"
    (tmp_path / "myfile.txt").write_bytes(content)

    result = run_cli("-t", str(target), "--process-current-dir", "c:\\", "--no-mp", *args)

    assert result.returncode == 0, result.stderr
    [read] = [e for e in json.loads(result.stdout)["runs"][0]["events"] if e["event"] == "file_read"]
    assert (read["data_ref"] == hashlib.sha256(content).hexdigest()) is mounted
