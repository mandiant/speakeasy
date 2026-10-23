import subprocess
import sys

import pytest

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
