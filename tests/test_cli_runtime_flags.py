import subprocess
import sys


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
