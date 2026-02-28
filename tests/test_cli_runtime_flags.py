import subprocess
import sys

import pytest


def get_cli_help_text() -> str:
    result = subprocess.run(
        [sys.executable, "-m", "speakeasy.cli", "-h"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def test_cli_help_includes_renamed_runtime_flags():
    help_text = get_cli_help_text()

    assert "--argv" in help_text
    assert "--raw-offset" in help_text
    assert "--memory-dump-path" in help_text
    assert "--dropped-files-path" in help_text


def test_cli_help_omits_removed_short_forms():
    help_text = get_cli_help_text()

    assert "-p, --argv" not in help_text
    assert "-r, --raw" not in help_text
    assert "-a, --arch" not in help_text
    assert "-d, --memory-dump-path" not in help_text
    assert "-z, --dropped-files-path" not in help_text


@pytest.mark.parametrize(
    "legacy_args",
    [
        ["--params", "foo"],
        ["--raw_offset", "0x10"],
        ["--dump", "memdump.zip"],
        ["--dropped-files", "dropped.zip"],
        ["-p", "foo"],
        ["-r"],
        ["-a", "x86"],
        ["-d", "memdump.zip"],
        ["-z", "dropped.zip"],
    ],
)
def test_cli_rejects_removed_runtime_flags(legacy_args: list[str]):
    result = subprocess.run(
        [sys.executable, "-m", "speakeasy.cli", "--dump-default-config", *legacy_args],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "unrecognized arguments" in result.stderr
