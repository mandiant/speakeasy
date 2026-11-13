import io
import logging
import subprocess
import sys

import pytest

from speakeasy.cli import setup_logging
from tests.pe_builder import build_pe


@pytest.fixture
def speakeasy_logger():
    root = logging.getLogger("speakeasy")
    handlers, level = list(root.handlers), root.level
    yield root
    root.handlers[:] = handlers
    root.setLevel(level)


def test_log_record_stays_on_one_line_when_stream_is_not_a_tty(speakeasy_logger):
    stream = io.StringIO()
    setup_logging(verbose=False, stream=stream)
    message = "Auto-mounted 2 file(s) from target directory " + "/very/long/path" * 20 + " into C:\\Windows\\system32"

    logging.getLogger("speakeasy.test").info(message)

    assert stream.getvalue() == message + "\n"


@pytest.mark.parametrize("mode", [[], ["--no-mp"]])
def test_cli_writes_one_line_per_record_to_a_pipe(tmp_path, mode):
    target_dir = tmp_path / ("x" * 100)
    target_dir.mkdir()
    image, _ = build_pe(text=b"\xc3")
    target = target_dir / "sample.exe"
    target.write_bytes(image)

    result = subprocess.run(
        [sys.executable, "-m", "speakeasy.cli", "-t", str(target), "-o", str(tmp_path / "report.json"), *mode],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr
    expected = f"Auto-mounted 1 file(s) from target directory {target_dir.resolve()} into C:\\Windows\\system32"
    assert expected in result.stderr.splitlines()
