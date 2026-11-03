"""The enum classes in speakeasy.winenv.defs.enums are what the generator writes for the win32json checkout."""

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR = REPO_ROOT / "scripts" / "gen_win32_enums.py"
ENUMS = REPO_ROOT / "speakeasy" / "winenv" / "defs" / "enums.py"
WIN32JSON = REPO_ROOT / "deps" / "win32json"


def test_defs_enums_match_the_generator_output(tmp_path: Path) -> None:
    if not (WIN32JSON / "api").is_dir():
        pytest.skip("deps/win32json is not checked out")
    output = tmp_path / "enums.py"
    cmd = [sys.executable, str(GENERATOR), "--win32json", str(WIN32JSON), "--output", str(output)]
    subprocess.run(cmd, check=True, capture_output=True)
    assert output.read_text() == ENUMS.read_text(), "run scripts/gen_win32_enums.py"
