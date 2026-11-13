import hashlib
from pathlib import Path, PureWindowsPath

import pytest

from speakeasy import Speakeasy
from speakeasy.config import SpeakeasyConfig, get_default_config_dict
from speakeasy.errors import ConfigError
from speakeasy.volumes import apply_volumes, parse_volume_spec


def test_parse_volume_spec_unix_paths():
    host, guest = parse_volume_spec("/tmp/samples:c:\\test")
    assert host == Path("/tmp/samples")
    assert guest == PureWindowsPath("c:\\test")


def test_apply_volumes_round_trip_validation(tmp_path: Path):
    f = tmp_path / "test.dll"
    f.write_bytes(b"MZ" + b"\x00" * 100)

    config = get_default_config_dict()
    apply_volumes(config, [f"{f}:c:\\windows\\system32\\test.dll"])

    model = SpeakeasyConfig.model_validate(config)
    first = model.filesystem.files[0]
    assert first.mode == "full_path"
    assert first.emu_path == "c:\\windows\\system32\\test.dll"


@pytest.mark.parametrize("spec", ["garbage", "/nonexistent:c:\\x"], ids=["malformed", "missing_host_path"])
def test_speakeasy_rejects_a_bad_volume_with_config_error(spec: str):
    with pytest.raises(ConfigError, match="volume"):
        Speakeasy(volumes=[spec])


@pytest.mark.parametrize("auto_mount", [True, False])
def test_the_guest_reads_a_file_next_to_the_input_only_with_auto_mount(tmp_path: Path, load_test_bin, auto_mount):
    # The sample opens and reads c:\myfile.txt.
    target = tmp_path / "file_access_test_x86.exe"
    target.write_bytes(load_test_bin("file_access_test_x86.exe.xz"))
    content = b"next to the input"
    (tmp_path / "myfile.txt").write_bytes(content)
    config = get_default_config_dict()
    config["process"]["current_dir"] = "c:\\"

    with Speakeasy(config=config, auto_mount=auto_mount) as se:
        se.run_module(se.load_module(str(target)))
        report = se.get_report()

    [read] = [e for e in report.runs[0].events if e.event == "file_read"]
    assert (read.data_ref == hashlib.sha256(content).hexdigest()) is auto_mount
