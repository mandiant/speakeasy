from pathlib import Path, PureWindowsPath

import pytest

from speakeasy import Speakeasy
from speakeasy.config import SpeakeasyConfig, get_default_config_dict
from speakeasy.errors import ConfigError
from speakeasy.volumes import apply_volumes, parse_volume_spec
from tests.pe_builder import build_pe


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
def test_load_module_mounts_the_target_directory_only_with_auto_mount(tmp_path: Path, auto_mount: bool):
    target = tmp_path / "sample.exe"
    target.write_bytes(build_pe(text=b"\xc3")[0])
    (tmp_path / "secret.txt").write_bytes(b"secret")

    with Speakeasy(auto_mount=auto_mount) as se:
        se.load_module(str(target))
        exists = se.emu.fileman.does_file_exist_by_path("C:\\Windows\\system32\\secret.txt")

    assert exists is auto_mount
