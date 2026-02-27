from __future__ import annotations

import copy
import json
from pathlib import Path, PureWindowsPath

import pytest

import speakeasy
from speakeasy.config import SpeakeasyConfig
from speakeasy.volumes import apply_volumes, expand_volume_to_entries, parse_volume_spec


@pytest.fixture(scope="session")
def default_config_data():
    config_path = Path(speakeasy.__file__).resolve().parent / "configs" / "default.json"
    return json.loads(config_path.read_text())


def test_parse_volume_spec_unix_paths():
    host, guest = parse_volume_spec("/tmp/samples:c:\\test")
    assert host == Path("/tmp/samples")
    assert guest == PureWindowsPath("c:\\test")


def test_parse_volume_spec_windows_host_and_guest():
    host, guest = parse_volume_spec("C:\\host\\dir:D:\\guest\\dir")
    assert host == Path("C:\\host\\dir")
    assert guest == PureWindowsPath("D:\\guest\\dir")


def test_parse_volume_spec_windows_host_unix_style_guest():
    host, guest = parse_volume_spec("C:\\data:\\windows\\system32")
    assert host == Path("C:\\data")
    assert guest == PureWindowsPath("\\windows\\system32")


def test_parse_volume_spec_empty_spec_raises():
    with pytest.raises(ValueError, match="Empty volume"):
        parse_volume_spec("")


def test_parse_volume_spec_missing_separator_raises():
    with pytest.raises(ValueError, match="missing ':'"):
        parse_volume_spec("/tmp/no_guest")


def test_parse_volume_spec_empty_host_raises():
    with pytest.raises(ValueError, match="Empty host"):
        parse_volume_spec(":c:\\guest")


def test_parse_volume_spec_empty_guest_raises():
    with pytest.raises(ValueError, match="Empty guest"):
        parse_volume_spec("/tmp/host:")


def test_expand_volume_single_file(tmp_path: Path):
    f = tmp_path / "payload.bin"
    f.write_bytes(b"\x90" * 16)

    entries = expand_volume_to_entries(f, PureWindowsPath("c:\\malware\\payload.bin"))
    assert len(entries) == 1
    assert entries[0]["mode"] == "full_path"
    assert entries[0]["emu_path"] == "c:\\malware\\payload.bin"
    assert entries[0]["path"] == str(f.resolve())


def test_expand_volume_directory_recursive(tmp_path: Path):
    (tmp_path / "a.txt").write_text("a")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "b.txt").write_text("b")

    entries = expand_volume_to_entries(tmp_path, PureWindowsPath("c:\\data"))
    assert len(entries) == 2

    emu_paths = {entry["emu_path"] for entry in entries}
    assert str(PureWindowsPath("c:\\data\\a.txt")) in emu_paths
    assert str(PureWindowsPath("c:\\data\\sub\\b.txt")) in emu_paths


def test_expand_volume_empty_directory(tmp_path: Path):
    empty = tmp_path / "empty"
    empty.mkdir()
    entries = expand_volume_to_entries(empty, PureWindowsPath("c:\\empty"))
    assert entries == []


def test_expand_volume_nonexistent_host_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        expand_volume_to_entries(tmp_path / "nope", PureWindowsPath("c:\\nope"))


def test_apply_volumes_prepends_entries(tmp_path: Path):
    f = tmp_path / "vol.bin"
    f.write_bytes(b"\xcc")

    config = {
        "filesystem": {
            "files": [
                {"mode": "default", "path": "original.bin"},
            ]
        }
    }

    apply_volumes(config, [f"{f}:c:\\vol.bin"])

    files = config["filesystem"]["files"]
    assert len(files) == 2
    assert files[0]["emu_path"] == "c:\\vol.bin"
    assert files[1]["mode"] == "default"


def test_apply_volumes_empty_list_is_noop():
    config = {"filesystem": {"files": []}}
    result = apply_volumes(config, [])
    assert result is config
    assert config["filesystem"]["files"] == []


def test_apply_volumes_creates_filesystem_key(tmp_path: Path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"\x00")

    config: dict = {}
    apply_volumes(config, [f"{f}:c:\\x.bin"])
    assert "filesystem" in config
    assert len(config["filesystem"]["files"]) == 1


def test_apply_volumes_round_trip_validation(default_config_data, tmp_path: Path):
    f = tmp_path / "test.dll"
    f.write_bytes(b"MZ" + b"\x00" * 100)

    config = copy.deepcopy(default_config_data)
    apply_volumes(config, [f"{f}:c:\\windows\\system32\\test.dll"])

    model = SpeakeasyConfig.model_validate(config)
    first = model.filesystem.files[0]
    assert first.mode == "full_path"
    assert first.emu_path == "c:\\windows\\system32\\test.dll"
