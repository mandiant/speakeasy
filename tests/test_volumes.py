"""Tests for speakeasy.volumes — Docker-style --volume support."""

from __future__ import annotations

import json
import os
from pathlib import Path, PureWindowsPath

import pytest

import speakeasy
from speakeasy.config import SpeakeasyConfig
from speakeasy.volumes import apply_volumes, expand_volume_to_entries, parse_volume_spec


# ---------------------------------------------------------------------------
# parse_volume_spec
# ---------------------------------------------------------------------------


class TestParseVolumeSpec:
    def test_unix_paths(self):
        host, guest = parse_volume_spec("/tmp/samples:c:\\test")
        assert host == Path("/tmp/samples")
        assert guest == PureWindowsPath("c:\\test")

    def test_windows_host_and_guest(self):
        host, guest = parse_volume_spec("C:\\host\\dir:D:\\guest\\dir")
        assert host == Path("C:\\host\\dir")
        assert guest == PureWindowsPath("D:\\guest\\dir")

    def test_windows_host_unix_style_guest(self):
        # Guest without a drive letter still parses fine.
        host, guest = parse_volume_spec("C:\\data:\\windows\\system32")
        assert host == Path("C:\\data")
        assert guest == PureWindowsPath("\\windows\\system32")

    def test_empty_spec_raises(self):
        with pytest.raises(ValueError, match="Empty volume"):
            parse_volume_spec("")

    def test_missing_separator_raises(self):
        with pytest.raises(ValueError, match="missing ':'"):
            parse_volume_spec("/tmp/no_guest")

    def test_empty_host_raises(self):
        with pytest.raises(ValueError, match="Empty host"):
            parse_volume_spec(":c:\\guest")

    def test_empty_guest_raises(self):
        with pytest.raises(ValueError, match="Empty guest"):
            parse_volume_spec("/tmp/host:")


# ---------------------------------------------------------------------------
# expand_volume_to_entries
# ---------------------------------------------------------------------------


class TestExpandVolume:
    def test_single_file(self, tmp_path: Path):
        f = tmp_path / "payload.bin"
        f.write_bytes(b"\x90" * 16)

        entries = expand_volume_to_entries(f, PureWindowsPath("c:\\malware\\payload.bin"))
        assert len(entries) == 1
        assert entries[0]["mode"] == "full_path"
        assert entries[0]["emu_path"] == "c:\\malware\\payload.bin"
        assert entries[0]["path"] == str(f.resolve())

    def test_directory_recursive(self, tmp_path: Path):
        (tmp_path / "a.txt").write_text("a")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "b.txt").write_text("b")

        entries = expand_volume_to_entries(tmp_path, PureWindowsPath("c:\\data"))
        assert len(entries) == 2

        emu_paths = {e["emu_path"] for e in entries}
        assert str(PureWindowsPath("c:\\data\\a.txt")) in emu_paths
        assert str(PureWindowsPath("c:\\data\\sub\\b.txt")) in emu_paths

    def test_empty_directory(self, tmp_path: Path):
        empty = tmp_path / "empty"
        empty.mkdir()
        entries = expand_volume_to_entries(empty, PureWindowsPath("c:\\empty"))
        assert entries == []

    def test_nonexistent_host_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            expand_volume_to_entries(tmp_path / "nope", PureWindowsPath("c:\\nope"))


# ---------------------------------------------------------------------------
# apply_volumes
# ---------------------------------------------------------------------------


class TestApplyVolumes:
    def test_prepend_ordering(self, tmp_path: Path):
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
        # Volume entry comes first.
        assert files[0]["emu_path"] == "c:\\vol.bin"
        # Original entry preserved.
        assert files[1]["mode"] == "default"

    def test_empty_volumes_noop(self):
        config = {"filesystem": {"files": []}}
        result = apply_volumes(config, [])
        assert result is config
        assert config["filesystem"]["files"] == []

    def test_creates_filesystem_key(self, tmp_path: Path):
        f = tmp_path / "x.bin"
        f.write_bytes(b"\x00")

        config: dict = {}
        apply_volumes(config, [f"{f}:c:\\x.bin"])
        assert "filesystem" in config
        assert len(config["filesystem"]["files"]) == 1

    def test_round_trip_validation(self, tmp_path: Path):
        """Volume entries produce valid FileEntryFullPath objects after model_validate."""
        f = tmp_path / "test.dll"
        f.write_bytes(b"MZ" + b"\x00" * 100)

        config_path = os.path.join(os.path.dirname(speakeasy.__file__), "configs", "default.json")
        with open(config_path) as fh:
            config = json.load(fh)

        apply_volumes(config, [f"{f}:c:\\windows\\system32\\test.dll"])

        # Should validate without error.
        model = SpeakeasyConfig.model_validate(config)

        # The first file entry should be our volume mount.
        first = model.filesystem.files[0]
        assert first.mode == "full_path"
        assert first.emu_path == "c:\\windows\\system32\\test.dll"
