from types import SimpleNamespace

import pytest

from speakeasy.config import SpeakeasyConfig
from speakeasy.windows.fileman import FileManager


def make_file_manager(file_entries):
    cfg = SpeakeasyConfig(
        filesystem={"files": file_entries},
        command_line="",
    )
    emu = SimpleNamespace(arch=0)
    return FileManager(cfg, emu)


@pytest.fixture()
def fm():
    return make_file_manager([
        {"mode": "full_path", "emu_path": "c:\\programdata\\mydir\\myfile.bin"},
        {"mode": "full_path", "emu_path": "c:\\Windows\\system32\\cmd.exe"},
        {"mode": "full_path", "emu_path": "c:\\Windows\\system32\\svchost.exe"},
        {"mode": "full_path", "emu_path": "c:\\pagefile.sys"},
    ])


def test_root_wildcard_finds_directories_and_files(fm):
    results = list(fm.find_matching_entries("C:\\*"))
    names = {name for name, _ in results}
    assert "programdata" in names
    assert "windows" in names
    assert "pagefile.sys" in names


def test_root_wildcard_marks_dirs_correctly(fm):
    results = {name: is_dir for name, is_dir in fm.find_matching_entries("C:\\*")}
    assert results["programdata"] is True
    assert results["windows"] is True
    assert results["pagefile.sys"] is False


def test_subdirectory_wildcard(fm):
    results = list(fm.find_matching_entries("c:\\Windows\\system32\\*"))
    names = {name for name, _ in results}
    assert "cmd.exe" in names
    assert "svchost.exe" in names
    assert len(results) == 2


def test_extension_pattern(fm):
    results = list(fm.find_matching_entries("c:\\Windows\\system32\\*.exe"))
    names = {name for name, _ in results}
    assert "cmd.exe" in names
    assert "svchost.exe" in names


def test_no_match(fm):
    results = list(fm.find_matching_entries("D:\\*"))
    assert results == []


def test_deduplicates_directories(fm):
    results = list(fm.find_matching_entries("c:\\Windows\\*"))
    dir_names = [name for name, is_dir in results if is_dir]
    assert dir_names.count("system32") == 1


def test_case_insensitive(fm):
    results_upper = {name for name, _ in fm.find_matching_entries("C:\\WINDOWS\\*")}
    results_lower = {name for name, _ in fm.find_matching_entries("c:\\windows\\*")}
    assert results_upper == results_lower
