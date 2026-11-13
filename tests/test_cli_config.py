import argparse
import json
import os
import re
import subprocess
import sys

import pytest

from speakeasy import Speakeasy
from speakeasy.cli_config import (
    add_config_cli_arguments,
    get_active_config,
    get_config_cli_field_specs,
)
from speakeasy.config import SpeakeasyConfig
from tests.handler_harness import alloc, call, load_emu


def get_cli_config(data: dict, argv: list[str]) -> SpeakeasyConfig:
    parser = argparse.ArgumentParser()
    specs = get_config_cli_field_specs()
    add_config_cli_arguments(parser, specs)
    return get_active_config(data, [], parser.parse_args(argv), specs)


def test_config_precedence_prefers_cli_over_config_file():
    config = get_cli_config(
        {"limits": {"per_run_time": 15}, "code": {"coverage": True}},
        ["--limits-per-run-time", "90", "--no-code-coverage"],
    )

    assert config.limits.per_run_time == 90
    assert config.code.coverage is False


def test_cli_and_library_give_the_same_config_for_a_partial_dict():
    part = {"user": {"name": "bob"}, "system": {"os_ver": {"major": 10, "minor": 0}}}

    library = Speakeasy(config=part).config

    assert get_cli_config(part, []) == library
    assert library.user.admin is True
    assert library.system.os_ver.build == 7601


FEATURE_PATHS = [
    "runs.exports",
    "runs.children",
    "memory.accesses",
    "memory.strings",
    "memory.final_contents",
    "memory.dynamic_code_contents.enabled",
    "memory.freed_regions",
    "code.coverage",
    "apis.stubs",
    "modules.stubs",
    "exceptions.dispatch",
]


def get_config_path_value(config: SpeakeasyConfig, path: str):
    value = config
    for name in path.split("."):
        value = getattr(value, name)
    return value


def test_features_are_on_by_default_and_each_no_flag_turns_one_off():
    assert all(get_config_path_value(get_cli_config({}, []), path) is True for path in FEATURE_PATHS)

    bool_specs = [spec for spec in get_config_cli_field_specs() if spec.kind == "bool"]
    argv = ["--no-" + spec.option.removeprefix("--") for spec in bool_specs]
    config = get_cli_config({}, argv)

    assert {spec.path for spec in bool_specs} >= set(FEATURE_PATHS)
    assert all(get_config_path_value(config, spec.path) is False for spec in bool_specs)


def test_each_flag_is_the_config_path_with_dashes():
    for spec in get_config_cli_field_specs():
        path = spec.path.removesuffix(".enabled")
        assert spec.option == "--" + path.replace(".", "-").replace("_", "-"), spec.path


def test_the_enabled_key_of_a_group_gives_the_flag_of_the_group():
    options = {spec.path: spec.option for spec in get_config_cli_field_specs()}
    assert options["memory.dynamic_code_contents.enabled"] == "--memory-dynamic-code-contents"
    assert options["memory.dynamic_code_contents.limit"] == "--memory-dynamic-code-contents-limit"

    off = {"memory": {"dynamic_code_contents": {"enabled": False}}}
    assert get_cli_config(off, ["--memory-dynamic-code-contents"]).memory.dynamic_code_contents.enabled is True
    config = get_cli_config({}, ["--no-memory-dynamic-code-contents", "--memory-dynamic-code-contents-limit", "3"])
    assert config.memory.dynamic_code_contents.enabled is False
    assert config.memory.dynamic_code_contents.limit == 3


def test_k_sets_runs_children():
    assert get_cli_config({"runs": {"children": False}}, ["-k"]).runs.children is True
    assert get_cli_config({}, ["--no-runs-children"]).runs.children is False


@pytest.mark.parametrize("flag", ["--emulate-children", "--all-entrypoints"])
def test_the_cli_rejects_a_run_flag_that_is_not_a_config_path(tmp_path, flag):
    target = tmp_path / "sc.bin"
    target.write_bytes(b"\xc3")

    result = subprocess.run(
        [sys.executable, "-m", "speakeasy.cli", "-t", str(target), "--raw", "--arch", "x86", "--no-mp", flag],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 2
    assert f"unrecognized arguments: {flag}" in result.stderr


def test_dump_default_config_flag_outputs_valid_json():
    result = subprocess.run(
        [sys.executable, "-m", "speakeasy.cli", "--dump-default-config"],
        check=True,
        capture_output=True,
        text=True,
    )
    SpeakeasyConfig.model_validate(json.loads(result.stdout))


@pytest.fixture(scope="module")
def cli_help() -> str:
    result = subprocess.run(
        [sys.executable, "-m", "speakeasy.cli", "--help"],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "COLUMNS": "1000"},
    )
    return result.stdout


def test_help_shows_the_default_flag_of_each_bool_pair(cli_help):
    assert "(default: True)" not in cli_help
    assert "(default: False)" not in cli_help
    assert "dispatch functions and run its unload routine. (default: --runs-exports)" in cli_help
    assert "Not in kernel mode. (default: --runs-children)" in cli_help


def test_help_shows_string_defaults_as_plain_text(cli_help):
    assert "Current directory of the process. (default: C:\\Windows\\system32)\n" in cli_help
    assert "(default: speakeasy_host)\n" in cli_help
    assert "'" not in "".join(re.findall(r"\(default: [^)]*\)", cli_help))


def test_help_leaves_out_a_none_default(cli_help):
    assert "(default: None)" not in cli_help
    assert "in place of the synthetic API modules.\n" in cli_help


@pytest.mark.parametrize(
    "usage",
    ["[-V HOST:GUEST]", "[--argv ARGS]", "[--raw-offset OFFSET]", "[-t PATH]", "[--limits-per-run-time SECONDS]"],
)
def test_help_gives_meaningful_metavars(cli_help, usage):
    assert usage in cli_help


def test_help_gives_no_metavar_that_is_its_flag_name(cli_help):
    for option, metavar in re.findall(r"\[(--[a-z0-9-]+) ([A-Z0-9_:=]+)\]", cli_help):
        assert metavar.lower().replace("_", "-") != option.removeprefix("--"), option


def test_env_names_from_the_cli_replace_the_defaults_in_any_case(load_test_bin):
    config = get_cli_config(
        {},
        ["--process-env", "TEMP=C:\\Windows\\Temp"]
        + ["--process-env", "APPDATA=C:\\Users\\jdoe\\AppData\\Roaming"]
        + ["--process-env", "COMPUTERNAME=WS-3471"],
    )

    assert config.process.env["temp"] == "C:\\Windows\\Temp"
    assert config.process.env["appdata"] == "C:\\Users\\jdoe\\AppData\\Roaming"
    assert config.process.env["computername"] == "WS-3471"
    assert all(name.islower() for name in config.process.env)

    for se in load_emu(config.model_dump(), load_test_bin("dll_test_x86.dll.xz")):
        name = alloc(se, b"ComputerName\x00")
        buf = alloc(se, b"\x00" * 0x40)
        rv, _ = call(se, "kernel32", "GetEnvironmentVariableA", [name, buf, 0x40])
        assert se.mem_read(buf, rv) == b"WS-3471"


def test_an_env_name_from_the_cli_replaces_a_config_file_name_in_any_case():
    config = get_cli_config({"process": {"env": {"TEMP": "C:\\config"}}}, ["--process-env", "temp=C:\\cli"])

    assert config.process.env["temp"] == "C:\\cli"
