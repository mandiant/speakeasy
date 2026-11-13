import argparse
import json
import subprocess
import sys

from speakeasy import Speakeasy
from speakeasy.cli_config import (
    add_config_cli_arguments,
    get_active_config,
    get_config_cli_field_specs,
    get_singular_word,
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
        {"max_run_time": 15, "analysis": {"coverage": True}}, ["--max-run-time", "90", "--no-analysis-coverage"]
    )

    assert config.max_run_time == 90
    assert config.analysis.coverage is False


def test_cli_and_library_give_the_same_config_for_a_partial_dict():
    part = {"user": {"name": "bob"}, "os_ver": {"major": 10, "minor": 0}}

    library = Speakeasy(config=part).config

    assert get_cli_config(part, []) == library
    assert library.user.is_admin is True
    assert library.os_ver.build == 7601


FEATURE_PATHS = [
    "analysis.memory_tracing",
    "analysis.coverage",
    "analysis.dynamic_code_snapshots",
    "keep_memory_on_free",
    "snapshot_memory_regions",
    "modules.modules_always_exist",
    "modules.functions_always_exist",
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


def test_no_config_flag_repeats_a_word():
    for spec in get_config_cli_field_specs():
        words = [get_singular_word(word) for word in spec.option.removeprefix("--").split("-")]
        assert len(words) == len(set(words)), spec.option


def test_dump_default_config_flag_outputs_valid_json():
    result = subprocess.run(
        [sys.executable, "-m", "speakeasy.cli", "--dump-default-config"],
        check=True,
        capture_output=True,
        text=True,
    )
    SpeakeasyConfig.model_validate(json.loads(result.stdout))


def test_env_names_from_the_cli_replace_the_defaults_in_any_case(load_test_bin):
    config = get_cli_config(
        {},
        ["--env", "TEMP=C:\\Windows\\Temp"]
        + ["--env", "APPDATA=C:\\Users\\jdoe\\AppData\\Roaming"]
        + ["--env", "COMPUTERNAME=WS-3471"],
    )

    assert config.env["temp"] == "C:\\Windows\\Temp"
    assert config.env["appdata"] == "C:\\Users\\jdoe\\AppData\\Roaming"
    assert config.env["computername"] == "WS-3471"
    assert all(name.islower() for name in config.env)

    for se in load_emu(config.model_dump(), load_test_bin("dll_test_x86.dll.xz")):
        name = alloc(se, b"ComputerName\x00")
        buf = alloc(se, b"\x00" * 0x40)
        rv, _ = call(se, "kernel32", "GetEnvironmentVariableA", [name, buf, 0x40])
        assert se.mem_read(buf, rv) == b"WS-3471"


def test_an_env_name_from_the_cli_replaces_a_config_file_name_in_any_case():
    config = get_cli_config({"env": {"TEMP": "C:\\config"}}, ["--env", "temp=C:\\cli"])

    assert config.env["temp"] == "C:\\cli"
