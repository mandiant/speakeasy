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
