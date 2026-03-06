import argparse
import json
import subprocess
import sys

from speakeasy.cli_config import (
    add_config_cli_arguments,
    apply_config_cli_overrides,
    get_config_cli_field_specs,
    get_default_config_dict,
    merge_config_dicts,
)
from speakeasy.config import SpeakeasyConfig


def test_config_precedence_prefers_cli_over_config_overlay():
    parser = argparse.ArgumentParser()
    specs = get_config_cli_field_specs()
    add_config_cli_arguments(parser, specs)

    base = get_default_config_dict()
    config_overlay = {"timeout": 15, "analysis": {"coverage": True}}
    layered = merge_config_dicts(base, config_overlay)

    args = parser.parse_args(["--timeout", "90", "--no-analysis-coverage"])
    final = apply_config_cli_overrides(layered, args, specs)

    assert final["timeout"] == 90
    assert final["analysis"]["coverage"] is False


def test_dump_default_config_flag_outputs_valid_json():
    result = subprocess.run(
        [sys.executable, "-m", "speakeasy.cli", "--dump-default-config"],
        check=True,
        capture_output=True,
        text=True,
    )
    dumped = json.loads(result.stdout)
    model = SpeakeasyConfig.model_validate(dumped)

    assert model.timeout == 60
    assert model.max_api_count == 10000
