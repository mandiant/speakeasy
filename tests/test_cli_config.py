import argparse
import copy
import json
import subprocess
import sys

from speakeasy.cli_config import (
    add_config_cli_arguments,
    apply_config_cli_overrides,
    get_config_cli_field_specs,
    get_config_value_items,
    get_default_config_dict,
    merge_config_dicts,
)
from speakeasy.config import SpeakeasyConfig


def test_get_config_cli_field_specs_includes_simple_paths():
    specs = get_config_cli_field_specs()
    paths = {spec.path for spec in specs}

    assert "analysis.memory_tracing" in paths
    assert "analysis.coverage" in paths
    assert "modules.module_directory_x86" in paths
    assert "network.dns.names" in paths


def test_get_config_cli_field_specs_excludes_complex_paths():
    specs = get_config_cli_field_specs()
    paths = {spec.path for spec in specs}

    assert "filesystem.files" not in paths
    assert "registry.keys" not in paths
    assert "processes" not in paths


def test_merge_config_dicts_merges_nested_mappings():
    base = {
        "analysis": {"memory_tracing": False, "coverage": False, "strings": True},
        "env": {"a": "1", "b": "2"},
        "modules": {"module_directory_x86": "x86", "module_directory_x64": "x64"},
    }
    overlay = {
        "analysis": {"coverage": True},
        "env": {"b": "3"},
    }

    merged = merge_config_dicts(base, overlay)

    assert merged["analysis"] == {"memory_tracing": False, "coverage": True, "strings": True}
    assert merged["env"] == {"a": "1", "b": "3"}
    assert merged["modules"] == {"module_directory_x86": "x86", "module_directory_x64": "x64"}


def test_apply_config_cli_overrides_updates_dict_keys_only():
    config = get_default_config_dict()
    original = copy.deepcopy(config)

    parser = argparse.ArgumentParser()
    specs = get_config_cli_field_specs()
    add_config_cli_arguments(parser, specs)
    args = parser.parse_args(
        [
            "--env",
            "newvar=value",
            "--network-dns-names",
            "example.org=203.0.113.10",
            "--analysis-coverage",
            "--no-analysis-strings",
        ]
    )

    updated = apply_config_cli_overrides(config, args, specs)

    assert updated["analysis"]["coverage"] is True
    assert updated["analysis"]["strings"] is False
    assert updated["env"]["newvar"] == "value"
    assert updated["env"]["comspec"] == original["env"]["comspec"]
    assert updated["network"]["dns"]["names"]["example.org"] == "203.0.113.10"
    assert updated["network"]["dns"]["names"]["localhost"] == original["network"]["dns"]["names"]["localhost"]


def test_get_config_value_items_walks_model_order():
    model = SpeakeasyConfig.model_validate(get_default_config_dict())
    paths = [path for path, _ in get_config_value_items(model)]

    assert paths[:7] == [
        "config_version",
        "description",
        "emu_engine",
        "timeout",
        "max_api_count",
        "max_instructions",
        "system",
    ]
    start = paths.index("analysis.memory_tracing")
    assert paths[start : start + 3] == [
        "analysis.memory_tracing",
        "analysis.strings",
        "analysis.coverage",
    ]


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


def test_default_config_dict_matches_model_defaults():
    assert get_default_config_dict() == SpeakeasyConfig().model_dump(mode="python")


def test_dump_default_config_flag_outputs_json():
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
