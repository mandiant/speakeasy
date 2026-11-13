import pytest
from pydantic import ValidationError

from speakeasy import Speakeasy
from speakeasy.config import SpeakeasyConfig, get_default_config_dict
from speakeasy.errors import ConfigError


def test_validation_rejects_invalid_engine():
    conf = get_default_config_dict()
    conf["emu_engine"] = "alternate_engine"

    with pytest.raises(ConfigError):
        Speakeasy(config=conf)


def test_validation_rejects_another_config_version():
    with pytest.raises(ConfigError, match="'2.0'"):
        Speakeasy(config={"config_version": 0.2})


def get_process_config(base_addr: int | str, stack_size: int | str) -> SpeakeasyConfig:
    process = {"name": "main", "base_addr": base_addr, "path": "C:\\main.exe"}
    return SpeakeasyConfig.model_validate({"processes": [process], "runs": {"stack_size": stack_size}})


def test_config_reads_a_hex_string_as_an_int():
    config = get_process_config("0x400000", "0x20000")

    assert config == get_process_config(0x400000, 0x20000)
    assert config.model_dump(mode="json")["processes"][0]["base_addr"] == "0x400000"
    with pytest.raises(ValueError, match="0x"):
        get_process_config("400000", 0)


@pytest.mark.parametrize(
    "data",
    [{"registry": None}, {"network": {"dns": None}}, {"network": {"http": None}}, {"network": {"winsock": None}}],
    ids=["registry", "network.dns", "network.http", "network.winsock"],
)
def test_validation_rejects_null_for_an_emulation_group(data):
    with pytest.raises(ValidationError):
        SpeakeasyConfig.model_validate(data)


@pytest.mark.parametrize("name", ["per_run_time", "total_time", "api_calls", "api_loop_calls", "instructions"])
def test_validation_rejects_a_negative_limit(name):
    assert getattr(SpeakeasyConfig.model_validate({"limits": {name: 0}}).limits, name) == 0
    with pytest.raises(ValidationError):
        SpeakeasyConfig.model_validate({"limits": {name: -1}})
