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


@pytest.mark.parametrize("byte", ["zz", "0x100", "100", "", "0x", "-1"])
def test_byte_fill_rejects_a_byte_that_is_not_one_hex_byte(byte):
    with pytest.raises(ConfigError, match="byte"):
        Speakeasy(config={"filesystem": {"files": [{"mode": "default", "byte_fill": {"byte": byte, "size": 16}}]}})


@pytest.mark.parametrize(
    "fields",
    [{}, {"path": "$ROOT$/resources/files/default.bin", "byte_fill": {"byte": "0x41", "size": 16}}],
    ids=["neither", "both"],
)
@pytest.mark.parametrize(
    "entry",
    [{"mode": "full_path", "emu_path": "C:\\a.bin"}, {"mode": "by_ext", "ext": "bin"}, {"mode": "default"}],
    ids=lambda entry: entry["mode"],
)
def test_file_entry_needs_exactly_one_of_path_and_byte_fill(entry, fields):
    with pytest.raises(ValidationError, match="path or byte_fill"):
        SpeakeasyConfig.model_validate({"filesystem": {"files": [{**entry, **fields}]}})
    with pytest.raises(ValidationError, match="path or byte_fill"):
        SpeakeasyConfig.model_validate({"network": {"winsock": {"responses": [{**entry, **fields}]}}})


@pytest.mark.parametrize(
    "data",
    [
        {"runs": {"stack_size": -1}},
        {"processes": [{"name": "main", "base_addr": -1, "path": "C:\\main.exe"}]},
        {"filesystem": {"files": [{"mode": "default", "byte_fill": {"byte": "0x41", "size": -3}}]}},
    ],
    ids=["stack_size", "base_addr", "byte_fill.size"],
)
def test_validation_rejects_a_negative_size_or_address(data):
    with pytest.raises(ValidationError, match="greater than or equal to 0"):
        SpeakeasyConfig.model_validate(data)


def get_registry_config(value_type: str, data: str) -> SpeakeasyConfig:
    value = {"name": "Start", "type": value_type, "data": data}
    return SpeakeasyConfig.model_validate(
        {"registry": {"keys": [{"path": "HKEY_LOCAL_MACHINE\\Probe", "values": [value]}]}}
    )


@pytest.mark.parametrize(
    ("value_type", "data"),
    [
        ("REG_SZ", "text"),
        ("REG_EXPAND_SZ", "%TEMP%"),
        ("REG_MULTI_SZ", "a\x00b"),
        ("REG_BINARY", ""),
        ("REG_DWORD", "0x3"),
        ("REG_DWORD", "3"),
        ("REG_QWORD", "0x100000000"),
    ],
)
def test_registry_value_accepts_the_types_that_the_registry_emulates(value_type, data):
    assert get_registry_config(value_type, data).registry.keys[0].values[0].type == value_type


@pytest.mark.parametrize(
    ("value_type", "data"),
    [("REG_BOGUS", "text"), ("REG_NONE", "text"), ("REG_DWORD", "notanumber"), ("REG_QWORD", "")],
)
def test_registry_value_rejects_a_type_or_number_that_the_registry_cannot_read(value_type, data):
    with pytest.raises(ValidationError):
        get_registry_config(value_type, data)


def test_drive_type_must_be_a_drive_type_name():
    drive = {"root_path": "C:\\", "drive_type": "DRIVE_BOGUS"}
    with pytest.raises(ValidationError, match="DRIVE_FIXED"):
        SpeakeasyConfig.model_validate({"system": {"drives": [drive]}})
