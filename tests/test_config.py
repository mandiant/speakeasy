import pytest

from speakeasy import Speakeasy
from speakeasy.config import get_default_config_dict
from speakeasy.errors import ConfigError


def test_validation_rejects_invalid_engine():
    conf = get_default_config_dict()
    conf["emu_engine"] = "alternate_engine"

    with pytest.raises(ConfigError):
        Speakeasy(config=conf)


def test_validation_rejects_another_config_version():
    with pytest.raises(ConfigError, match="'2.0'"):
        Speakeasy(config={"config_version": 0.2})
