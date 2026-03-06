import pytest
from pydantic import ValidationError

import speakeasy.speakeasy
from speakeasy.config import get_default_config_dict


def test_default_config_validates():
    speakeasy.speakeasy.validate_config(get_default_config_dict())


def test_validation_rejects_invalid_engine():
    conf = get_default_config_dict()
    conf["emu_engine"] = "alternate_engine"

    with pytest.raises(ValidationError):
        speakeasy.speakeasy.validate_config(conf)
