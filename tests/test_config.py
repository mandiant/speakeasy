import json
import os

import pytest
from pydantic import ValidationError

import speakeasy
import speakeasy.speakeasy
from speakeasy.config import get_default_config_dict


def test_shipped_configs_validate():
    config_dir = os.path.join(os.path.dirname(speakeasy.__file__), "configs")
    assert os.path.isdir(config_dir)

    for fname in os.listdir(config_dir):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(config_dir, fname)
        with open(fpath) as ff:
            config = json.load(ff)
        speakeasy.speakeasy.validate_config(config)


def test_validation_rejects_invalid_engine():
    conf = get_default_config_dict()
    conf["emu_engine"] = "alternate_engine"

    with pytest.raises(ValidationError):
        speakeasy.speakeasy.validate_config(conf)
