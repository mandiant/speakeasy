# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import json
import os

import pytest
from pydantic import ValidationError

import speakeasy
import speakeasy.speakeasy
from speakeasy.config import SpeakeasyConfig, get_default_config_dict


def get_default_config():
    return get_default_config_dict()


def test_speakeasy_configs():
    config_dir = os.path.join(os.path.dirname(speakeasy.__file__), "configs")
    assert os.path.isdir(config_dir)
    for fname in os.listdir(config_dir):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(config_dir, fname)
        assert os.path.isfile(fpath)
        with open(fpath) as ff:
            config = json.load(ff)
        speakeasy.speakeasy.validate_config(config)


def test_validation_non_enum():
    conf = get_default_config()
    assert "emu_engine" in conf
    speakeasy.speakeasy.validate_config(conf)

    conf["emu_engine"] = "alternate_engine"
    with pytest.raises(ValidationError):
        speakeasy.speakeasy.validate_config(conf)


def test_validation_missing_field_uses_model_default():
    conf = get_default_config()
    conf.pop("emu_engine", None)
    model = speakeasy.speakeasy.validate_config(conf)
    assert model.emu_engine == "unicorn"


def test_validation_incorrect_type():
    conf = get_default_config()
    conf["emu_engine"] = 1.0
    with pytest.raises(ValidationError):
        speakeasy.speakeasy.validate_config(conf)


def test_config_model_direct():
    conf = get_default_config()
    model = SpeakeasyConfig.model_validate(conf)
    assert model.emu_engine == "unicorn"
    assert model.config_version == 0.2
    assert model.timeout == 60
    assert model.user.name == "speakeasy_user"
