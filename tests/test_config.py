# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import json
import os

import jsonschema
import pytest

import speakeasy
import speakeasy.speakeasy


def get_default_config():
    fpath = os.path.join(os.path.dirname(speakeasy.__file__), "configs", "default.json")
    with open(fpath) as ff:
        return json.load(ff)


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
    with pytest.raises(jsonschema.exceptions.ValidationError):
        speakeasy.speakeasy.validate_config(conf)


def test_validation_missing_required_field():
    conf = get_default_config()
    conf.pop("emu_engine", None)
    with pytest.raises(jsonschema.exceptions.ValidationError):
        speakeasy.speakeasy.validate_config(conf)


def test_validation_incorrect_type():
    conf = get_default_config()
    conf["emu_engine"] = 1.0
    with pytest.raises(jsonschema.exceptions.ValidationError):
        speakeasy.speakeasy.validate_config(conf)
