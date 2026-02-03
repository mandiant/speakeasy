# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import json
import lzma
import os

import pytest

from speakeasy import Speakeasy


@pytest.fixture(scope="session")
def config():
    fp = os.path.join(os.path.dirname(__file__), 'test.json')
    with open(fp) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def load_test_bin():
    def _load(bin_name):
        fp = os.path.join(os.path.dirname(__file__), 'bins', bin_name)
        with lzma.open(fp) as f:
            return f.read()
    return _load


@pytest.fixture(scope="session")
def run_test():
    def _run(cfg, target, logger=None, argv=None):
        if argv is None:
            argv = []
        se = Speakeasy(config=cfg, logger=logger, argv=argv)
        module = se.load_module(data=target)
        se.run_module(module, all_entrypoints=True)
        return se.get_report()
    return _run
