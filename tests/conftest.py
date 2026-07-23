import copy
import json
import lzma
from functools import cache
from pathlib import Path

import pytest

from speakeasy import Speakeasy

TESTS_DIR = Path(__file__).resolve().parent
BINS_DIR = TESTS_DIR / "bins"


@pytest.fixture(scope="session")
def base_config():
    with (TESTS_DIR / "test.json").open() as f:
        return json.load(f)


@pytest.fixture
def config(base_config):
    return copy.deepcopy(base_config)


@pytest.fixture(scope="session")
def load_test_bin():
    @cache
    def _load(bin_name: str) -> bytes:
        with lzma.open(BINS_DIR / bin_name) as f:
            return f.read()

    return _load


@pytest.fixture
def run_test():
    def _run(cfg, target, argv=None):
        se = Speakeasy(config=cfg, argv=argv or [])
        try:
            module = se.load_module(data=target)
            se.run_module(module, all_entrypoints=True)
            return se.get_report()
        finally:
            se.shutdown()

    return _run
