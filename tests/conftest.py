import copy
import json
import lzma
from functools import cache
from pathlib import Path

import pytest

from speakeasy import Speakeasy
from speakeasy.windows.cryptman import CryptContext
from speakeasy.windows.fileman import File, FileMap, Pipe
from speakeasy.windows.netman import WininetComponent
from speakeasy.windows.objman import Console, KernelObject
from speakeasy.windows.regman import RegKey
from speakeasy.windows.sessman import Session

TESTS_DIR = Path(__file__).resolve().parent
BINS_DIR = TESTS_DIR / "bins"

_HANDLE_DEFAULTS: list[tuple[type, str, int]] = [
    (File, "curr_handle", 0x80),
    (FileMap, "curr_handle", 0x280),
    (Pipe, "curr_handle", 0x400),
    (RegKey, "curr_handle", 0x180),
    (Console, "curr_handle", 0x340),
    (KernelObject, "curr_handle", 0x220),
    (KernelObject, "curr_id", 0x400),
    (Session, "curr_handle", 0x120),
    (CryptContext, "curr_handle", 0x680),
    (WininetComponent, "curr_handle", 0x20),
]


@pytest.fixture(autouse=True)
def _reset_handle_counters():
    for cls, attr, default in _HANDLE_DEFAULTS:
        setattr(cls, attr, default)
    yield
    for cls, attr, default in _HANDLE_DEFAULTS:
        setattr(cls, attr, default)


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
