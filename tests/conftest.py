import copy
import json
import lzma
from collections.abc import Callable, Iterator
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from speakeasy import Speakeasy
from tests.handler_harness import load_emu
from tests.strict_report import get_strict_report

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
            se.run_module(module)
            report = se.get_report()
            get_strict_report(report.model_dump_json(exclude_none=True))
            return report
        finally:
            se.shutdown()

    return _run


@pytest.fixture
def dll_emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> Iterator[Speakeasy]:
    yield from load_emu(config, load_test_bin("dll_test_x86.dll.xz"))


@pytest.fixture
def dll64_emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> Iterator[Speakeasy]:
    yield from load_emu(config, load_test_bin("dll_test_x64.dll.xz"))


@pytest.fixture
def driver_emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> Iterator[Speakeasy]:
    yield from load_emu(config, load_test_bin("wdm_test_x86.sys.xz"))


@pytest.fixture
def driver64_emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> Iterator[Speakeasy]:
    yield from load_emu(config, load_test_bin("wdm_test_x64.sys.xz"))
