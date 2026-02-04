# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import copy

import pytest

from speakeasy import Speakeasy


@pytest.mark.parametrize(
    "bin_file",
    [
        "dll_test_x86.dll.xz",
    ],
)
def test_coverage_enabled(config, load_test_bin, bin_file):
    cfg = copy.deepcopy(config)
    cfg["analysis"] = cfg.get("analysis", {})
    cfg["analysis"]["coverage"] = True

    data = load_test_bin(bin_file)
    se = Speakeasy(config=cfg)
    module = se.load_module(data=data)
    se.run_module(module, all_entrypoints=True)
    report = se.get_report()

    eps = report["entry_points"]
    assert len(eps) > 0

    eps_with_coverage = [ep for ep in eps if "coverage" in ep]
    assert len(eps_with_coverage) > 0, "Expected at least one entry point with coverage"

    for ep in eps_with_coverage:
        coverage = ep["coverage"]
        assert isinstance(coverage, list)
        assert len(coverage) > 0
        for addr in coverage:
            assert isinstance(addr, int)
            assert addr > 0
