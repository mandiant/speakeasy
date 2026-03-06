import os

import pytest

from tests.pma_cases import PMA_CASES
from tests.pma_harness import assert_case, collect_behavior, get_sample_path, run_case

CURATED_CASE_NAMES = {
    "pma-01-02-exe",
    "pma-03-02-dll",
    "pma-03-04-in",
    "pma-05-01-dll",
    "pma-06-03-exe",
    "pma-10-03-sys",
    "pma-11-02-dll",
    "pma-12-02-exe",
    "pma-12-04-exe",
    "pma-14-01-exe",
    "pma-16-03-exe",
    "pma-21-01-exe",
}


if os.environ.get("SPEAKEASY_PMA_FULL") == "1":
    CASES = PMA_CASES
else:
    CASES = tuple(case for case in PMA_CASES if case.name in CURATED_CASE_NAMES)


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_pma_case_declarative(base_config, case, tmp_path):
    sample_path = get_sample_path(case)
    if not sample_path.exists():
        pytest.skip(f"missing sample: {sample_path}")

    report = run_case(base_config, case, tmp_path)
    observed = collect_behavior(report)
    assert_case(case, report, observed)
