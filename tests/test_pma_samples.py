import pytest

from tests.pma_cases import PMA_CASES
from tests.pma_harness import assert_case, collect_behavior, get_sample_path, run_case


@pytest.mark.parametrize("case", PMA_CASES, ids=[case.name for case in PMA_CASES])
def test_pma_case_declarative(base_config, case, tmp_path):
    sample_path = get_sample_path(case)
    if not sample_path.exists():
        pytest.skip(f"missing sample: {sample_path}")

    report = run_case(base_config, case, tmp_path)
    observed = collect_behavior(report)
    assert_case(case, report, observed)
