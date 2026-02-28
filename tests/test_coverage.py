from speakeasy import Speakeasy


def test_coverage_enabled(config, load_test_bin):
    config["analysis"] = dict(config.get("analysis", {}))
    config["analysis"]["coverage"] = True

    data = load_test_bin("dll_test_x86.dll.xz")
    se = Speakeasy(config=config)
    try:
        module = se.load_module(data=data)
        se.run_module(module, all_entrypoints=True)
        report = se.get_report()
    finally:
        se.shutdown()

    eps = report.entry_points
    assert len(eps) > 0

    eps_with_coverage = [ep for ep in eps if ep.coverage is not None]
    assert len(eps_with_coverage) > 0

    for ep in eps_with_coverage:
        coverage = ep.coverage
        assert isinstance(coverage, list)
        assert len(coverage) > 0
        for addr in coverage:
            assert isinstance(addr, int)
            assert addr > 0
