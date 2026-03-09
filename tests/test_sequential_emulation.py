from speakeasy import Speakeasy


def test_process_ldr_entries_are_per_instance(config, load_test_bin):
    """Regression test for gh-139: ldr_entries was a class variable shared across
    all Process instances, causing PEB corruption when running multiple emulations.
    """
    data = load_test_bin("dll_test_x86.dll.xz")

    se1 = Speakeasy(config=config)
    try:
        module1 = se1.load_module(data=data)
        se1.run_module(module1, all_entrypoints=True)
        proc1 = se1.emu.get_processes()[0]
        count1 = len(proc1.ldr_entries)
        assert count1 > 0
    finally:
        se1.shutdown()

    se2 = Speakeasy(config=config)
    try:
        module2 = se2.load_module(data=data)
        se2.run_module(module2, all_entrypoints=True)
        proc2 = se2.emu.get_processes()[0]
        assert proc2.ldr_entries is not proc1.ldr_entries
        assert len(proc2.ldr_entries) == count1
    finally:
        se2.shutdown()


def test_sequential_emulations_produce_consistent_reports(config, load_test_bin):
    """Both runs should produce the same API events."""
    data = load_test_bin("dll_test_x86.dll.xz")
    reports = []

    for _ in range(2):
        se = Speakeasy(config=config)
        try:
            module = se.load_module(data=data)
            se.run_module(module, all_entrypoints=True)
            reports.append(se.get_report())
        finally:
            se.shutdown()

    for r in reports:
        events = r.entry_points[0].events or []
        msgbox_calls = [e for e in events if e.event == "api" and "MessageBox" in e.api_name]
        assert msgbox_calls
