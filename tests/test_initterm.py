def test_initterm_reports_function_table(config, load_test_bin, run_test):
    """_initterm and _initterm_e should parse the function pointer table
    and include the entries in the API event args."""
    data = load_test_bin("argv_test_x86.exe.xz")
    report = run_test(config, data)
    ep = report.entry_points

    initterm_events = []
    for evt in ep[0].events or []:
        if evt.event == "api" and "_initterm" in evt.api_name:
            initterm_events.append(evt)

    assert len(initterm_events) > 0, "expected at least one _initterm call"

    for evt in initterm_events:
        assert len(evt.args) == 3, f"expected 3 args (pfbegin, pfend, func_table) but got {len(evt.args)}: {evt.args}"
        func_table_str = evt.args[2]
        assert "0x" in func_table_str, f"expected hex addresses in func table: {func_table_str}"


def test_initterm_does_not_crash_emulation(config, load_test_bin, run_test):
    """_initterm should not crash the emulation - main() should still execute."""
    data = load_test_bin("argv_test_x86.exe.xz")
    report = run_test(config, data, argv=["arg1"])
    ep = report.entry_points

    printfs = []
    for evt in ep[0].events or []:
        if evt.event == "api" and "__stdio_common_vfprintf" in evt.api_name:
            printfs.append(evt)

    assert len(printfs) > 0, "main() should have executed and called printf"
