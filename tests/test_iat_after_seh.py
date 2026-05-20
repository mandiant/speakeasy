def test_iat_call_after_seh_resolved_pointer_call(config, load_test_bin, run_test):
    data = load_test_bin("seh_iat_after_resolved_x86.exe.xz")
    report = run_test(config, data)
    ep = report.entry_points[0]

    apis = [e.api_name for e in (ep.events or []) if e.event == "api"]
    assert "kernel32.GetTickCount" in apis
    assert "kernel32.GetCurrentProcessId" in apis
    assert "kernel32.ExitProcess" in apis
    assert apis.index("kernel32.GetTickCount") < apis.index("kernel32.GetCurrentProcessId")
    assert ep.error is None
