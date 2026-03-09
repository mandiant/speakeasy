"""Test that module names are normalized (case-insensitive, no extension) in get_proc."""

from speakeasy.windows.winemu import _normalize_mod_name


def test_normalize_mod_name_lowercase():
    assert _normalize_mod_name("KERNEL32") == "kernel32"
    assert _normalize_mod_name("Kernel32") == "kernel32"
    assert _normalize_mod_name("kernel32") == "kernel32"


def test_normalize_mod_name_strips_extension():
    assert _normalize_mod_name("kernel32.dll") == "kernel32"
    assert _normalize_mod_name("kernel32.DLL") == "kernel32"
    assert _normalize_mod_name("ntdll.dll") == "ntdll"


def test_normalize_mod_name_case_and_extension():
    assert _normalize_mod_name("KERNEL32.DLL") == "kernel32"
    assert _normalize_mod_name("Kernel32.Dll") == "kernel32"


def test_normalize_mod_name_no_extension():
    assert _normalize_mod_name("kernel32") == "kernel32"


def test_normalize_mod_name_preserves_dotted_names():
    assert _normalize_mod_name("api-ms-win-crt-runtime-l1-1-0.dll") == "api-ms-win-crt-runtime-l1-1-0"


def test_get_proc_case_insensitive(config, load_test_bin, run_test):
    data = load_test_bin("GetProcAddress.exe.xz")
    report = run_test(config, data)
    eps = report.entry_points
    events = eps[0].events or []
    api_calls = [e for e in events if e.event == "api" and e.api_name == "kernel32.GetProcAddress"]
    assert api_calls[2].args[1] == "AreFileApisANSI"
    assert api_calls[2].ret_val != "0x0"
