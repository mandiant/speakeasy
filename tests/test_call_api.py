import pytest

from speakeasy import Speakeasy


@pytest.mark.parametrize(
    "bin_file",
    [
        "dll_test_x86.dll.xz",
        "dll_test_x64.dll.xz",
    ],
)
def test_call_without_run_module(config, load_test_bin, bin_file):
    """call() should work without run_module() being called first (GH-21)."""
    data = load_test_bin(bin_file)
    se = Speakeasy(config=config)
    try:
        mod = se.load_module(data=data)
        se.call(mod.base + mod.ep, [mod.base, 1, 0])
    finally:
        se.shutdown()


@pytest.mark.parametrize(
    "bin_file",
    [
        "dll_test_x86.dll.xz",
        "dll_test_x64.dll.xz",
    ],
)
def test_call_after_run_module(config, load_test_bin, bin_file):
    """call() should still work after run_module() has set up context."""
    data = load_test_bin(bin_file)
    se = Speakeasy(config=config)
    try:
        mod = se.load_module(data=data)
        se.run_module(mod)
        se.call(mod.base + mod.ep, [mod.base, 1, 0])
    finally:
        se.shutdown()
