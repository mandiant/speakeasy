"""Test that module names are normalized (case-insensitive, no extension) in get_proc."""

import pytest

from speakeasy.windows.api_registry import module_name


@pytest.mark.parametrize(
    "name, expected",
    [
        ("KERNEL32", "kernel32"),
        ("Kernel32", "kernel32"),
        ("kernel32", "kernel32"),
        ("kernel32.dll", "kernel32"),
        ("kernel32.DLL", "kernel32"),
        ("Kernel32.Dll", "kernel32"),
        ("api-ms-win-crt-runtime-l1-1-0.dll", "api-ms-win-crt-runtime-l1-1-0"),
        ("windows.storage.dll", "windows.storage"),
        ("windows.storage", "windows.storage"),
    ],
)
def test_module_name(name, expected):
    assert module_name(name) == expected
