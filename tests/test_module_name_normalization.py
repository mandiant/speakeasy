"""Test that module names are normalized (case-insensitive, no extension) in get_proc."""

import pytest

from speakeasy.windows.api_registry import module_name


@pytest.mark.parametrize(
    "name, expected",
    [
        ("KERNEL32", "kernel32"),
        ("kernel32.dll", "kernel32"),
        ("Kernel32.Dll", "kernel32"),
        ("windows.storage.dll", "windows.storage"),
        ("windows.storage", "windows.storage"),
    ],
)
def test_module_name(name, expected):
    assert module_name(name) == expected
