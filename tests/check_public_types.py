"""
Static type checks of the public ``Speakeasy`` API.

mypy checks this file in CI, so that a decorator that hides a signature fails the build.
pytest does not collect it.
"""

# mypy: disable-error-code="func-returns-value"

from typing_extensions import assert_type

from speakeasy import Speakeasy
from speakeasy.report import Report


def check_speakeasy_types(se: Speakeasy) -> None:
    module = se.load_module(path="sample.exe")
    assert_type(se.run_module(module), None)
    assert_type(se.run_shellcode(0x1000), None)
    assert_type(se.call(0x401000, [1, 2]), None)
    assert_type(se.resume(0x401000), None)
    assert_type(se.get_report(), Report)
    assert_type(se.get_json_report(), str)
