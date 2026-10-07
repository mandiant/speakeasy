from typing import Any

import pytest

from speakeasy.config import SpeakeasyConfig
from speakeasy.windows.objman import HandleAllocator
from speakeasy.windows.regman import RegistryManager, RegValue
from speakeasy.winenv.defs.registry import reg as regdefs


def test_config_values_have_type_codes(config: dict[str, Any]) -> None:
    regman = RegistryManager(HandleAllocator(), SpeakeasyConfig.model_validate(config).registry)
    key = regman.get_key_from_config("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\usbsamp")
    assert key is not None
    name = key.get_value("DisplayName")
    start = key.get_value("Start")
    assert (name.get_type(), name.get_data()) == (regdefs.REG_SZ, "An example service")
    assert (start.get_type(), start.get_data()) == (regdefs.REG_DWORD, 3)


@pytest.mark.parametrize(
    "val_type, data, width, expected",
    [
        (regdefs.REG_SZ, "ab", 1, b"ab\x00"),
        (regdefs.REG_EXPAND_SZ, "ab", 2, "ab\x00".encode("utf-16le")),
        (regdefs.REG_MULTI_SZ, "a\x00b", 1, b"a\x00b\x00\x00"),
        (regdefs.REG_DWORD, "0x3", 1, b"\x03\x00\x00\x00"),
        (regdefs.REG_QWORD, 5, 1, b"\x05" + b"\x00" * 7),
        (regdefs.REG_BINARY, b"\x01\x02", 1, b"\x01\x02"),
    ],
)
def test_value_bytes(val_type: int, data: str | int | bytes, width: int, expected: bytes) -> None:
    assert RegValue("v", val_type, data).get_bytes(width) == expected
