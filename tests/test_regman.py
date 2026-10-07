from typing import Any

from speakeasy.config import SpeakeasyConfig
from speakeasy.windows.objman import HandleAllocator
from speakeasy.windows.regman import RegistryManager
from speakeasy.winenv.defs.registry import reg as regdefs


def test_config_values_have_type_codes(config: dict[str, Any]) -> None:
    regman = RegistryManager(HandleAllocator(), SpeakeasyConfig.model_validate(config).registry)
    key = regman.get_key_from_config("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\usbsamp")
    assert key is not None
    name = key.get_value("DisplayName")
    start = key.get_value("Start")
    assert (name.get_type(), name.get_data()) == (regdefs.REG_SZ, "An example service")
    assert (start.get_type(), start.get_data()) == (regdefs.REG_DWORD, 3)
