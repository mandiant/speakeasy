"""The enum classes in speakeasy.winenv.defs agree with win32json, so handlers decode as the signature database does."""

import importlib
import importlib.util
import inspect
import pkgutil
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from pathlib import Path
from types import ModuleType

import pytest

import speakeasy.winenv.defs

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR = REPO_ROOT / "scripts" / "gen_win32_signatures.py"
OVERRIDES = REPO_ROOT / "scripts" / "win32_overrides.json"
WIN32JSON = REPO_ROOT / "deps" / "win32json"

# Flag sets that the SDK keeps as loose constants, with no enum type in win32json
NOT_IN_WIN32JSON = {
    "DRIVE_TYPE",
    "HKEY",
    "INTERNET_FLAGS",
    "LCID",
    "LCTYPE",
    "SOCKET_OPTION",
    "SOCKET_OPTION_LEVEL",
    "SOCKET_TYPE",
}


@dataclass
class Win32Json:
    gen: ModuleType
    enums: dict[str, dict]
    constants: dict[str, int]
    overrides: dict


def get_defs_enums() -> list[type[IntEnum | IntFlag]]:
    classes = []
    for info in pkgutil.walk_packages(speakeasy.winenv.defs.__path__, speakeasy.winenv.defs.__name__ + "."):
        module = importlib.import_module(info.name)
        for cls in vars(module).values():
            if inspect.isclass(cls) and issubclass(cls, (IntEnum, IntFlag)) and cls.__module__ == module.__name__:
                classes.append(cls)
    return classes


DEFS_ENUMS = get_defs_enums()


@pytest.fixture(scope="module")
def win32json() -> Win32Json:
    if not (WIN32JSON / "api").is_dir():
        pytest.skip("deps/win32json is not checked out")
    spec = importlib.util.spec_from_file_location("gen_win32_signatures", GENERATOR)
    assert spec is not None and spec.loader is not None
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    namespaces, _, constants = gen.load_win32json(str(WIN32JSON))
    enums = {name: td for ns in namespaces.values() for name, td in ns.items() if td["Kind"] == "Enum"}
    return Win32Json(gen, enums, constants, gen.load_overrides(str(OVERRIDES)))


@pytest.mark.parametrize("cls", [c for c in DEFS_ENUMS if c.__name__ not in NOT_IN_WIN32JSON], ids=lambda c: c.__name__)
def test_defs_enum_has_the_members_of_the_win32json_enum(win32json: Win32Json, cls: type[IntEnum | IntFlag]) -> None:
    td = win32json.enums[cls.__name__]
    expected = win32json.gen.get_enum_values(td, win32json.constants, win32json.overrides)
    assert [[name, int(member)] for name, member in cls.__members__.items()] == expected
    assert issubclass(cls, IntFlag) == bool(td.get("Flags"))


@pytest.mark.parametrize("cls", [c for c in DEFS_ENUMS if c.__name__ in NOT_IN_WIN32JSON], ids=lambda c: c.__name__)
def test_defs_flag_set_has_the_values_of_the_win32json_constants(
    win32json: Win32Json, cls: type[IntEnum | IntFlag]
) -> None:
    assert cls.__name__ not in win32json.enums
    known = {name: int(member) for name, member in cls.__members__.items() if name in win32json.constants}
    assert known == {name: win32json.constants[name] & 0xFFFFFFFF for name in known}
