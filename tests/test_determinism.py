from collections.abc import Callable, Iterator
from typing import Any

import pytest

from speakeasy import Speakeasy
from tests.handler_harness import alloc, call, load_emu

RANDOM_APIS: list[tuple[str, str, Callable[[int], list[int]]]] = [
    ("advapi32", "SystemFunction036", lambda buf: [buf, 16]),
    ("advapi32", "CryptGenRandom", lambda buf: [0x1234, 16, buf]),
    ("bcrypt", "BCryptGenRandom", lambda buf: [0, buf, 16, 2]),
    ("bcryptprimitives", "ProcessPrng", lambda buf: [buf, 16]),
    ("ole32", "CoCreateGuid", lambda buf: [buf]),
    ("rpcrt4", "UuidCreate", lambda buf: [buf]),
]


@pytest.fixture
def other_dll_emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> Iterator[Speakeasy]:
    yield from load_emu(config, load_test_bin("dll_test_x86.dll.xz"))


def get_random_values(se: Speakeasy) -> list[bytes]:
    values = []
    for dll, name, get_argv in RANDOM_APIS:
        buf = alloc(se, b"\x00" * 16)
        call(se, dll, name, get_argv(buf))
        values.append(bytes(se.mem_read(buf, 16)))
    return values


def test_random_apis_repeat_across_emulators(dll_emu: Speakeasy, other_dll_emu: Speakeasy) -> None:
    values = get_random_values(dll_emu)
    assert values == get_random_values(other_dll_emu)
    # One generator serves all the APIs, so no two calls return the same bytes.
    assert len(set(values)) == len(values)


def test_random_seed_changes_the_random_values(
    dll_emu: Speakeasy, config: dict[str, Any], load_test_bin: Callable[[str], bytes]
) -> None:
    config["random_seed"] = 1
    for se in load_emu(config, load_test_bin("dll_test_x86.dll.xz")):
        assert get_random_values(se) != get_random_values(dll_emu)
