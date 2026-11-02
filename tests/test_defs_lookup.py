"""The defs lookup decodes a value to its SDK names with the rules of the signature database."""

from enum import IntEnum, IntFlag

import pytest

from speakeasy.winenv.defs.lookup import decode, decode_flags


class Mode(IntEnum):
    MODE_OFF = 0
    MODE_ON = 1
    MODE_ENABLED = 1


class Access(IntFlag):
    ACCESS_READ = 0x1
    ACCESS_WRITE = 0x2
    ACCESS_LIST = 0x1
    ACCESS_EXECUTE = 0x4
    ACCESS_READ_WRITE = 0x3
    ACCESS_HIGH = 0x80000000


@pytest.mark.parametrize(
    ("value", "names"),
    [
        (0x1, ["ACCESS_READ"]),
        (0x7, ["ACCESS_READ_WRITE", "ACCESS_EXECUTE"]),
        (0x80000005, ["ACCESS_HIGH", "ACCESS_EXECUTE", "ACCESS_READ"]),
        (0x14, ["ACCESS_EXECUTE", "0x10"]),
        (0, ["0x0"]),
    ],
)
def test_decode_flags_gives_the_widest_members_first_and_the_other_bits_as_hex(value: int, names: list[str]) -> None:
    assert decode_flags(Access, value) == names


@pytest.mark.parametrize(("value", "text"), [(0, "MODE_OFF"), (1, "MODE_ON"), (5, "0x5")])
def test_decode_gives_the_primary_name_of_an_enum_value(value: int, text: str) -> None:
    assert decode(Mode, value) == text


def test_decode_joins_flags_with_a_bar() -> None:
    assert decode(Access, 0x80000005) == "ACCESS_HIGH|ACCESS_EXECUTE|ACCESS_READ"
