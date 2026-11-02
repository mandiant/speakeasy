"""
Decode Windows constants to their SDK names.

The signature database decodes its enums with the same rules, so one value gets the same name in the handler
text and in the signature rendering.
"""

from collections.abc import Iterable
from enum import IntEnum, IntFlag
from functools import cache


def get_value_names(members: Iterable[tuple[str, int]], value: int, flags: bool) -> list[str]:
    """
    Get the names of the members that make up value.

    An exact match gives the first member with the value, so an alias declared later does not replace the primary
    name. Otherwise a flags set gives the members that fit, widest first, so a composite name such as
    FILE_GENERIC_READ takes precedence over its single bits. The bits that no member has come last, as hex. A value
    that is not a member of an enum, and a 0 that is not a member of a flags set, give only the hex.
    """
    members = list(members)
    for name, member in members:
        if member == value:
            return [name]
    if not flags or value == 0:
        return [hex(value)]
    remaining = value
    names = []
    # High bits first among equally wide members. The sort is stable, so the primary name of an alias comes first.
    for name, member in sorted(members, key=lambda nv: (-bin(nv[1]).count("1"), -nv[1])):
        if member and remaining & member == member:
            names.append(name)
            remaining &= ~member
            if not remaining:
                break
    if remaining or not names:
        names.append(hex(remaining))
    return names


@cache
def _get_members(cls: type[IntEnum | IntFlag]) -> tuple[tuple[str, int], ...]:
    # __members__ has the aliases too, in the order of declaration
    return tuple((name, int(member)) for name, member in cls.__members__.items())


def decode_flags(cls: type[IntEnum | IntFlag], value: int) -> list[str]:
    """Get the names of the members of cls that make up value."""
    return get_value_names(_get_members(cls), value, issubclass(cls, IntFlag))


def decode(cls: type[IntEnum | IntFlag], value: int) -> str:
    """Get the name of value in cls. A flags value gives its names joined with "|"."""
    return "|".join(decode_flags(cls, value))
