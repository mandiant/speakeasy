from typing import Annotated, Any

from pydantic import BeforeValidator, PlainSerializer, StringConstraints


def hex_serializer(v: int | None) -> str | None:
    """Serialize an int as a ``0x``-prefixed hex string. ``None`` does not change."""
    if v is None:
        return None
    return hex(v)


def _parse_hex_int(v: Any) -> Any:
    """
    Convert a string, such as ``"0x1f"``, to an int. Other values do not change.

    The prefix of the string gives the base, so a string without a prefix is decimal.
    """
    if isinstance(v, str):
        return int(v, 0)
    return v


HexStr = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]+$")]

HexInt = Annotated[int, BeforeValidator(_parse_hex_int), PlainSerializer(hex_serializer, return_type=HexStr)]
"""
A machine word, such as an address, a pointer, a handle or a register value.

The report writes it as a ``0x``-prefixed hex string. A 64-bit word can be
above 2**53 or 2**63. JavaScript, Go ``interface{}``, jq and int64 stores such
as SQLite lose such a value as a JSON number, and they give no error.
"""
HexIntOptional = Annotated[
    int | None,
    BeforeValidator(_parse_hex_int),
    PlainSerializer(hex_serializer, return_type=HexStr | None),
]
