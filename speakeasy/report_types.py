from typing import Annotated, Any

from pydantic import BeforeValidator, PlainSerializer, StringConstraints


def hex_serializer(v: int | None) -> str | None:
    """
    Serialize integer values as ``0x``-prefixed hexadecimal strings.

    Args:
        v: Integer value to serialize.

    Returns:
        Hexadecimal string, or ``None`` when the input is ``None``.
    """
    if v is None:
        return None
    return hex(v)


def _parse_hex_int(v: Any) -> Any:
    """
    Parse integer-like strings accepted by report models.

    Args:
        v: Raw input value.

    Returns:
        Parsed integer when ``v`` is a numeric string, otherwise ``v`` unchanged.
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
