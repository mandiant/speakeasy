from typing import Annotated, Any

from pydantic import BeforeValidator, PlainSerializer


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


HexInt = Annotated[int, BeforeValidator(_parse_hex_int), PlainSerializer(hex_serializer, return_type=str)]
HexIntOptional = Annotated[
    int | None,
    BeforeValidator(_parse_hex_int),
    PlainSerializer(hex_serializer, return_type=str | None),
]
