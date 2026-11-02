"""
Encode and decode 1-byte guest strings with the code page that the guest sees.

``GetACP`` returns 1252, so ANSI strings use Windows-1252. Python's ``cp1252`` codec has no mapping
for 0x81, 0x8D, 0x8F, 0x90 and 0x9D. Windows maps them to the C1 controls with the same value, so
the table here does too. Then each byte decodes to one character, and a decode then an encode gives
the same bytes.
"""

import codecs

CP_ACP = 0
CP_OEMCP = 1
CP_THREAD_ACP = 3
CP_UTF8 = 65001

ANSI_CODE_PAGE = 1252
OEM_CODE_PAGE = 437

DECODING_TABLE = "".join(bytes([b]).decode("cp1252", errors="ignore") or chr(b) for b in range(256))
ENCODING_TABLE = codecs.charmap_build(DECODING_TABLE)


def decode_ansi(data: bytes) -> str:
    """Decode ANSI bytes. Each byte gives one character, so the result has ``len(data)`` characters."""
    return codecs.charmap_decode(data, "strict", DECODING_TABLE)[0]  # type: ignore[arg-type, unused-ignore]


def encode_ansi(text: str) -> bytes:
    """
    Encode ``text`` as ANSI bytes.

    A character that is not in the code page becomes ``?``, the ``DefaultChar`` that ``GetCPInfo`` gives.
    """
    return codecs.charmap_encode(text, "replace", ENCODING_TABLE)[0]


def get_codec(code_page: int) -> str | None:
    """
    Get the Python codec for a code page that the conversion functions take.

    Return None for the ANSI code page, which uses ``decode_ansi`` and ``encode_ansi``.

    Raises:
        ValueError: if speakeasy does not support the code page.
    """
    if code_page in (CP_ACP, CP_THREAD_ACP, ANSI_CODE_PAGE):
        return None
    if code_page in (CP_OEMCP, OEM_CODE_PAGE):
        return "cp437"
    if code_page == CP_UTF8:
        return "utf-8"
    raise ValueError(f"unsupported code page: {code_page}")


def decode_code_page(data: bytes, code_page: int) -> str:
    """
    Decode bytes in ``code_page``.

    Raises:
        ValueError: if speakeasy does not support the code page.
    """
    codec = get_codec(code_page)
    if codec is None:
        return decode_ansi(data)
    return data.decode(codec, "replace")


def encode_code_page(text: str, code_page: int) -> bytes:
    """
    Encode ``text`` in ``code_page``.

    Raises:
        ValueError: if speakeasy does not support the code page.
    """
    codec = get_codec(code_page)
    if codec is None:
        return encode_ansi(text)
    return text.encode(codec, "replace")
