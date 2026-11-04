"""
Order two guest strings the way the Windows and C runtime compare functions do.

The compare functions differ in how they fold case, and the direction is important. The C locale
folds ``A`` to ``Z`` to lower case, so ``_stricmp("_", "A")`` is less than 0, because ``_`` (0x5F)
is less than ``a`` (0x61). A fold to upper case gives a result that is greater than 0.
"""

import enum

from speakeasy.winenv.codepage import DECODING_TABLE

ASCII_LOWER_TABLE = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


class Fold(enum.Enum):
    NONE = "none"  # strcmp, wcscmp, CompareStringOrdinal
    ASCII_LOWER = "ascii_lower"  # _stricmp, _wcsicmp, _wcsnicmp: the C locale
    UPPER = "upper"  # CompareStringOrdinal(bIgnoreCase), RtlCompareUnicodeString(CaseInSensitive)
    LINGUISTIC = "linguistic"  # lstrcmp, CompareString
    LINGUISTIC_IGNORE_CASE = "linguistic_ignore_case"  # lstrcmpi, CompareString(NORM_IGNORECASE)


def fold_upper(c: str) -> str:
    # Windows folds each UTF-16 code unit to one code unit, so it does not change "ß" or a character
    # outside the BMP.
    upper = c.upper()
    return upper if len(upper) == 1 and ord(c) < 0x10000 else c


# RtlUpperChar folds a byte in the ANSI code page. If the upper case of a byte is not in the code page,
# RtlUpperChar does not change the byte.
ANSI_UPPER_TABLE = bytes(
    DECODING_TABLE.index(u) if (u := fold_upper(c)) in DECODING_TABLE else b for b, c in enumerate(DECODING_TABLE)
)


def get_sort_key(s: str, fold: Fold) -> tuple[str | bytes, ...]:
    if fold == Fold.LINGUISTIC:
        # Case is only a tie breaker in a linguistic sort, and lower case sorts first.
        return (s.casefold(), s.swapcase())
    if fold == Fold.LINGUISTIC_IGNORE_CASE:
        return (s.casefold(),)
    if fold == Fold.ASCII_LOWER:
        s = s.translate(ASCII_LOWER_TABLE)
    elif fold == Fold.UPPER:
        s = "".join(map(fold_upper, s))
    # Big-endian UTF-16 bytes sort in the order of the code units.
    return (s.encode("utf-16-be", "surrogatepass"),)


def get_string_order(s1: str, s2: str, fold: Fold) -> int:
    """
    Get -1 if s1 sorts before s2, 0 if they are equal, and 1 if s1 sorts after s2.

    The linguistic folds approximate the CompareString sort: they compare the case folded strings
    first, and do not use the Windows weights for punctuation and symbols. The other folds compare
    UTF-16 code units. To compare bytes in byte order, decode them as Latin-1.
    """
    k1, k2 = get_sort_key(s1, fold), get_sort_key(s2, fold)
    return (k1 > k2) - (k1 < k2)
