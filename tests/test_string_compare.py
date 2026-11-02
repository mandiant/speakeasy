import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.api.compare import Fold, get_string_order
from tests.handler_harness import alloc, ansi_string, call, unicode_string

PAIRS = [("a", "b"), ("b", "a"), ("a", "a"), ("ABC", "abc"), ("ab", "abc"), ("_", "A")]

# The sign that Windows gives for each pair.
LINGUISTIC = [-1, 1, 0, 1, -1, -1]
LINGUISTIC_IGNORE_CASE = [-1, 1, 0, 0, -1, -1]
ORDINAL = [-1, 1, 0, -1, -1, 1]
ORDINAL_UPPER = [-1, 1, 0, 0, -1, 1]
C_LOCALE_IGNORE_CASE = [-1, 1, 0, 0, -1, -1]


def sign(value: int) -> int:
    return (value > 0) - (value < 0)


@pytest.mark.parametrize(
    "dll, name, width, extra, signs",
    [
        ("kernel32", "lstrcmpA", 1, [], LINGUISTIC),
        ("kernel32", "lstrcmpW", 2, [], LINGUISTIC),
        ("kernel32", "lstrcmpiA", 1, [], LINGUISTIC_IGNORE_CASE),
        ("kernel32", "lstrcmpiW", 2, [], LINGUISTIC_IGNORE_CASE),
        ("msvcrt", "wcscmp", 2, [], ORDINAL),
        ("msvcrt", "_stricmp", 1, [], C_LOCALE_IGNORE_CASE),
        ("msvcrt", "_strnicmp", 1, [8], C_LOCALE_IGNORE_CASE),
        ("msvcrt", "_wcsicmp", 2, [], C_LOCALE_IGNORE_CASE),
        ("msvcrt", "_wcsnicmp", 2, [8], C_LOCALE_IGNORE_CASE),
    ],
)
def test_compare_functions_give_the_windows_sign(
    dll_emu: Speakeasy, dll: str, name: str, width: int, extra: list[int], signs: list[int]
) -> None:
    codec = "latin-1" if width == 1 else "utf-16le"
    for (s1, s2), expected in zip(PAIRS, signs, strict=True):
        args = [alloc(dll_emu, f"{s}\0".encode(codec)) for s in (s1, s2)]
        rv, _ = call(dll_emu, dll, name, [*args, *extra])
        assert sign(rv) == expected, (s1, s2)


@pytest.mark.parametrize(
    "name, case_insensitive, signs",
    [
        ("RtlCompareString", 0, ORDINAL),
        ("RtlCompareString", 1, ORDINAL_UPPER),
        ("RtlCompareUnicodeString", 0, ORDINAL),
        ("RtlCompareUnicodeString", 1, ORDINAL_UPPER),
    ],
)
def test_rtl_compare_functions_give_the_windows_sign(
    driver_emu: Speakeasy, name: str, case_insensitive: int, signs: list[int]
) -> None:
    for (s1, s2), expected in zip(PAIRS, signs, strict=True):
        if name == "RtlCompareString":
            args = [ansi_string(driver_emu, s.encode()) for s in (s1, s2)]
        else:
            args = [unicode_string(driver_emu, s) for s in (s1, s2)]
        rv, _ = call(driver_emu, "ntoskrnl", name, [*args, case_insensitive])
        assert sign(rv) == expected, (s1, s2)


# RtlUpperChar folds in code page 1252: "š" (0x9A) to "Š" (0x8A), and "ÿ" (0xFF) to "Ÿ" (0x9F),
# which sorts before "À" (0xC0).
@pytest.mark.parametrize("s1, s2, expected", [(b"\x9a", b"\x8a", 0), (b"\xff", b"\xe0", -1)])
def test_rtl_compare_string_folds_case_in_the_ansi_code_page(
    driver_emu: Speakeasy, s1: bytes, s2: bytes, expected: int
) -> None:
    args = [ansi_string(driver_emu, s) for s in (s1, s2)]
    rv, _ = call(driver_emu, "ntoskrnl", "RtlCompareString", [*args, 1])
    assert sign(rv) == expected


@pytest.mark.parametrize(
    "s1, s2, fold, rv",
    [
        # The C locale folds only A to Z.
        ("É", "é", Fold.ASCII_LOWER, -1),
        ("É", "é", Fold.UPPER, 0),
        ("É", "é", Fold.LINGUISTIC_IGNORE_CASE, 0),
        # An ordinal fold changes one code unit to one code unit, so "ß" does not become "SS".
        ("ß", "SS", Fold.UPPER, 1),
    ],
)
def test_string_order_folds_non_ascii_letters(s1: str, s2: str, fold: Fold, rv: int) -> None:
    assert get_string_order(s1, s2, fold) == rv
