import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.api.compare import Fold, get_string_order
from tests.handler_harness import alloc, call

PAIRS = [("a", "b"), ("b", "a"), ("a", "a"), ("ABC", "abc"), ("ab", "abc"), ("_", "A")]

# The sign that Windows gives for each pair.
LINGUISTIC = [-1, 1, 0, 1, -1, -1]
LINGUISTIC_IGNORE_CASE = [-1, 1, 0, 0, -1, -1]


def sign(value: int) -> int:
    return (value > 0) - (value < 0)


@pytest.mark.parametrize(
    "dll, name, width, extra, signs",
    [
        ("kernel32", "lstrcmpA", 1, [], LINGUISTIC),
        ("kernel32", "lstrcmpW", 2, [], LINGUISTIC),
        ("kernel32", "lstrcmpiA", 1, [], LINGUISTIC_IGNORE_CASE),
        ("kernel32", "lstrcmpiW", 2, [], LINGUISTIC_IGNORE_CASE),
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
