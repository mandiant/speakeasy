"""Unit tests for ApiHandler.do_str_format printf-style emulation."""

import pytest

from speakeasy.winenv.api.api import MAX_FORMAT_FIELD, ApiHandler


class FakeFormatApi:
    def __init__(self, ptr_size=8):
        self.ptr_size = ptr_size
        self.strings: dict[int, bytes] = {}

    def get_ptr_size(self):
        return self.ptr_size

    def read_string(self, addr, max_chars=0):
        return self.strings[addr].decode("utf-8")

    def read_wide_string(self, addr, max_chars=0):
        return self.strings[addr].decode("utf-16le")


@pytest.fixture
def api():
    return FakeFormatApi(ptr_size=8)


def do_format(api, string, args):
    return ApiHandler.do_str_format(api, string, list(args))


def test_c99_z_modifier_consumes_full_arg_on_x64(api):
    assert do_format(api, "%zu", [0x1122334455667788]) == str(0x1122334455667788)
    assert do_format(api, "%zx", [0xAABBCCDDEEFF1122]) == "aabbccddeeff1122"


def test_c99_z_modifier_masks_to_32_bits_on_x86():
    api = FakeFormatApi(ptr_size=4)

    assert do_format(api, "%zu", [0x1122334455667788]) == str(0x55667788)


@pytest.mark.parametrize(
    "fmt,value,expected",
    [
        ("%ju", 0x1000, "4096"),
        ("%td", 7, "7"),
        ("%ti", 9, "9"),
    ],
    ids=["ju", "td", "ti"],
)
def test_c99_j_and_t_modifiers_format_value(api, fmt, value, expected):
    assert do_format(api, fmt, [value]) == expected


def test_multiple_ll_conversions_keep_output_index_correct(api):
    assert do_format(api, "%llx %llx", [0x1111, 0x2222]) == "1111 2222"


def test_narrow_string_after_z_splice_formats_both_args(api):
    api.strings[0x500000] = b"hello"

    assert do_format(api, "%zu %s", [42, 0x500000]) == "42 hello"


def test_p_conversion_after_z_splice_lands_in_correct_slot(api):
    assert do_format(api, "%zu %p", [42, 0xDEADBEEF]) == "42 deadbeef"


def test_upper_p_conversion_after_ll_splice_lands_in_correct_slot(api):
    assert do_format(api, "%llx %P", [0xAB, 0xDEADBEEF]) == "ab DEADBEEF"


def test_S_conversion_after_ll_splice_lands_in_correct_slot(api):
    api.strings[0x600000] = "wide".encode("utf-16le")

    assert do_format(api, "%llx %S", [0xAB, 0x600000]) == "ab wide"


def test_wide_s_after_ll_splice_lands_in_correct_slot(api):
    api.strings[0x600000] = "wide".encode("utf-16le")

    assert do_format(api, "%llx %ws", [0xAB, 0x600000]) == "ab wide"


def test_percent_escapes_are_preserved(api):
    assert do_format(api, "100%% %zu", [7]) == "100% 7"


@pytest.mark.parametrize(
    "fmt, args, expected",
    [
        ("%hhd", [0x1FF], "-1"),
        ("%hhu", [0x1FF], "255"),
        ("%hd", [0x18000], "-32768"),
        ("%d", [0xFFFFFFFF], "-1"),
        ("%ld", [0xFFFFFFFE], "-2"),
        ("%5d|%-5d|%05x", [7, 7, 0xAB], "    7|7    |000ab"),
        ("%*d", [4, 7], "   7"),
        ("%-*d|", [-4, 7], "7   |"),
        ("%.*s", [3, 0x500000], "hel"),
        ("%c%c", [ord("o"), ord("k")], "ok"),
        ("%I64x", [0x1122334455667788], "1122334455667788"),
        ("%Iu", [0x1122334455667788], str(0x1122334455667788)),
        ("%o", [8], "10"),
        ("%.2f", [0x400921FB54442D18], "3.14"),
        ("%g", [0x3FF8000000000000], "1.5"),
        ("%s", [0], "(null)"),
        ("%hs", [0x500000], "hello"),
        ("%d%n!", [1, 0x700000], "1!"),
        ("%y %d", [5], "%y 5"),
        ("%d %d", [5], "5 0"),
    ],
)
def test_conversions_follow_the_msvc_printf_rules(api, fmt, args, expected):
    api.strings[0x500000] = b"hello"

    assert do_format(api, fmt, args) == expected


def test_x86_64_bit_values_take_two_slots():
    api = FakeFormatApi(ptr_size=4)

    assert do_format(api, "%I64x %.1f %d", [0x55667788, 0x11223344, 0, 0x3FF80000, 7]) == "1122334455667788 1.5 7"


def test_wide_functions_swap_the_default_string_width(api):
    api.strings[0x500000] = b"narrow"
    api.strings[0x600000] = "wide".encode("utf-16le")

    assert ApiHandler.do_str_format(
        api, "%s %S %hs %ls %C", [0x600000, 0x500000, 0x500000, 0x600000, 0x41], wide=True
    ) == ("wide narrow narrow wide A")


@pytest.mark.parametrize(
    "ptr_size, fmt, slots",
    [
        (4, "%d %s", 2),
        (4, "%lld %f %I64x", 6),
        (4, "%*.*s %%", 3),
        (8, "%lld %f %I64x", 3),
        (8, "100%% %hhd %n", 2),
    ],
)
def test_va_arg_count_counts_argument_slots(ptr_size, fmt, slots):
    assert ApiHandler.get_va_arg_count(FakeFormatApi(ptr_size), fmt) == slots


@pytest.mark.parametrize("fmt", ["%*d", "%.*d", "%2147483647d", "%.2147483647f"])
def test_a_field_width_or_precision_is_capped(api, fmt):
    args = [0x7FFFFFFF, 1] if "*" in fmt else [1]

    assert len(do_format(api, fmt, args)) <= MAX_FORMAT_FIELD + 2
