"""Unit tests for ApiHandler.do_str_format printf-style emulation."""

import pytest

from speakeasy.winenv.api.api import ApiHandler


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
