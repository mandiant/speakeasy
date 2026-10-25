import struct
from collections.abc import Callable, Iterator
from typing import Any

import pytest
import unicorn

from speakeasy import Speakeasy
from speakeasy.winenv import arch as e_arch
from speakeasy.winenv.api.usermode.msvcrt import (
    EINVAL,
    ENOENT,
    ERANGE,
    SIG_DFL,
    SIG_ERR,
    SIG_IGN,
    SIGFPE,
    SIGINT,
    SIGSEGV,
    STRUNCATE,
    TIME_BASE,
    get_full_path,
    get_winmain_command_line,
    scan_c_format,
)
from tests.handler_harness import alloc, call, load_emu, start_process


@pytest.mark.parametrize(
    "api, c, rv",
    [
        ("tolower", ord("A"), ord("a")),
        ("tolower", ord("Z"), ord("z")),
        ("tolower", ord("\\"), ord("\\")),
        ("tolower", ord("_"), ord("_")),
        ("tolower", ord("@"), ord("@")),
        ("tolower", 0xC9, 0xC9),
        ("toupper", ord("a"), ord("A")),
        ("toupper", ord("z"), ord("Z")),
        ("toupper", ord("`"), ord("`")),
        ("toupper", 0xE9, 0xE9),
    ],
)
def test_case_conversion_changes_only_ascii_letters(dll_emu: Speakeasy, api: str, c: int, rv: int) -> None:
    assert call(dll_emu, "msvcrt", api, [c])[0] == rv


@pytest.mark.parametrize("value, byte", [(0x41, b"A"), (0xFFFFFFFF, b"\xff"), (0x1E9, b"\xe9")])
def test_memset_fills_low_byte(dll_emu: Speakeasy, value: int, byte: bytes) -> None:
    buf = alloc(dll_emu, b"\xcc" * 5)
    assert call(dll_emu, "msvcrt", "memset", [buf, value, 4])[0] == buf
    assert dll_emu.mem_read(buf, 5) == byte * 4 + b"\xcc"


def test_time_writes_a_pointer_sized_time_t_on_x64(dll64_emu: Speakeasy) -> None:
    out = alloc(dll64_emu, b"\xcc" * 9)
    rv, _ = call(dll64_emu, "msvcrt", "time", [out])
    assert dll64_emu.mem_read(out, 9) == rv.to_bytes(8, "little") + b"\xcc"


@pytest.mark.parametrize("needle, offset", [("XYZ", 3), ("abc", 0), ("Q", None)])
def test_wcsstr_returns_pointer_to_match(dll_emu: Speakeasy, needle: str, offset: int | None) -> None:
    hay = alloc(dll_emu, "abcXYZ\0".encode("utf-16le"))
    rv, _ = call(dll_emu, "msvcrt", "wcsstr", [hay, alloc(dll_emu, f"{needle}\0".encode("utf-16le"))])
    assert rv == (0 if offset is None else hay + offset * 2)


@pytest.mark.parametrize(
    "src, count, written",
    [
        (b"abcdefgh", 4, b"abcd"),
        (b"ab", 4, b"ab\x00\x00"),
        (b"\x8f\xe9", 2, b"\x8f\xe9"),
        (b"ab", 0, b""),
    ],
)
def test_strncpy_writes_exactly_count_bytes(dll_emu: Speakeasy, src: bytes, count: int, written: bytes) -> None:
    dest = alloc(dll_emu, b"\xcc" * 9)
    assert call(dll_emu, "msvcrt", "strncpy", [dest, alloc(dll_emu, src + b"\x00"), count])[0] == dest
    assert dll_emu.mem_read(dest, 9) == written + b"\xcc" * (9 - len(written))


@pytest.mark.parametrize(
    "src, count, written",
    [
        ("abcdefgh", 4, "abcd"),
        ("ab", 4, "ab\0\0"),
        ("ab", 0, ""),
    ],
)
def test_wcsncpy_writes_exactly_count_chars(dll_emu: Speakeasy, src: str, count: int, written: str) -> None:
    dest = alloc(dll_emu, b"\xcc" * 18)
    assert call(dll_emu, "msvcrt", "wcsncpy", [dest, alloc(dll_emu, f"{src}\0".encode("utf-16le")), count])[0] == dest
    data = written.encode("utf-16le")
    assert dll_emu.mem_read(dest, 18) == data + b"\xcc" * (18 - len(data))


@pytest.mark.parametrize("count, result", [(2, b"\xe9\x8fa"), (9, b"\xe9\x8fabc"), (0, b"\xe9")])
def test_strncat_appends_at_most_count_bytes(dll_emu: Speakeasy, count: int, result: bytes) -> None:
    dest = alloc(dll_emu, b"\xe9\x00" + b"\xcc" * 8)
    assert call(dll_emu, "msvcrt", "strncat", [dest, alloc(dll_emu, b"\x8fabc\x00"), count])[0] == dest
    assert dll_emu.mem_read(dest, len(result) + 1) == result + b"\x00"


@pytest.mark.parametrize(
    "size, src, count, rv, result",
    [
        (16, b"cdef", 2, 0, b"abcd"),
        (16, b"cd", 5, 0, b"abcd"),
        (16, b"cdef", None, 0, b"abcdef"),
        (5, b"cdef", None, STRUNCATE, b"abcd"),
        (5, b"cdef", 3, ERANGE, b""),
    ],
)
@pytest.mark.parametrize("emu_name", ["dll_emu", "dll64_emu"])
def test_strncat_s_appends_within_buffer(
    request: pytest.FixtureRequest, emu_name: str, size: int, src: bytes, count: int | None, rv: int, result: bytes
) -> None:
    se: Speakeasy = request.getfixturevalue(emu_name)
    assert se.emu is not None
    if count is None:
        count = (1 << (8 * se.emu.get_ptr_size())) - 1
    dest = alloc(se, b"ab\x00" + b"\xcc" * 13)
    assert call(se, "msvcrt", "strncat_s", [dest, size, alloc(se, src + b"\x00"), count])[0] == rv
    assert se.mem_read(dest, len(result) + 1) == result + b"\x00"


@pytest.mark.parametrize(
    "fmt, count, rv, written",
    [
        ("%s-%s", 4, -1, "AAAA"),
        ("%s-%s", 17, 17, "AAAAAAAA-BBBBBBBB"),
        ("%s-%s", 18, 17, "AAAAAAAA-BBBBBBBB\0"),
        ("hello", 3, -1, "hel"),
        ("hello", 8, 5, "hello\0"),
    ],
)
@pytest.mark.parametrize("api, width", [("_snprintf", 1), ("_snwprintf", 2)])
def test_snprintf_writes_at_most_count_chars(
    dll_emu: Speakeasy, api: str, width: int, fmt: str, count: int, rv: int, written: str
) -> None:
    enc = "utf-8" if width == 1 else "utf-16le"
    buf = alloc(dll_emu, b"\xcc" * 40)
    args = [alloc(dll_emu, f"{s}\0".encode(enc)) for s in (fmt, "AAAAAAAA", "BBBBBBBB")]
    assert call(dll_emu, "msvcrt", api, [buf, count, *args])[0] == rv
    data = written.encode(enc)
    assert dll_emu.mem_read(buf, len(data) + width) == data + b"\xcc" * width


@pytest.mark.parametrize(
    "value, radix, text",
    [
        (255, 16, "ff"),
        (255, 10, "255"),
        (5, 2, "101"),
        (0, 10, "0"),
        (0xFFFFFFFB, 10, "-5"),
        (0xFFFFFFFB, 16, "fffffffb"),
        (0x80000000, 10, "-2147483648"),
    ],
)
@pytest.mark.parametrize("api, enc", [("_ltoa", "utf-8"), ("_itoa", "utf-8"), ("_itow", "utf-16le")])
def test_itoa_formats_in_radix(dll_emu: Speakeasy, api: str, enc: str, value: int, radix: int, text: str) -> None:
    buf = alloc(dll_emu, b"\xcc" * 40)
    assert call(dll_emu, "msvcrt", api, [value, buf, radix])[0] == buf
    data = f"{text}\0".encode(enc)
    assert dll_emu.mem_read(buf, len(data)) == data


def test_itoa_uses_32_bit_value_on_x64(dll64_emu: Speakeasy) -> None:
    buf = alloc(dll64_emu, b"\xcc" * 16)
    call(dll64_emu, "msvcrt", "_itoa", [0xFFFFFFFFFFFFFFFB, buf, 10])
    assert dll64_emu.mem_read(buf, 3) == b"-5\x00"


XTOX_S_APIS = [
    "_itoa_s",
    "_itow_s",
    "_ltoa_s",
    "_ltow_s",
    "_ultoa_s",
    "_ultow_s",
    "_i64toa_s",
    "_i64tow_s",
    "_ui64toa_s",
    "_ui64tow_s",
]


def call_xtox_s(se: Speakeasy, api: str, value: int, buf: int, size: int, radix: int) -> int:
    assert se.emu is not None
    value &= 0xFFFFFFFFFFFFFFFF
    if se.emu.get_ptr_size() == 4:
        argv = [value & 0xFFFFFFFF, value >> 32] if "64" in api else [value & 0xFFFFFFFF]
    else:
        argv = [value]
    argv += [buf, size, radix]
    if "64" in api and se.emu.get_ptr_size() == 8:
        argv.append(0)
    return call(se, "msvcrt", api, argv)[0]


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
@pytest.mark.parametrize(
    "api, value, radix, text",
    [
        ("_itoa_s", -123, 10, "-123"),
        ("_ltow_s", -123, 10, "-123"),
        ("_itow_s", 255, 16, "ff"),
        ("_ltoa_s", -1, 16, "ffffffff"),
        ("_ultoa_s", -123, 10, "4294967173"),
        ("_ultow_s", 35, 36, "z"),
        ("_i64toa_s", -(2**40), 10, "-1099511627776"),
        ("_i64tow_s", -1, 2, "1" * 64),
        ("_ui64toa_s", -1, 10, "18446744073709551615"),
        ("_ui64tow_s", 2**40, 16, "10000000000"),
    ],
)
def test_xtox_s_formats_in_radix(
    request: pytest.FixtureRequest, fixture: str, api: str, value: int, radix: int, text: str
) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    enc = "utf-16le" if "tow" in api else "latin-1"
    buf = alloc(se, b"\xcc" * 160)
    assert call_xtox_s(se, api, value, buf, len(text) + 1, radix) == 0
    data = f"{text}\0".encode(enc)
    assert se.mem_read(buf, len(data)) == data

    assert call_xtox_s(se, api, value, buf, len(text), radix) == ERANGE
    assert se.mem_read(buf, len("\0".encode(enc))) == "\0".encode(enc)


@pytest.mark.parametrize("api", XTOX_S_APIS)
def test_xtox_s_checks_its_arguments(dll_emu: Speakeasy, api: str) -> None:
    width = 2 if "tow" in api else 1
    buf = alloc(dll_emu, b"\xcc" * 16)
    assert call_xtox_s(dll_emu, api, 1, 0, 12, 10) == EINVAL
    assert call_xtox_s(dll_emu, api, 1, buf, 0, 10) == EINVAL
    assert dll_emu.mem_read(buf, 16) == b"\xcc" * 16

    assert call_xtox_s(dll_emu, api, 1, buf, 12, 37) == EINVAL
    assert dll_emu.mem_read(buf, width + 1) == b"\x00" * width + b"\xcc"

    assert call_xtox_s(dll_emu, api, 12345, buf, 3, 10) == ERANGE
    assert dll_emu.mem_read(buf, width) == b"\x00" * width
    errno_ptr, _ = call(dll_emu, "msvcrt", "_errno", [])
    assert int.from_bytes(dll_emu.mem_read(errno_ptr, 4), "little") == ERANGE


@pytest.mark.parametrize(
    "text, count, rv, written",
    [
        ("hi", 8, 2, b"hi\x00"),
        ("hello", 3, 3, b"hel"),
        ("hello", 5, 5, b"hello"),
        ("caf\xe9", 8, 4, b"caf\xe9\x00"),
        ("中", 8, 0xFFFFFFFF, b""),
    ],
)
def test_wcstombs_converts_at_most_count_bytes(
    dll_emu: Speakeasy, text: str, count: int, rv: int, written: bytes
) -> None:
    buf = alloc(dll_emu, b"\xcc" * 16)
    assert call(dll_emu, "msvcrt", "wcstombs", [buf, alloc(dll_emu, f"{text}\0".encode("utf-16le")), count])[0] == rv
    assert dll_emu.mem_read(buf, len(written) + 1) == written + b"\xcc"


def test_wcstombs_returns_size_for_null_buffer(dll_emu: Speakeasy) -> None:
    assert call(dll_emu, "msvcrt", "wcstombs", [0, alloc(dll_emu, "hello\0".encode("utf-16le")), 0])[0] == 5


@pytest.mark.parametrize(
    "text, count, rv, written",
    [
        (b"hi", 8, 2, "hi\0"),
        (b"hello", 3, 3, "hel"),
        (b"caf\xe9", 8, 4, "caf\xe9\0"),
        (b"hello", 0, 0, ""),
    ],
)
def test_mbstowcs_converts_at_most_count_chars(
    dll_emu: Speakeasy, text: bytes, count: int, rv: int, written: str
) -> None:
    buf = alloc(dll_emu, b"\xcc" * 32)
    assert call(dll_emu, "msvcrt", "mbstowcs", [buf, alloc(dll_emu, text + b"\x00"), count])[0] == rv
    data = written.encode("utf-16le")
    assert dll_emu.mem_read(buf, len(data) + 1) == data + b"\xcc"


def test_mbstowcs_returns_size_for_null_buffer(dll_emu: Speakeasy) -> None:
    assert call(dll_emu, "msvcrt", "mbstowcs", [0, alloc(dll_emu, b"hello\x00"), 0])[0] == 5


@pytest.mark.parametrize(
    "size, count, rv, converted, written",
    [
        (8, None, 0, 3, "hi\0"),
        (8, 1, 0, 2, "h\0"),
        (2, None, STRUNCATE, 2, "h\0"),
        (2, 5, ERANGE, 0, "\0"),
    ],
)
@pytest.mark.parametrize("emu_name", ["dll_emu", "dll64_emu"])
def test_mbstowcs_s_converts_within_buffer(
    request: pytest.FixtureRequest,
    emu_name: str,
    size: int,
    count: int | None,
    rv: int,
    converted: int,
    written: str,
) -> None:
    se: Speakeasy = request.getfixturevalue(emu_name)
    assert se.emu is not None
    ptr_size = se.emu.get_ptr_size()
    if count is None:
        count = (1 << (8 * ptr_size)) - 1
    out = alloc(se, b"\xcc" * 16)
    ret = alloc(se, b"\xcc" * 8)
    assert call(se, "msvcrt", "mbstowcs_s", [ret, out, size, alloc(se, b"hi\x00"), count])[0] == rv
    assert se.mem_read(ret, 8) == converted.to_bytes(ptr_size, "little") + b"\xcc" * (8 - ptr_size)
    data = written.encode("utf-16le")
    assert se.mem_read(out, len(data)) == data


def test_mbstowcs_s_returns_size_for_null_buffer(dll_emu: Speakeasy) -> None:
    ret = alloc(dll_emu, b"\xcc" * 4)
    assert call(dll_emu, "msvcrt", "mbstowcs_s", [ret, 0, 0, alloc(dll_emu, b"hello\x00"), 0])[0] == 0
    assert dll_emu.mem_read(ret, 4) == (6).to_bytes(4, "little")


@pytest.mark.parametrize("emu_name", ["dll_emu", "dll64_emu"])
def test_fseek_takes_a_signed_offset(request: pytest.FixtureRequest, emu_name: str) -> None:
    se: Speakeasy = request.getfixturevalue(emu_name)
    assert se.emu is not None
    minus = (1 << (8 * se.emu.get_ptr_size())) - 1
    path = alloc(se, b"c:\\windows\\system32\\cmd.exe\x00")
    stream, _ = call(se, "msvcrt", "fopen", [path, alloc(se, b"rb\x00")])
    assert stream

    assert call(se, "msvcrt", "fseek", [stream, minus - 3, 2])[0] == 0
    assert call(se, "msvcrt", "ftell", [stream])[0] == 4092
    assert call(se, "msvcrt", "fseek", [stream, minus, 0])[0] == -1
    assert call(se, "msvcrt", "fseek", [stream, minus - 1, 1])[0] == 0
    assert call(se, "msvcrt", "fread", [alloc(se, b"\x00" * 16), 1, 16, stream])[0] == 6


@pytest.mark.parametrize(
    "text, rv",
    [
        (b"123abc", 123),
        (b" \t-42x", -42),
        (b"+7", 7),
        (b"1_0", 1),
        (b"abc", 0),
        (b"99999999999", 0x7FFFFFFF),
        (b"-99999999999", -0x80000000),
    ],
)
def test_atoi_parses_leading_digits(dll_emu: Speakeasy, text: bytes, rv: int) -> None:
    assert call(dll_emu, "msvcrt", "atoi", [alloc(dll_emu, text + b"\x00")])[0] == rv


@pytest.mark.parametrize(
    "api, a, b, rv",
    [
        ("strcmp", b"a\xff", b"a\xfe", 1),
        ("strcmp", b"abc", b"abd", -1),
        ("strcmp", b"abc", b"abc", 0),
        ("_stricmp", b"a\xff", b"A\xfe", 1),
        ("_stricmp", b"ABC", b"abd", -1),
        ("_stricmp", b"ABC", b"abc", 0),
        ("_stricmp", b"\xc9", b"\xe9", -1),
        ("_strcmpi", b"a\xff", b"A\xfe", 1),
        ("_strcmpi", b"Path\\X", b"path\\x", 0),
    ],
)
def test_strcmp_compares_bytes(dll_emu: Speakeasy, api: str, a: bytes, b: bytes, rv: int) -> None:
    result, _ = call(dll_emu, "msvcrt", api, [alloc(dll_emu, a + b"\x00"), alloc(dll_emu, b + b"\x00")])
    assert result == rv


@pytest.mark.parametrize(
    "a, b, count, rv",
    [
        (b"\x8fABx", b"\x8fabY", 3, 0),
        (b"\x8fABx", b"\x8fabY", 4, -1),
        (b"a\xff", b"a\xfe", 2, 1),
        (b"a", b"b", 0, 0),
    ],
)
def test_strnicmp_compares_count_bytes(dll_emu: Speakeasy, a: bytes, b: bytes, count: int, rv: int) -> None:
    result, _ = call(dll_emu, "msvcrt", "_strnicmp", [alloc(dll_emu, a + b"\x00"), alloc(dll_emu, b + b"\x00"), count])
    assert result == rv


def test_strlwr_lowers_only_ascii_letters_in_place(dll_emu: Speakeasy) -> None:
    s = alloc(dll_emu, b"C:\\\x8f\xc9AB\x00\xcc")
    assert call(dll_emu, "msvcrt", "_strlwr", [s])[0] == s
    assert dll_emu.mem_read(s, 9) == b"c:\\\x8f\xc9ab\x00\xcc"


@pytest.mark.parametrize("a, b, count, rv", [("abX", "ABy", 2, 0), ("a", "b", 0, 0), ("ab", "ac", 2, 1)])
def test_wcsnicmp_compares_count_chars(dll_emu: Speakeasy, a: str, b: str, count: int, rv: int) -> None:
    args = [alloc(dll_emu, f"{s}\0".encode("utf-16le")) for s in (a, b)]
    assert call(dll_emu, "msvcrt", "_wcsnicmp", [*args, count])[0] == rv


def test_snwprintf_reads_s_as_wide_and_S_as_ansi(dll_emu: Speakeasy) -> None:
    buf = alloc(dll_emu, b"\xcc" * 40)
    fmt = alloc(dll_emu, "%s|%S|%%s\0".encode("utf-16le"))
    args = [alloc(dll_emu, "ab\0".encode("utf-16le")), alloc(dll_emu, b"cd\0")]
    assert call(dll_emu, "msvcrt", "_snwprintf", [buf, 20, fmt, *args])[0] == 8
    assert dll_emu.mem_read(buf, 18) == "ab|cd|%s\0".encode("utf-16le")


def test_snprintf_reads_no_argument_for_percent_escape(dll_emu: Speakeasy) -> None:
    buf = alloc(dll_emu, b"\xcc" * 16)
    fmt = alloc(dll_emu, b"%d%%\0")
    assert call(dll_emu, "msvcrt", "_snprintf", [buf, 16, fmt, 5])[0] == 2
    assert dll_emu.mem_read(buf, 3) == b"5%\0"


@pytest.mark.parametrize(
    "api, head",
    [("sprintf", []), ("_snprintf", [16])],
)
def test_sprintf_writes_one_percent_for_escape_without_arguments(dll_emu: Speakeasy, api: str, head: list[int]) -> None:
    buf = alloc(dll_emu, b"\xcc" * 16)
    fmt = alloc(dll_emu, b"100%%\0")
    assert call(dll_emu, "msvcrt", api, [buf, *head, fmt])[0] == 4
    assert dll_emu.mem_read(buf, 5) == b"100%\0"


def test_snwprintf_writes_one_percent_for_escape_without_arguments(dll_emu: Speakeasy) -> None:
    buf = alloc(dll_emu, b"\xcc" * 16)
    fmt = alloc(dll_emu, "100%%\0".encode("utf-16le"))
    assert call(dll_emu, "msvcrt", "_snwprintf", [buf, 8, fmt])[0] == 4
    assert dll_emu.mem_read(buf, 10) == "100%\0".encode("utf-16le")


def test_printf_counts_one_character_for_percent_escape(dll_emu: Speakeasy) -> None:
    fmt = alloc(dll_emu, b"100%%\n\0")
    assert call(dll_emu, "msvcrt", "printf", [fmt])[0] == 5


def test_signal_returns_the_previous_handler_of_each_signal(dll_emu: Speakeasy) -> None:
    assert call(dll_emu, "msvcrt", "signal", [SIGSEGV, 0x401000])[0] == SIG_DFL
    assert call(dll_emu, "msvcrt", "signal", [SIGSEGV, SIG_IGN])[0] == 0x401000
    assert call(dll_emu, "msvcrt", "signal", [SIGINT, SIG_IGN])[0] == SIG_DFL
    assert call(dll_emu, "msvcrt", "signal", [SIGSEGV, SIG_DFL])[0] == SIG_IGN


def test_signal_rejects_an_unknown_signal(dll_emu: Speakeasy) -> None:
    assert call(dll_emu, "msvcrt", "signal", [5, SIG_IGN])[0] == SIG_ERR


@pytest.mark.parametrize("api", ["_seh_filter_exe", "_seh_filter_dll"])
@pytest.mark.parametrize("code", [0xE06D7363, 0x80000003, 0xC0000005, 0xC000001D, 0xC000008E])
def test_seh_filter_continues_the_search_without_a_signal_action(dll_emu: Speakeasy, api: str, code: int) -> None:
    assert call(dll_emu, "msvcrt", api, [code, 0])[0] == 0


def test_seh_filter_exe_continues_execution_for_an_ignored_signal(dll_emu: Speakeasy) -> None:
    call(dll_emu, "msvcrt", "signal", [SIGSEGV, SIG_IGN])
    assert call(dll_emu, "msvcrt", "_seh_filter_exe", [0xC0000005, 0])[0] == 0xFFFFFFFF
    assert call(dll_emu, "msvcrt", "_seh_filter_exe", [0xC000001D, 0])[0] == 0
    assert call(dll_emu, "msvcrt", "_seh_filter_dll", [0xC0000005, 0])[0] == 0


@pytest.mark.parametrize("code, sig, args", [(0xC0000005, SIGSEGV, (SIGSEGV,)), (0xC000008E, SIGFPE, (SIGFPE, 0x83))])
def test_seh_filter_exe_calls_the_signal_handler_once(
    dll_emu: Speakeasy, code: int, sig: int, args: tuple[int, ...]
) -> None:
    call(dll_emu, "msvcrt", "signal", [sig, 0x401000])
    assert dll_emu.emu is not None
    rv, _ = call(dll_emu, "msvcrt", "_seh_filter_exe", [code, 0])
    assert rv is None
    assert [cb.function for cb in dll_emu.emu.get_current_run().guest_callbacks] == [0x401000]
    assert tuple(dll_emu.emu.get_func_argv(e_arch.CALL_CONV_CDECL, len(args))) == args
    assert call(dll_emu, "msvcrt", "signal", [sig, SIG_DFL])[0] == SIG_DFL


@pytest.mark.parametrize("c", [0xFFFFFFE2, 0xE2])
def test_fputc_writes_the_low_byte_of_a_sign_extended_char(dll_emu: Speakeasy, c: int) -> None:
    rv, displays = call(dll_emu, "msvcrt", "fputc", [c, 0])
    assert rv == 0xE2
    assert displays[0] == "\\xe2"


def test_fwrite_writes_to_a_file_stream(dll_emu: Speakeasy) -> None:
    path = alloc(dll_emu, b"c:\\users\\public\\out.bin\x00")
    stream, _ = call(dll_emu, "msvcrt", "fopen", [path, alloc(dll_emu, b"wb\x00")])
    assert stream

    assert call(dll_emu, "msvcrt", "fwrite", [alloc(dll_emu, b"abcdef"), 2, 3, stream])[0] == 3
    out = alloc(dll_emu, b"\x00" * 16)
    assert call(dll_emu, "msvcrt", "fread", [out, 1, 16, stream])[0] == 6
    assert dll_emu.mem_read(out, 6) == b"abcdef"


@pytest.mark.parametrize("path", [b"CONOUT$\x00", b"conin$\x00"])
def test_freopen_s_to_the_console_keeps_the_stream(dll64_emu: Speakeasy, path: bytes) -> None:
    pfile = alloc(dll64_emu, b"\xcc" * 8)
    rv, _ = call(dll64_emu, "msvcrt", "freopen_s", [pfile, alloc(dll64_emu, path), alloc(dll64_emu, b"w\x00"), 1])
    assert (rv, struct.unpack("<Q", dll64_emu.mem_read(pfile, 8))[0]) == (0, 1)


def test_freopen_s_to_a_file_redirects_the_stream(dll_emu: Speakeasy) -> None:
    pfile = alloc(dll_emu, b"\xcc" * 4)
    path = alloc(dll_emu, b"c:\\users\\public\\log.txt\x00")
    rv, _ = call(dll_emu, "msvcrt", "freopen_s", [pfile, path, alloc(dll_emu, b"w+\x00"), 1])
    assert (rv, struct.unpack("<I", dll_emu.mem_read(pfile, 4))[0]) == (0, 1)

    assert call(dll_emu, "msvcrt", "fwrite", [alloc(dll_emu, b"abc"), 1, 3, 1])[0] == 3
    out = alloc(dll_emu, b"\x00" * 16)
    assert call(dll_emu, "msvcrt", "fread", [out, 1, 16, 1])[0] == 3
    assert dll_emu.mem_read(out, 3) == b"abc"


def test_freopen_returns_the_stream(dll_emu: Speakeasy) -> None:
    rv, _ = call(dll_emu, "msvcrt", "freopen", [alloc(dll_emu, b"CONOUT$\x00"), alloc(dll_emu, b"w\x00"), 2])
    assert rv == 2


@pytest.mark.parametrize(
    "dll, name",
    [
        ("msvcrt", "__CxxFrameHandler2"),
        ("msvcrt", "__CxxFrameHandler3"),
        ("vcruntime140_1", "__CxxFrameHandler4"),
    ],
)
def test_cxx_frame_handlers_continue_the_search(dll64_emu: Speakeasy, dll: str, name: str) -> None:
    rec = alloc(dll64_emu, struct.pack("<IIQQI", 0xC0000005, 0, 0, 0, 0))
    assert call(dll64_emu, dll, name, [rec, 0, 0, 0])[0] == 1


@pytest.mark.parametrize("emu_name", ["dll_emu", "dll64_emu"])
def test_localeconv_has_a_dot_decimal_point(request: pytest.FixtureRequest, emu_name: str) -> None:
    se: Speakeasy = request.getfixturevalue(emu_name)
    assert se.emu is not None
    ptr_size = se.emu.get_ptr_size()
    lconv, _ = call(se, "msvcrt", "localeconv", [])
    decimal_point = int.from_bytes(se.mem_read(lconv, ptr_size), "little")
    assert se.mem_read(decimal_point, 2) == b".\x00"


def test_setlocale_reports_the_c_locale(dll_emu: Speakeasy) -> None:
    rv, displays = call(dll_emu, "msvcrt", "setlocale", [0, alloc(dll_emu, b"\x00")])
    assert dll_emu.mem_read(rv, 2) == b"C\x00"
    assert displays[1] == ""
    assert call(dll_emu, "msvcrt", "setlocale", [0, 0])[0] == rv


def test_fgets_reads_one_line_at_a_time(dll_emu: Speakeasy) -> None:
    path = alloc(dll_emu, b"c:\\users\\public\\lines.txt\x00")
    stream, _ = call(dll_emu, "msvcrt", "fopen", [path, alloc(dll_emu, b"w+\x00")])
    call(dll_emu, "msvcrt", "fwrite", [alloc(dll_emu, b"PING\nSTATUS"), 1, 11, stream])
    buf = alloc(dll_emu, b"\xcc" * 16)

    assert call(dll_emu, "msvcrt", "fgets", [buf, 16, stream])[0] == buf
    assert dll_emu.mem_read(buf, 6) == b"PING\n\x00"
    assert call(dll_emu, "msvcrt", "fgets", [buf, 4, stream])[0] == buf
    assert dll_emu.mem_read(buf, 4) == b"STA\x00"
    assert call(dll_emu, "msvcrt", "fgets", [buf, 16, stream])[0] == buf
    assert dll_emu.mem_read(buf, 4) == b"TUS\x00"
    assert call(dll_emu, "msvcrt", "fgets", [buf, 16, stream])[0] == 0


def test_strdup_copies_the_bytes_to_a_new_buffer(dll_emu: Speakeasy) -> None:
    src = alloc(dll_emu, b"a\xe9b\x00\xcc")
    dst, _ = call(dll_emu, "msvcrt", "_strdup", [src])
    assert dst not in (0, src)
    assert dll_emu.mem_read(dst, 4) == b"a\xe9b\x00"
    assert call(dll_emu, "msvcrt", "_strdup", [0])[0] == 0


def test_realloc_keeps_the_contents(dll_emu: Speakeasy) -> None:
    first, _ = call(dll_emu, "msvcrt", "realloc", [0, 4])
    dll_emu.mem_write(first, b"abcd")
    grown, _ = call(dll_emu, "msvcrt", "realloc", [first, 0x2000])
    assert dll_emu.mem_read(grown, 4) == b"abcd"
    dll_emu.mem_write(grown + 0x1FFC, b"wxyz")
    shrunk, _ = call(dll_emu, "msvcrt", "realloc", [grown, 2])
    assert dll_emu.mem_read(shrunk, 2) == b"ab"
    assert call(dll_emu, "msvcrt", "realloc", [shrunk, 0])[0] == 0


def test_realloc_uses_the_size_of_the_current_block_at_a_reused_address(dll_emu: Speakeasy) -> None:
    large, _ = call(dll_emu, "msvcrt", "malloc", [0x2000])
    call(dll_emu, "msvcrt", "free", [large])
    small, _ = call(dll_emu, "msvcrt", "malloc", [0x1000])
    assert small == large
    dll_emu.mem_write(small, b"\x5a" * 0x1000)
    grown, _ = call(dll_emu, "msvcrt", "realloc", [small, 0x3000])
    assert dll_emu.mem_read(grown, 0x1000) == b"\x5a" * 0x1000


@pytest.mark.parametrize(
    "api, argv", [("malloc", [0x82844002]), ("calloc", [0x10000, 0x10001]), ("calloc", [0x2, 0x50000000])]
)
def test_an_allocation_larger_than_the_x86_address_space_returns_null(
    dll_emu: Speakeasy, api: str, argv: list[int]
) -> None:
    assert call(dll_emu, "msvcrt", api, argv)[0] == 0


def test_recalloc_keeps_the_contents_and_zeroes_the_new_bytes(dll_emu: Speakeasy) -> None:
    block, _ = call(dll_emu, "msvcrt", "malloc", [4])
    dll_emu.mem_write(block, struct.pack("<I", 0x11223344))
    grown, _ = call(dll_emu, "msvcrt", "_recalloc", [block, 2, 4])
    assert dll_emu.mem_read(grown, 8) == struct.pack("<II", 0x11223344, 0)


def test_recalloc_of_null_allocates_zeroed_memory(dll_emu: Speakeasy) -> None:
    block, _ = call(dll_emu, "msvcrt", "_recalloc", [0, 3, 2])
    assert block
    assert dll_emu.mem_read(block, 6) == b"\x00" * 6
    assert call(dll_emu, "msvcrt", "_recalloc", [block, 0x10000, 0x10001])[0] == 0


def test_crt_internal_allocators_allocate_like_the_public_ones(dll_emu: Speakeasy) -> None:
    block, _ = call(dll_emu, "msvcrt", "_calloc_crt", [4, 4])
    assert dll_emu.mem_read(block, 16) == b"\x00" * 16
    dll_emu.mem_write(block, b"abcd")
    grown, _ = call(dll_emu, "msvcrt", "_realloc_crt", [block, 0x20])
    assert dll_emu.mem_read(grown, 4) == b"abcd"
    assert call(dll_emu, "msvcrt", "_malloc_crt", [0x80])[0]


def test_crt_pointer_encoding_round_trips(dll_emu: Speakeasy) -> None:
    encoded, _ = call(dll_emu, "msvcrt", "_encode_pointer", [0x1234])
    assert call(dll_emu, "msvcrt", "_decode_pointer", [encoded])[0] == 0x1234
    null, _ = call(dll_emu, "msvcrt", "_encoded_null", [])
    assert null == call(dll_emu, "kernel32", "EncodePointer", [0])[0]
    assert call(dll_emu, "msvcrt", "_decode_pointer", [null])[0] == 0


def test_realloc_that_cannot_grow_returns_null_and_keeps_the_block(dll_emu: Speakeasy) -> None:
    block, _ = call(dll_emu, "msvcrt", "malloc", [4])
    dll_emu.mem_write(block, b"abcd")
    assert call(dll_emu, "msvcrt", "realloc", [block, 0x82844002])[0] == 0
    assert dll_emu.mem_read(block, 4) == b"abcd"


def test_getenv_ignores_case_and_returns_null_when_missing(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    name, value = next(iter(dll_emu.emu.get_env().items()))
    rv, _ = call(dll_emu, "msvcrt", "getenv", [alloc(dll_emu, name.upper().encode() + b"\x00")])
    assert dll_emu.mem_read(rv, len(value) + 1) == value.encode() + b"\x00"
    assert call(dll_emu, "msvcrt", "getenv", [alloc(dll_emu, b"NO_SUCH_VARIABLE\x00")])[0] == 0


@pytest.mark.parametrize(
    "c, count, offset", [(ord("c"), 8, 3), (0x163, 8, 3), (0, 8, 2), (ord("c"), 3, None), (ord("q"), 8, None)]
)
def test_memchr_searches_count_bytes(dll_emu: Speakeasy, c: int, count: int, offset: int | None) -> None:
    buf = alloc(dll_emu, b"ab\x00cdefg")
    rv, _ = call(dll_emu, "msvcrt", "memchr", [buf, c, count])
    assert rv == (0 if offset is None else buf + offset)


@pytest.mark.parametrize(
    "text, base, value, used",
    [
        (b"  -0x1Fz", 0, -31, 7),
        (b"077", 0, 63, 3),
        (b"077", 10, 77, 3),
        (b"0x", 16, 0, 1),
        (b"zz", 36, 1295, 2),
        (b"+12 ", 10, 12, 3),
        (b"abc", 10, 0, 0),
        (b"-", 10, 0, 0),
        (b"99999999999", 10, 0x7FFFFFFF, 11),
        (b"-99999999999", 10, -0x80000000, 12),
    ],
)
def test_strtol_parses_like_the_crt(dll_emu: Speakeasy, text: bytes, base: int, value: int, used: int) -> None:
    src = alloc(dll_emu, text + b"\x00")
    end = alloc(dll_emu, b"\xcc" * 4)
    assert call(dll_emu, "msvcrt", "strtol", [src, end, base])[0] == value
    assert dll_emu.mem_read(end, 4) == (src + used).to_bytes(4, "little")


@pytest.mark.parametrize(
    "text, base, value",
    [(b"ff", 16, 255), (b"-1", 10, 0xFFFFFFFF), (b"4294967295", 10, 0xFFFFFFFF), (b"4294967296", 10, 0xFFFFFFFF)],
)
def test_strtoul_wraps_negative_values_and_saturates(dll_emu: Speakeasy, text: bytes, base: int, value: int) -> None:
    assert call(dll_emu, "msvcrt", "strtoul", [alloc(dll_emu, text + b"\x00"), 0, base])[0] == value


def test_strtol_writes_a_pointer_sized_endptr_on_x64(dll64_emu: Speakeasy) -> None:
    src = alloc(dll64_emu, b"12x\x00")
    end = alloc(dll64_emu, b"\xcc" * 9)
    call(dll64_emu, "msvcrt", "strtol", [src, end, 10])
    assert dll64_emu.mem_read(end, 9) == (src + 2).to_bytes(8, "little") + b"\xcc"


def i32(v: int) -> bytes:
    return (v & 0xFFFFFFFF).to_bytes(4, "little")


@pytest.mark.parametrize(
    "text, fmt, values, rv",
    [
        (b"12 abc 0x1f", b"%d %s %x", [i32(12), b"abc\x00", i32(0x1F)], 3),
        (b"http://example.com/a", b"%15[^\n/:]:%3[/]%[^\n]", [b"http\x00", b"//\x00", b"example.com/a\x00"], 3),
        (b"12345", b"%2d%3d", [i32(12), i32(345)], 2),
        (b" x", b"%c", [b" "], 1),
        (b"abc123", b"%[a-z]%d", [b"abc\x00", i32(123)], 2),
        (b"010 0x10 -3", b"%i %i %u", [i32(8), i32(16), i32(-3)], 3),
        (b"-1 7", b"%hhd %lld", [b"\xff", (7).to_bytes(8, "little")], 2),
        (b"1.5 2.25", b"%f %lf", [struct.pack("<f", 1.5), struct.pack("<d", 2.25)], 2),
        (b"key=val", b"%*[^=]=%n%s", [i32(4), b"val\x00"], 1),
        (b"50%", b"%d%%", [i32(50)], 1),
        (b"abc", b"%d", [], 0),
        (b"7 abc", b"%d %d", [i32(7)], 1),
        (b"", b"%d", [], -1),
        (b"   ", b" %s", [], -1),
    ],
)
def test_scan_c_format_matches_the_crt(text: bytes, fmt: bytes, values: list[bytes], rv: int) -> None:
    assert scan_c_format(text, fmt, 4) == (values, rv)


def test_scan_c_format_stores_pointers_at_pointer_size() -> None:
    assert scan_c_format(b"1234abcd", b"%p", 8) == ([(0x1234ABCD).to_bytes(8, "little")], 1)


def test_sscanf_writes_through_the_variadic_pointers(dll_emu: Speakeasy) -> None:
    method, path, major, minor = (alloc(dll_emu, b"\xcc" * 16) for _ in range(4))
    text = alloc(dll_emu, b"GET /index.html HTTP/1.1\x00")
    fmt = alloc(dll_emu, b"%7s %15s HTTP/%d.%d\x00")
    assert call(dll_emu, "msvcrt", "sscanf", [text, fmt, method, path, major, minor])[0] == 4
    assert dll_emu.mem_read(method, 4) == b"GET\x00"
    assert dll_emu.mem_read(path, 12) == b"/index.html\x00"
    assert dll_emu.mem_read(major, 5) + dll_emu.mem_read(minor, 5) == i32(1) + b"\xcc" + i32(1) + b"\xcc"


@pytest.mark.parametrize(
    "emu_name, api, size_fmt, time_fmt, length",
    [
        ("dll_emu", "_stat", "<20xi", "<24x3i", 36),
        ("dll_emu", "_stati64", "<24xq", "<32x3i", 48),
        ("dll_emu", "_stat64", "<24xq", "<32x3q", 56),
        ("dll64_emu", "_stat", "<20xi", "<24x3q", 48),
        ("dll64_emu", "_stati64", "<24xq", "<32x3q", 56),
    ],
)
def test_stat_fills_the_struct_for_an_emulated_file(
    request: pytest.FixtureRequest, emu_name: str, api: str, size_fmt: str, time_fmt: str, length: int
) -> None:
    se: Speakeasy = request.getfixturevalue(emu_name)
    buf = alloc(se, b"\xcc" * 64)
    path = alloc(se, b"c:\\programdata\\mydir\\myfile.bin\x00")

    assert call(se, "msvcrt", api, [path, buf])[0] == 0

    data = se.mem_read(buf, 64)
    assert struct.unpack_from("<HhI", data, 6)[0:2] == (0x81B6, 1)
    assert struct.unpack_from(size_fmt, data)[0] == 512
    times = struct.unpack_from(time_fmt, data)
    assert times[0] == times[1] == times[2] > 0
    assert data[length:] == b"\xcc" * (64 - length)


def test_wstati64_reads_a_wide_path(dll_emu: Speakeasy) -> None:
    buf = alloc(dll_emu, b"\x00" * 48)
    path = alloc(dll_emu, "c:\\programdata\\mydir\\myfile.bin\x00".encode("utf-16le"))

    assert call(dll_emu, "msvcrt", "_wstati64", [path, buf])[0] == 0
    assert struct.unpack_from("<q", dll_emu.mem_read(buf, 48), 24)[0] == 512


def test_stat_sets_enoent_for_a_missing_file(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> None:
    files = config["filesystem"]["files"]
    files[:] = [f for f in files if f["mode"] != "default"]
    for se in load_emu(config, load_test_bin("dll_test_x86.dll.xz")):
        buf = alloc(se, b"\x00" * 48)
        path = alloc(se, b"c:\\missing\\file.dat\x00")

        assert call(se, "msvcrt", "_stati64", [path, buf])[0] == -1
        errno_ptr, _ = call(se, "msvcrt", "_errno", [])
        assert int.from_bytes(se.mem_read(errno_ptr, 4), "little") == ENOENT


@pytest.mark.parametrize("api, enc", [("_unlink", "latin-1"), ("_wunlink", "utf-16le"), ("remove", "latin-1")])
def test_unlink_deletes_a_written_file(dll_emu: Speakeasy, api: str, enc: str) -> None:
    assert dll_emu.emu is not None
    name = "c:\\users\\public\\drop.bin"
    stream, _ = call(dll_emu, "msvcrt", "fopen", [alloc(dll_emu, name.encode() + b"\x00"), alloc(dll_emu, b"wb\x00")])
    call(dll_emu, "msvcrt", "fwrite", [alloc(dll_emu, b"MZ"), 1, 2, stream])
    call(dll_emu, "msvcrt", "fclose", [stream])
    assert [f.path for f in dll_emu.get_dropped_files()] == [name]

    path = alloc(dll_emu, (name + "\x00").encode(enc))
    assert call(dll_emu, "msvcrt", api, [path])[0] == 0
    assert dll_emu.get_dropped_files() == []


def test_unlink_sets_enoent_for_a_missing_file(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> None:
    files = config["filesystem"]["files"]
    files[:] = [f for f in files if f["mode"] != "default"]
    for se in load_emu(config, load_test_bin("dll_test_x86.dll.xz")):
        assert call(se, "msvcrt", "_unlink", [alloc(se, b"c:\\missing\\file.dat\x00")])[0] == -1
        errno_ptr, _ = call(se, "msvcrt", "_errno", [])
        assert int.from_bytes(se.mem_read(errno_ptr, 4), "little") == ENOENT


@pytest.mark.parametrize("size", [0x10, 0x6000])
def test_operator_new_returns_writable_memory(dll_emu: Speakeasy, size: int) -> None:
    ptr, _ = call(dll_emu, "msvcrt", "??2@YAPAXI@Z", [size])
    perms = [p for begin, end, p in dll_emu.emu.emu_eng.mem_regions() if begin <= ptr and ptr + size - 1 <= end]
    assert perms == [unicorn.UC_PROT_ALL]


@pytest.mark.parametrize(
    "cmdline, tail",
    [
        ('"C:\\Program Files\\a.exe" -x  y', "-x  y"),
        ("a.exe\t -x", "-x"),
        ("a.exe", ""),
        ('"a b.exe', ""),
        ("", ""),
    ],
)
def test_winmain_command_line_skips_the_program_name(cmdline: str, tail: str) -> None:
    assert get_winmain_command_line(cmdline) == tail


@pytest.mark.parametrize("api, width", [("_get_narrow_winmain_command_line", 1), ("_get_wide_winmain_command_line", 2)])
def test_get_winmain_command_line_points_after_the_program_name(dll_emu: Speakeasy, api: str, width: int) -> None:
    assert dll_emu.emu is not None
    start_process(dll_emu)
    dll_emu.emu.get_current_process().cmdline = '"C:\\x y\\a.exe" -v one'
    rv, _ = call(dll_emu, "msvcrt", api, [])
    assert call(dll_emu, "msvcrt", api, [])[0] == rv
    encoded = "-v one".encode("utf-16le" if width == 2 else "utf-8")
    assert dll_emu.mem_read(rv, len(encoded) + width) == encoded + b"\x00" * width


def test_rand_s_writes_a_value(dll_emu: Speakeasy) -> None:
    out = alloc(dll_emu, b"\xcc" * 8)
    assert call(dll_emu, "msvcrt", "rand_s", [out])[0] == 0
    first = dll_emu.mem_read(out, 4)
    assert call(dll_emu, "msvcrt", "rand_s", [out])[0] == 0
    assert dll_emu.mem_read(out, 4) != first
    assert dll_emu.mem_read(out + 4, 4) == b"\xcc" * 4
    assert call(dll_emu, "msvcrt", "rand_s", [0])[0] == EINVAL


@pytest.mark.parametrize("mode, rv", [(0, 0), (0x40, 0), (4, 0), (3, -1)])
def test_setvbuf_accepts_only_known_modes(dll_emu: Speakeasy, mode: int, rv: int) -> None:
    assert call(dll_emu, "msvcrt", "setvbuf", [0x1000, 0, mode, 0x200])[0] == rv


def test_setbuf_accepts_a_stream_and_buffer(dll_emu: Speakeasy) -> None:
    assert call(dll_emu, "msvcrt", "setbuf", [0x1000, 0])[0] is None


def test_getpid_matches_the_current_process(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    assert dll_emu.emu is not None
    assert call(dll_emu, "msvcrt", "_getpid", [])[0] == dll_emu.emu.get_current_process().id


def test_mbsdup_copies_the_string(dll_emu: Speakeasy) -> None:
    src = alloc(dll_emu, b"\x82\xa0abc\x00")
    rv, _ = call(dll_emu, "msvcrt", "_mbsdup", [src])
    assert rv not in (0, src)
    assert dll_emu.mem_read(rv, 6) == b"\x82\xa0abc\x00"
    assert call(dll_emu, "msvcrt", "_mbsdup", [0])[0] == 0


def test_mbscpy_and_mbscat_copy_through_the_nul(dll_emu: Speakeasy) -> None:
    src = alloc(dll_emu, b"abc\x00")
    dest = alloc(dll_emu, b"\xcc" * 8)
    assert call(dll_emu, "msvcrt", "_mbscpy", [dest, src])[0] == dest
    assert dll_emu.mem_read(dest, 5) == b"abc\x00\xcc"
    assert call(dll_emu, "msvcrt", "_mbscat", [dest, src])[0] == dest
    assert dll_emu.mem_read(dest, 8) == b"abcabc\x00\xcc"
    assert call(dll_emu, "msvcrt", "_mbslen", [dest])[0] == 6


@pytest.mark.parametrize("api", ["_mbsncpy", "_mbsnbcpy"])
@pytest.mark.parametrize("count, out", [(2, b"ab\xcc\xcc\xcc\xcc"), (5, b"abc\x00\x00\xcc")])
def test_mbsncpy_copies_count_bytes_and_pads(dll_emu: Speakeasy, api: str, count: int, out: bytes) -> None:
    src = alloc(dll_emu, b"abc\x00")
    dest = alloc(dll_emu, b"\xcc" * 6)
    assert call(dll_emu, "msvcrt", api, [dest, src, count])[0] == dest
    assert dll_emu.mem_read(dest, 6) == out


@pytest.mark.parametrize("c, offset", [("\\", 7), ("a", 0), ("Q", None), ("\0", 9)])
def test_wcsrchr_returns_the_last_match(dll_emu: Speakeasy, c: str, offset: int | None) -> None:
    s = alloc(dll_emu, "a\\b\\c\\d\\e\0".encode("utf-16le"))
    rv, _ = call(dll_emu, "msvcrt", "wcsrchr", [s, ord(c)])
    assert rv == (0 if offset is None else s + offset * 2)


@pytest.mark.parametrize(
    "size, rv, out",
    [
        (8, 0, b"hello\x00\xcc\xcc"),
        (6, 0, b"hello\x00\xcc\xcc"),
        (5, ERANGE, b"\x00ello\xcc\xcc\xcc"),
        (0, EINVAL, b"\xcc" * 8),
    ],
)
def test_strcpy_s_copies_only_when_the_string_fits(dll_emu: Speakeasy, size: int, rv: int, out: bytes) -> None:
    dest = alloc(dll_emu, b"\xcc" * 8)
    src = alloc(dll_emu, b"hello\x00")
    if size == 5:
        dll_emu.mem_write(dest, b"xello")
    assert call(dll_emu, "msvcrt", "strcpy_s", [dest, size, src])[0] == rv
    assert dll_emu.mem_read(dest, 8) == out


def test_strcpy_s_without_a_source_clears_the_destination(dll_emu: Speakeasy) -> None:
    dest = alloc(dll_emu, b"abc\x00")
    assert call(dll_emu, "msvcrt", "strcpy_s", [dest, 4, 0])[0] == EINVAL
    assert dll_emu.mem_read(dest, 2) == b"\x00b"


@pytest.mark.parametrize("c", [" ", "\t", "\n", "\v", "\f", "\r"])
def test_isspace_accepts_white_space(dll_emu: Speakeasy, c: str) -> None:
    assert call(dll_emu, "msvcrt", "isspace", [ord(c)])[0] != 0


@pytest.mark.parametrize("c", [0, ord("a"), ord("_"), 0xA0, 0xFFFFFFFF])
def test_isspace_rejects_other_characters(dll_emu: Speakeasy, c: int) -> None:
    assert call(dll_emu, "msvcrt", "isspace", [c])[0] == 0


@pytest.mark.parametrize("fd", [0, 1, 2, 7])
def test_isatty_reports_no_console(dll_emu: Speakeasy, fd: int) -> None:
    assert call(dll_emu, "msvcrt", "_isatty", [fd])[0] == 0


def test_crtdll_get_main_args_fills_the_arguments(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    out = alloc(dll_emu, b"\xcc" * 12)
    call(dll_emu, "crtdll", "__GetMainArgs", [out, out + 4, out + 8, 0])
    argc, argv, envp = struct.unpack("<III", dll_emu.mem_read(out, 12))
    assert argc == len(dll_emu.emu.get_argv())
    assert dll_emu.mem_read(argv + 4 * argc, 4) == b"\x00" * 4
    assert envp != 0xCCCCCCCC


def test_crtdll_uses_the_msvcrt_handlers(dll_emu: Speakeasy) -> None:
    buf = alloc(dll_emu, b"\xcc" * 4)
    assert call(dll_emu, "crtdll", "memset", [buf, 0x41, 3])[0] == buf
    assert dll_emu.mem_read(buf, 4) == b"AAA\xcc"


@pytest.mark.parametrize("dll", ["api-ms-win-crt-private-l1-1-0", "ucrtbase", "msvcrt"])
def test_private_crt_exports_use_the_public_handlers(dll_emu: Speakeasy, dll: str) -> None:
    buf = alloc(dll_emu, b"\xcc" * 4)
    assert call(dll_emu, dll, "_o_memset", [buf, 0x41, 3])[0] == buf
    assert dll_emu.mem_read(buf, 4) == b"AAA\xcc"
    assert call(dll_emu, dll, "_o__initialize_onexit_table", [buf])[0] == 0


def test_sleep_returns(dll_emu: Speakeasy) -> None:
    assert call(dll_emu, "crtdll", "_sleep", [1000])[0] is None


@pytest.mark.parametrize("api", ["localtime", "gmtime"])
def test_time_conversion_fills_struct_tm(dll_emu: Speakeasy, api: str) -> None:
    t = alloc(dll_emu, (951782400 + 3 * 3600 + 4 * 60 + 5).to_bytes(4, "little"))
    rv, _ = call(dll_emu, "msvcrt", api, [t])
    # 2000-02-29 03:04:05 UTC, a Tuesday, day 59 of the year
    assert struct.unpack("<9i", dll_emu.mem_read(rv, 36)) == (5, 4, 3, 29, 1, 100, 2, 59, 0)
    assert call(dll_emu, "msvcrt", api, [0])[0] == 0


@pytest.mark.parametrize("api", ["localtime", "gmtime"])
@pytest.mark.parametrize("value", [1 << 62, (1 << 63) - 1])
def test_time_conversion_of_an_out_of_range_time_returns_null(dll64_emu: Speakeasy, api: str, value: int) -> None:
    t = alloc(dll64_emu, value.to_bytes(8, "little"))
    assert call(dll64_emu, "msvcrt", api, [t])[0] == 0


def test_mktime_normalizes_the_fields(dll_emu: Speakeasy) -> None:
    tm = alloc(dll_emu, struct.pack("<9i", 65, 3, 3, 29, 13, 99, 0, 0, -1))
    assert call(dll_emu, "msvcrt", "mktime", [tm])[0] == 951782400 + 3 * 3600 + 4 * 60 + 5
    assert struct.unpack("<9i", dll_emu.mem_read(tm, 36)) == (5, 4, 3, 29, 1, 100, 2, 59, 0)


def test_mktime_rejects_a_time_before_the_epoch(dll_emu: Speakeasy) -> None:
    tm = alloc(dll_emu, struct.pack("<9i", 0, 0, 0, 1, 0, 60, 0, 0, 0))
    assert call(dll_emu, "msvcrt", "mktime", [tm])[0] == -1


# 2023-11-14 22:13:20 UTC, a Tuesday, day 317 of the year
TM_1700000000 = (20, 13, 22, 14, 10, 123, 2, 317, 0)
# 2242-03-16 12:56:32 UTC, past the range of a 32-bit time_t
TM_2_POW_33 = (32, 56, 12, 16, 2, 342, 3, 74, 0)


def get_int64_return(se: Speakeasy, low: int) -> int:
    assert se.emu is not None
    if se.emu.get_arch() == e_arch.ARCH_X86:
        return se.emu.reg_read(e_arch.X86_REG_EDX) << 32 | low
    return low


@pytest.mark.parametrize("api", ["_localtime64", "_gmtime64"])
@pytest.mark.parametrize("emu_name", ["dll_emu", "dll64_emu"])
def test_time64_conversion_reads_an_8_byte_time_t(request: pytest.FixtureRequest, emu_name: str, api: str) -> None:
    se: Speakeasy = request.getfixturevalue(emu_name)
    rv, _ = call(se, "ucrtbase", api, [alloc(se, (1700000000).to_bytes(8, "little"))])
    assert struct.unpack("<9i", se.mem_read(rv, 36)) == TM_1700000000
    rv, _ = call(se, "ucrtbase", api, [alloc(se, (1 << 33).to_bytes(8, "little"))])
    assert struct.unpack("<9i", se.mem_read(rv, 36)) == TM_2_POW_33
    assert call(se, "ucrtbase", api, [0])[0] == 0


@pytest.mark.parametrize("api", ["_localtime64_s", "_gmtime64_s"])
@pytest.mark.parametrize("emu_name", ["dll_emu", "dll64_emu"])
def test_time64_s_conversion_fills_the_callers_struct_tm(
    request: pytest.FixtureRequest, emu_name: str, api: str
) -> None:
    se: Speakeasy = request.getfixturevalue(emu_name)
    tm = alloc(se, b"\xcc" * 36)
    assert call(se, "ucrtbase", api, [tm, alloc(se, (1700000000).to_bytes(8, "little"))])[0] == 0
    assert struct.unpack("<9i", se.mem_read(tm, 36)) == TM_1700000000
    assert call(se, "ucrtbase", api, [tm, 0])[0] == EINVAL
    assert struct.unpack("<9i", se.mem_read(tm, 36)) == (-1,) * 9
    assert call(se, "ucrtbase", api, [0, alloc(se, (1700000000).to_bytes(8, "little"))])[0] == EINVAL


@pytest.mark.parametrize("emu_name", ["dll_emu", "dll64_emu"])
def test_time64_writes_an_8_byte_time_t(request: pytest.FixtureRequest, emu_name: str) -> None:
    se: Speakeasy = request.getfixturevalue(emu_name)
    out = alloc(se, b"\xcc" * 9)
    rv = get_int64_return(se, call(se, "ucrtbase", "_time64", [out])[0])
    assert rv == TIME_BASE
    assert se.mem_read(out, 9) == TIME_BASE.to_bytes(8, "little") + b"\xcc"


@pytest.mark.parametrize("emu_name", ["dll_emu", "dll64_emu"])
def test_mktime64_returns_an_8_byte_time_t(request: pytest.FixtureRequest, emu_name: str) -> None:
    se: Speakeasy = request.getfixturevalue(emu_name)
    tm = alloc(se, struct.pack("<9i", *TM_2_POW_33[:6], 0, 0, -1))
    assert get_int64_return(se, call(se, "ucrtbase", "_mktime64", [tm])[0]) == 1 << 33
    assert struct.unpack("<9i", se.mem_read(tm, 36)) == TM_2_POW_33


def test_time32_functions_use_a_4_byte_time_t_on_x64(dll64_emu: Speakeasy) -> None:
    out = alloc(dll64_emu, b"\xcc" * 5)
    assert call(dll64_emu, "ucrtbase", "_time32", [out])[0] == TIME_BASE
    assert dll64_emu.mem_read(out, 5) == TIME_BASE.to_bytes(4, "little") + b"\xcc"
    t = alloc(dll64_emu, (1700000000).to_bytes(4, "little") + b"\xff" * 4)
    for api in ("_localtime32", "_gmtime32"):
        rv, _ = call(dll64_emu, "ucrtbase", api, [t])
        assert struct.unpack("<9i", dll64_emu.mem_read(rv, 36)) == TM_1700000000
    tm = alloc(dll64_emu, struct.pack("<9i", *TM_2_POW_33[:6], 0, 0, -1))
    assert call(dll64_emu, "ucrtbase", "_mktime32", [tm])[0] == -1


def test_fputs_reports_the_string(dll_emu: Speakeasy) -> None:
    rv, displays = call(dll_emu, "msvcrt", "fputs", [alloc(dll_emu, b"hi there\x00"), 0x1000])
    assert rv == 0
    assert displays[0] == "hi there"


@pytest.mark.parametrize(
    "cwd, path, full",
    [
        ("C:\\work", "a\\..\\b.txt", "C:\\work\\b.txt"),
        ("C:\\work", "\\x\\y", "C:\\x\\y"),
        ("C:\\work", "D:\\p\\.\\q", "D:\\p\\q"),
        ("C:\\", "f", "C:\\f"),
    ],
)
def test_full_path_resolves_relative_paths(cwd: str, path: str, full: str) -> None:
    assert get_full_path(cwd, path) == full


def test_fullpath_writes_into_the_buffer(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    full = get_full_path(dll_emu.emu.get_cd(), "a.txt").encode() + b"\x00"
    buf = alloc(dll_emu, b"\xcc" * 0x100)
    assert call(dll_emu, "msvcrt", "_fullpath", [buf, alloc(dll_emu, b"a.txt\x00"), 0x100])[0] == buf
    assert dll_emu.mem_read(buf, len(full)) == full
    assert call(dll_emu, "msvcrt", "_fullpath", [buf, alloc(dll_emu, b"a.txt\x00"), 3])[0] == 0
    rv, _ = call(dll_emu, "msvcrt", "_fullpath", [0, alloc(dll_emu, b"a.txt\x00"), 0])
    assert rv not in (0, buf)
    assert dll_emu.mem_read(rv, len(full)) == full


@pytest.mark.parametrize("api", ["fgetc", "getc"])
def test_fgetc_reads_one_byte_and_then_eof(dll_emu: Speakeasy, api: str) -> None:
    path = alloc(dll_emu, b"c:\\users\\public\\chars.txt\x00")
    stream, _ = call(dll_emu, "msvcrt", "fopen", [path, alloc(dll_emu, b"w+\x00")])
    call(dll_emu, "msvcrt", "fwrite", [alloc(dll_emu, b"\xffA"), 1, 2, stream])

    assert call(dll_emu, "msvcrt", api, [stream])[0] == 0xFF
    assert call(dll_emu, "msvcrt", api, [stream])[0] == ord("A")
    assert call(dll_emu, "msvcrt", api, [stream])[0] & 0xFFFFFFFF == 0xFFFFFFFF


@pytest.mark.parametrize("emu_name", ["dll_emu", "dll64_emu"])
@pytest.mark.parametrize("api, width", [("_dupenv_s", 1), ("_wdupenv_s", 2)])
def test_dupenv_s_copies_the_value(request: pytest.FixtureRequest, emu_name: str, api: str, width: int) -> None:
    se: Speakeasy = request.getfixturevalue(emu_name)
    assert se.emu is not None
    ptr_size = se.emu.get_ptr_size()
    encoding = "utf-16le" if width == 2 else "latin-1"
    name, value = next(iter(se.emu.get_env().items()))
    out = alloc(se, b"\xcc" * ptr_size)
    count = alloc(se, b"\xcc" * ptr_size)

    assert call(se, "msvcrt", api, [out, count, alloc(se, (name.upper() + "\0").encode(encoding))])[0] == 0
    copy = int.from_bytes(se.mem_read(out, ptr_size), "little")
    assert se.mem_read(copy, (len(value) + 1) * width) == (value + "\0").encode(encoding)
    assert int.from_bytes(se.mem_read(count, ptr_size), "little") == len(value) + 1

    assert call(se, "msvcrt", api, [out, count, alloc(se, "NO_SUCH_VARIABLE\0".encode(encoding))])[0] == 0
    assert se.mem_read(out, ptr_size) == b"\0" * ptr_size
    assert se.mem_read(count, ptr_size) == b"\0" * ptr_size
    assert call(se, "msvcrt", api, [0, count, alloc(se, (name + "\0").encode(encoding))])[0] == EINVAL


@pytest.mark.parametrize(
    "size, rv, out",
    [
        (6, 0, "hello\x00".encode("utf-16le") + b"\xcc" * 4),
        (5, ERANGE, b"\x00\x00" + "ello".encode("utf-16le") + b"\xcc" * 6),
        (0, EINVAL, b"\xcc" * 16),
    ],
)
def test_wcscpy_s_copies_only_when_the_string_fits(dll_emu: Speakeasy, size: int, rv: int, out: bytes) -> None:
    dest = alloc(dll_emu, b"\xcc" * 16)
    src = alloc(dll_emu, "hello\x00".encode("utf-16le"))
    if size == 5:
        dll_emu.mem_write(dest, "xello".encode("utf-16le"))
    assert call(dll_emu, "msvcrt", "wcscpy_s", [dest, size, src])[0] == rv
    assert dll_emu.mem_read(dest, 16) == out


def test_fwprintf_formats_wide_text(dll_emu: Speakeasy) -> None:
    fmt = alloc(dll_emu, "%s=%d\x00".encode("utf-16le"))
    name = alloc(dll_emu, "n\x00".encode("utf-16le"))
    rv, displays = call(dll_emu, "msvcrt", "fwprintf", [0x1234, fmt, name, 42])
    assert rv == 4
    assert "n=42" in displays.values()


def test_p_wcmdln_points_at_the_wide_command_line(dll_emu: Speakeasy) -> None:
    pp = call(dll_emu, "msvcrt", "__p__wcmdln", [])[0]
    p = int.from_bytes(dll_emu.mem_read(pp, 4), "little")
    cmdln = dll_emu.mem_read(p, 0x200)
    text = cmdln[: next(i for i in range(0, len(cmdln), 2) if cmdln[i : i + 2] == b"\0\0")].decode("utf-16le")
    assert text == " ".join(dll_emu.emu.get_argv())


def test_fileno_returns_the_descriptor_of_a_standard_stream(dll_emu: Speakeasy) -> None:
    stdout = call(dll_emu, "msvcrt", "__acrt_iob_func", [1])[0]
    iob = call(dll_emu, "msvcrt", "__iob_func", [])[0]
    assert call(dll_emu, "msvcrt", "_fileno", [stdout])[0] == 1
    assert call(dll_emu, "msvcrt", "_fileno", [iob + 2 * 0x20])[0] == 2
    assert call(dll_emu, "msvcrt", "_fileno", [alloc(dll_emu, b"\0" * 0x20)])[0] == -1


def test_p_iob_returns_the_iob_array(dll_emu: Speakeasy) -> None:
    iob = call(dll_emu, "msvcrt", "__p__iob", [])[0]
    assert iob == call(dll_emu, "msvcrt", "__iob_func", [])[0]
    assert call(dll_emu, "msvcrt", "_fileno", [iob + 2 * 0x20])[0] == 2


@pytest.mark.parametrize("fd, result", [(0, 0), (7, -1)])
def test_read_gives_end_of_file_on_stdin_and_fails_on_other_descriptors(
    dll_emu: Speakeasy, fd: int, result: int
) -> None:
    assert call(dll_emu, "msvcrt", "_read", [fd, alloc(dll_emu, b"\0" * 8), 8])[0] == result


def test_mutex_functions_of_the_cpp_runtime_succeed_at_once(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    mtx = alloc(dll_emu, b"\0" * 0x50)
    call(dll_emu, "msvcrt", "_Mtx_init_in_situ", [mtx, 2])
    results = [call(dll_emu, "msvcrt", name, [mtx])[0] for name in ("_Mtx_lock", "_Mtx_trylock", "_Mtx_unlock")]
    call(dll_emu, "msvcrt", "_Mtx_destroy_in_situ", [mtx])
    assert results == [0, 0, 0]
    assert call(dll_emu, "msvcrt", "_Thrd_id", [])[0] == call(dll_emu, "kernel32", "GetCurrentThreadId", [])[0]


@pytest.mark.parametrize("name", ["__telemetry_main_invoke_trigger", "__telemetry_main_return_trigger"])
def test_telemetry_triggers_are_accepted(dll_emu: Speakeasy, name: str) -> None:
    call(dll_emu, "msvcrt", name, [0x10000000])


@pytest.mark.parametrize("fd, result", [(1, 0x4000), (7, -1)])
def test_setmode_returns_text_mode_for_a_standard_descriptor(dll_emu: Speakeasy, fd: int, result: int) -> None:
    o_u16text = 0x20000
    assert call(dll_emu, "msvcrt", "_setmode", [fd, o_u16text])[0] == result


@pytest.mark.parametrize("fixture, ptr", [("dll_emu", 4), ("dll64_emu", 8)])
def test_lc_locale_name_func_gives_the_c_locale_names(request: pytest.FixtureRequest, fixture: str, ptr: int) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    names = call(se, "msvcrt", "___lc_locale_name_func", [])[0]
    assert names == call(se, "msvcrt", "___lc_locale_name_func", [])[0]
    assert se.mem_read(names, 6 * ptr) == b"\x00" * 6 * ptr


@pytest.mark.parametrize("name", ["_lock_file", "_unlock_file"])
def test_file_locks_are_accepted(dll_emu: Speakeasy, name: str) -> None:
    call(dll_emu, "msvcrt", name, [alloc(dll_emu, b"\x00" * 0x20)])


def put_with(api: str) -> Callable[[Speakeasy, int], None]:
    def write(se: Speakeasy, stream: int) -> None:
        if api == "fputs":
            call(se, "msvcrt", "fputs", [alloc(se, b"id=7\x00"), stream])
        elif api == "fputc":
            for c in b"id=7":
                call(se, "msvcrt", "fputc", [c, stream])
        elif api == "fputws":
            assert call(se, "msvcrt", "fputws", [alloc(se, "id=7\x00".encode("utf-16le")), stream])[0] == 0
        elif api == "fputwc":
            for c in "id=7":
                assert call(se, "msvcrt", "fputwc", [ord(c), stream])[0] == ord(c)
        elif api == "fprintf":
            call(se, "msvcrt", "fprintf", [stream, alloc(se, b"%s=%d\x00"), alloc(se, b"id\x00"), 7])
        elif api == "fwprintf":
            call(
                se,
                "msvcrt",
                "fwprintf",
                [stream, alloc(se, "%s=%d\x00".encode("utf-16le")), alloc(se, "id\x00".encode("utf-16le")), 7],
            )
        elif api == "vfprintf":
            va = alloc(se, struct.pack("<II", alloc(se, b"id\x00"), 7))
            call(se, "msvcrt", "vfprintf", [stream, alloc(se, b"%s=%d\x00"), va])
        elif api == "__stdio_common_vfprintf":
            va = alloc(se, struct.pack("<II", alloc(se, b"id\x00"), 7))
            call(se, "msvcrt", api, [0, 0, stream, alloc(se, b"%s=%d\x00"), 0, va])
        elif api in ("__stdio_common_vfwprintf", "_o___stdio_common_vfwprintf"):
            va = alloc(se, struct.pack("<II", alloc(se, "id\x00".encode("utf-16le")), 7))
            assert call(se, "msvcrt", api, [0x24, 0, stream, alloc(se, "%s=%d\x00".encode("utf-16le")), 0, va])[0] == 4

    return write


@pytest.mark.parametrize(
    "api",
    [
        "fputs",
        "fputc",
        "fputws",
        "fputwc",
        "fprintf",
        "fwprintf",
        "vfprintf",
        "__stdio_common_vfprintf",
        "__stdio_common_vfwprintf",
        "_o___stdio_common_vfwprintf",
    ],
)
def test_text_output_reaches_a_file_stream(dll_emu: Speakeasy, api: str) -> None:
    path = alloc(dll_emu, b"c:\\users\\public\\run.bat\x00")
    stream, _ = call(dll_emu, "msvcrt", "fopen", [path, alloc(dll_emu, b"w+\x00")])
    put_with(api)(dll_emu, stream)
    out = alloc(dll_emu, b"\x00" * 16)

    assert call(dll_emu, "msvcrt", "fread", [out, 1, 16, stream])[0] == 4
    assert dll_emu.mem_read(out, 4) == b"id=7"


@pytest.mark.parametrize(
    "api, c, rv", [("towlower", ord("Q"), ord("q")), ("towlower", 0xC9, 0xC9), ("towupper", ord("q"), ord("Q"))]
)
def test_wide_case_conversion_maps_ascii_letters_in_the_c_locale(dll_emu: Speakeasy, api: str, c: int, rv: int) -> None:
    assert call(dll_emu, "msvcrt", api, [c])[0] == rv


@pytest.mark.parametrize("c, offset", [(ord("b"), 2), (0, 6), (ord("z"), None)])
def test_wcschr_finds_the_first_match_or_the_terminator(dll_emu: Speakeasy, c: int, offset: int | None) -> None:
    s = alloc(dll_emu, "abb\x00".encode("utf-16le"))
    assert call(dll_emu, "msvcrt", "wcschr", [s, c])[0] == (0 if offset is None else s + offset)


@pytest.mark.parametrize("api", ["_initialize_wide_environment", "_configure_wide_argv"])
def test_wide_startup_initializers_succeed(dll_emu: Speakeasy, api: str) -> None:
    argv = [] if api == "_initialize_wide_environment" else [1]
    assert call(dll_emu, "msvcrt", api, argv)[0] == 0


def test_wide_environ_points_at_wide_key_value_strings(dll_emu: Speakeasy) -> None:
    pp = call(dll_emu, "msvcrt", "__p__wenviron", [])[0]
    envp = int.from_bytes(dll_emu.mem_read(pp, 4), "little")
    first = int.from_bytes(dll_emu.mem_read(envp, 4), "little")
    assert "=" in dll_emu.read_mem_string(first, 2)


@pytest.mark.parametrize(
    "size, rv, out",
    [
        (6, 0, "abcde\x00".encode("utf-16le")),
        (5, ERANGE, "\x00b\x00".encode("utf-16le") + b"\xcc" * 6),
        (0, EINVAL, "ab\x00".encode("utf-16le") + b"\xcc" * 6),
    ],
)
def test_wcscat_s_appends_only_when_the_result_fits(dll_emu: Speakeasy, size: int, rv: int, out: bytes) -> None:
    dest = alloc(dll_emu, "ab\x00".encode("utf-16le") + b"\xcc" * 6)
    src = alloc(dll_emu, "cde\x00".encode("utf-16le"))
    assert call(dll_emu, "msvcrt", "wcscat_s", [dest, size, src])[0] == rv
    assert dll_emu.mem_read(dest, 12) == out


def test_query_perf_counter_returns_64_bits_at_the_reported_frequency(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None

    def query(api: str) -> int:
        low = call(dll_emu, "msvcrt", api, [])[0]
        return dll_emu.emu.reg_read(e_arch.X86_REG_EDX) << 32 | low

    assert query("_Query_perf_frequency") == 10_000_000
    first = query("_Query_perf_counter")
    assert first > 0xFFFFFFFF
    assert query("_Query_perf_counter") > first


@pytest.mark.parametrize("emu_name", ["dll_emu", "dll64_emu"])
def test_wgetmainargs_writes_wide_argv_and_environment(request: pytest.FixtureRequest, emu_name: str) -> None:
    se: Speakeasy = request.getfixturevalue(emu_name)
    emu = se.emu
    assert emu is not None
    ptr_size = emu.get_ptr_size()
    argc_out = alloc(se, b"\xff" * 4)
    argv_out = alloc(se, b"\xff" * ptr_size)
    env_out = alloc(se, b"\xff" * ptr_size)

    rv, _ = call(se, "msvcrt", "__wgetmainargs", [argc_out, argv_out, env_out, 0, 0])

    def read_ptr(addr: int) -> int:
        return int.from_bytes(se.mem_read(addr, ptr_size), "little")

    assert rv == 0
    args = emu.get_argv()
    assert int.from_bytes(se.mem_read(argc_out, 4), "little") == len(args)
    argv = read_ptr(argv_out)
    assert [se.read_mem_string(read_ptr(argv + i * ptr_size), 2) for i in range(len(args))] == args
    assert read_ptr(argv + len(args) * ptr_size) == 0
    env = read_ptr(env_out)
    first = se.read_mem_string(read_ptr(env), 2)
    key, value = next(iter(emu.get_env().items()))
    assert first == f"{key}={value}"


@pytest.mark.parametrize(
    "api, argv",
    [
        ("_crt_atexit", [0x1000]),
        ("_controlfp_s", [0, 0, 0]),
        ("_initialize_narrow_environment", []),
        ("_configure_narrow_argv", [1]),
        ("_set_fmode", [0x8000]),
    ],
)
def test_crt_startup_functions_return_zero(dll64_emu: Speakeasy, api: str, argv: list[int]) -> None:
    assert call(dll64_emu, "msvcrt", api, argv)[0] == 0


def test_set_fmode_sets_the_fmode_global(dll_emu: Speakeasy) -> None:
    assert call(dll_emu, "msvcrt", "_set_fmode", [0x8000])[0] == 0
    fmode, _ = call(dll_emu, "msvcrt", "__p__fmode", [])
    assert int.from_bytes(dll_emu.mem_read(fmode, 4), "little") == 0x8000
    assert call(dll_emu, "msvcrt", "_set_fmode", [0x1234])[0] == EINVAL


def test_set_new_mode_returns_the_previous_mode(dll_emu: Speakeasy) -> None:
    assert call(dll_emu, "msvcrt", "_set_new_mode", [1])[0] == 0
    assert call(dll_emu, "msvcrt", "_set_new_mode", [0])[0] == 1


def test_configthreadlocale_returns_the_previous_setting(dll_emu: Speakeasy) -> None:
    assert call(dll_emu, "msvcrt", "_configthreadlocale", [0])[0] == 2
    assert call(dll_emu, "msvcrt", "_configthreadlocale", [1])[0] == 2
    assert call(dll_emu, "msvcrt", "_configthreadlocale", [0])[0] == 1


@pytest.mark.parametrize("api", ["__current_exception", "__current_exception_context"])
def test_current_exception_returns_an_empty_slot(dll64_emu: Speakeasy, api: str) -> None:
    slot, _ = call(dll64_emu, "msvcrt", api, [])
    assert slot
    assert dll64_emu.mem_read(slot, 8) == b"\x00" * 8


@pytest.mark.parametrize(
    "api, needle, offset",
    [
        ("_mbsstr", b"\\Windows", 2),
        ("_mbsstr", b"zz", None),
        ("_mbspbrk", b"/\\", 2),
        ("_mbspbrk", b"/", None),
    ],
)
def test_mbs_search_finds_a_substring_or_a_character_set(
    dll_emu: Speakeasy, api: str, needle: bytes, offset: int | None
) -> None:
    hay = alloc(dll_emu, b"C:\\Windows\\system32\\sample\x00")
    rv, _ = call(dll_emu, "msvcrt", api, [hay, alloc(dll_emu, needle + b"\x00")])
    assert rv == (0 if offset is None else hay + offset)


@pytest.mark.parametrize("api, c, offset", [("_mbschr", ord("\\"), 2), ("_mbsrchr", ord("\\"), 19), ("_mbschr", 0, 26)])
def test_mbs_character_search_finds_the_first_or_last_match(dll_emu: Speakeasy, api: str, c: int, offset: int) -> None:
    hay = alloc(dll_emu, b"C:\\Windows\\system32\\sample\x00")
    assert call(dll_emu, "msvcrt", api, [hay, c])[0] == hay + offset


@pytest.mark.parametrize(
    "api, a, b, rv",
    [
        ("_mbscmp", b"abc", b"abd", -1),
        ("_mbscoll", b"abc", b"abc", 0),
        ("_mbsicmp", b"ABC", b"abc", 0),
        ("_mbsicoll", b"abd", b"ABC", 1),
    ],
)
def test_mbs_compare_orders_the_strings(dll_emu: Speakeasy, api: str, a: bytes, b: bytes, rv: int) -> None:
    assert call(dll_emu, "msvcrt", api, [alloc(dll_emu, a + b"\x00"), alloc(dll_emu, b + b"\x00")])[0] == rv


@pytest.mark.parametrize("api", ["_mbsnbcmp", "_mbsncmp"])
def test_mbs_count_compare_stops_after_count(dll_emu: Speakeasy, api: str) -> None:
    a, b = alloc(dll_emu, b"abcX\x00"), alloc(dll_emu, b"abcY\x00")
    assert call(dll_emu, "msvcrt", api, [a, b, 3])[0] == 0
    assert call(dll_emu, "msvcrt", api, [a, b, 4])[0] == -1


@pytest.mark.parametrize(
    "api, result", [("_mbslwr", b"c:\\ab\x00"), ("_mbsupr", b"C:\\AB\x00"), ("_mbsrev", b"bA\\:c\x00")]
)
def test_mbs_in_place_changes_return_the_string(dll_emu: Speakeasy, api: str, result: bytes) -> None:
    s = alloc(dll_emu, b"c:\\Ab\x00")
    assert call(dll_emu, "msvcrt", api, [s])[0] == s
    assert dll_emu.mem_read(s, 6) == result


def test_mbs_character_steps_are_one_byte_in_a_single_byte_code_page(dll_emu: Speakeasy) -> None:
    s = alloc(dll_emu, b"ab\x00")
    assert call(dll_emu, "msvcrt", "_mbsinc", [s])[0] == s + 1
    assert call(dll_emu, "msvcrt", "_mbclen", [s])[0] == 1


@pytest.mark.parametrize(
    "api, c, rv", [("_ismbcdigit", ord("7"), True), ("_ismbcdigit", ord("a"), False), ("_ismbcspace", 9, True)]
)
def test_mbc_classification_matches_the_c_locale(dll_emu: Speakeasy, api: str, c: int, rv: bool) -> None:
    assert bool(call(dll_emu, "msvcrt", api, [c])[0]) == rv


def test_vsprintf_formats_from_a_va_list(dll_emu: Speakeasy) -> None:
    buf = alloc(dll_emu, b"\xcc" * 32)
    va = alloc(dll_emu, struct.pack("<II", alloc(dll_emu, b"id\x00"), 7))
    assert call(dll_emu, "msvcrt", "vsprintf", [buf, alloc(dll_emu, b"%s=%d\x00"), va])[0] == 4
    assert dll_emu.mem_read(buf, 6) == b"id=7\x00\xcc"


def test_rename_moves_a_file(dll_emu: Speakeasy) -> None:
    old, new = alloc(dll_emu, b"c:\\users\\public\\a.txt\x00"), alloc(dll_emu, b"c:\\users\\public\\b.txt\x00")
    stream, _ = call(dll_emu, "msvcrt", "fopen", [old, alloc(dll_emu, b"wb\x00")])
    call(dll_emu, "msvcrt", "fwrite", [alloc(dll_emu, b"abc"), 1, 3, stream])
    call(dll_emu, "msvcrt", "fclose", [stream])

    assert call(dll_emu, "msvcrt", "rename", [old, new])[0] == 0
    stream, _ = call(dll_emu, "msvcrt", "fopen", [new, alloc(dll_emu, b"rb\x00")])
    out = alloc(dll_emu, b"\x00" * 8)
    assert call(dll_emu, "msvcrt", "fread", [out, 1, 8, stream])[0] == 3
    assert dll_emu.mem_read(out, 3) == b"abc"


def test_tzset_is_accepted(dll_emu: Speakeasy) -> None:
    call(dll_emu, "msvcrt", "_tzset", [])


@pytest.mark.parametrize(
    "fmt, text",
    [
        (b"%Y-%m-%d %H:%M:%S", b"2019-12-29 08:04:05"),
        (b"%a %A %b %B %j %w %y %p %I %%", b"Sun Sunday Dec December 363 0 19 AM 08 %"),
        (b"%c|%x|%X", b"12/29/19 08:04:05|12/29/19|08:04:05"),
        (b"%#d/%#m", b"29/12"),
    ],
)
def test_strftime_formats_a_struct_tm_in_the_c_locale(dll_emu: Speakeasy, fmt: bytes, text: bytes) -> None:
    tm = alloc(dll_emu, struct.pack("<9i", 5, 4, 8, 29, 11, 119, 0, 362, 0))
    buf = alloc(dll_emu, b"\xcc" * 64)
    assert call(dll_emu, "msvcrt", "strftime", [buf, 64, alloc(dll_emu, fmt + b"\x00"), tm])[0] == len(text)
    assert dll_emu.mem_read(buf, len(text) + 1) == text + b"\x00"


def test_strftime_returns_zero_when_the_text_does_not_fit(dll_emu: Speakeasy) -> None:
    tm = alloc(dll_emu, struct.pack("<9i", 5, 4, 8, 29, 11, 119, 0, 362, 0))
    buf = alloc(dll_emu, b"\xcc" * 16)
    assert call(dll_emu, "msvcrt", "strftime", [buf, 4, alloc(dll_emu, b"%Y\x00"), tm])[0] == 0


@pytest.mark.parametrize(
    "size, count, rv, out",
    [
        (8, 3, 0, b"hel\x00\xcc\xcc\xcc\xcc"),
        (8, 9, 0, b"hello\x00\xcc\xcc"),
        (4, 3, 0, b"hel\x00\xcc\xcc\xcc\xcc"),
        (4, 4, ERANGE, b"\x00ell\xcc\xcc\xcc\xcc"),
        (4, 0xFFFFFFFF, STRUNCATE, b"hel\x00\xcc\xcc\xcc\xcc"),
        (0, 3, EINVAL, b"\xcc" * 8),
    ],
)
def test_strncpy_s_copies_at_most_count_bytes_within_the_buffer(
    dll_emu: Speakeasy, size: int, count: int, rv: int, out: bytes
) -> None:
    dest = alloc(dll_emu, b"\xcc" * 8)
    src = alloc(dll_emu, b"hello\x00")
    assert call(dll_emu, "msvcrt", "strncpy_s", [dest, size, src, count])[0] == rv
    assert dll_emu.mem_read(dest, 8) == out


@pytest.mark.parametrize(
    "size, count, rv, out",
    [
        (8, 3, 0, "hel\x00".encode("utf-16le")),
        (4, 4, ERANGE, "\x00ell".encode("utf-16le")),
        (4, 0xFFFFFFFF, STRUNCATE, "hel\x00".encode("utf-16le")),
    ],
)
def test_wcsncpy_s_copies_at_most_count_chars_within_the_buffer(
    dll_emu: Speakeasy, size: int, count: int, rv: int, out: bytes
) -> None:
    dest = alloc(dll_emu, b"\xcc" * 16)
    src = alloc(dll_emu, "hello\x00".encode("utf-16le"))
    assert call(dll_emu, "msvcrt", "wcsncpy_s", [dest, size, src, count])[0] == rv
    assert dll_emu.mem_read(dest, 8) == out


@pytest.mark.parametrize("a, b, count, rv", [("abcd", "abce", 3, 0), ("abcd", "abce", 4, -1), ("b", "a", 1, 1)])
def test_wcsncmp_compares_count_chars(dll_emu: Speakeasy, a: str, b: str, count: int, rv: int) -> None:
    args = [alloc(dll_emu, f"{s}\0".encode("utf-16le")) for s in (a, b)]
    assert call(dll_emu, "msvcrt", "wcsncmp", [*args, count])[0] == rv


@pytest.mark.parametrize(
    "api, c, rv",
    [
        ("iswalpha", ord("I"), 1),
        ("iswalpha", ord("1"), 0),
        ("iswalpha", 0x3B1, 1),
        ("iswspace", ord(" "), 1),
        ("iswspace", ord("\t"), 1),
        ("iswspace", ord("x"), 0),
        ("iswspace", 0x1F, 0),
    ],
)
def test_wide_char_classes(dll_emu: Speakeasy, api: str, c: int, rv: int) -> None:
    assert bool(call(dll_emu, "msvcrt", api, [c])[0]) == bool(rv)


@pytest.mark.parametrize("charset, offset", [(" ", 1), ("cb", 2), ("z", None)])
def test_wcspbrk_returns_pointer_to_first_char_in_set(dll_emu: Speakeasy, charset: str, offset: int | None) -> None:
    s = alloc(dll_emu, "a b\0".encode("utf-16le"))
    rv, _ = call(dll_emu, "msvcrt", "wcspbrk", [s, alloc(dll_emu, f"{charset}\0".encode("utf-16le"))])
    assert rv == (0 if offset is None else s + offset * 2)


def test_rand_uses_the_msvc_generator(dll_emu: Speakeasy) -> None:
    assert [call(dll_emu, "msvcrt", "rand", [])[0] for _ in range(2)] == [41, 18467]
    call(dll_emu, "msvcrt", "srand", [1])
    assert [call(dll_emu, "msvcrt", "rand", [])[0] for _ in range(4)] == [41, 18467, 6334, 26500]
    call(dll_emu, "msvcrt", "srand", [0x12345678])
    assert call(dll_emu, "msvcrt", "rand", [])[0] == ((0x12345678 * 214013 + 2531011) & 0xFFFFFFFF) >> 16 & 0x7FFF


def test_system_reports_success(dll_emu: Speakeasy) -> None:
    command = alloc(dll_emu, b"schtasks /Delete /TN Upkeep /F\x00")
    assert call(dll_emu, "msvcrt", "system", [command])[0] == 0
    assert call(dll_emu, "msvcrt", "system", [0])[0] != 0


@pytest.mark.parametrize(("api", "enc"), [("_popen", "utf-8"), ("_wpopen", "utf-16le")])
def test_popen_reads_nothing_and_closes_with_pclose(dll_emu: Speakeasy, api: str, enc: str) -> None:
    command = "cmd.exe /c dir"
    stream, args = call(
        dll_emu, "msvcrt", api, [alloc(dll_emu, (command + "\0").encode(enc)), alloc(dll_emu, "rt\0".encode(enc))]
    )
    assert stream and command in args.values()
    buf = alloc(dll_emu, b"\x00" * 128)
    assert call(dll_emu, "msvcrt", "fgets", [buf, 128, stream])[0] == 0
    assert call(dll_emu, "msvcrt", "fread", [buf, 1, 128, stream])[0] == 0
    assert call(dll_emu, "msvcrt", "_pclose", [stream])[0] == 0
    assert call(dll_emu, "msvcrt", "_pclose", [stream])[0] == -1


def test_popen_write_mode_discards_the_data(dll_emu: Speakeasy) -> None:
    stream, _ = call(dll_emu, "msvcrt", "_popen", [alloc(dll_emu, b"sort\x00"), alloc(dll_emu, b"w\x00")])
    assert call(dll_emu, "msvcrt", "fwrite", [alloc(dll_emu, b"abc"), 1, 3, stream])[0] == 3
    assert call(dll_emu, "msvcrt", "_pclose", [stream])[0] == 0


def test_popen_rejects_a_bad_mode_and_pclose_an_unknown_stream(dll_emu: Speakeasy) -> None:
    assert call(dll_emu, "msvcrt", "_popen", [alloc(dll_emu, b"dir\x00"), alloc(dll_emu, b"a\x00")])[0] == 0
    assert call(dll_emu, "msvcrt", "_popen", [0, alloc(dll_emu, b"r\x00")])[0] == 0
    assert call(dll_emu, "msvcrt", "_pclose", [0])[0] == -1


@pytest.fixture
def strict_fs_emu(config: dict[str, Any], load_test_bin: Callable[[str], bytes]) -> Iterator[Speakeasy]:
    config["filesystem"]["files"] = [f for f in config["filesystem"]["files"] if f["mode"] == "full_path"]
    for se in load_emu(config, load_test_bin("dll_test_x86.dll.xz")):
        start_process(se)
        yield se


def fopen_text(se: Speakeasy, api: str, text: str) -> int:
    return alloc(se, (text + "\0").encode("utf-8" if api == "fopen" else "utf-16le"))


def write_stream(se: Speakeasy, api: str, path: str, mode: str, data: bytes) -> None:
    stream, _ = call(se, "msvcrt", api, [fopen_text(se, api, path), fopen_text(se, api, mode)])
    assert stream
    assert call(se, "msvcrt", "fwrite", [alloc(se, data), 1, len(data), stream])[0] == len(data)
    call(se, "msvcrt", "fclose", [stream])


@pytest.mark.parametrize("api", ["fopen", "_wfopen"])
def test_fopen_append_mode_keeps_the_file_content(strict_fs_emu: Speakeasy, api: str) -> None:
    se = strict_fs_emu
    path = "c:\\users\\public\\log.txt"
    write_stream(se, api, path, "ab", b"new")
    write_stream(se, api, path, "wb", b"hello")
    write_stream(se, api, path, "ab", b"world")

    stream, _ = call(se, "msvcrt", api, [fopen_text(se, api, path), fopen_text(se, api, "rb")])
    out = alloc(se, b"\x00" * 16)
    assert call(se, "msvcrt", "fread", [out, 1, 16, stream])[0] == 10
    assert se.mem_read(out, 10) == b"helloworld"


@pytest.mark.parametrize("api", ["fopen", "_wfopen"])
@pytest.mark.parametrize("mode", ["r", "rb", "r+", "r+b"])
def test_fopen_read_modes_do_not_create_a_missing_file(strict_fs_emu: Speakeasy, api: str, mode: str) -> None:
    path = fopen_text(strict_fs_emu, api, "c:\\users\\public\\missing.txt")
    assert call(strict_fs_emu, "msvcrt", api, [path, fopen_text(strict_fs_emu, api, mode)])[0] == 0


@pytest.mark.parametrize("api, enc", [("_access", "utf-8"), ("_waccess", "utf-16le")])
def test_access_finds_files_and_directories(strict_fs_emu: Speakeasy, api: str, enc: str) -> None:
    se = strict_fs_emu
    write_stream(se, "fopen", "c:\\users\\public\\log.txt", "wb", b"data")

    def access(path: str, mode: int) -> tuple[int, int]:
        rv, _ = call(se, "msvcrt", api, [alloc(se, (path + "\0").encode(enc)), mode])
        errno_ptr, _ = call(se, "msvcrt", "_errno", [])
        return rv, int.from_bytes(se.mem_read(errno_ptr, 4), "little")

    assert access("C:\\Windows", 0)[0] == 0
    assert access("c:\\users\\public\\log.txt", 6)[0] == 0
    assert access("C:\\Windows\\system32\\mingw32\\bin", 0) == (-1, ENOENT)
    assert access("C:\\Windows", 1) == (-1, EINVAL)


@pytest.mark.parametrize(
    "api, argv",
    [
        ("_unlink", [0]),
        ("_wunlink", [0]),
        ("remove", [0]),
        ("_wremove", [0]),
        ("rename", [0, "new"]),
        ("rename", ["old", 0]),
    ],
)
def test_file_functions_reject_a_null_path(dll_emu: Speakeasy, api: str, argv: list) -> None:
    args = [alloc(dll_emu, f"c:\\users\\public\\{a}.txt\0".encode()) if isinstance(a, str) else a for a in argv]
    assert call(dll_emu, "msvcrt", api, args)[0] == -1
    errno_ptr, _ = call(dll_emu, "msvcrt", "_errno", [])
    assert int.from_bytes(dll_emu.mem_read(errno_ptr, 4), "little") == EINVAL


@pytest.mark.parametrize(
    "api, enc", [("_mkdir", "utf-8"), ("_wmkdir", "utf-16le"), ("_rmdir", "utf-8"), ("_wrmdir", "utf-16le")]
)
def test_directory_functions_succeed_and_show_the_path(dll_emu: Speakeasy, api: str, enc: str) -> None:
    path = "c:\\users\\public\\work"
    rv, displays = call(dll_emu, "msvcrt", api, [alloc(dll_emu, (path + "\0").encode(enc))])
    assert rv == 0
    assert path in str(next(iter(displays.values())))
    assert call(dll_emu, "msvcrt", api, [0])[0] == -1
    errno_ptr, _ = call(dll_emu, "msvcrt", "_errno", [])
    assert int.from_bytes(dll_emu.mem_read(errno_ptr, 4), "little") == EINVAL


@pytest.mark.parametrize("api", ["swprintf", "_swprintf"])
def test_swprintf_formats_without_a_count(dll_emu: Speakeasy, api: str) -> None:
    buf = alloc(dll_emu, b"\xcc" * 40)
    fmt = alloc(dll_emu, "%s\\%x%d\0".encode("utf-16le"))
    text = alloc(dll_emu, "C:\\t\0".encode("utf-16le"))
    assert call(dll_emu, "msvcrt", api, [buf, fmt, text, 0x10, 5])[0] == 8
    assert dll_emu.mem_read(buf, 20) == "C:\\t\\105\0".encode("utf-16le") + b"\xcc\xcc"


@pytest.mark.parametrize("api", ["vswprintf", "_vswprintf"])
def test_vswprintf_formats_from_a_va_list(dll_emu: Speakeasy, api: str) -> None:
    buf = alloc(dll_emu, b"\xcc" * 32)
    va = alloc(dll_emu, struct.pack("<II", alloc(dll_emu, "id\0".encode("utf-16le")), 7))
    assert call(dll_emu, "msvcrt", api, [buf, alloc(dll_emu, "%s=%d\0".encode("utf-16le")), va])[0] == 4
    assert dll_emu.mem_read(buf, 12) == "id=7\0".encode("utf-16le") + b"\xcc\xcc"


@pytest.mark.parametrize("count, rv, written", [(3, -1, "hel"), (5, 5, "hello"), (8, 5, "hello\0")])
def test_vsnwprintf_writes_at_most_count_chars(dll_emu: Speakeasy, count: int, rv: int, written: str) -> None:
    buf = alloc(dll_emu, b"\xcc" * 32)
    va = alloc(dll_emu, struct.pack("<I", alloc(dll_emu, "hello\0".encode("utf-16le"))))
    fmt = alloc(dll_emu, "%s\0".encode("utf-16le"))
    assert call(dll_emu, "msvcrt", "_vsnwprintf", [buf, count, fmt, va])[0] == rv
    data = written.encode("utf-16le")
    assert dll_emu.mem_read(buf, len(data) + 2) == data + b"\xcc\xcc"


@pytest.mark.parametrize("size, rv, written", [(6, 5, "hello\0"), (5, -1, "\0")])
@pytest.mark.parametrize(
    "api, width, va",
    [("sprintf_s", 1, False), ("swprintf_s", 2, False), ("vsprintf_s", 1, True), ("vswprintf_s", 2, True)],
)
def test_sprintf_s_empties_the_buffer_when_the_text_does_not_fit(
    dll_emu: Speakeasy, api: str, width: int, va: bool, size: int, rv: int, written: str
) -> None:
    enc = "utf-8" if width == 1 else "utf-16le"
    buf = alloc(dll_emu, b"\xcc" * 32)
    fmt = alloc(dll_emu, "%s\0".encode(enc))
    text = alloc(dll_emu, "hello\0".encode(enc))
    args = [alloc(dll_emu, struct.pack("<I", text))] if va else [text]
    assert call(dll_emu, "msvcrt", api, [buf, size, fmt, *args])[0] == rv
    data = written.encode(enc)
    assert dll_emu.mem_read(buf, len(data) + width) == data + b"\xcc" * width


@pytest.mark.parametrize(
    "size, count, rv, written",
    [(16, 3, -1, "hel\0"), (16, 5, 5, "hello\0"), (4, 0xFFFFFFFF, -1, "hel\0"), (4, 8, -1, "\0")],
)
@pytest.mark.parametrize("api, width", [("_snprintf_s", 1), ("_snwprintf_s", 2)])
def test_snprintf_s_limits_the_text_to_count(
    dll_emu: Speakeasy, api: str, width: int, size: int, count: int, rv: int, written: str
) -> None:
    enc = "utf-8" if width == 1 else "utf-16le"
    buf = alloc(dll_emu, b"\xcc" * 32)
    fmt = alloc(dll_emu, "%s\0".encode(enc))
    text = alloc(dll_emu, "hello\0".encode(enc))
    assert call(dll_emu, "msvcrt", api, [buf, size, count, fmt, text])[0] == rv
    data = written.encode(enc)
    assert dll_emu.mem_read(buf, len(data) + width) == data + b"\xcc" * width


@pytest.mark.parametrize(
    "api, width, va",
    [("_scprintf", 1, False), ("_scwprintf", 2, False), ("_vscprintf", 1, True), ("_vscwprintf", 2, True)],
)
def test_scprintf_counts_the_formatted_characters(dll_emu: Speakeasy, api: str, width: int, va: bool) -> None:
    enc = "utf-8" if width == 1 else "utf-16le"
    fmt = alloc(dll_emu, "%s-%d\0".encode(enc))
    text = alloc(dll_emu, "abc\0".encode(enc))
    args = [alloc(dll_emu, struct.pack("<II", text, 42))] if va else [text, 42]
    assert call(dll_emu, "msvcrt", api, [fmt, *args])[0] == 6


@pytest.mark.parametrize(
    "api, c, rv",
    [
        ("isalnum", ord("a"), True),
        ("isalnum", ord("_"), False),
        ("isalpha", ord("Z"), True),
        ("isalpha", ord("5"), False),
        ("isalpha", 0xE9, False),
        ("isalpha", 0xFFFFFFFF, False),
        ("isupper", ord("A"), True),
        ("isupper", ord("a"), False),
        ("islower", ord("z"), True),
        ("islower", ord("Z"), False),
        ("isxdigit", ord("f"), True),
        ("isxdigit", ord("g"), False),
        ("ispunct", ord("!"), True),
        ("ispunct", ord("a"), False),
        ("isprint", ord(" "), True),
        ("isprint", 0x1F, False),
        ("iscntrl", 0x7F, True),
        ("iscntrl", ord("a"), False),
        ("isgraph", ord("~"), True),
        ("isgraph", ord(" "), False),
        ("iswalnum", 0xE9, True),
        ("iswalnum", ord("-"), False),
        ("iswdigit", ord("7"), True),
        ("iswdigit", ord("x"), False),
        ("iswupper", 0xC9, True),
        ("iswupper", 0xE9, False),
        ("iswlower", 0xE9, True),
        ("iswlower", ord("Q"), False),
        ("iswxdigit", ord("C"), True),
        ("iswxdigit", ord("G"), False),
    ],
)
def test_ctype_classification_matches_the_c_locale(dll_emu: Speakeasy, api: str, c: int, rv: bool) -> None:
    assert bool(call(dll_emu, "msvcrt", api, [c])[0]) == rv


def test_pctype_points_to_the_c_locale_table(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    table, _ = call(dll_emu, "msvcrt", "__pctype_func", [])
    flags = struct.unpack("<257H", dll_emu.mem_read(table - 2, 514))
    assert flags[0] == 0
    assert [flags[1 + ord(c)] for c in "\t A7a!\x7f"] == [0x68, 0x48, 0x181, 0x84, 0x182, 0x10, 0x20]
    assert flags[1 + 0xE9] == 0
    variable = dll_emu.emu.get_proc("msvcrt", "_pctype")
    assert call(dll_emu, "msvcrt", "__p__pctype", [])[0] == variable
    assert int.from_bytes(dll_emu.mem_read(variable, 4), "little") == table
    assert call(dll_emu, "msvcrt", "_isctype", [ord("7"), 0x4])[0] == 0x4
    assert call(dll_emu, "msvcrt", "_isctype", [ord("g"), 0x80])[0] == 0


def test_mb_cur_max_is_one_in_the_c_locale(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None
    variable = dll_emu.emu.get_proc("msvcrt", "__mb_cur_max")
    assert call(dll_emu, "msvcrt", "__p___mb_cur_max", [])[0] == variable
    assert int.from_bytes(dll_emu.mem_read(variable, 4), "little") == 1


@pytest.mark.parametrize("api, enc", [("_fsopen", "utf-8"), ("_wfsopen", "utf-16le")])
def test_fsopen_opens_a_stream_like_fopen(strict_fs_emu: Speakeasy, api: str, enc: str) -> None:
    se = strict_fs_emu
    path = alloc(se, "c:\\users\\public\\shared.txt\0".encode(enc))
    stream, _ = call(se, "msvcrt", api, [path, alloc(se, "wb\0".encode(enc)), 0x40])
    assert stream
    assert call(se, "msvcrt", "fwrite", [alloc(se, b"abc"), 1, 3, stream])[0] == 3
    call(se, "msvcrt", "fclose", [stream])

    stream, _ = call(se, "msvcrt", api, [path, alloc(se, "rb\0".encode(enc)), 0x40])
    out = alloc(se, b"\x00" * 8)
    assert call(se, "msvcrt", "fread", [out, 1, 8, stream])[0] == 3
    assert se.mem_read(out, 3) == b"abc"


@pytest.mark.parametrize("api, enc", [("fopen_s", "utf-8"), ("_wfopen_s", "utf-16le")])
def test_fopen_s_writes_the_stream_or_null(strict_fs_emu: Speakeasy, api: str, enc: str) -> None:
    se = strict_fs_emu
    out = alloc(se, b"\xcc" * 4)
    missing = alloc(se, "c:\\users\\public\\missing.txt\0".encode(enc))
    assert call(se, "msvcrt", api, [out, missing, alloc(se, "rb\0".encode(enc))])[0] == ENOENT
    assert se.mem_read(out, 4) == b"\x00" * 4

    path = alloc(se, "c:\\users\\public\\new.txt\0".encode(enc))
    assert call(se, "msvcrt", api, [out, path, alloc(se, "wb\0".encode(enc))])[0] == 0
    stream = int.from_bytes(se.mem_read(out, 4), "little")
    assert call(se, "msvcrt", "fwrite", [alloc(se, b"abc"), 1, 3, stream])[0] == 3
    assert call(se, "msvcrt", api, [0, path, alloc(se, "rb\0".encode(enc))])[0] == EINVAL


@pytest.mark.parametrize(
    "api, size, src, count, rv, dest",
    [
        ("memcpy_s", 8, b"abcd", 4, 0, b"abcd\xcc\xcc\xcc\xcc"),
        ("memcpy_s", 2, b"abcd", 4, ERANGE, b"\x00\x00\xcc\xcc\xcc\xcc\xcc\xcc"),
        ("memcpy_s", 4, None, 4, EINVAL, b"\x00\x00\x00\x00\xcc\xcc\xcc\xcc"),
        ("memcpy_s", 4, None, 0, 0, b"\xcc" * 8),
        ("memmove_s", 8, b"abcd", 4, 0, b"abcd\xcc\xcc\xcc\xcc"),
        ("memmove_s", 2, b"abcd", 4, ERANGE, b"\xcc" * 8),
        ("memmove_s", 4, None, 4, EINVAL, b"\xcc" * 8),
    ],
)
def test_memcpy_s_checks_the_sizes(
    dll_emu: Speakeasy, api: str, size: int, src: bytes | None, count: int, rv: int, dest: bytes
) -> None:
    buf = alloc(dll_emu, b"\xcc" * 8)
    source = alloc(dll_emu, src) if src else 0
    assert call(dll_emu, "msvcrt", api, [buf, size, source, count])[0] == rv
    assert dll_emu.mem_read(buf, 8) == dest
    assert call(dll_emu, "msvcrt", api, [0, size, source, 4])[0] == EINVAL


@pytest.mark.parametrize("size, rv, dest", [(8, 0, b"abcdef\x00"), (6, ERANGE, b"\x00"), (7, 0, b"abcdef\x00")])
def test_strcat_s_appends_when_the_result_fits(dll_emu: Speakeasy, size: int, rv: int, dest: bytes) -> None:
    buf = alloc(dll_emu, b"abc\x00\xcc\xcc\xcc\xcc")
    assert call(dll_emu, "msvcrt", "strcat_s", [buf, size, alloc(dll_emu, b"def\x00")])[0] == rv
    assert dll_emu.mem_read(buf, len(dest)) == dest


def test_xtime_get_ticks_counts_100ns_units_since_1970(dll_emu: Speakeasy) -> None:
    assert dll_emu.emu is not None

    def query() -> int:
        low = call(dll_emu, "msvcrt", "_Xtime_get_ticks", [])[0]
        return dll_emu.emu.reg_read(e_arch.X86_REG_EDX) << 32 | low

    first = query()
    assert first // 10_000_000 >= TIME_BASE
    assert query() > first


def test_random_device_returns_new_values(dll_emu: Speakeasy) -> None:
    values = {call(dll_emu, "msvcrt", "_Random_device", [])[0] for _ in range(4)}
    assert len(values) == 4


@pytest.mark.parametrize("fixture, size", [("dll_emu", 0x20), ("dll64_emu", 0x30)])
def test_acrt_iob_func_gives_the_standard_files_of_iob(request: pytest.FixtureRequest, fixture: str, size: int) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    iob = call(se, "msvcrt", "__iob_func", [])[0]
    for fd in range(3):
        stream = call(se, "msvcrt", "__acrt_iob_func", [fd])[0]
        assert stream == iob + fd * size
        assert call(se, "msvcrt", "_fileno", [stream])[0] == fd


@pytest.mark.parametrize("fixture, file_offset", [("strict_fs_emu", 0x10), ("dll64_emu", 0x1C)])
def test_fopen_gives_a_file_whose_descriptor_reads_the_file(
    request: pytest.FixtureRequest, fixture: str, file_offset: int
) -> None:
    se: Speakeasy = request.getfixturevalue(fixture)
    path = "c:\\users\\public\\log.txt"
    write_stream(se, "fopen", path, "wb", b"helloworld")

    stream, _ = call(se, "msvcrt", "fopen", [fopen_text(se, "fopen", path), fopen_text(se, "fopen", "rb")])
    fd = struct.unpack("<i", se.mem_read(stream + file_offset, 4))[0]
    assert fd >= 3
    assert call(se, "msvcrt", "_fileno", [stream])[0] == fd

    out = alloc(se, b"\x00" * 16)
    assert call(se, "msvcrt", "_read", [fd, out, 16])[0] == 10
    assert se.mem_read(out, 10) == b"helloworld"


def test_open_write_seek_and_read_a_descriptor(strict_fs_emu: Speakeasy) -> None:
    se = strict_fs_emu
    path = fopen_text(se, "fopen", "c:\\users\\public\\log.txt")
    o_rdwr_creat_trunc_binary = 0x2 | 0x100 | 0x200 | 0x8000
    fd = call(se, "msvcrt", "_open", [path, o_rdwr_creat_trunc_binary, 0x180])[0]
    assert fd >= 3

    assert call(se, "msvcrt", "_write", [fd, alloc(se, b"hello world"), 11])[0] == 11
    assert call(se, "msvcrt", "_lseek", [fd, -5 & 0xFFFFFFFF, 2])[0] == 6
    out = alloc(se, b"\x00" * 16)
    assert call(se, "msvcrt", "_read", [fd, out, 16])[0] == 5
    assert se.mem_read(out, 5) == b"world"

    assert call(se, "msvcrt", "_lseeki64", [fd, 0, 0, 0])[0] == 0
    assert call(se, "msvcrt", "_read", [fd, out, 5])[0] == 5
    assert se.mem_read(out, 5) == b"hello"

    assert call(se, "msvcrt", "_close", [fd])[0] == 0
    assert call(se, "msvcrt", "_close", [fd])[0] == -1
    assert call(se, "msvcrt", "_read", [fd, out, 5])[0] == -1


@pytest.mark.parametrize("api, width", [("_open", 1), ("_wopen", 2)])
def test_open_without_create_fails_on_a_missing_file(strict_fs_emu: Speakeasy, api: str, width: int) -> None:
    text = "c:\\users\\public\\missing.txt\0"
    path = alloc(strict_fs_emu, text.encode("utf-8" if width == 1 else "utf-16le"))
    assert call(strict_fs_emu, "msvcrt", api, [path, 0, 0])[0] == -1


def test_fdopen_gives_a_stream_on_the_descriptor(strict_fs_emu: Speakeasy) -> None:
    se = strict_fs_emu
    path = "c:\\users\\public\\log.txt"
    write_stream(se, "fopen", path, "wb", b"helloworld")
    fd = call(se, "msvcrt", "_open", [fopen_text(se, "fopen", path), 0x8000, 0])[0]

    stream = call(se, "msvcrt", "_fdopen", [fd, fopen_text(se, "fopen", "rb")])[0]
    assert call(se, "msvcrt", "_fileno", [stream])[0] == fd
    out = alloc(se, b"\x00" * 16)
    assert call(se, "msvcrt", "fread", [out, 1, 16, stream])[0] == 10
    assert se.mem_read(out, 10) == b"helloworld"

    call(se, "msvcrt", "fclose", [stream])
    assert call(se, "msvcrt", "_read", [fd, out, 1])[0] == -1


@pytest.mark.parametrize("fstat, stat", [("_fstat", "_stat"), ("_fstati64", "_stati64"), ("_fstat64", "_stat64")])
def test_fstat_matches_stat_of_the_same_file(strict_fs_emu: Speakeasy, fstat: str, stat: str) -> None:
    se = strict_fs_emu
    path = fopen_text(se, "fopen", "c:\\users\\public\\log.txt")
    write_stream(se, "fopen", "c:\\users\\public\\log.txt", "wb", b"helloworld")
    fd = call(se, "msvcrt", "_open", [path, 0, 0])[0]

    by_fd = alloc(se, b"\xcc" * 0x40)
    by_path = alloc(se, b"\xcc" * 0x40)
    assert call(se, "msvcrt", fstat, [fd, by_fd])[0] == 0
    assert call(se, "msvcrt", stat, [path, by_path])[0] == 0
    assert se.mem_read(by_fd, 0x40) == se.mem_read(by_path, 0x40)
    assert call(se, "msvcrt", fstat, [77, by_fd])[0] == -1


def test_write_to_stdout_goes_to_the_file_that_freopen_opens(strict_fs_emu: Speakeasy) -> None:
    se = strict_fs_emu
    stdout = call(se, "msvcrt", "__acrt_iob_func", [1])[0]
    path = fopen_text(se, "fopen", "c:\\users\\public\\log.txt")
    assert call(se, "msvcrt", "freopen", [path, fopen_text(se, "fopen", "w+"), stdout])[0] == stdout

    assert call(se, "msvcrt", "_write", [1, alloc(se, b"abc"), 3])[0] == 3
    call(se, "msvcrt", "fseek", [stdout, 0, 0])
    out = alloc(se, b"\x00" * 16)
    assert call(se, "msvcrt", "fread", [out, 1, 16, stdout])[0] == 3
    assert se.mem_read(out, 3) == b"abc"


@pytest.mark.parametrize("fd", [1, 2])
def test_write_to_a_standard_descriptor_succeeds(dll_emu: Speakeasy, fd: int) -> None:
    assert call(dll_emu, "msvcrt", "_write", [fd, alloc(dll_emu, b"abc"), 3])[0] == 3


@pytest.mark.parametrize("emu_name, size", [("dll_emu", 24), ("dll64_emu", 40)])
def test_vcrt_initialize_critical_section_ex_zeroes_the_critical_section(
    request: pytest.FixtureRequest, emu_name: str, size: int
) -> None:
    se = request.getfixturevalue(emu_name)
    cs = alloc(se, b"\xcc" * (size + 1))
    assert call(se, "vcruntime140", "__vcrt_InitializeCriticalSectionEx", [cs, 4000, 0])[0] == 1
    assert se.mem_read(cs, size + 1) == b"\x00" * size + b"\xcc"


def get_int64_result(se: Speakeasy, rv: int) -> int:
    assert se.emu is not None
    if se.emu.get_ptr_size() == 4:
        rv |= se.emu.reg_read(e_arch.X86_REG_EDX) << 32
    return rv & 0xFFFFFFFFFFFFFFFF


def get_errno(se: Speakeasy) -> int:
    errno_ptr, _ = call(se, "msvcrt", "_errno", [])
    return int.from_bytes(se.mem_read(errno_ptr, 4), "little")


@pytest.mark.parametrize("emu_name", ["dll_emu", "dll64_emu"])
@pytest.mark.parametrize(
    "api, text, base, value, used, overflow",
    [
        ("_strtoi64", '1,"x"', 10, 1, 1, False),
        ("_strtoi64", "  -0x1Fz", 0, -31, 7, False),
        ("_strtoi64", "9223372036854775807", 10, 2**63 - 1, 19, False),
        ("_strtoi64", "9223372036854775808", 10, 2**63 - 1, 19, True),
        ("_strtoi64", "-9223372036854775809", 10, -(2**63), 20, True),
        ("_strtoi64", "abc", 10, 0, 0, False),
        ("_strtoui64", "ffffffffffffffff", 16, 2**64 - 1, 16, False),
        ("_strtoui64", "-1", 10, 2**64 - 1, 2, False),
        ("_strtoui64", "18446744073709551616", 10, 2**64 - 1, 20, True),
        ("_wcstoi64", "  -42x", 10, -42, 5, False),
        ("_wcstoi64", "-99999999999999999999", 10, -(2**63), 21, True),
        ("_wcstoui64", "0x100000000", 0, 2**32, 11, False),
    ],
)
def test_strtoi64_parses_64_bit_values_and_saturates(
    request: pytest.FixtureRequest,
    emu_name: str,
    api: str,
    text: str,
    base: int,
    value: int,
    used: int,
    overflow: bool,
) -> None:
    se = request.getfixturevalue(emu_name)
    assert se.emu is not None
    width = 2 if api.startswith("_wcs") else 1
    ptr_size = se.emu.get_ptr_size()
    src = alloc(se, (text + "\0").encode("utf-16le" if width == 2 else "latin-1"))
    end = alloc(se, b"\xcc" * (ptr_size + 1))
    rv, _ = call(se, "msvcrt", api, [src, end, base])
    assert get_int64_result(se, rv) == value & 0xFFFFFFFFFFFFFFFF
    assert se.mem_read(end, ptr_size + 1) == (src + used * width).to_bytes(ptr_size, "little") + b"\xcc"
    assert (get_errno(se) == ERANGE) == overflow


@pytest.mark.parametrize("text, charset, rv", [("abc=def", "=;", 3), ("abc", "x", 3), ("", "a", 0), ("éa", "a", 1)])
def test_wcscspn_returns_the_length_of_the_leading_run_outside_the_set(
    dll_emu: Speakeasy, text: str, charset: str, rv: int
) -> None:
    args = [alloc(dll_emu, (s + "\0").encode("utf-16le")) for s in (text, charset)]
    assert call(dll_emu, "msvcrt", "wcscspn", args)[0] == rv


@pytest.mark.parametrize("api", ["_wtoi", "_wtol"])
@pytest.mark.parametrize(
    "text, rv",
    [("  -42x", 0xFFFFFFD6), ("300", 300), ("abc", 0), ("99999999999", 0x7FFFFFFF), ("-99999999999", 0x80000000)],
)
def test_wtoi_parses_leading_digits(dll_emu: Speakeasy, api: str, text: str, rv: int) -> None:
    assert call(dll_emu, "msvcrt", api, [alloc(dll_emu, (text + "\0").encode("utf-16le"))])[0] & 0xFFFFFFFF == rv


@pytest.mark.parametrize("emu_name", ["dll_emu", "dll64_emu"])
@pytest.mark.parametrize(
    "text, value",
    [("\t-42x", -42), ("4294967296", 2**32), ("99999999999999999999", 2**63 - 1), ("-99999999999999999999", -(2**63))],
)
def test_wtoi64_parses_a_64_bit_value(request: pytest.FixtureRequest, emu_name: str, text: str, value: int) -> None:
    se = request.getfixturevalue(emu_name)
    rv, _ = call(se, "msvcrt", "_wtoi64", [alloc(se, (text + "\0").encode("utf-16le"))])
    assert get_int64_result(se, rv) == value & 0xFFFFFFFFFFFFFFFF


def test_set_invalid_parameter_handler_returns_the_previous_handler(dll_emu: Speakeasy) -> None:
    assert call(dll_emu, "msvcr80", "_get_invalid_parameter_handler", [])[0] == 0
    assert call(dll_emu, "msvcr80", "_set_invalid_parameter_handler", [0x401000])[0] == 0
    assert call(dll_emu, "msvcr80", "_get_invalid_parameter_handler", [])[0] == 0x401000
    assert call(dll_emu, "msvcr80", "_set_invalid_parameter_handler", [0x402000])[0] == 0x401000


def test_thread_local_invalid_parameter_handler_is_per_thread(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    assert dll_emu.emu is not None
    first = dll_emu.emu.curr_thread
    assert call(dll_emu, "msvcrt", "_set_thread_local_invalid_parameter_handler", [0x401000])[0] == 0
    assert call(dll_emu, "msvcrt", "_get_thread_local_invalid_parameter_handler", [])[0] == 0x401000
    start_process(dll_emu)
    assert call(dll_emu, "msvcrt", "_get_thread_local_invalid_parameter_handler", [])[0] == 0
    dll_emu.emu.curr_thread = first
    assert call(dll_emu, "msvcrt", "_set_thread_local_invalid_parameter_handler", [0])[0] == 0x401000
    assert call(dll_emu, "msvcrt", "_get_invalid_parameter_handler", [])[0] == 0


@pytest.mark.parametrize("emu_name", ["dll_emu", "dll64_emu"])
def test_std_exception_copy_duplicates_an_owned_message(request: pytest.FixtureRequest, emu_name: str) -> None:
    se = request.getfixturevalue(emu_name)
    assert se.emu is not None
    ptr_size = se.emu.get_ptr_size()
    what = alloc(se, b"bad allocation\x00")
    src = alloc(se, what.to_bytes(ptr_size, "little") + b"\x01" + b"\x00" * (ptr_size - 1))
    dst = alloc(se, b"\x00" * ptr_size * 2 + b"\xcc")

    call(se, "vcruntime140", "__std_exception_copy", [src, dst])
    copy = int.from_bytes(se.mem_read(dst, ptr_size), "little")
    assert copy not in (0, what)
    assert se.mem_read(copy, 15) == b"bad allocation\x00"
    assert se.mem_read(dst + ptr_size, ptr_size + 1) == b"\x01" + b"\x00" * (ptr_size - 1) + b"\xcc"

    call(se, "vcruntime140", "__std_exception_destroy", [dst])
    assert se.mem_read(dst, ptr_size * 2 + 1) == b"\x00" * ptr_size * 2 + b"\xcc"


@pytest.mark.parametrize("emu_name", ["dll_emu", "dll64_emu"])
def test_std_exception_copy_shares_a_message_it_does_not_own(request: pytest.FixtureRequest, emu_name: str) -> None:
    se = request.getfixturevalue(emu_name)
    assert se.emu is not None
    ptr_size = se.emu.get_ptr_size()
    what = alloc(se, b"bad allocation\x00")
    src = alloc(se, what.to_bytes(ptr_size, "little") + b"\x00" * ptr_size)
    dst = alloc(se, b"\x00" * ptr_size * 2 + b"\xcc")

    call(se, "vcruntime140", "__std_exception_copy", [src, dst])
    assert se.mem_read(dst, ptr_size * 2 + 1) == what.to_bytes(ptr_size, "little") + b"\x00" * ptr_size + b"\xcc"

    call(se, "vcruntime140", "__std_exception_destroy", [dst])
    assert se.mem_read(dst, ptr_size * 2) == b"\x00" * ptr_size * 2
    assert se.mem_read(what, 15) == b"bad allocation\x00"
