import struct
from collections.abc import Callable
from typing import Any

import pytest
import unicorn

from speakeasy import Speakeasy
from speakeasy.winenv.api.usermode.msvcrt import (
    ENOENT,
    ERANGE,
    SIG_DFL,
    SIG_ERR,
    SIG_IGN,
    SIGINT,
    SIGSEGV,
    STRUNCATE,
    scan_c_format,
)
from tests.handler_harness import alloc, call, load_emu


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
