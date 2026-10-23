import struct
from collections.abc import Callable
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
    SIGINT,
    SIGSEGV,
    STRUNCATE,
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


def test_realloc_uses_the_size_of_the_current_block_at_a_reused_address(dll_emu: Speakeasy) -> None:
    large, _ = call(dll_emu, "msvcrt", "malloc", [0x2000])
    call(dll_emu, "msvcrt", "free", [large])
    small, _ = call(dll_emu, "msvcrt", "malloc", [0x1000])
    assert small == large
    dll_emu.mem_write(small, b"\x5a" * 0x1000)
    grown, _ = call(dll_emu, "msvcrt", "realloc", [small, 0x3000])
    assert dll_emu.mem_read(grown, 0x1000) == b"\x5a" * 0x1000


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

    return write


@pytest.mark.parametrize("api", ["fputs", "fputc", "fprintf", "fwprintf", "vfprintf", "__stdio_common_vfprintf"])
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
