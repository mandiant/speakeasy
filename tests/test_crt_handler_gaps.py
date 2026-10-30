import struct
from collections.abc import Iterator
from typing import Any

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv import arch as e_arch
from speakeasy.winenv.api.usermode.msvcrt import SIG_DFL, SIG_IGN, SIGABRT, SIGFPE, SIGSEGV
from tests.handler_harness import alloc, call, start_process


def dword(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def qword(value: int) -> bytes:
    return struct.pack("<Q", value)


@pytest.fixture(params=["x86", "amd64"])
def shellcode_emu(request: pytest.FixtureRequest, config: dict[str, Any]) -> Iterator[Speakeasy]:
    config["timeout"] = 5
    config["max_api_count"] = 200
    se = Speakeasy(config=config)
    try:
        se.run_shellcode(se.load_shellcode(data=b"\xc3", arch=request.param))
        yield se
    finally:
        se.shutdown()


def get_api_names(se: Speakeasy) -> list[str]:
    run = se.get_report().entry_points[-1]
    assert run.error is None
    return [event.api_name for event in run.events if event.event == "api"]


def test_execute_onexit_table_calls_the_registered_functions_in_reverse_order(config: dict[str, Any]) -> None:
    with Speakeasy(config=config) as se:
        se.run_shellcode(se.load_shellcode(data=b"\xc3", arch="x86"))
        emu = se.emu
        code, data = se.mem_alloc(0x1000), se.mem_alloc(0x1000)
        table, count, log, result = data, data + 0x10, data + 0x20, data + 0x30
        se.mem_write(result, dword(0xCCCCCCCC))

        functions = []
        for n in (1, 2, 3):
            function = code + 0x100 * n
            se.mem_write(function, b"\xa1" + dword(count) + b"\xc6\x80" + dword(log) + bytes([n]))
            se.mem_write(function + 12, b"\xff\x05" + dword(count) + b"\xc3")
            functions.append(function)

        main = b""
        for function in functions:
            main += b"\x68" + dword(function) + b"\x68" + dword(table)
            main += b"\xb8" + dword(emu.get_proc("ucrtbase", "_register_onexit_function")) + b"\xff\xd0\x83\xc4\x08"
        main += b"\x68" + dword(table)
        main += b"\xb8" + dword(emu.get_proc("ucrtbase", "_execute_onexit_table")) + b"\xff\xd0\x83\xc4\x04"
        main += b"\xa3" + dword(result) + b"\xc3"
        se.mem_write(code, main)

        se.call(code)

        names = get_api_names(se)
        assert names == ["msvcrt._register_onexit_function"] * 3 + ["msvcrt._execute_onexit_table"]
        assert se.mem_read(log, 4) == b"\x03\x02\x01\x00"
        assert se.mem_read(result, 4) == dword(0)
        assert se.mem_read(table, 12) == b"\x00" * 12


def test_register_onexit_function_appends_to_the_table(dll64_emu: Speakeasy) -> None:
    table = alloc(dll64_emu, b"\x00" * 24)
    assert call(dll64_emu, "ucrtbase", "_initialize_onexit_table", [table])[0] == 0
    for function in range(0x140001000, 0x140001000 + 40 * 0x10, 0x10):
        assert call(dll64_emu, "ucrtbase", "_register_onexit_function", [table, function])[0] == 0
    first, last, end = struct.unpack("<3Q", dll64_emu.mem_read(table, 24))
    assert last - first == 40 * 8 <= end - first
    assert struct.unpack("<40Q", dll64_emu.mem_read(first, 40 * 8)) == tuple(range(0x140001000, 0x140001280, 0x10))


@pytest.mark.parametrize("width", [4, 8])
def test_qsort_sorts_with_the_guest_comparator(shellcode_emu: Speakeasy, width: int) -> None:
    se = shellcode_emu
    emu = se.emu
    keys = [5, 1, 4, 2, 3, 0xFFFFFFFF]
    records = [dword(k) + dword(k * 10)[: width - 4] for k in keys]
    code, data = se.mem_alloc(0x1000), se.mem_alloc(0x1000)
    se.mem_write(data, b"".join(records))
    qsort = emu.get_proc("msvcrt", "qsort")
    compare = code + 0x800
    if emu.get_ptr_size() == 4:
        se.mem_write(compare, bytes.fromhex("8b4424048b008b4c24082b01c3"))
        main = b"\x68" + dword(compare) + b"\x68" + dword(width) + b"\x68" + dword(len(keys)) + b"\x68" + dword(data)
        main += b"\xb8" + dword(qsort) + b"\xff\xd0\x83\xc4\x10\xc3"
    else:
        se.mem_write(compare, bytes.fromhex("8b012b02c3"))
        main = b"\x48\x83\xec\x28\x48\xb9" + qword(data) + b"\xba" + dword(len(keys)) + b"\x41\xb8" + dword(width)
        main += b"\x49\xb9" + qword(compare) + b"\x48\xb8" + qword(qsort) + b"\xff\xd0\x48\x83\xc4\x28\xc3"
    se.mem_write(code, main)

    se.call(code)

    assert get_api_names(se) == ["msvcrt.qsort"]
    expected = sorted(records, key=lambda r: struct.unpack("<i", r[:4])[0])
    assert se.mem_read(data, width * len(keys)) == b"".join(expected)


def test_crtdll_raise_with_the_default_action_ends_the_process(dll_emu: Speakeasy) -> None:
    emu = dll_emu.emu
    emu.is_run_complete = False
    call(dll_emu, "crtdll", "raise", [SIGABRT])
    assert emu.is_run_complete


def test_raise_of_an_ignored_signal_returns_zero(dll_emu: Speakeasy) -> None:
    emu = dll_emu.emu
    emu.is_run_complete = False
    call(dll_emu, "crtdll", "signal", [SIGABRT, SIG_IGN])
    assert call(dll_emu, "crtdll", "raise", [SIGABRT])[0] == 0
    assert not emu.is_run_complete


@pytest.mark.parametrize("sig, args", [(SIGSEGV, (SIGSEGV,)), (SIGFPE, (SIGFPE, 0x8C))])
def test_raise_calls_the_signal_handler_once(dll_emu: Speakeasy, sig: int, args: tuple[int, ...]) -> None:
    emu = dll_emu.emu
    call(dll_emu, "msvcrt", "signal", [sig, 0x401000])
    assert call(dll_emu, "msvcrt", "raise", [sig])[0] is None
    assert [cb.function for cb in emu.get_current_run().guest_callbacks] == [0x401000]
    assert tuple(emu.get_func_argv(e_arch.CALL_CONV_CDECL, len(args))) == args
    assert call(dll_emu, "msvcrt", "signal", [sig, SIG_DFL])[0] == SIG_DFL


@pytest.mark.parametrize(
    "dll, api, argv",
    [
        ("api-ms-win-crt-runtime-l1-1-0", "_invalid_parameter_noinfo_noreturn", []),
        ("api-ms-win-crt-runtime-l1-1-0", "_invoke_watson", [0, 0, 0, 0, 0]),
        ("vcruntime140", "__std_terminate", []),
        ("vcruntime140", "_purecall", []),
        ("api-ms-win-crt-private-l1-1-0", "_o__purecall", []),
        ("api-ms-win-crt-runtime-l1-1-0", "_assert", [0, 0, 7]),
    ],
)
def test_fatal_error_functions_end_the_process(dll_emu: Speakeasy, dll: str, api: str, argv: list[int]) -> None:
    emu = dll_emu.emu
    emu.is_run_complete = False
    call(dll_emu, dll, api, argv)
    assert emu.is_run_complete


def test_assert_shows_the_message_and_the_file(dll_emu: Speakeasy) -> None:
    message = alloc(dll_emu, b"x > 0\x00")
    file = alloc(dll_emu, b"main.c\x00")
    _, displays = call(dll_emu, "ucrtbase", "_assert", [message, file, 12])
    assert displays[0] == "x > 0"
    assert displays[1] == "main.c"


@pytest.mark.parametrize("api", ["_invalid_parameter_noinfo", "_o__invalid_parameter_noinfo"])
def test_invalid_parameter_noinfo_returns_without_a_handler(dll_emu: Speakeasy, api: str) -> None:
    start_process(dll_emu)
    emu = dll_emu.emu
    emu.is_run_complete = False
    assert call(dll_emu, "api-ms-win-crt-private-l1-1-0", api, [])[0] is None
    assert not emu.is_run_complete
    assert not emu.get_current_run().guest_callbacks


def test_invalid_parameter_noinfo_calls_the_handler(dll_emu: Speakeasy) -> None:
    start_process(dll_emu)
    emu = dll_emu.emu
    call(dll_emu, "ucrtbase", "_set_invalid_parameter_handler", [0x401000])
    call(dll_emu, "ucrtbase", "_invalid_parameter_noinfo", [])
    assert [cb.function for cb in emu.get_current_run().guest_callbacks] == [0x401000]
    assert emu.get_func_argv(e_arch.CALL_CONV_CDECL, 5) == [0, 0, 0, 0, 0]


@pytest.mark.parametrize("emu_name", ["dll_emu", "dll64_emu"])
def test_iob_holds_the_standard_streams(request: pytest.FixtureRequest, emu_name: str) -> None:
    se: Speakeasy = request.getfixturevalue(emu_name)
    emu = se.emu
    size = 0x30 if emu.get_ptr_size() == 8 else 0x20
    iob = emu.get_proc("msvcrt", "_iob")
    assert call(se, "msvcrt", "__iob_func", [])[0] == iob
    assert call(se, "ucrtbase", "__acrt_iob_func", [2])[0] == iob + 2 * size
    assert emu.get_proc("crtdll", "_iob") == iob
    for fd in (0, 1, 2):
        assert call(se, "msvcrt", "_fileno", [iob + fd * size])[0] == fd


def test_wcsdup_copies_the_string_to_a_new_buffer(dll_emu: Speakeasy) -> None:
    src = alloc(dll_emu, "abc\0".encode("utf-16le"))
    dst, displays = call(dll_emu, "api-ms-win-crt-string-l1-1-0", "_wcsdup", [src])
    assert dst not in (0, src)
    assert dll_emu.mem_read(dst, 8) == "abc\0".encode("utf-16le")
    assert call(dll_emu, "msvcrt", "_wcsdup", [0])[0] == 0


@pytest.mark.parametrize(
    "text, base, value, used",
    [
        (" 0x1fZ", 0, 0x1F, 5),
        ("-1", 10, 0xFFFFFFFF, 2),
        ("99999999999", 10, 0xFFFFFFFF, 11),
        ("z", 10, 0, 0),
    ],
)
def test_wcstoul_parses_like_the_crt(dll_emu: Speakeasy, text: str, base: int, value: int, used: int) -> None:
    src = alloc(dll_emu, (text + "\0").encode("utf-16le"))
    end = alloc(dll_emu, b"\xcc" * 4)
    assert call(dll_emu, "api-ms-win-crt-convert-l1-1-0", "wcstoul", [src, end, base])[0] == value
    assert dll_emu.mem_read(end, 4) == dword(src + used * 2)


def open_stream(se: Speakeasy, data: bytes) -> int:
    path = alloc(se, b"c:\\users\\public\\stream.bin\x00")
    stream, _ = call(se, "msvcrt", "fopen", [path, alloc(se, b"w+b\x00")])
    assert stream
    assert call(se, "msvcrt", "fwrite", [alloc(se, data), 1, len(data), stream])[0] == len(data)
    return stream


def seek_args(se: Speakeasy, stream: int, offset: int, origin: int) -> list[int]:
    if se.emu.get_ptr_size() == 4:
        return [stream, offset & 0xFFFFFFFF, (offset >> 32) & 0xFFFFFFFF, origin]
    return [stream, offset & 0xFFFFFFFFFFFFFFFF, origin, 0]


@pytest.mark.parametrize("emu_name", ["dll_emu", "dll64_emu"])
def test_fseeki64_and_file_positions_move_the_stream(request: pytest.FixtureRequest, emu_name: str) -> None:
    se: Speakeasy = request.getfixturevalue(emu_name)
    stream = open_stream(se, b"abcdef")
    assert call(se, "ucrtbase", "_fseeki64", seek_args(se, stream, -4, 2))[0] == 0
    assert call(se, "msvcrt", "fgetc", [stream])[0] == ord("c")

    pos = alloc(se, b"\xcc" * 8)
    assert call(se, "msvcrt", "fgetpos", [stream, pos])[0] == 0
    assert se.mem_read(pos, 8) == qword(3)
    assert call(se, "msvcrt", "fgetc", [stream])[0] == ord("d")

    se.mem_write(pos, qword(1))
    assert call(se, "msvcrt", "fsetpos", [stream, pos])[0] == 0
    assert call(se, "msvcrt", "fgetc", [stream])[0] == ord("b")

    assert call(se, "ucrtbase", "_fseeki64", seek_args(se, stream, -1, 0))[0] == -1
    assert call(se, "ucrtbase", "_fseeki64", seek_args(se, 0x1234, 0, 0))[0] == -1


def test_ungetc_pushes_back_the_character_that_was_read(dll_emu: Speakeasy) -> None:
    stream = open_stream(dll_emu, b"abc")
    call(dll_emu, "msvcrt", "fseek", [stream, 0, 0])
    assert call(dll_emu, "msvcrt", "fgetc", [stream])[0] == ord("a")
    assert call(dll_emu, "msvcrt", "ungetc", [ord("a"), stream])[0] == ord("a")
    assert call(dll_emu, "msvcrt", "fgetc", [stream])[0] == ord("a")
    assert call(dll_emu, "msvcrt", "ungetc", [0xFFFFFFFF, stream])[0] == -1
    assert call(dll_emu, "msvcrt", "ungetc", [ord("z"), stream])[0] == -1
    assert call(dll_emu, "msvcrt", "fgetc", [stream])[0] == ord("b")


def test_mbrtowc_converts_one_byte(dll_emu: Speakeasy) -> None:
    out = alloc(dll_emu, b"\xcc" * 4)
    assert call(dll_emu, "ucrtbase", "mbrtowc", [out, alloc(dll_emu, b"\xe9z"), 2, 0])[0] == 1
    assert dll_emu.mem_read(out, 4) == b"\xe9\x00\xcc\xcc"
    assert call(dll_emu, "ucrtbase", "mbrtowc", [out, alloc(dll_emu, b"\x00"), 1, 0])[0] == 0
    assert dll_emu.mem_read(out, 2) == b"\x00\x00"
    assert call(dll_emu, "ucrtbase", "mbrtowc", [out, alloc(dll_emu, b"a"), 0, 0])[0] == -2
    assert call(dll_emu, "ucrtbase", "mbrtowc", [0, 0, 0, 0])[0] == 0


def test_mbsrtowcs_converts_the_whole_string(dll_emu: Speakeasy) -> None:
    text = alloc(dll_emu, b"abc\x00")
    src = alloc(dll_emu, dword(text))
    assert call(dll_emu, "ucrtbase", "mbsrtowcs", [0, src, 0, 0])[0] == 3
    assert dll_emu.mem_read(src, 4) == dword(text)

    dst = alloc(dll_emu, b"\xcc" * 10)
    assert call(dll_emu, "ucrtbase", "mbsrtowcs", [dst, src, 5, 0])[0] == 3
    assert dll_emu.mem_read(dst, 10) == "abc\0".encode("utf-16le") + b"\xcc\xcc"
    assert dll_emu.mem_read(src, 4) == dword(0)


def test_mbsrtowcs_stops_at_len_and_advances_the_source(dll_emu: Speakeasy) -> None:
    text = alloc(dll_emu, b"abc\x00")
    src = alloc(dll_emu, dword(text))
    dst = alloc(dll_emu, b"\xcc" * 6)
    assert call(dll_emu, "ucrtbase", "mbsrtowcs", [dst, src, 2, 0])[0] == 2
    assert dll_emu.mem_read(dst, 6) == "ab".encode("utf-16le") + b"\xcc\xcc"
    assert dll_emu.mem_read(src, 4) == dword(text + 2)
