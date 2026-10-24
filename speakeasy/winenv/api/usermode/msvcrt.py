# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import io
import math
import ntpath
import re
import struct
from datetime import datetime, timedelta, timezone
from typing import Any

import speakeasy.windows.seh32 as seh32
import speakeasy.winenv.arch as e_arch
import speakeasy.winenv.defs.windows.windows as windef
from speakeasy.profiler_events import FILE_WRITE

from .. import api, exception_apis

ENOENT = 2
EBADF = 9
EINVAL = 22
ERANGE = 34
THRD_SUCCESS = 0
O_TEXT = 0x4000
STRUNCATE = 80
_CRT_INTERNAL_PRINTF_LEGACY_VSPRINTF_NULL_TERMINATION = 1
_CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR = 2

TIME_BASE = 1576292568
S_IFREG_RW = 0x81B6
DRIVE_C = 2
RAND_BASE = 0
TICK_BASE = 86400000  # 1 day in millisecs
PERF_COUNTER_BASE = 0x5FD27D571F
PERF_FREQUENCY = 10_000_000

# Signal types
SIGINT = 2  # interrupt
SIGILL = 4  # illegal instruction - invalid function image
SIGFPE = 8  # floating point exception
SIGSEGV = 11  # segment violation
SIGTERM = 15  # Software termination signal from kill
SIGBREAK = 21  # Ctrl-Break sequence
SIGABRT = 22  # abnormal termination triggered by abort call

# Signal action codes
SIG_DFL = 0  # default signal action
SIG_IGN = 1  # ignore signal
SIG_GET = 2  # return current value
SIG_SGE = 3  # signal gets error
SIG_ACK = 4  # acknowledge
SIG_ERR = -1  # signal error value

# Messages of the errno values 0 to 42, in _sys_errlist order
SYS_ERRLIST = [
    "No error",
    "Operation not permitted",
    "No such file or directory",
    "No such process",
    "Interrupted function call",
    "Input/output error",
    "No such device or address",
    "Arg list too long",
    "Exec format error",
    "Bad file descriptor",
    "No child processes",
    "Resource temporarily unavailable",
    "Not enough space",
    "Permission denied",
    "Bad address",
    "Unknown error",
    "Resource device",
    "File exists",
    "Improper link",
    "No such device",
    "Not a directory",
    "Is a directory",
    "Invalid argument",
    "Too many open files in system",
    "Too many open files",
    "Inappropriate I/O control operation",
    "Unknown error",
    "File too large",
    "No space left on device",
    "Invalid seek",
    "Read-only file system",
    "Too many links",
    "Broken pipe",
    "Domain error",
    "Result too large",
    "Unknown error",
    "Resource deadlock avoided",
    "Unknown error",
    "Filename too long",
    "No locks available",
    "Function not implemented",
    "Directory not empty",
    "Illegal byte sequence",
]


DIGITS = b"0123456789abcdefghijklmnopqrstuvwxyz"


def get_digit(c: bytes, base: int) -> int:
    d = DIGITS.find(c.lower()) if len(c) == 1 else -1
    return d if d < base else -1


def parse_c_integer(text: bytes, base: int, width: int = 0) -> tuple[int, int]:
    """
    Parse an integer like strtol, from at most ``width`` bytes when ``width`` is
    not 0. Return the value and the number of bytes used. With no digits, the
    number of bytes used is 0.
    """
    if width:
        text = text[:width]
    i = len(text) - len(text.lstrip(b" \t\n\v\f\r"))
    sign = -1 if text[i : i + 1] == b"-" else 1
    i += text[i : i + 1] in (b"+", b"-")
    if base in (0, 16) and text[i : i + 2].lower() == b"0x" and get_digit(text[i + 2 : i + 3], 16) >= 0:
        base, i = 16, i + 2
    elif base == 0:
        base = 8 if text[i : i + 1] == b"0" else 10
    start = i
    val = 0
    while (d := get_digit(text[i : i + 1], base)) >= 0:
        val = val * base + d
        i += 1
    return (sign * val, i) if i > start else (0, 0)


SCANF_SPEC = re.compile(rb"%(\*?)(\d*)(hh|h|ll|l|L|I64|I32|I|j|z|t)?([%diouxXpneEfgGaAcs]|\[\^?\]?[^\]]*\])")
SCANF_FLOAT = re.compile(rb"[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?")
SCANF_SPACE = b" \t\n\v\f\r"


def get_scanf_set(spec: bytes) -> tuple[set[int], bool]:
    """Return the bytes of a %[...] set and whether the set is negated."""
    negate = spec.startswith(b"[^")
    body = spec[2 if negate else 1 : -1]
    chars: set[int] = set()
    i = 0
    while i < len(body):
        if i + 2 < len(body) and body[i + 1 : i + 2] == b"-":
            chars.update(range(min(body[i], body[i + 2]), max(body[i], body[i + 2]) + 1))
            i += 3
        else:
            chars.add(body[i])
            i += 1
    return chars, negate


def scan_c_format(text: bytes, fmt: bytes, ptr_size: int) -> tuple[list[bytes], int]:
    """
    Match ``text`` against a narrow scanf format. Return the bytes to store for
    each conversion that takes a pointer, in argument order, and the scanf
    return value. The integer, float, %s, %c, %[...] and %n conversions are
    supported, with widths, %* and length modifiers.
    """
    out: list[bytes] = []
    pos = i = assigned = 0
    while i < len(fmt):
        if fmt[i] in SCANF_SPACE:
            pos = len(text) - len(text[pos:].lstrip(SCANF_SPACE))
            i += 1
            continue
        m = SCANF_SPEC.match(fmt, i) if fmt[i : i + 1] == b"%" else None
        if m is None or m.group(4) == b"%":
            literal = fmt[i + 1] if m else fmt[i]
            if m:
                pos = len(text) - len(text[pos:].lstrip(SCANF_SPACE))
            if pos >= len(text):
                return out, assigned or -1
            if text[pos] != literal:
                break
            pos, i = pos + 1, (m.end() if m else i + 1)
            continue
        i = m.end()
        suppress, width, mod, conv = m.group(1), int(m.group(2) or 0), m.group(3) or b"", m.group(4)
        size = {b"hh": 1, b"h": 2, b"ll": 8, b"I64": 8, b"j": 8, b"I": ptr_size, b"z": ptr_size, b"t": ptr_size}.get(
            mod, 4
        )
        if conv == b"n":
            out.append((pos & ((1 << (8 * size)) - 1)).to_bytes(size, "little"))
            continue
        if conv[:1] not in (b"c", b"["):
            pos = len(text) - len(text[pos:].lstrip(SCANF_SPACE))
        if pos >= len(text):
            return out, assigned or -1
        rest = text[pos : pos + width] if width else text[pos:]
        if conv in b"diouxXp":
            base = {b"d": 10, b"i": 0, b"o": 8, b"u": 10}.get(conv, 16)
            val, used = parse_c_integer(rest, base)
            size = ptr_size if conv == b"p" else size
            data = (val & ((1 << (8 * size)) - 1)).to_bytes(size, "little")
        elif conv in b"eEfgGaA":
            fm = SCANF_FLOAT.match(rest)
            used = fm.end() if fm else 0
            data = struct.pack("<d" if mod in (b"l", b"L") else "<f", float(rest[:used])) if used else b""
        elif conv == b"c":
            used = width or 1
            data = rest[:used]
            if len(data) < used:
                break
        else:
            chars, negate = get_scanf_set(conv) if conv != b"s" else (set(SCANF_SPACE), True)
            used = next((k for k, b in enumerate(rest) if (b in chars) == negate), len(rest))
            data = rest[:used] + b"\x00"
        if not used:
            break
        pos += used
        if not suppress:
            out.append(data)
            assigned += 1
    return out, assigned


def get_winmain_command_line(cmdline: str) -> str:
    """Get the part of a command line that the CRT passes to WinMain, after the program name."""
    if cmdline.startswith('"'):
        end = cmdline.find('"', 1)
        pos = len(cmdline) if end < 0 else end + 1
    else:
        pos = next((i for i, c in enumerate(cmdline) if c in " \t"), len(cmdline))
    return cmdline[pos:].lstrip(" \t")


def get_full_path(cwd: str, path: str) -> str:
    """Resolve a path against a current directory, as the CRT _fullpath does."""
    drive, rest = ntpath.splitdrive(path)
    if not drive:
        path = (
            ntpath.join(ntpath.splitdrive(cwd)[0] + "\\", rest)
            if rest.startswith(("\\", "/"))
            else ntpath.join(cwd, path)
        )
    return ntpath.normpath(path)


def get_struct_tm(t: datetime) -> bytes:
    """Encode a time as a C struct tm."""
    tt = t.timetuple()
    return struct.pack(
        "<9i",
        tt.tm_sec,
        tt.tm_min,
        tt.tm_hour,
        tt.tm_mday,
        tt.tm_mon - 1,
        tt.tm_year - 1900,
        (tt.tm_wday + 1) % 7,
        tt.tm_yday - 1,
        0,
    )


class Msvcrt(api.ApiHandler):
    """
    Implements functions from various versions of the C runtime on Windows
    """

    name = "msvcrt"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.stdin = 0
        self.stdout = 1
        self.stderr = 2

        self.rand_int = RAND_BASE

        self.funcs: dict[str, Any] = {}
        self.data: dict[str, Any] = {}
        self.wintypes = windef

        self.tick_counter: int = TICK_BASE
        self.perf_counter: int = PERF_COUNTER_BASE
        self.errno_t: int | None = None
        self.file_streams: dict[int, Any] = {}
        self.signal_handlers: dict[int, int] = {}
        self.lconv: int | None = None
        self.locale_name: int | None = None
        self.strerror_buf: int | None = None
        self.lc_locale_names: int | None = None
        self.iob: int | None = None
        self.winmain_command_lines: dict[int, int] = {}
        self.tm_buf: int | None = None

        super().__get_hook_attrs__(self)

    def hex_to_double(self, x):
        x = x.to_bytes(8, "little")
        x = struct.unpack("d", x)[0]
        return x

    def read_cstr(self, addr, max_chars=0, width=1):
        """
        Read the bytes of a NUL-terminated string, without the NUL. The CRT
        string functions work on raw characters, which a decoded string can drop.
        """
        data = b""
        while not max_chars or len(data) < max_chars * width:
            char = self.mem_read(addr + len(data), width)
            if char == b"\x00" * width:
                break
            data += char
        return data

    def format_int32(self, val, radix):
        """
        Format a 32-bit int as _itoa does: signed in radix 10, unsigned in any
        other radix, with lowercase digits.
        """
        if not 2 <= radix <= 36:
            return ""
        val &= 0xFFFFFFFF
        sign = ""
        if radix == 10 and val & 0x80000000:
            sign = "-"
            val = 0x100000000 - val
        digits = ""
        while True:
            val, d = divmod(val, radix)
            digits = "0123456789abcdefghijklmnopqrstuvwxyz"[d] + digits
            if not val:
                return sign + digits

    def double_to_hex(self, x):
        return struct.unpack("<Q", struct.pack("<d", x))[0]

    @impdata("_acmdln")
    def _acmdln(self, ptr):
        """Command line global CRT variable"""

        _argv = self.emu.get_argv()
        _argv = " ".join(_argv).encode("utf-8")

        ptr_size = self.emu.get_ptr_size()

        p_cmdln = self.mem_alloc(len(_argv) + 1, base=None, tag="api.msvcrt.command_line")
        self.emu.mem_write(ptr, p_cmdln.to_bytes(ptr_size, "little"))
        self.emu.mem_write(p_cmdln, _argv + b"\x00")
        return ptr

    @impdata("_wcmdln")
    def _wcmdln(self, ptr):
        """Wide command line global CRT variable"""
        data = (" ".join(self.emu.get_argv()) + "\x00").encode("utf-16le")
        p_cmdln = self.mem_alloc(len(data), tag="api.msvcrt.command_line")
        self.emu.mem_write(ptr, p_cmdln.to_bytes(self.emu.get_ptr_size(), "little"))
        self.emu.mem_write(p_cmdln, data)
        return ptr

    @apihook("__p__wcmdln", argc=0)
    def __p__wcmdln(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """Wide command line global CRT variable"""
        return emu.get_proc("msvcrt", "_wcmdln")

    @apihook("__p__acmdln", argc=0)
    def __p__acmdln(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """Command line global CRT variable"""

        cmdln = emu.get_proc("msvcrt", "_acmdln")

        return cmdln

    def get_winmain_command_line_ptr(self, emu, width: int) -> int:
        ptr = self.winmain_command_lines.get(width)
        if ptr is None:
            tail = get_winmain_command_line(emu.get_current_process().cmdline)
            data = (tail + "\x00").encode("utf-16le" if width == 2 else "utf-8")
            ptr = self.mem_alloc(len(data), tag="api.msvcrt.winmain_command_line")
            self.mem_write(ptr, data)
            self.winmain_command_lines[width] = ptr
        return ptr

    @apihook("_sleep", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _sleep(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void _sleep(unsigned long duration);
        """
        return

    @apihook("_get_narrow_winmain_command_line", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _get_narrow_winmain_command_line(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """char* _get_narrow_winmain_command_line();"""
        return self.get_winmain_command_line_ptr(emu, 1)

    @apihook("_get_wide_winmain_command_line", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _get_wide_winmain_command_line(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """wchar_t* _get_wide_winmain_command_line();"""
        return self.get_winmain_command_line_ptr(emu, 2)

    @apihook("_onexit", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _onexit(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        _onexit_t _onexit(
            _onexit_t function
        )
        """

        (func,) = argv
        return func

    @apihook("atexit", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def atexit(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int atexit(
            void (__cdecl *func)(void)
        );
        """
        return 0

    @apihook("mbstowcs_s", argc=5, conv=e_arch.CALL_CONV_CDECL)
    def mbstowcs_s(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        errno_t mbstowcs_s(
            size_t *pReturnValue,
            wchar_t *wcstr,
            size_t sizeInWords,
            const char *mbstr,
            size_t count
        )
        """

        pReturnValue, wcstr, sizeInWords, mbstr, count = argv
        ptr_size = self.get_ptr_size()

        rv = 0
        if pReturnValue:
            self.mem_write(pReturnValue, (0).to_bytes(ptr_size, "little"))

        # Sanity checks
        if sizeInWords > 0 and not wcstr:
            rv = EINVAL
        elif not mbstr:
            rv = EINVAL
        elif sizeInWords == 0 and wcstr:
            rv = EINVAL
        else:
            is_truncated = count == self.get_max_int()
            if wcstr and not is_truncated:
                mbs = self.read_cstr(mbstr, max_chars=count) if count else b""
            else:
                mbs = self.read_cstr(mbstr)
            text = mbs.decode("latin-1")
            ctx.args[3].display = text

            n = len(text) + 1
            if wcstr:
                if n > sizeInWords:
                    if not is_truncated:
                        self.mem_write(wcstr, b"\x00\x00")
                        return ERANGE
                    n = sizeInWords
                    rv = STRUNCATE
                self.mem_write(wcstr, (text[: n - 1] + "\x00").encode("utf-16le"))
            if pReturnValue:
                self.mem_write(pReturnValue, n.to_bytes(ptr_size, "little"))

        return rv

    @apihook("_wcsnicmp", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _wcsnicmp(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _wcsnicmp(
            const wchar_t *string1,
            const wchar_t *string2,
            size_t count
        )
        """

        string1, string2, count = argv
        rv = 1
        if not count:
            return 0

        ws1 = self.read_wide_string(string1, max_chars=count)
        ws2 = self.read_wide_string(string2, max_chars=count)

        ctx.args[0].display = ws1
        ctx.args[1].display = ws2

        if ws1.lower() == ws2.lower():
            rv = 0

        return rv

    # Reference: https://wiki.osdev.org/Visual_C%2B%2B_Runtime
    @apihook("_initterm_e", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _initterm_e(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        static int _initterm_e(_PIFV * pfbegin,
                                 _PIFV * pfend)
        """

        pfbegin, pfend = argv

        rv = 0

        return rv

    @apihook("_initterm", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _initterm(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """static void _initterm (_PVFV * pfbegin, _PVFV * pfend)"""

        pfbegin, pfend = argv

        rv = 0

        return rv

    @apihook("__getmainargs", argc=5, conv=e_arch.CALL_CONV_CDECL)
    def __getmainargs(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int __getmainargs(
            int * _Argc,
            char *** _Argv,
            char *** _Env,
            int _DoWildCard,
            _startupinfo * _StartInfo);
        """

        _Argc, _Argv, _Env, _DoWildCard, _StartInfo = argv
        rv = 0

        ptr_size = self.get_ptr_size()
        _argv = emu.get_argv()

        argc = len(_argv)

        if _Argc:
            self.mem_write(_Argc, argc.to_bytes(4, "little"))

        if _Argv:
            argv_list = [(a + "\x00").encode("utf-8") for a in _argv]
            array_size = ptr_size * (len(argv_list) + 1)
            total = sum([len(a) for a in argv_list]) + array_size

            arg_mem = self.mem_alloc(size=total, tag="api.argv")
            pptr = arg_mem
            sptr = arg_mem + array_size

            for a in argv_list:
                self.mem_write(pptr, sptr.to_bytes(ptr_size, "little"))
                pptr += ptr_size
                self.mem_write(sptr, a)
                sptr += len(a)
            self.mem_write(pptr, b"\x00" * ptr_size)

            self.mem_write(_Argv, arg_mem.to_bytes(ptr_size, "little"))

        if _Env:
            env = emu.get_env()
            fmt_env = []
            total = ptr_size
            for k, v in env.items():
                envstr = f"{k}={v}\x00"
                envstr = envstr.encode("utf-8")
                total += len(envstr)
                fmt_env.append(envstr)
                total += ptr_size

            env_mem = self.mem_alloc(size=total, tag="api.envp")
            pptr = env_mem
            sptr = env_mem + ptr_size * (len(fmt_env) + 1)

            for v in fmt_env:
                self.mem_write(pptr, sptr.to_bytes(ptr_size, "little"))
                pptr += ptr_size
                self.mem_write(sptr, v)
                sptr += len(v)
            self.mem_write(pptr, b"\x00" * ptr_size)

            self.mem_write(_Env, env_mem.to_bytes(ptr_size, "little"))

        return rv

    @apihook("__GetMainArgs", argc=4, conv=e_arch.CALL_CONV_CDECL)
    def __GetMainArgs(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void __GetMainArgs(
            int * _Argc,
            char *** _Argv,
            char *** _Env,
            int _DoWildCard);
        """
        self.__getmainargs(emu, [*argv, 0], ctx)

    @apihook("__wgetmainargs", argc=5, conv=e_arch.CALL_CONV_CDECL)
    def __wgetmainargs(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int __wgetmainargs (
           int *_Argc,
           wchar_t ***_Argv,
           wchar_t ***_Env,
           int _DoWildCard,
           _startupinfo * _StartInfo);
        """

        _Argc, _Argv, _Env, _DoWildCard, _StartInfo = argv
        rv = 0

        return rv

    @apihook("__p___wargv", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __p___wargv(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """WCHAR *** __p___wargv ()"""

        ptr_size = self.get_ptr_size()
        _argv = emu.get_argv()

        argv = [(a + "\x00\x00\x00\x00").encode("utf-16le") for a in _argv]
        array_size = ptr_size * (len(argv) + 2)
        total = sum([len(a) for a in argv])
        total += array_size

        sptr = 0
        pptr = 0

        arg_mem = self.mem_alloc(size=total, tag="api.argv")
        pptr = arg_mem + ptr_size
        self.mem_write(arg_mem, pptr.to_bytes(ptr_size, "little"))
        sptr = pptr + array_size

        for a in argv:
            self.mem_write(pptr, sptr.to_bytes(ptr_size, "little"))
            pptr += ptr_size
            self.mem_write(sptr, a)
            sptr += len(a)
        self.mem_write(pptr, b"\x00" * ptr_size)
        rv = arg_mem

        # TODO: dispatch the VFV function array
        return rv

    @apihook("__p___argv", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __p___argv(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """char *** __p___argv ()"""

        ptr_size = self.get_ptr_size()
        _argv = emu.get_argv()

        argv = [(a + "\x00\x00\x00\x00").encode("utf-8") for a in _argv]

        array_size = ptr_size * (len(argv) + 2)
        total = sum([len(a) for a in argv])
        total += array_size

        sptr = 0
        pptr = 0

        arg_mem = self.mem_alloc(size=total, tag="api.argv")
        pptr = arg_mem + ptr_size
        self.mem_write(arg_mem, pptr.to_bytes(ptr_size, "little"))
        sptr = pptr + array_size

        for a in argv:
            self.mem_write(pptr, sptr.to_bytes(ptr_size, "little"))
            pptr += ptr_size
            self.mem_write(sptr, a)
            sptr += len(a)
        self.mem_write(pptr, b"\x00" * ptr_size)

        rv = arg_mem
        return rv

    @apihook("__p___argc", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __p___argc(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """int * __p___argc ()"""

        _argv = emu.get_argv()

        argc = self.mem_alloc(size=4, tag="api.argc")
        self.mem_write(argc, len(_argv).to_bytes(4, "little"))
        return argc

    @impdata("__initenv")
    def __initenv(self, ptr):
        """Writable char ** global, shared with __p___initenv."""
        self.mem_write(ptr, b"\x00" * self.get_ptr_size())
        return ptr

    @apihook("__p___initenv", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __p___initenv(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """char *** __p___initenv ()"""
        return emu.get_proc("msvcrt", "__initenv")

    @impdata("_environ")
    def _environ(self, ptr):
        """Writable char ** global, shared with __p__environ."""
        envp = self._get_initial_narrow_environment(self.emu, [])
        self.mem_write(ptr, envp.to_bytes(self.get_ptr_size(), "little"))
        return ptr

    @apihook("__p__environ", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __p__environ(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """char *** __p__environ ()"""
        return emu.get_proc("msvcrt", "_environ")

    @impdata("_wenviron")
    def _wenviron(self, ptr):
        """Writable wchar_t ** global, shared with __p__wenviron."""
        envp = self._get_initial_wide_environment(self.emu, [])
        self.mem_write(ptr, envp.to_bytes(self.get_ptr_size(), "little"))
        return ptr

    @apihook("__p__wenviron", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __p__wenviron(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """wchar_t *** __p__wenviron ()"""
        return emu.get_proc("msvcrt", "_wenviron")

    @apihook("_get_initial_narrow_environment", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _get_initial_narrow_environment(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """char** _get_initial_narrow_environment ()"""

        ptr_size = self.get_ptr_size()
        env = emu.get_env()
        total = ptr_size
        sptr = total
        pptr = 0
        fmt_env = []
        for k, v in env.items():
            envstr = f"{k}={v}\x00"
            envstr = envstr.encode("utf-8")
            total += len(envstr)
            fmt_env.append(envstr)
            total += ptr_size
            sptr += ptr_size

        envp = self.mem_alloc(size=total, tag="api.envp")
        pptr = envp
        sptr += envp

        for v in fmt_env:
            self.mem_write(pptr, sptr.to_bytes(ptr_size, "little"))
            pptr += ptr_size
            self.mem_write(sptr, v)
            sptr += len(v)

        return envp

    @apihook("_get_initial_wide_environment", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _get_initial_wide_environment(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """WCHAR** _get_initial_wide_environment ()"""

        ptr_size = self.get_ptr_size()
        env = emu.get_env()
        total = ptr_size
        sptr = total
        pptr = 0
        fmt_env = []
        for k, v in env.items():
            envstr = f"{k}={v}\x00"
            envstr = envstr.encode("utf-16le")
            total += len(envstr)
            fmt_env.append(envstr)
            total += ptr_size
            sptr += ptr_size

        envp = self.mem_alloc(size=total, tag="api.envp")
        pptr = envp
        sptr += envp

        for v in fmt_env:
            self.mem_write(pptr, sptr.to_bytes(ptr_size, "little"))
            pptr += ptr_size
            self.mem_write(sptr, v)
            sptr += len(v)

        return envp

    @apihook("exit", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def exit(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void exit(
           int const status
        );
        """

        self.exit_process()

    @apihook("_exit", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _exit(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void _exit(
           int const status
        );
        """

        self.exit_process()

    @apihook("_amsg_exit", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _amsg_exit(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void _amsg_exit(
           int rterrnum
        );
        """

        self.exit_process()

    @apihook("abort", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def abort(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void abort(void);
        """

        self.exit_process()

    @apihook("_XcptFilter", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _XcptFilter(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _XcptFilter(
            unsigned long xcptnum,
            struct _EXCEPTION_POINTERS *pxcptinfoptrs
        );
        """
        _xcptnum, _pxcptinfoptrs = argv

        return 0

    @apihook("_CxxThrowException", argc=2, conv=e_arch.CALL_CONV_STDCALL)
    def _CxxThrowException(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void _CxxThrowException(
            void *pExceptionObject,
            _ThrowInfo *pThrowInfo
        );
        """
        return

    @apihook("__acrt_iob_func", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def __acrt_iob_func(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """FILE * __acrt_iob_func (fd)"""

        (fd,) = argv

        return fd

    @apihook("__iob_func", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __iob_func(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        FILE *__iob_func(void);

        Return the _iob array of stdin, stdout, and stderr. A FILE is 0x20
        bytes on x86 and 0x30 bytes on x64, and _file is its fifth field.
        """
        if self.iob:
            return self.iob

        size, file_offset = (0x30, 0x1C) if self.get_ptr_size() == 8 else (0x20, 0x10)
        self.iob = self.mem_alloc(size * 3, tag="api.msvcrt._iob")
        for fd in (self.stdin, self.stdout, self.stderr):
            self.mem_write(self.iob + fd * size + file_offset, fd.to_bytes(4, "little"))
        return self.iob

    @apihook("pow", argc=2, conv=e_arch.CALL_CONV_FLOAT)
    def pow(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        double pow(
           double x,
           double y
        );
        """
        x, y = argv

        x = self.hex_to_double(x)
        y = self.hex_to_double(y)

        z = pow(x, y)

        z = self.double_to_hex(z)

        return z

    @apihook("floor", argc=1, conv=e_arch.CALL_CONV_FLOAT)
    def floor(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        double floor(
           double x
        );
        """
        (x,) = argv

        y = self.hex_to_double(x)
        z = math.floor(y)
        z = self.double_to_hex(z)

        return z

    @apihook("sin", argc=1, conv=e_arch.CALL_CONV_FLOAT)
    def sin(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        double sin(
           double x
        );
        """
        (x,) = argv

        y = self.hex_to_double(x)
        z = math.sin(y)
        z = self.double_to_hex(z)

        return z

    @apihook("abs", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def abs(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int abs(
           int x
        );
        """
        (x,) = argv
        y = abs(x)
        return y

    @apihook("strstr", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def strstr(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        char *strstr(
           const char *str,
           const char *strSearch
        );
        """
        hay, needle = argv

        _hay = self.read_cstr(hay)
        _needle = self.read_cstr(needle)
        ctx.args[0].display = _hay.decode("utf-8", "ignore")
        ctx.args[1].display = _needle.decode("utf-8", "ignore")

        ret = _hay.find(_needle)
        return hay + ret if ret != -1 else 0

    @apihook("strcspn", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def strcspn(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        size_t strcspn(
           const char *str,
           const char *strCharSet
        );
        """
        s, charset = argv

        _s = self.read_cstr(s)
        _charset = set(self.read_cstr(charset))
        ctx.args[0].display = _s.decode("utf-8", "ignore")
        ctx.args[1].display = bytes(sorted(_charset)).decode("utf-8", "ignore")
        return next((i for i, c in enumerate(_s) if c in _charset), len(_s))

    @apihook("strpbrk", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def strpbrk(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        char *strpbrk(
           const char *str,
           const char *strCharSet
        );
        """
        s, charset = argv

        _s = self.read_cstr(s)
        _charset = set(self.read_cstr(charset))
        ctx.args[0].display = _s.decode("utf-8", "ignore")
        ctx.args[1].display = bytes(sorted(_charset)).decode("utf-8", "ignore")
        return next((s + i for i, c in enumerate(_s) if c in _charset), 0)

    @apihook("wcsstr", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def wcsstr(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        wchar_t *wcsstr(
            const wchar_t *str,
            const wchar_t *strSearch
        );
        """
        hay, needle = argv

        if hay:
            _hay = self.read_mem_string(hay, 2)
            ctx.args[0].display = _hay

        if needle:
            needle = self.read_mem_string(needle, 2)
            ctx.args[1].display = needle

        ret = _hay.find(needle)
        if ret != -1:
            ret = hay + ret * 2
        else:
            ret = 0

        return ret

    @apihook("strncat_s", argc=4, conv=e_arch.CALL_CONV_CDECL)
    def strncat_s(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        errno_t strncat_s(
           char *strDest,
           size_t numberOfElements,
           const char *strSource,
           size_t count
        );
        """
        strDest, num, src, count = argv

        is_truncated = count == self.get_max_int()

        s1 = self.read_cstr(strDest)
        s2 = self.read_cstr(src, max_chars=0 if is_truncated else count) if count else b""
        ctx.args[0].display = s1.decode("utf-8", "ignore")
        ctx.args[2].display = s2.decode("utf-8", "ignore")

        rem = num - len(s1)
        if rem <= 0:
            return EINVAL

        if len(s2) < rem:
            self.mem_write(strDest + len(s1), s2 + b"\x00")
            return 0

        if is_truncated:
            self.mem_write(strDest + len(s1), s2[: rem - 1] + b"\x00")
            return STRUNCATE

        self.mem_write(strDest, b"\x00")
        return ERANGE

    @apihook("__stdio_common_vfprintf", argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def __stdio_common_vfprintf(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        arch = emu.get_arch()
        if arch == e_arch.ARCH_AMD64:
            opts, stream, fmt, _, va_list = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 5)[:5]
        else:
            opts, opts2, stream, fmt, _, va_list = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 6)[:6]

        rv = 0

        fmt_str = self.read_mem_string(fmt, 1)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args(va_list, fmt_cnt)
        fin = self.do_str_format(fmt_str, vargs)

        ctx.args.clear()
        ctx.args.append(hex(opts))
        ctx.args.append(hex(stream))
        ctx.args.append(fin)
        self.write_stream(stream, fin.encode("latin-1", "replace"))

        rv = len(fin)
        return rv

    @apihook("fprintf", argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def fprintf(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int fprintf(
            FILE *stream,
            const char *format,
            ...
            );
        """
        stream, fmt = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 2)
        fmt_str = self.read_string(fmt)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        _argv = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 2 + fmt_cnt)[2:]
        fin = self.do_str_format(fmt_str, _argv)
        ctx.args.clear()
        ctx.args.append(hex(stream))
        ctx.args.append(fin)
        self.write_stream(stream, fin.encode("latin-1", "replace"))
        return len(fin)

    @apihook("fwprintf", argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def fwprintf(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int fwprintf(
            FILE *stream,
            const wchar_t *format,
            ...
            );
        """
        stream, fmt = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 2)
        fmt_str = self.read_wide_string(fmt)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        _argv = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 2 + fmt_cnt)[2:]
        fin = self.do_str_format(fmt_str, _argv, wide=True)
        ctx.args.clear()
        ctx.args.append(hex(stream))
        ctx.args.append(fin)
        self.write_stream(stream, fin.encode("latin-1", "replace"))
        return len(fin)

    @apihook("vfprintf", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def vfprintf(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int vfprintf(
            FILE *stream,
            const char *format,
            va_list argptr
            );
        """
        stream, fmt, argptr = argv
        fmt_str = self.read_string(fmt)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        fin = self.do_str_format(fmt_str, self.va_args(argptr, fmt_cnt))
        ctx.args.clear()
        ctx.args.append(hex(stream))
        ctx.args.append(fin)
        self.write_stream(stream, fin.encode("latin-1", "replace"))
        return len(fin)

    @apihook("printf", argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def printf(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int printf(
            const char *format,
            ...
            );
        """
        (fmt,) = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 1)
        fmt_str = self.read_string(fmt)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        fmt_argv = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 1 + fmt_cnt)[1:]
        fin = self.do_str_format(fmt_str, fmt_argv)
        ctx.args.clear()
        ctx.args.append(fin)
        return len(fin)

    @apihook("memset", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def memset(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void *memset ( void * ptr,
                       int value,
                       size_t num );
        """

        ptr, value, num = argv

        data = bytes([value & 0xFF]) * num
        self.mem_write(ptr, data)

        return ptr

    @apihook("time", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def time(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        time_t time( time_t *destTime );
        """

        (destTime,) = argv

        out_time = TIME_BASE
        if destTime:
            self.mem_write(destTime, out_time.to_bytes(self.get_ptr_size(), "little"))

        return out_time

    def get_time_size(self, emu) -> int:
        # x86 msvcrt.dll uses a 32-bit time_t
        return emu.get_ptr_size()

    def write_struct_tm(self, timer: int, emu) -> int:
        if not timer:
            return 0
        value = int.from_bytes(self.mem_read(timer, self.get_time_size(emu)), "little", signed=True)
        if value < 0:
            return 0
        try:
            t = datetime.fromtimestamp(value, timezone.utc)
        except (ValueError, OverflowError, OSError):
            return 0
        if self.tm_buf is None:
            self.tm_buf = self.mem_alloc(36, tag="api.msvcrt.tm")
        self.mem_write(self.tm_buf, get_struct_tm(t))
        return self.tm_buf

    @apihook("localtime", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def localtime(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        struct tm *localtime(const time_t *sourceTime);
        """
        # The emulated time zone is UTC
        (timer,) = argv
        return self.write_struct_tm(timer, emu)

    @apihook("gmtime", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def gmtime(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        struct tm *gmtime(const time_t *sourceTime);
        """
        (timer,) = argv
        return self.write_struct_tm(timer, emu)

    @apihook("mktime", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def mktime(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        time_t mktime(struct tm *timeptr);
        """
        (tm,) = argv
        sec, minute, hour, mday, mon, year = struct.unpack("<6i", self.mem_read(tm, 24))
        year, mon = year + 1900 + mon // 12, mon % 12
        try:
            t = datetime(year, mon + 1, 1, tzinfo=timezone.utc) + timedelta(
                days=mday - 1, hours=hour, minutes=minute, seconds=sec
            )
        except (ValueError, OverflowError):
            return -1
        value = int(t.timestamp())
        if value < 0 or value >= 1 << (8 * self.get_time_size(emu) - 1):
            return -1
        self.mem_write(tm, get_struct_tm(t))
        return value

    @apihook("_strtime", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _strtime(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        char *_strtime(char *buffer);
        """
        (buffer,) = argv
        if not buffer:
            return 0
        self.mem_write(buffer, b"12:34:56\x00")
        return buffer

    @apihook("_strdate", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _strdate(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        char *_strdate(char *buffer);
        """
        (buffer,) = argv
        if not buffer:
            return 0
        self.mem_write(buffer, b"12/29/19\x00")
        return buffer

    @apihook("clock", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def clock(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        clock_t clock( void );
        """

        self.tick_counter += 200

        return self.tick_counter

    def return_int64(self, emu, value: int) -> int:
        if emu.get_arch() == e_arch.ARCH_X86:
            emu.reg_write(e_arch.X86_REG_EDX, value >> 32)
            return value & 0xFFFFFFFF
        return value

    @apihook("_Query_perf_frequency", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _Query_perf_frequency(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """long long _Query_perf_frequency();"""
        return self.return_int64(emu, PERF_FREQUENCY)

    @apihook("_Query_perf_counter", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _Query_perf_counter(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """long long _Query_perf_counter();"""
        self.perf_counter += PERF_FREQUENCY // 50
        return self.return_int64(emu, self.perf_counter)

    @apihook("srand", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def srand(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void srand (unsigned int seed);
        """

        (seed,) = argv

        return

    @apihook("sprintf", argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def sprintf(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int sprintf(
            char *buffer,
            const char *format [,
            argument] ...
            );
        """
        buf, fmt = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 2)
        fmt_str = self.read_string(fmt)
        fmt_cnt = self.get_va_arg_count(fmt_str)
        _argv = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 2 + fmt_cnt)[2:]
        fin = self.do_str_format(fmt_str, _argv)

        self.write_string(fin, buf)
        ctx.args.clear()
        ctx.args.append(fin)
        return len(fin)

    @apihook("_snprintf", argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def _snprintf(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _snprintf(
        char *buffer,
        size_t count,
        const char *format [,
        argument] ...
        );
        """
        buf, count, fmt = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 3)
        fmt_str = self.read_string(fmt)
        fmt_cnt = self.get_va_arg_count(fmt_str)
        _argv = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 3 + fmt_cnt)[3:]
        fin = self.do_str_format(fmt_str, _argv)
        ctx.args.clear()
        ctx.args.append(fin)

        out = fin[:count].encode("utf-8")
        if len(fin) < count:
            out += b"\x00"
        self.mem_write(buf, out)
        return len(fin) if len(fin) <= count else -1

    @apihook("atoi", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def atoi(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int atoi(
            const char *str
        );
        """

        (_str,) = argv

        i = self.read_cstr(_str)
        ctx.args[0].display = i.decode("utf-8", "ignore")

        m = re.match(rb"[ \t\n\v\f\r]*([+-]?[0-9]+)", i)
        if not m:
            return 0
        return max(-0x80000000, min(int(m.group(1)), 0x7FFFFFFF))

    @apihook("rand", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def rand(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int rand( void );
        """

        self.rand_int += 1

        return self.rand_int

    @apihook("rand_s", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def rand_s(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        errno_t rand_s(unsigned int* randomValue);
        """
        (out,) = argv
        if not out:
            return EINVAL
        self.rand_int += 1
        self.mem_write(out, (self.rand_int & 0xFFFFFFFF).to_bytes(4, "little"))
        return 0

    @apihook("__set_app_type", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def __set_app_type(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void __set_app_type (
            int at
        )
        """
        return

    @apihook("_set_app_type", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _set_app_type(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        return

    @impdata("_fmode")
    def _fmode(self, ptr):
        """Writable file-mode global, initialized to _O_TEXT."""
        _O_TEXT = 0x4000

        self.mem_write(ptr, _O_TEXT.to_bytes(4, "little"))
        return ptr

    @apihook("__p__fmode", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __p__fmode(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """int* __p__fmode();"""
        return emu.get_proc("msvcrt", "_fmode")

    @impdata("_commode")
    def _commode(self, ptr):
        """Writable commit-mode global, initialized to _IOCOMMIT."""
        _IOCOMMIT = 0x4000

        self.mem_write(ptr, _IOCOMMIT.to_bytes(4, "little"))
        return ptr

    @apihook("__p__commode", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __p__commode(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """int* __p__commode();"""
        return emu.get_proc("msvcrt", "_commode")

    @apihook("_controlfp", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _controlfp(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        unsigned int _controlfp(unsigned int new,
                                unsinged int mask)
        """
        return 0

    @apihook("strcpy", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def strcpy(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        char *strcpy(
           char *strDestination,
           const char *strSource
        );
        """
        dest, src = argv
        s = self.read_cstr(src)

        self.mem_write(dest, s + b"\x00")
        ctx.args[1].display = s.decode("utf-8", "ignore")
        return dest

    @apihook("strcpy_s", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def strcpy_s(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        errno_t strcpy_s(
           char *dest,
           rsize_t dest_size,
           const char *src
        );
        """
        dest, size, src = argv
        if not dest or not size:
            return EINVAL
        if not src:
            self.mem_write(dest, b"\x00")
            return EINVAL
        s = self.read_cstr(src)
        ctx.args[2].display = s.decode("utf-8", "ignore")
        if len(s) >= size:
            self.mem_write(dest, b"\x00")
            return ERANGE
        self.mem_write(dest, s + b"\x00")
        return 0

    @apihook("wcscpy_s", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def wcscpy_s(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        errno_t wcscpy_s(
           wchar_t *dest,
           rsize_t dest_size,
           const wchar_t *src
        );
        """
        dest, size, src = argv
        if not dest or not size:
            return EINVAL
        if not src:
            self.mem_write(dest, b"\x00\x00")
            return EINVAL
        ws = self.read_wide_string(src)
        ctx.args[2].display = ws
        if len(ws) >= size:
            self.mem_write(dest, b"\x00\x00")
            return ERANGE
        self.write_wide_string(ws + "\x00", dest)
        return 0

    @apihook("wcscpy", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def wcscpy(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        wchar_t *wcscpy(
            wchar_t *strDestination,
            const wchar_t *strSource
        );
        """
        dest, src = argv
        ws = self.read_wide_string(src)
        self.write_wide_string(ws, dest)
        ctx.args[1].display = ws
        return dest

    @apihook("strncpy", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def strncpy(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        char * strncpy(
            char * destination,
            const char * source,
            size_t num
        );
        """
        dest, src, length = argv
        if length:
            s = self.read_cstr(src, max_chars=length)
            self.mem_write(dest, s.ljust(length, b"\x00"))
            ctx.args[1].display = s.decode("utf-8", "ignore")
        return dest

    @apihook("wcsncpy", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def wcsncpy(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        wchar_t *wcsncpy(
           wchar_t *strDest,
           const wchar_t *strSource,
           size_t count
        );
        """
        dest, src, count = argv
        if count:
            ws = self.read_cstr(src, max_chars=count, width=2)
            self.mem_write(dest, ws.ljust(count * 2, b"\x00"))
            ctx.args[1].display = ws.decode("utf-16le", "ignore")
        return dest

    @apihook("memcpy", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def memcpy(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void *memcpy(
            void *dest,
            const void *src,
            size_t count
            );
        """
        dest, src, count = argv
        data = self.mem_read(src, count)
        self.mem_write(dest, data)
        return dest

    @apihook("memmove", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def memmove(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void *memmove(
            void *dest,
            const void *src,
            size_t count
        );
        """
        dest, src, count = argv
        data = self.mem_read(src, count)
        self.mem_write(dest, data)
        return dest

    @apihook("memcmp", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def memcmp(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int memcmp(
           const void *buffer1,
           const void *buffer2,
           size_t count
        );
        """
        buff1, buff2, cnt = argv
        b1 = self.mem_read(buff1, cnt)
        b2 = self.mem_read(buff2, cnt)
        return (b1 > b2) - (b1 < b2)

    @apihook("_except_handler4_common", argc=6, conv=e_arch.CALL_CONV_CDECL)
    def _except_handler4_common(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        EXCEPTION_DISPOSITION _except_handler4_common(
            PUINT_PTR CookiePointer,
            PCOOKIE_CHECK CookieCheckFunction,
            PEXCEPTION_RECORD ExceptionRecord,
            PEXCEPTION_REGISTRATION_RECORD EstablisherFrame,
            PCONTEXT ContextRecord,
            PVOID DispatcherContext
        );
        """
        return seh32.except_handler4_common(emu, *argv)

    @apihook("_seh_filter_exe", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _seh_filter_exe(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int __cdecl _seh_filter_exe(
           unsigned long _ExceptionNum,
           struct _EXCEPTION_POINTERS* _ExceptionPtr
        );
        """
        except_num, exc_ptr = argv
        rv = 1

        return rv

    @apihook("__C_specific_handler", argc=4, conv=e_arch.CALL_CONV_CDECL)
    def __C_specific_handler(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        EXCEPTION_DISPOSITION __C_specific_handler(
            PEXCEPTION_RECORD ExceptionRecord,
            PVOID EstablisherFrame,
            PCONTEXT ContextRecord,
            PDISPATCHER_CONTEXT DispatcherContext
        );
        """
        return exception_apis.c_specific_handler(emu, argv)

    @apihook("_except_handler3", argc=4, conv=e_arch.CALL_CONV_CDECL)
    def _except_handler3(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        EXCEPTION_DISPOSITION _except_handler3(
            PEXCEPTION_RECORD ExceptionRecord,
            PEXCEPTION_REGISTRATION_RECORD EstablisherFrame,
            PCONTEXT ContextRecord,
            PVOID DispatcherContext
        );
        """
        return seh32.except_handler3(emu, *argv)

    @apihook("_seh_filter_dll", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _seh_filter_dll(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int __cdecl _seh_filter_dll(
           unsigned long _ExceptionNum,
           struct _EXCEPTION_POINTERS* _ExceptionPtr
        );
        """
        except_num, exc_ptr = argv
        rv = 1

        return rv

    @apihook("puts", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def puts(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int puts(
           const char *str
        );
        """
        (s,) = argv

        string = self.read_mem_string(s, 1)
        ctx.args[0].display = string
        rv = len(string)

        return rv

    @apihook("_initialize_onexit_table", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _initialize_onexit_table(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _initialize_onexit_table(
            _onexit_table_t* table
            );
        """
        rv = 0

        return rv

    @apihook("_register_onexit_function", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _register_onexit_function(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _register_onexit_function(
            _onexit_table_t* table,
            _onexit_t        function
            );
        """
        rv = 0

        return rv

    @apihook("malloc", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def malloc(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void *malloc(
        size_t size
        );
        """
        (size,) = argv

        chunk = self.heap_alloc(size, heap="HeapAlloc")
        return chunk

    @apihook("_strdup", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _strdup(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        char *_strdup(
            const char *strSource
        );
        """
        (src,) = argv
        if not src:
            return 0
        data = self.read_cstr(src) + b"\x00"
        dst = self.heap_alloc(len(data), heap="HeapAlloc")
        self.mem_write(dst, data)
        return dst

    @apihook("_mbsdup", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _mbsdup(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        unsigned char *_mbsdup(
            const unsigned char *strSource
        );
        """
        return self._strdup(emu, argv, ctx)

    @apihook("realloc", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def realloc(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void *realloc(
            void *memblock,
            size_t size
        );
        """
        mem, size = argv
        if mem and not size:
            self.mem_free(mem)
            return 0
        dst = self.heap_alloc(size, heap="HeapAlloc")
        if mem:
            old = next((n for a, n, _ in reversed(emu.heap_allocs) if a == mem), None)
            if old is None:
                mm = emu.get_address_map(mem)
                old = mm.base + mm.size - mem if mm else 0
            self.mem_write(dst, self.mem_read(mem, min(old, size)))
            self.mem_free(mem)
        return dst

    @apihook("getenv", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def getenv(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        char *getenv(
            const char *varname
        );
        """
        (name,) = argv
        key = self.read_cstr(name).decode("latin-1")
        ctx.args[0].display = key
        val = next((v for k, v in emu.get_env().items() if k.lower() == key.lower()), None)
        if val is None:
            return 0
        data = val.encode("latin-1") + b"\x00"
        dst = self.heap_alloc(len(data), heap="HeapAlloc")
        self.mem_write(dst, data)
        return dst

    def dupenv(self, emu, argv, ctx, width):
        buffer, count, name = argv
        key = self.read_mem_string(name, width) if name else ""
        ctx.args[2].display = key
        if not buffer or not name:
            self.set_errno(EINVAL)
            return EINVAL
        ptr_size = self.get_ptr_size()
        val = next((v for k, v in emu.get_env().items() if k.lower() == key.lower()), None)
        dst = 0
        if val is not None:
            data = (val + "\x00").encode("utf-16le" if width == 2 else "latin-1")
            dst = self.heap_alloc(len(data), heap="HeapAlloc")
            self.mem_write(dst, data)
        self.mem_write(buffer, dst.to_bytes(ptr_size, "little"))
        if count:
            self.mem_write(count, (len(val) + 1 if val is not None else 0).to_bytes(ptr_size, "little"))
        return 0

    @apihook("_dupenv_s", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _dupenv_s(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        errno_t _dupenv_s(
            char **buffer,
            size_t *numberOfElements,
            const char *varname
        );
        """
        return self.dupenv(emu, argv, ctx, 1)

    @apihook("_wdupenv_s", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _wdupenv_s(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        errno_t _wdupenv_s(
            wchar_t **buffer,
            size_t *numberOfElements,
            const wchar_t *varname
        );
        """
        return self.dupenv(emu, argv, ctx, 2)

    @apihook("memchr", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def memchr(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void *memchr(
            const void *buffer,
            int c,
            size_t count
        );
        """
        buf, c, count = argv
        needle = bytes([c & 0xFF])
        for off in range(0, count, 0x1000):
            i = self.mem_read(buf + off, min(0x1000, count - off)).find(needle)
            if i >= 0:
                return buf + off + i
        return 0

    @apihook("strtol", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def strtol(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        long strtol(
            const char *strSource,
            char **endptr,
            int base
        );
        """
        src, endptr, base = argv
        val, used = parse_c_integer(self.read_cstr(src), base)
        if endptr:
            emu.write_ptr(endptr, src + used)
        return max(-0x80000000, min(val, 0x7FFFFFFF))

    @apihook("strtoul", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def strtoul(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        unsigned long strtoul(
            const char *strSource,
            char **endptr,
            int base
        );
        """
        src, endptr, base = argv
        val, used = parse_c_integer(self.read_cstr(src), base)
        if endptr:
            emu.write_ptr(endptr, src + used)
        return 0xFFFFFFFF if abs(val) > 0xFFFFFFFF else val & 0xFFFFFFFF

    @apihook("calloc", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def calloc(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void *calloc(
        size_t num,
        size_t size
        );
        """
        (
            num,
            size,
        ) = argv

        chunk = self.heap_alloc(num * size, heap="HeapAlloc")

        buf = b"\x00" * (num * size)
        self.mem_write(chunk, buf)

        return chunk

    @apihook("free", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def free(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void free(
        void *memblock
        );
        """
        (mem,) = argv
        self.mem_free(mem)

    @apihook("_beginthreadex", argc=6, conv=e_arch.CALL_CONV_CDECL)
    def _beginthreadex(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        uintptr_t _beginthreadex(
            void *security,
            unsigned stack_size,
            unsigned ( __stdcall *start_address )( void * ),
            void *arglist,
            unsigned initflag,
            unsigned *thrdaddr
        );
        """
        security, stack_size, start_address, arglist, initflag, thrdaddr = argv

        handle, obj = self.create_thread(start_address, arglist, emu.get_current_process())

        if thrdaddr:
            self.mem_write(thrdaddr, obj.id.to_bytes(4, "little"))

        return handle

    @apihook("_beginthread", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _beginthread(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        uintptr_t _beginthread
        void( __cdecl *start_address )( void * ),
        unsigned stack_size,
        void *arglist
        );
        """
        start_address, stack_size, arglist = argv

        handle, obj = self.create_thread(start_address, arglist, emu.get_current_process())
        return handle

    @apihook("system", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def system(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int system(
           const char *command
        );
        """
        (s,) = argv

        string = self.read_mem_string(s, 1)
        ctx.args[0].display = string
        rv = len(string)

        return rv

    @apihook("toupper", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def toupper(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int toupper(
           int c
        );
        """
        (c,) = argv
        if ord("a") <= c <= ord("z"):
            c -= 0x20
        return c

    @apihook("strlen", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def strlen(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        size_t strlen(
            const char *str
        );
        """
        (s,) = argv

        string = self.read_cstr(s)
        ctx.args[0].display = string.decode("utf-8", "ignore")

        return len(string)

    @apihook("strcat", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def strcat(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        char *strcat(
            char *strDestination,
            const char *strSource
        );
        """
        _str1, _str2 = argv
        s1 = self.read_cstr(_str1)
        s2 = self.read_cstr(_str2)
        ctx.args[0].display = s1.decode("utf-8", "ignore")
        ctx.args[1].display = s2.decode("utf-8", "ignore")
        self.mem_write(_str1 + len(s1), s2 + b"\x00")
        return _str1

    @apihook("_strlwr", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _strlwr(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        char *_strlwr(
            char *str
            );
        """
        (string_ptr,) = argv

        if not string_ptr:
            return 0

        string = self.read_cstr(string_ptr)
        ctx.args[0].display = string.decode("utf-8", "ignore")
        self.mem_write(string_ptr, string.lower())
        return string_ptr

    @apihook("strncat", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def strncat(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        char *strncat(
            char *destination,
            const char *source,
            size_t num
        );
        """
        dest, src, count = argv
        s1 = self.read_cstr(dest)
        s2 = self.read_cstr(src, max_chars=count) if count else b""
        ctx.args[0].display = s1.decode("utf-8", "ignore")
        ctx.args[1].display = s2.decode("utf-8", "ignore")
        self.mem_write(dest + len(s1), s2 + b"\x00")
        return dest

    @apihook("wcscat", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def wcscat(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        wchar_t *wcscat(
           wchar_t *strDestination,
           const wchar_t *strSource
        );
        """
        _str1, _str2 = argv
        s1 = self.read_mem_string(_str1, 2)
        s2 = self.read_mem_string(_str2, 2)
        ctx.args[0].display = s1
        ctx.args[1].display = s2
        new = (s1 + s2).encode("utf-16le")
        self.mem_write(_str1, new + b"\x00\x00")
        return _str1

    @apihook("wcscat_s", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def wcscat_s(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        errno_t wcscat_s(
           wchar_t *strDestination,
           size_t numberOfElements,
           const wchar_t *strSource
        );
        """
        dest, size, src = argv
        if not dest or not size:
            return EINVAL
        if not src:
            self.mem_write(dest, b"\x00\x00")
            return EINVAL
        s1 = self.read_wide_string(dest)
        s2 = self.read_wide_string(src)
        ctx.args[0].display = s1
        ctx.args[2].display = s2
        if len(s1) + len(s2) >= size:
            self.mem_write(dest, b"\x00\x00")
            return ERANGE
        self.write_wide_string(s1 + s2 + "\x00", dest)
        return 0

    @apihook("wcslen", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def wcslen(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        size_t wcslen(
          const wchar_t* wcs
        );
        """
        (s,) = argv
        string = self.read_wide_string(s)
        ctx.args[0].display = string
        rv = len(string)

        return rv

    @apihook("_lock", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _lock(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void __cdecl _lock
            int locknum
        );
        """
        return

    @apihook("_unlock", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _unlock(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void __cdecl _unlock
            int locknum
        );
        """
        return

    @apihook("_lock_file", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _lock_file(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void _lock_file(
            FILE* file
        );
        """
        return

    @apihook("_unlock_file", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _unlock_file(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void _unlock_file(
            FILE* file
        );
        """
        return

    @apihook("_ltoa", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _ltoa(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        char *_ltoa(
            long value,
            char *str,
            int radix
        );
        """
        (
            val,
            out_str,
            radix,
        ) = argv

        self.write_string(self.format_int32(val, radix), out_str)
        return out_str

    @apihook("__dllonexit", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def __dllonexit(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        onexit_t __dllonexit(
            _onexit_t func,
            _PVFV **  pbegin,
            _PVFV **  pend
        )
        """
        (
            func,
            pbegin,
            pend,
        ) = argv
        return func

    @apihook("strncmp", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def strncmp(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int strncmp(
            const char *string1,
            const char *string2,
            size_t count
        );
        """
        s1, s2, c = argv
        if not c:
            return 0

        string1 = self.read_cstr(s1, c)
        string2 = self.read_cstr(s2, c)
        ctx.args[0].display = string1.decode("utf-8", "ignore")
        ctx.args[1].display = string2.decode("utf-8", "ignore")

        return (string1 > string2) - (string1 < string2)

    @apihook("strcmp", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def strcmp(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int strcmp(
            const char *string1,
            const char *string2,
        );
        """
        s1, s2 = argv

        string1 = self.read_cstr(s1)
        string2 = self.read_cstr(s2)
        ctx.args[0].display = string1.decode("utf-8", "ignore")
        ctx.args[1].display = string2.decode("utf-8", "ignore")

        return (string1 > string2) - (string1 < string2)

    @apihook("strrchr", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def strrchr(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        char *strrchr(
            const char *str,
            int c
            );
        """
        cstr, c = argv
        # The terminator is part of the string, so a NUL finds it
        hay = self.read_cstr(cstr) + b"\x00"
        needle = bytes([c & 0xFF])

        offset = hay.rfind(needle)

        ctx.args[0].display = hay[:-1].decode("utf-8", "ignore")
        ctx.args[1].display = needle.decode("latin-1")

        return cstr + offset if offset >= 0 else 0

    @apihook("wcsrchr", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def wcsrchr(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        wchar_t *wcsrchr(
            const wchar_t *str,
            wchar_t c
            );
        """
        wstr, c = argv
        hay = self.read_mem_string(wstr, 2) + "\x00"
        offset = hay.rfind(chr(c & 0xFFFF))
        ctx.args[0].display = hay[:-1]
        return wstr + offset * 2 if offset >= 0 else 0

    @apihook("wcschr", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def wcschr(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        wchar_t *wcschr(
            const wchar_t *str,
            wchar_t c
            );
        """
        wstr, c = argv
        hay = self.read_mem_string(wstr, 2) + "\x00"
        offset = hay.find(chr(c & 0xFFFF))
        ctx.args[0].display = hay[:-1]
        return wstr + offset * 2 if offset >= 0 else 0

    @apihook("_ftol", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _ftol(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _ftol(int);
        """
        (f,) = argv
        return int(f)

    @apihook("_adjust_fdiv", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _adjust_fdiv(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void _adjust_fdiv(void)
        """
        return

    @apihook("tolower", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def tolower(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int tolower ( int c );
        """
        (c,) = argv
        if ord("A") <= c <= ord("Z"):
            c += 0x20
        return c

    @apihook("towlower", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def towlower(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        wint_t towlower(wint_t c);
        """
        (c,) = argv
        c &= 0xFFFF
        if ord("A") <= c <= ord("Z"):
            c += 0x20
        return c

    @apihook("towupper", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def towupper(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        wint_t towupper(wint_t c);
        """
        (c,) = argv
        c &= 0xFFFF
        if ord("a") <= c <= ord("z"):
            c -= 0x20
        return c

    @apihook("isdigit", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def isdigit(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int isdigit(
            int c
            );
        """
        (c,) = argv
        return int(48 <= c <= 57)

    @apihook("isspace", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def isspace(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int isspace(
            int c
            );
        """
        (c,) = argv
        return int(0 <= c < 0x100 and c in SCANF_SPACE)

    @apihook("_isatty", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _isatty(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _isatty(int fd);
        """
        # Standard streams are files, as kernel32.GetFileType reports
        return 0

    @apihook("_fileno", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _fileno(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _fileno(FILE *stream);
        """
        (stream,) = argv
        if stream in (self.stdin, self.stdout, self.stderr):
            return stream
        if self.iob:
            index, rest = divmod(stream - self.iob, 0x30 if self.get_ptr_size() == 8 else 0x20)
            if not rest and index in (self.stdin, self.stdout, self.stderr):
                return index
        self.set_errno(EINVAL)
        return -1

    @apihook("_setmode", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _setmode(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _setmode(int fd, int mode);
        """
        fd, mode = argv
        if fd in (self.stdin, self.stdout, self.stderr):
            return O_TEXT
        self.set_errno(EBADF)
        return -1

    @apihook("_read", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _read(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _read(int fd, void *buffer, unsigned int count);
        """
        fd, buf, count = argv
        if fd == self.stdin:
            return 0
        self.set_errno(EBADF)
        return -1

    @apihook("_Mtx_init_in_situ", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _Mtx_init_in_situ(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void _Mtx_init_in_situ(_Mtx_t mtx, int type);
        """
        return

    @apihook("_Mtx_destroy_in_situ", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _Mtx_destroy_in_situ(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void _Mtx_destroy_in_situ(_Mtx_t mtx);
        """
        return

    @apihook("_Mtx_lock", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _Mtx_lock(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        _Thrd_result _Mtx_lock(_Mtx_t mtx);
        """
        return THRD_SUCCESS

    @apihook("_Mtx_trylock", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _Mtx_trylock(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        _Thrd_result _Mtx_trylock(_Mtx_t mtx);
        """
        return THRD_SUCCESS

    @apihook("_Mtx_unlock", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _Mtx_unlock(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        _Thrd_result _Mtx_unlock(_Mtx_t mtx);
        """
        return THRD_SUCCESS

    @apihook("_Thrd_id", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _Thrd_id(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        _Thrd_id_t _Thrd_id(void);
        """
        return emu.get_current_thread().id

    @apihook("__telemetry_main_invoke_trigger", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def __telemetry_main_invoke_trigger(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void __telemetry_main_invoke_trigger(HINSTANCE instance);
        """
        return

    @apihook("__telemetry_main_return_trigger", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def __telemetry_main_return_trigger(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void __telemetry_main_return_trigger(HINSTANCE instance);
        """
        return

    @apihook("setvbuf", argc=4, conv=e_arch.CALL_CONV_CDECL)
    def setvbuf(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int setvbuf(
           FILE *stream,
           char *buffer,
           int mode,
           size_t size
        );
        """
        _IOFBF, _IONBF, _IOLBF = 0, 4, 0x40
        stream, buf, mode, size = argv
        return 0 if stream and mode in (_IOFBF, _IONBF, _IOLBF) else -1

    @apihook("_getpid", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _getpid(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """int _getpid( void );"""
        return emu.get_current_process().id

    @apihook("setbuf", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def setbuf(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void setbuf(
           FILE *stream,
           char *buffer
        );
        """
        return

    @apihook("sscanf", argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def sscanf(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int sscanf ( const char * s, const char * format, ...);
        """
        buf, fmt = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 2)
        text, fmt_str = self.read_cstr(buf), self.read_cstr(fmt)
        values, rv = scan_c_format(text, fmt_str, emu.get_ptr_size())
        ptrs = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 2 + len(values))[2:]
        for ptr, data in zip(ptrs, values):
            self.mem_write(ptr, data)
        ctx.args.clear()
        ctx.args.append(text.decode("latin-1"))
        ctx.args.append(fmt_str.decode("latin-1"))
        return rv

    @apihook("strchr", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def strchr(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        char *strchr(
            const char *str,
            int c
            );
        """
        cstr, c = argv
        # The terminator is part of the string, so a NUL finds it
        hay = self.read_cstr(cstr) + b"\x00"
        needle = bytes([c & 0xFF])

        offset = hay.find(needle)

        ctx.args[0].display = hay[:-1].decode("utf-8", "ignore")
        ctx.args[1].display = needle.decode("latin-1")

        return cstr + offset if offset >= 0 else 0

    @apihook("_set_invalid_parameter_handler", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _set_invalid_parameter_handler(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        _invalid_parameter_handler _set_invalid_parameter_handler(
        _invalid_parameter_handler pNew
        );
        """
        (pNew,) = argv

        return 0

    @apihook("__CxxFrameHandler", argc=4, conv=e_arch.CALL_CONV_CDECL)
    def __CxxFrameHandler(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        EXCEPTION_DISPOSITION __CxxFrameHandler(
            EHExceptionRecord  *pExcept,
            EHRegistrationNode *pRN,
            void               *pContext,
            DispatcherContext  *pDC
        )
        """
        (
            pExcept,
            pRN,
            pContext,
            pDC,
        ) = argv
        return 0

    @apihook("_vsnprintf", argc=4, conv=e_arch.CALL_CONV_CDECL)
    def _vsnprintf(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _vsnprintf(
            char *buffer,
            size_t count,
            const char *format,
            va_list argptr
        );
        """
        buffer, count, _format, argptr = argv

        fmt_str = self.read_mem_string(_format, 1)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args(argptr, fmt_cnt)

        fin = self.do_str_format(fmt_str, vargs)
        out = fin[:count].encode("utf-8")
        if len(fin) < count:
            out += b"\x00"
        self.mem_write(buffer, out)
        ctx.args[0].display = fin[:count]
        ctx.args[2].display = fmt_str

        return len(fin) if len(fin) <= count else -1

    def stdio_common_format(self, emu, argv, ctx, width, secure=False, max_count=False):
        """
        Format into a buffer for the __stdio_common_v*printf* family. The
        64-bit options take two slots on x86. The _s variants empty the
        buffer when the text does not fit, and the n variants also limit the
        text to a count of characters, where _TRUNCATE allows truncation.
        """
        options = argv[0]
        first = 1 if emu.get_arch() == e_arch.ARCH_AMD64 else 2
        fields = argv[first : first + (6 if max_count else 5)]
        if max_count:
            buffer, size, count, _format, _, argptr = fields
        else:
            buffer, size, _format, _, argptr = fields
            count = None
        fmt_str = self.read_mem_string(_format, width)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args(argptr, fmt_cnt)

        fin = self.do_str_format(fmt_str, vargs, wide=width == 2)
        ctx.args[first + len(fields) - 3].display = fmt_str
        encoding = "utf-16le" if width == 2 else "utf-8"

        if secure:
            if not buffer or not size:
                return -1
            truncate = count == (1 << (self.get_ptr_size() * 8)) - 1
            text = fin if count is None or truncate else fin[:count]
            if len(text) < size:
                out, rv = text, len(fin) if text == fin else -1
            elif truncate:
                out, rv = text[: size - 1], -1
            else:
                out, rv = "", -1
            self.mem_write(buffer, (out + "\x00").encode(encoding))
            ctx.args[first].display = out
            return rv

        if not buffer and not size:
            return len(fin)

        if options & _CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR:
            out = fin[: size - 1] + "\x00"
            rv = len(fin)
        elif options & _CRT_INTERNAL_PRINTF_LEGACY_VSPRINTF_NULL_TERMINATION:
            out = fin[:size] if len(fin) >= size else fin + "\x00"
            rv = len(fin) if len(fin) <= size else -1
        else:
            out = fin[: size - 1] + "\x00"
            rv = len(fin) if len(fin) < size else -1

        if size:
            self.mem_write(buffer, out.encode(encoding))
            ctx.args[first].display = out.rstrip("\x00")

        return rv

    @apihook("__stdio_common_vsprintf", argc=7, conv=e_arch.CALL_CONV_CDECL)
    def __stdio_common_vsprintf(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int __stdio_common_vsprintf(
            unsigned int64 Options,
            char *Buffer,
            unsigned int BufferCount,
            const char *format,
            locale_t Locale,
            va_list argptr
        );
        """
        return self.stdio_common_format(emu, argv, ctx, 1)

    @apihook("__stdio_common_vswprintf", argc=7, conv=e_arch.CALL_CONV_CDECL)
    def __stdio_common_vswprintf(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int __stdio_common_vswprintf(
            unsigned int64 Options,
            wchar_t *Buffer,
            size_t BufferCount,
            const wchar_t *format,
            locale_t Locale,
            va_list argptr
        );
        """
        return self.stdio_common_format(emu, argv, ctx, 2)

    @apihook("__stdio_common_vsprintf_s", argc=7, conv=e_arch.CALL_CONV_CDECL)
    def __stdio_common_vsprintf_s(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int __stdio_common_vsprintf_s(
            unsigned int64 Options,
            char *Buffer,
            size_t BufferCount,
            const char *format,
            locale_t Locale,
            va_list argptr
        );
        """
        return self.stdio_common_format(emu, argv, ctx, 1, secure=True)

    @apihook("__stdio_common_vswprintf_s", argc=7, conv=e_arch.CALL_CONV_CDECL)
    def __stdio_common_vswprintf_s(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int __stdio_common_vswprintf_s(
            unsigned int64 Options,
            wchar_t *Buffer,
            size_t BufferCount,
            const wchar_t *format,
            locale_t Locale,
            va_list argptr
        );
        """
        return self.stdio_common_format(emu, argv, ctx, 2, secure=True)

    @apihook("__stdio_common_vsnprintf_s", argc=8, conv=e_arch.CALL_CONV_CDECL)
    def __stdio_common_vsnprintf_s(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int __stdio_common_vsnprintf_s(
            unsigned int64 Options,
            char *Buffer,
            size_t BufferCount,
            size_t MaxCount,
            const char *format,
            locale_t Locale,
            va_list argptr
        );
        """
        return self.stdio_common_format(emu, argv, ctx, 1, secure=True, max_count=True)

    @apihook("__stdio_common_vsnwprintf_s", argc=8, conv=e_arch.CALL_CONV_CDECL)
    def __stdio_common_vsnwprintf_s(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int __stdio_common_vsnwprintf_s(
            unsigned int64 Options,
            wchar_t *Buffer,
            size_t BufferCount,
            size_t MaxCount,
            const wchar_t *format,
            locale_t Locale,
            va_list argptr
        );
        """
        return self.stdio_common_format(emu, argv, ctx, 2, secure=True, max_count=True)

    @apihook("_strcmpi", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _strcmpi(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _strcmpi(
                const char *string1,
                const char *string2
                );
        """
        string1, string2 = argv
        rv = 1

        if not string1 or not string2:
            return rv

        cs1 = self.read_cstr(string1)
        cs2 = self.read_cstr(string2)

        ctx.args[0].display = cs1.decode("utf-8", "ignore")
        ctx.args[1].display = cs2.decode("utf-8", "ignore")

        cs1, cs2 = cs1.lower(), cs2.lower()
        return (cs1 > cs2) - (cs1 < cs2)

    @apihook("_wcsicmp", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _wcsicmp(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _wcsicmp(
                const wchar_t *string1,
                const wchar_t *string2
                );
        """
        string1, string2 = argv
        rv = 1

        if not string1 or not string2:
            return rv

        cs1 = self.read_wide_string(string1)
        cs2 = self.read_wide_string(string2)

        ctx.args[0].display = cs1
        ctx.args[1].display = cs2

        if cs1.lower() == cs2.lower():
            rv = 0

        return rv

    @apihook("??3@YAXPAX@Z", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def __3_YAXPAX_Z(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        (ptr,) = argv
        if ptr:
            self.mem_free(ptr)
        return

    @apihook("??2@YAPAXI@Z", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def __2_YAPAXI_Z(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        (size,) = argv
        if size <= 0:
            size = self.get_ptr_size()
        return self.mem_alloc(size, tag="api.msvcrt.operator_new")

    @apihook("__current_exception_context", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __current_exception_context(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        return

    @apihook("__current_exception", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __current_exception(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        return

    @apihook("_set_new_mode", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _set_new_mode(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        return

    @apihook("_configthreadlocale", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _configthreadlocale(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        return

    @apihook("_setusermatherr", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _setusermatherr(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        return

    @apihook("__setusermatherr", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def __setusermatherr(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        return

    @apihook("_cexit", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _cexit(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        # TODO: handle atexit flavor functions
        self.exit_process()

    @apihook("_c_exit", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _c_exit(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        self.exit_process()

    @apihook("_register_thread_local_exe_atexit_callback", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _register_thread_local_exe_atexit_callback(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        return

    @apihook("_crt_atexit", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _crt_atexit(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        return

    @apihook("_controlfp_s", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _controlfp_s(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        return

    @apihook("terminate", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def terminate(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        self.exit_process()

    @apihook("_initialize_narrow_environment", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _initialize_narrow_environment(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        return

    @apihook("_configure_narrow_argv", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _configure_narrow_argv(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        return

    @apihook("_initialize_wide_environment", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _initialize_wide_environment(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        return 0

    @apihook("_configure_wide_argv", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _configure_wide_argv(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        return 0

    @apihook("_set_fmode", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _set_fmode(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        return

    @apihook("_itoa", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _itoa(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        char *_itoa(
            int value,
            char *buffer,
            int radix
        );
        """
        val, out_str, radix = argv
        self.write_string(self.format_int32(val, radix), out_str)
        return out_str

    @apihook("_itow", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _itow(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        wchar_t *_itow(
            int value,
            wchar_t *buffer,
            int radix
        );
        """
        val, out_str, radix = argv
        self.write_wide_string(self.format_int32(val, radix), out_str)
        return out_str

    @apihook("_EH_prolog", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _EH_prolog(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        # push    -1
        emu.push_stack(0xFFFFFFFF)

        # push    eax
        emu.push_stack(emu.reg_read(e_arch.X86_REG_EAX))

        # mov     eax, DWORD PTR fs:[0]
        # push    eax
        emu.push_stack(emu.read_ptr(emu.fs_addr + 0))

        # mov     eax, DWORD PTR [esp+12]
        eax = emu.read_ptr(emu.reg_read(e_arch.X86_REG_ESP) + 12)

        # mov     DWORD PTR fs:[0], esp
        emu.write_ptr(emu.fs_addr + 0, emu.reg_read(e_arch.X86_REG_ESP))

        # mov     DWORD PTR [esp+12], ebp
        emu.write_ptr(emu.reg_read(e_arch.X86_REG_ESP) + 12, emu.reg_read(e_arch.X86_REG_EBP))

        # lea     ebp, DWORD PTR [esp+12]
        emu.reg_write(e_arch.X86_REG_EBP, emu.reg_read(e_arch.X86_REG_ESP) + 12)

        # push    eax
        # ret     0
        emu.push_stack(eax)
        emu.do_call_return(0, eax, conv=e_arch.CALL_CONV_CDECL)
        return

    def jump_buffer_layout(self, emu):
        if emu.get_arch() == e_arch.ARCH_X86:
            return (
                [
                    (0x0, e_arch.X86_REG_EBP),
                    (0x4, e_arch.X86_REG_EBX),
                    (0x8, e_arch.X86_REG_EDI),
                    (0xC, e_arch.X86_REG_ESI),
                ],
                0x10,
                0x14,
            )
        return (
            [
                (0x8, e_arch.AMD64_REG_RBX),
                (0x18, e_arch.AMD64_REG_RBP),
                (0x20, e_arch.AMD64_REG_RSI),
                (0x28, e_arch.AMD64_REG_RDI),
                (0x30, e_arch.AMD64_REG_R12),
                (0x38, e_arch.AMD64_REG_R13),
                (0x40, e_arch.AMD64_REG_R14),
                (0x48, e_arch.AMD64_REG_R15),
            ],
            0x10,
            0x50,
        )

    def save_jump_buffer(self, emu, buf):
        regs, sp_off, pc_off = self.jump_buffer_layout(emu)
        for off, reg in regs:
            emu.write_ptr(buf + off, emu.reg_read(reg))
        sp = emu.get_stack_ptr()
        emu.write_ptr(buf + sp_off, sp + emu.get_ptr_size())
        emu.write_ptr(buf + pc_off, emu.read_ptr(sp))
        if emu.get_arch() == e_arch.ARCH_X86:
            emu.write_ptr(buf + 0x18, emu.read_ptr(emu.fs_addr))
            emu.write_ptr(buf + 0x1C, 0xFFFFFFFF)
        else:
            emu.write_ptr(buf, 0)
        return 0

    @apihook("_setjmp", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _setjmp(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """int _setjmp(jmp_buf env);"""
        return self.save_jump_buffer(emu, argv[0])

    @apihook("_setjmp3", argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def _setjmp3(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """int _setjmp3(jmp_buf env, int count, ...);"""
        return self.save_jump_buffer(emu, emu.read_ptr(emu.get_stack_ptr() + 4))

    @apihook("_setjmpex", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _setjmpex(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """int _setjmpex(jmp_buf env, void *frame);"""
        return self.save_jump_buffer(emu, argv[0])

    @apihook("__intrinsic_setjmp", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def __intrinsic_setjmp(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """int __intrinsic_setjmp(jmp_buf env, void *frame);"""
        return self.save_jump_buffer(emu, argv[0])

    @apihook("__intrinsic_setjmpex", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def __intrinsic_setjmpex(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """int __intrinsic_setjmpex(jmp_buf env, void *frame);"""
        return self.save_jump_buffer(emu, argv[0])

    @apihook("longjmp", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def longjmp(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """void longjmp(jmp_buf env, int value);"""
        buf, value = argv
        value = (value & 0xFFFFFFFF) or 1
        regs, sp_off, pc_off = self.jump_buffer_layout(emu)
        for off, reg in regs:
            emu.reg_write(reg, emu.read_ptr(buf + off))
        if emu.get_arch() == e_arch.ARCH_X86:
            emu.write_ptr(emu.fs_addr, emu.read_ptr(buf + 0x18))
            emu.reg_write(e_arch.X86_REG_EAX, value)
        else:
            emu.reg_write(e_arch.AMD64_REG_RAX, value)
        emu.set_stack_ptr(emu.read_ptr(buf + sp_off))
        emu.set_pc(emu.read_ptr(buf + pc_off))
        return value

    @apihook("wcstombs", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def wcstombs(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        size_t wcstombs(
            char *mbstr,
            const wchar_t *wcstr,
            size_t count
        );
        """
        mbstr, wcstr, count = argv

        ws = self.read_cstr(wcstr, max_chars=count if mbstr else 0, width=2).decode("utf-16le", "surrogatepass")
        ctx.args[1].display = ws
        try:
            s = ws.encode("latin-1")
        except UnicodeEncodeError:
            return self.get_max_int()

        if not mbstr:
            return len(s)
        if len(s) < count:
            self.mem_write(mbstr, s + b"\x00")
        else:
            self.mem_write(mbstr, s[:count])
        return min(len(s), count)

    @apihook("mbstowcs", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def mbstowcs(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        size_t mbstowcs(
            wchar_t *wcstr,
            const char *mbstr,
            size_t count
        );
        """
        wcstr, mbstr, count = argv

        if wcstr and not count:
            return 0
        s = self.read_cstr(mbstr, max_chars=count if wcstr else 0)
        ctx.args[1].display = s.decode("latin-1")
        if not wcstr:
            return len(s)
        ws = s.decode("latin-1").encode("utf-16le")
        self.mem_write(wcstr, ws + b"\x00\x00" if len(s) < count else ws)
        return len(s)

    @apihook("_stricmp", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _stricmp(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _stricmp(
                const char *string1,
                const char *string2
                );
        """
        string1, string2 = argv
        rv = 1

        if not string1 or not string2:
            return rv

        cs1 = self.read_cstr(string1)
        cs2 = self.read_cstr(string2)

        ctx.args[0].display = cs1.decode("utf-8", "ignore")
        ctx.args[1].display = cs2.decode("utf-8", "ignore")

        cs1, cs2 = cs1.lower(), cs2.lower()
        return (cs1 > cs2) - (cs1 < cs2)

    @apihook("_strnicmp", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _strnicmp(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _strnicmp(
            const char *string1,
            const char *string2,
            size_t count
        );
        """
        string1, string2, count = argv
        rv = 1

        if not string1 or not string2:
            return rv

        if not count:
            return 0

        cs1 = self.read_cstr(string1, count)
        cs2 = self.read_cstr(string2, count)

        ctx.args[0].display = cs1.decode("utf-8", "ignore")
        ctx.args[1].display = cs2.decode("utf-8", "ignore")

        cs1, cs2 = cs1.lower(), cs2.lower()
        return (cs1 > cs2) - (cs1 < cs2)

    @apihook("_wcsicmp", argc=2, conv=e_arch.CALL_CONV_CDECL)  # type: ignore[no-redef]
    def _wcsicmp(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int wcsicmp(
            const wchar_t *string1,
            const wchar_t *string2
            );
        """
        string1, string2 = argv
        rv = 1

        ws1 = self.read_wide_string(string1)
        ws2 = self.read_wide_string(string2)

        ctx.args[0].display = ws1
        ctx.args[1].display = ws2

        if ws1.lower() == ws2.lower():
            rv = 0

        return rv

    @apihook("wcscmp", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def wcscmp(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int wcscmp(
            const wchar_t *string1,
            const wchar_t *string2,
        );
        """
        s1, s2 = argv
        rv = 1

        string1 = self.read_wide_string(s1)
        string2 = self.read_wide_string(s2)
        if string1 == string2:
            rv = 0
        ctx.args[0].display = string1
        ctx.args[1].display = string2

        return rv

    @apihook("_snwprintf", argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def _snwprintf(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _snwprintf(
            wchar_t *buffer,
            size_t count,
            const wchar_t *format [,
            argument] ...
            );
        """
        buf, cnt, fmt = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 3)
        fmt_str = self.read_wide_string(fmt)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        argv = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 3 + fmt_cnt)[3:]
        fin = self.do_str_format(fmt_str, argv, wide=True)
        ctx.args.clear()
        ctx.args.append(fin)

        out = fin[:cnt].encode("utf-16le")
        if len(fin) < cnt:
            out += b"\x00\x00"
        self.mem_write(buf, out)
        return len(fin) if len(fin) <= cnt else -1

    @apihook("_errno", argc=0)
    def _errno(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """ """
        _VAL = 0x0C

        if not self.errno_t:
            self.errno_t = self.mem_alloc(4, tag="api.msvcrt._errno")
            self.mem_write(self.errno_t, _VAL.to_bytes(4, "little"))

        return self.errno_t

    @apihook("strerror", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def strerror(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        char *strerror(
           int errnum
        );

        Each call writes the message to the same buffer.
        """
        (errnum,) = argv
        errnum &= 0xFFFFFFFF
        message = SYS_ERRLIST[errnum] if errnum < len(SYS_ERRLIST) else "Unknown error"

        if not self.strerror_buf:
            self.strerror_buf = self.mem_alloc(0x100, tag="api.msvcrt.strerror")
        self.mem_write(self.strerror_buf, message.encode("ascii") + b"\x00")
        ctx.args[0].display = f"{errnum} ({message})"
        return self.strerror_buf

    @apihook("___lc_codepage_func", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def ___lc_codepage_func(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT ___lc_codepage_func(void);

        The C locale has code page 0.
        """
        return 0

    @apihook("___lc_locale_name_func", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def ___lc_locale_name_func(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        wchar_t** ___lc_locale_name_func(void);

        The C locale has no name for any category.
        """
        if not self.lc_locale_names:
            self.lc_locale_names = self.mem_alloc(6 * emu.get_ptr_size(), tag="api.msvcrt.lc_locale_names")
        return self.lc_locale_names

    @apihook("___mb_cur_max_func", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def ___mb_cur_max_func(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int ___mb_cur_max_func(void);

        The C locale has single-byte characters.
        """
        return 1

    @apihook("_ismbblead", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _ismbblead(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _ismbblead(
            unsigned int c
        );

        The C locale has no lead bytes.
        """
        return 0

    @apihook("localeconv", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def localeconv(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        struct lconv *localeconv(void);

        The struct has 10 char pointers, 8 chars, and 8 wchar_t pointers. The
        C locale has "." as the decimal point, empty strings for the other
        strings, and CHAR_MAX for the chars.
        """
        if self.lconv:
            return self.lconv

        ptr_size = self.get_ptr_size()
        fmt = "<" + ("Q" if ptr_size == 8 else "I")
        size = 18 * ptr_size + 8
        self.lconv = self.mem_alloc(size + 10, tag="api.msvcrt.localeconv")
        dot, empty, wdot, wempty = (self.lconv + size + off for off in (0, 2, 4, 8))
        narrow = [dot] + [empty] * 9
        wide = [wdot] + [wempty] * 7
        data = b"".join(struct.pack(fmt, p) for p in narrow)
        data += b"\x7f" * 8
        data += b"".join(struct.pack(fmt, p) for p in wide)
        data += b".\x00\x00\x00" + ".".encode("utf-16le") + b"\x00\x00" + b"\x00\x00"
        self.mem_write(self.lconv, data)
        return self.lconv

    @apihook("setlocale", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def setlocale(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        char *setlocale(
            int category,
            const char *locale
        );

        The emulated CRT stays in the C locale, so every call returns "C".
        """
        category, locale = argv
        if locale:
            ctx.args[1].display = self.read_cstr(locale).decode("latin-1")
        if not self.locale_name:
            self.locale_name = self.mem_alloc(2, tag="api.msvcrt.setlocale")
            self.mem_write(self.locale_name, b"C\x00")
        return self.locale_name

    @apihook("fopen", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def fopen(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        FILE *fopen(
            const char *filename,
            const char *mode
            );
        """
        filename, mode = argv

        if not filename or not mode:
            return 0

        path = self.read_string(filename)
        mode_str = self.read_string(mode)

        ctx.args[0].display = path
        ctx.args[1].display = mode_str

        create = any(flag in mode_str for flag in ("w", "a", "+"))
        truncate = "w" in mode_str and "a" not in mode_str

        hfile = self.file_open(path, create=create, truncate=truncate)
        if hfile is None:
            return 0

        stream = self.mem_alloc(self.get_ptr_size(), tag="api.msvcrt.fopen")
        self.mem_write(stream, int(hfile).to_bytes(self.get_ptr_size(), "little"))
        self.file_streams[stream] = hfile
        return stream

    @apihook("_wfopen", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _wfopen(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        FILE *_wfopen(
            const wchar_t *filename,
            const wchar_t *mode
            );
        """
        filename, mode = argv

        if not filename or not mode:
            return 0

        path = self.read_wide_string(filename)
        mode_str = self.read_wide_string(mode)

        ctx.args[0].display = path
        ctx.args[1].display = mode_str

        create = any(flag in mode_str for flag in ("w", "a", "+"))
        truncate = "w" in mode_str and "a" not in mode_str

        hfile = self.file_open(path, create=create, truncate=truncate)
        if hfile is None:
            return 0

        stream = self.mem_alloc(self.get_ptr_size(), tag="api.msvcrt._wfopen")
        self.mem_write(stream, int(hfile).to_bytes(self.get_ptr_size(), "little"))
        self.file_streams[stream] = hfile
        return stream

    @apihook("fclose", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def fclose(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int fclose(
            FILE *stream
            );
        """
        (stream,) = argv

        if not stream:
            return -1

        self.file_streams.pop(stream, None)
        self.mem_free(stream)
        return 0

    def set_errno(self, value):
        self._errno(self.emu, [])
        self.mem_write(self.errno_t, value.to_bytes(4, "little"))

    def stat_file(self, argv, ctx, wide, size64, time64):
        """
        Fill a struct _stat* for an emulated file.

        The variants differ in the width of st_size and of the three time
        fields. st_size and the times follow 4 bytes of padding when they are
        64-bit.
        """
        path_ptr, buf = argv
        path = self.read_wide_string(path_ptr) if wide else self.read_string(path_ptr)
        ctx.args[0].display = path

        hfile = self.file_open(path)
        if hfile is None:
            self.set_errno(ENOENT)
            return -1
        size = self.file_get(hfile).get_size()

        data = struct.pack("<IHHhhhxxI", DRIVE_C, 0, S_IFREG_RW, 1, 0, 0, DRIVE_C)
        data += struct.pack("<4xq", size) if size64 else struct.pack("<i", size)
        data += struct.pack("<3q" if time64 else "<3i", TIME_BASE, TIME_BASE, TIME_BASE)
        if size64 or time64:
            data += b"\x00" * (-len(data) % 8)
        self.mem_write(buf, data)
        return 0

    @apihook("_stat", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _stat(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _stat(
            const char *path,
            struct _stat *buffer
        );
        """
        return self.stat_file(argv, ctx, False, False, self.get_ptr_size() == 8)

    @apihook("_stati64", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _stati64(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _stati64(
            const char *path,
            struct _stati64 *buffer
        );
        """
        return self.stat_file(argv, ctx, False, True, self.get_ptr_size() == 8)

    @apihook("_stat64", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _stat64(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _stat64(
            const char *path,
            struct __stat64 *buffer
        );
        """
        return self.stat_file(argv, ctx, False, True, True)

    @apihook("_wstat", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _wstat(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _wstat(
            const wchar_t *path,
            struct _stat *buffer
        );
        """
        return self.stat_file(argv, ctx, True, False, self.get_ptr_size() == 8)

    @apihook("_wstati64", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _wstati64(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _wstati64(
            const wchar_t *path,
            struct _stati64 *buffer
        );
        """
        return self.stat_file(argv, ctx, True, True, self.get_ptr_size() == 8)

    @apihook("_wstat64", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _wstat64(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _wstat64(
            const wchar_t *path,
            struct __stat64 *buffer
        );
        """
        return self.stat_file(argv, ctx, True, True, True)

    def delete_file(self, emu, argv, ctx, wide):
        (path_ptr,) = argv
        path = self.read_wide_string(path_ptr) if wide else self.read_string(path_ptr)
        ctx.args[0].display = path

        if not emu.does_file_exist(path):
            self.set_errno(ENOENT)
            return -1
        emu.file_delete(path)
        return 0

    @apihook("_unlink", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _unlink(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _unlink(
            const char *filename
        );
        """
        return self.delete_file(emu, argv, ctx, False)

    @apihook("_wunlink", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _wunlink(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _wunlink(
            const wchar_t *filename
        );
        """
        return self.delete_file(emu, argv, ctx, True)

    @apihook("remove", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def remove(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int remove(
            const char *path
        );
        """
        return self.delete_file(emu, argv, ctx, False)

    @apihook("_wremove", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _wremove(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _wremove(
            const wchar_t *path
        );
        """
        return self.delete_file(emu, argv, ctx, True)

    @apihook("fflush", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def fflush(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int fflush(
            FILE *stream
            );
        """
        return 0

    @apihook("fseek", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def fseek(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int fseek(
            FILE *stream,
            long offset,
            int origin
            );
        """
        stream, offset, origin = argv
        hfile = self.file_streams.get(stream)
        ctx.args[0].display = hex(hfile or 0)
        if hfile is None:
            return -1

        fobj = self.file_get(hfile)
        if not fobj:
            return -1

        offset &= 0xFFFFFFFF
        offset -= (offset & 0x80000000) << 1
        size = fobj.get_size()
        if origin == io.SEEK_SET:
            pos = offset
        elif origin == io.SEEK_CUR:
            pos = (fobj.tell() or 0) + offset
        elif origin == io.SEEK_END:
            pos = size + offset
        else:
            return -1
        if pos < 0:
            return -1

        fobj.seek(pos, io.SEEK_SET)
        return 0

    @apihook("ftell", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def ftell(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        long ftell(
            FILE *stream
            );
        """
        (stream,) = argv
        hfile = self.file_streams.get(stream)
        ctx.args[0].display = hex(hfile or 0)
        if hfile is None:
            return -1

        fobj = self.file_get(hfile)
        if not fobj:
            return -1

        pos = fobj.tell()
        if pos is None:
            return -1
        return pos

    @apihook("fread", argc=4, conv=e_arch.CALL_CONV_CDECL)
    def fread(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        size_t fread(
            void *ptr,
            size_t size,
            size_t count,
            FILE *stream
            );
        """
        ptr, size, count, stream = argv
        hfile = self.file_streams.get(stream)
        ctx.args[3].display = hex(hfile or 0)

        if not ptr or size == 0 or count == 0 or hfile is None:
            return 0

        fobj = self.file_get(hfile)
        if not fobj:
            return 0

        total = size * count
        data = fobj.get_data(size=total)
        if not data:
            return 0

        self.mem_write(ptr, data)
        return len(data) // size

    @apihook("fgets", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def fgets(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        char *fgets(
            char *str,
            int numChars,
            FILE *stream
            );

        A stream that is not from fopen, such as stdin, is at end of file.
        """
        buf, num_chars, stream = argv
        num_chars &= 0xFFFFFFFF
        hfile = self.file_streams.get(stream)
        fobj = self.file_get(hfile) if hfile is not None else None
        if not buf or not 1 < num_chars < 0x80000000 or not fobj:
            return 0

        pos = fobj.tell()
        data = fobj.get_data(size=num_chars - 1)
        if not data:
            return 0

        newline = data.find(b"\n")
        if newline != -1:
            data = data[: newline + 1]
        fobj.seek(pos + len(data), io.SEEK_SET)
        self.mem_write(buf, data + b"\x00")
        ctx.args[0].display = data.decode("utf-8", errors="replace")
        return buf

    @apihook("fgetc", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def fgetc(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int fgetc(
            FILE *stream
            );

        A stream that is not from fopen, such as stdin, is at end of file.
        """
        (stream,) = argv
        hfile = self.file_streams.get(stream)
        fobj = self.file_get(hfile) if hfile is not None else None
        data = fobj.get_data(size=1) if fobj else b""
        return data[0] if data else -1

    @apihook("getc", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def getc(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int getc(
            FILE *stream
            );
        """
        return self.fgetc(emu, argv, ctx)

    @apihook("fwrite", argc=4, conv=e_arch.CALL_CONV_CDECL)
    def fwrite(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        size_t fwrite(
            const void *buffer,
            size_t size,
            size_t count,
            FILE *stream
            );
        """
        buffer, size, count, stream = argv
        if not buffer or size == 0 or count == 0:
            return 0

        data = self.mem_read(buffer, size * count)
        hfile = self.write_stream(stream, data, buffer)
        if hfile is None:
            ctx.args[0].display = data.decode("utf-8", errors="replace")
            return count

        ctx.args[0].display = f"{hex(buffer)} ({data.hex()[:0x20]})"
        ctx.args[3].display = hex(hfile)
        return count

    def write_stream(self, stream, data, buffer=0):
        """
        Append ``data`` to the file that ``stream`` writes to.
        Return the file handle, or None when the stream has no file.
        """
        hfile = self.file_streams.get(stream)
        fobj = self.file_get(hfile) if hfile is not None else None
        if hfile is None or not fobj:
            return None
        fobj.add_data(data)
        self.record_file_access_event(fobj.path, FILE_WRITE, data=data, buffer=buffer, size=len(data))
        return hfile

    @apihook("fputc", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def fputc(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int fputc(
            int c,
            FILE *stream
        );
        """
        c, stream = argv
        c &= 0xFF
        ctx.args[0].display = chr(c) if c < 0x80 else f"\\x{c:02x}"
        self.write_stream(stream, bytes([c]))
        return c

    @apihook("fputs", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def fputs(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int fputs(
            const char *str,
            FILE *stream
        );
        """
        s, stream = argv
        data = self.read_cstr(s)
        ctx.args[0].display = data.decode("utf-8", "ignore")
        self.write_stream(stream, data, s)
        return 0

    @apihook("_fullpath", argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _fullpath(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        char *_fullpath(
           char *absPath,
           const char *relPath,
           size_t maxLength
        );
        """
        abs_path, rel_path, max_length = argv
        rel = self.read_cstr(rel_path).decode("utf-8", "ignore") if rel_path else ""
        ctx.args[1].display = rel
        full = get_full_path(emu.get_cd(), rel or ".").encode("utf-8") + b"\x00"
        if not abs_path:
            abs_path = self.heap_alloc(len(full), heap="HeapAlloc")
        elif len(full) > max_length:
            return 0
        self.mem_write(abs_path, full)
        return abs_path

    @apihook("signal", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def signal(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void __cdecl *signal(
            int sig,
            int (*func)(int, int)
        );
        """
        sig, func = argv

        if sig not in [SIGINT, SIGILL, SIGFPE, SIGSEGV, SIGTERM, SIGBREAK, SIGABRT]:
            return SIG_ERR
        previous = self.signal_handlers.get(sig, SIG_DFL)
        self.signal_handlers[sig] = func
        return previous
