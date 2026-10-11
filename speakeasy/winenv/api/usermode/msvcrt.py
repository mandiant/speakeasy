# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import io
import math
import re
import struct
from typing import Any

import speakeasy.winenv.arch as e_arch
import speakeasy.winenv.defs.windows.windows as windef

from .. import api

EINVAL = 22
ERANGE = 34
STRUNCATE = 80
_CRT_INTERNAL_PRINTF_LEGACY_VSPRINTF_NULL_TERMINATION = 1
_CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR = 2

TIME_BASE = 1576292568
RAND_BASE = 0
TICK_BASE = 86400000  # 1 day in millisecs

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
        self.errno_t: int | None = None
        self.file_streams: dict[int, Any] = {}

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

    @apihook("__p__acmdln", argc=0)
    def __p__acmdln(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """Command line global CRT variable"""

        cmdln = emu.get_proc("msvcrt", "_acmdln")

        return cmdln

    @apihook("_onexit", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _onexit(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        _onexit_t _onexit(
            _onexit_t function
        )
        """

        (func,) = argv
        return func

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
        _CRTIMP  __C_specific_handler(
        _In_    struct _EXCEPTION_RECORD   *ExceptionRecord,
        _In_    void                       *EstablisherFrame,
        _Inout_ struct _CONTEXT            *ContextRecord,
        _Inout_ struct _DISPATCHER_CONTEXT *DispatcherContext
        );
        """
        # Inferred from the SEH teardowns described here:
        # https://bytepointer.com/resources/pietrek_crash_course_depths_of_win32_seh.htm
        # http://www.openrce.org/articles/full_view/21

        # Two additional arguments are pushed to the function to check security cookies
        cookie_ptr, cookie_func, record, frame, context, dispath_ctx = argv
        rv = 0

        cookie = self.mem_read(cookie_ptr, 4)
        cookie = int.from_bytes(cookie, "little")

        thread = emu.get_current_thread()

        # Break down the exception records into something more manageable
        curr_frame = frame
        seh = thread.seh

        _ctx = self.wintypes.CONTEXT(emu.get_ptr_size())
        _ctx = self.mem_cast(_ctx, context)

        seh.set_context(_ctx, address=context)
        seh.record = record

        seh.clear_frames()

        while curr_frame != 0:
            reg = self.wintypes.EXCEPTION_REGISTRATION(emu.get_ptr_size())
            reg = self.mem_cast(reg, curr_frame)

            scope_table = reg.ScopeTable ^ cookie

            st = self.wintypes.EH4_SCOPETABLE(emu.get_ptr_size())
            st = self.mem_cast(st, scope_table)

            rec = self.wintypes.EH4_SCOPETABLE_RECORD(emu.get_ptr_size())
            # The trylevel will tell us what scope record to get
            scope_record_offset = scope_table + st.sizeof()
            tl = reg.TryLevel
            if reg.TryLevel & 0x80000000:
                tl = -0x100000000 + reg.TryLevel

            if tl == -2:  # -2 is the outermost scope
                tl = 0

            scope_record_offset += rec.sizeof() * tl
            rec = self.mem_cast(rec, scope_record_offset)

            seh.add_frame(
                reg,
                st,
                [
                    rec,
                ],
            )

            curr_frame = reg.Next

        return rv

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

    @apihook("_except_handler3", argc=4, conv=e_arch.CALL_CONV_CDECL)
    def _except_handler3(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int _except_handler3(
        PEXCEPTION_RECORD exception_record,
        PEXCEPTION_REGISTRATION registration,
        PCONTEXT context,
        PEXCEPTION_REGISTRATION dispatcher
        );
        """
        rv = 1
        return rv

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

    @apihook("isdigit", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def isdigit(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int isdigit(
            int c
            );
        """
        (c,) = argv
        return int(48 <= c <= 57)

    @apihook("sscanf", argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def sscanf(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int sscanf ( const char * s, const char * format, ...);
        """
        return

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
        options = argv[0]
        first = 1 if emu.get_arch() == e_arch.ARCH_AMD64 else 2
        buffer, count, _format, _, argptr = argv[first : first + 5]
        fmt_str = self.read_mem_string(_format, 1)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args(argptr, fmt_cnt)

        fin = self.do_str_format(fmt_str, vargs)
        ctx.args[first + 2].display = fmt_str
        if not buffer and not count:
            return len(fin)

        if options & _CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR:
            out = fin[: count - 1] + "\x00"
            rv = len(fin)
        elif options & _CRT_INTERNAL_PRINTF_LEGACY_VSPRINTF_NULL_TERMINATION:
            out = fin[:count] if len(fin) >= count else fin + "\x00"
            rv = len(fin) if len(fin) <= count else -1
        else:
            out = fin[: count - 1] + "\x00"
            rv = len(fin) if len(fin) < count else -1

        if count:
            self.mem_write(buffer, out.encode("utf-8"))
            ctx.args[first].display = out.rstrip("\x00")

        return rv

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

    @apihook("_crt_atexit", argc=1, conv=e_arch.CALL_CONV_CDECL)  # type: ignore[no-redef]
    def _crt_atexit(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        return

    @apihook("_initialize_narrow_environment", argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _initialize_narrow_environment(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        return

    @apihook("_configure_narrow_argv", argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _configure_narrow_argv(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        return

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

    @apihook("fputc", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def fputc(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int fputc(
            int c,
            FILE *stream
        );
        """
        c, _ = argv
        return c

    @apihook("signal", argc=2, conv=e_arch.CALL_CONV_CDECL)
    def signal(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void __cdecl *signal(
            int sig,
            int (*func)(int, int)
        );
        """
        sig, _ = argv

        if sig in [SIGINT, SIGILL, SIGFPE, SIGSEGV, SIGTERM, SIGBREAK, SIGABRT]:
            return SIG_IGN
        else:
            return SIG_ERR
