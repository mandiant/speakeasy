# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import math
import struct

import speakeasy.winenv.arch as e_arch
import speakeasy.winenv.defs.windows.windows as windef

from .. import api

EINVAL = 22
ERANGE = 34
_TRUNCATE = 0xFFFFFFFF

TIME_BASE = 1576292568
RAND_BASE = 0
TICK_BASE = 86400000  # 1 day in millisecs


class Msvcrt(api.ApiHandler):
    """
    Implements functions from various versions of the C runtime on Windows
    """
    name = 'msvcrt'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Msvcrt, self).__init__(emu)

        self.stdin = 0
        self.stdout = 1
        self.stderr = 2

        self.rand_int = RAND_BASE

        self.funcs = {}
        self.data = {}
        self.wintypes = windef

        self.tick_counter = TICK_BASE

        super(Msvcrt, self).__get_hook_attrs__(self)

    def hex_to_double(self, x):
        x = x.to_bytes(8, 'little')
        x = struct.unpack('d', x)[0]
        return x

    def double_to_hex(self, x):
        return struct.unpack('<Q', struct.pack('<d', x))[0]

    @impdata('_acmdln')
    def _acmdln(self, ptr=0):
        """Command line global CRT variable"""

        cmdln = ptr
        _argv = self.emu.get_argv()
        _argv = " ".join(_argv).encode('utf-8')

        ptr_size = self.emu.get_ptr_size()

        if not ptr:
            cmdln = self.mem_alloc(len(_argv) + ptr_size,
                                   base=None, tag='api.msvcrt._acmdln')
            p_cmdln = cmdln + ptr_size
            self.emu.mem_write(cmdln, p_cmdln.to_bytes(ptr_size, 'little'))
            self.emu.mem_write(p_cmdln, _argv)
        return cmdln

    @apihook('__p__acmdln', argc=0)
    def __p__acmdln(self, emu, argv, ctx={}):
        """Command line global CRT variable"""

        cmdln = self._acmdln()

        return cmdln

    @apihook('_onexit', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _onexit(self, emu, argv, ctx={}):
        """
        _onexit_t _onexit(
            _onexit_t function
        )
        """

        func, = argv
        return func

    @apihook('mbstowcs_s', argc=5, conv=e_arch.CALL_CONV_CDECL)
    def mbstowcs_s(self, emu, argv, ctx={}):
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

        rv = 0
        if pReturnValue:
            self.mem_write(pReturnValue, struct.pack("<I",0))

        # Sanity checks
        if sizeInWords > 0 and not wcstr:
            rv = EINVAL
        elif not mbstr:
            rv = EINVAL
        elif sizeInWords == 0 and wcstr:
            rv = EINVAL
        else:
            # Convert the string
            mbs = self.read_mem_string(mbstr, 1)
            argv[3] = mbs
            mbs += '\x00'
            ws = mbs.encode('utf-16le')

            if (len(ws) / 2 > sizeInWords and count != _TRUNCATE) and (count >= sizeInWords):
                # Buffer too small
                rv = ERANGE
            else:
                if count == _TRUNCATE:
                    self.mem_write(wcstr, ws[:(sizeInWords - 1) * 2])
                    if pReturnValue:
                        self.mem_write(pReturnValue, struct.pack("<I",sizeInWords))
                else:
                    self.mem_write(wcstr, ws[:count * 2])
                    if pReturnValue:
                        self.mem_write(pReturnValue, struct.pack("<I",count + 1))

        return rv

    @apihook('_wcsnicmp', argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _wcsnicmp(self, emu, argv, ctx={}):
        """
        int _wcsnicmp(
            const wchar_t *string1,
            const wchar_t *string2,
            size_t count
        )
        """

        string1, string2, count = argv
        rv = 1

        ws1 = self.read_wide_string(string1, max_chars=count)
        ws2 = self.read_wide_string(string2, max_chars=count)

        argv[0] = ws1
        argv[1] = ws2

        if ws1.lower() == ws2.lower():
            rv = 0

        return rv

    # Reference: https://wiki.osdev.org/Visual_C%2B%2B_Runtime
    @apihook('_initterm_e', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _initterm_e(self, emu, argv, ctx={}):
        """
        static int _initterm_e(_PIFV * pfbegin,
                                 _PIFV * pfend)
        """

        pfbegin, pfend = argv

        rv = 0

        return rv

    @apihook('_initterm', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _initterm(self, emu, argv, ctx={}):
        """static void _initterm (_PVFV * pfbegin, _PVFV * pfend)"""

        pfbegin, pfend = argv

        rv = 0

        return rv

    @apihook('__getmainargs', argc=5)
    def __getmainargs(self, emu, argv, ctx={}):
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

        return rv

    @apihook('__wgetmainargs', argc=5)
    def __wgetmainargs(self, emu, argv, ctx={}):
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

    @apihook('__p___wargv', argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __p___wargv(self, emu, argv, ctx={}):
        """WCHAR *** __p___wargv ()"""

        ptr_size = self.get_ptr_size()
        _argv = emu.get_argv()

        argv = [(a + '\x00\x00\x00\x00').encode('utf-16le') for a in _argv]
        array_size = (ptr_size * (len(argv) + 2))
        total = sum([len(a) for a in argv])
        total += array_size

        sptr = 0
        pptr = 0

        arg_mem = self.mem_alloc(size=total, tag='api.argv')
        pptr = arg_mem + ptr_size
        self.mem_write(arg_mem, pptr.to_bytes(ptr_size, 'little'))
        sptr = pptr + array_size

        for a in argv:
            self.mem_write(pptr, sptr.to_bytes(ptr_size, 'little'))
            pptr += ptr_size
            self.mem_write(sptr, a)
            sptr += len(a)
        self.mem_write(pptr, b'\x00' * ptr_size)
        rv = arg_mem

        # TODO: dispatch the VFV function array
        return rv

    @apihook('__p___argv', argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __p___argv(self, emu, argv, ctx={}):
        """char *** __p___argv ()"""

        ptr_size = self.get_ptr_size()
        _argv = emu.get_argv()

        argv = [(a + '\x00\x00\x00\x00').encode('utf-8') for a in _argv]

        array_size = (ptr_size * (len(argv) + 1))
        total = sum([len(a) for a in argv])
        total += array_size

        sptr = 0
        pptr = 0

        arg_mem = self.mem_alloc(size=total, tag='api.argv')
        pptr = arg_mem + ptr_size
        self.mem_write(arg_mem, pptr.to_bytes(ptr_size, 'little'))
        sptr = pptr + array_size

        for a in argv:
            self.mem_write(pptr, sptr.to_bytes(ptr_size, 'little'))
            pptr += ptr_size
            self.mem_write(sptr, a)
            sptr += len(a)
        self.mem_write(pptr, b'\x00' * ptr_size)

        rv = arg_mem
        return rv

    @apihook('__p___argc', argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __p___argc(self, emu, argv, ctx={}):
        """int * __p___argc ()"""

        _argv = emu.get_argv()

        argc = self.mem_alloc(size=4, tag='api.argc')
        self.mem_write(argc, len(_argv).to_bytes(4, 'little'))
        return argc

    @apihook('_get_initial_narrow_environment', argc=0,
             conv=e_arch.CALL_CONV_CDECL)
    def _get_initial_narrow_environment(self, emu, argv, ctx={}):
        """char** _get_initial_narrow_environment ()"""

        ptr_size = self.get_ptr_size()
        env = emu.get_env()
        total = ptr_size
        sptr = total
        pptr = 0
        fmt_env = []
        for k, v in env.items():
            envstr = '%s=%s\x00' % (k, v)
            envstr = envstr.encode('utf-8')
            total += len(envstr)
            fmt_env.append(envstr)
            total += ptr_size
            sptr += ptr_size

        envp = self.mem_alloc(size=total, tag='api.envp')
        pptr = envp
        sptr += envp

        for v in fmt_env:
            self.mem_write(pptr, sptr.to_bytes(ptr_size, 'little'))
            pptr += ptr_size
            self.mem_write(sptr, v)
            sptr += len(v)

        return envp

    @apihook('_get_initial_wide_environment', argc=0,
             conv=e_arch.CALL_CONV_CDECL)
    def _get_initial_wide_environment(self, emu, argv, ctx={}):
        """WCHAR** _get_initial_wide_environment ()"""

        ptr_size = self.get_ptr_size()
        env = emu.get_env()
        total = ptr_size
        sptr = total
        pptr = 0
        fmt_env = []
        for k, v in env.items():
            envstr = '%s=%s\x00' % (k, v)
            envstr = envstr.encode('utf-16le')
            total += len(envstr)
            fmt_env.append(envstr)
            total += ptr_size
            sptr += ptr_size

        envp = self.mem_alloc(size=total, tag='api.envp')
        pptr = envp
        sptr += envp

        for v in fmt_env:
            self.mem_write(pptr, sptr.to_bytes(ptr_size, 'little'))
            pptr += ptr_size
            self.mem_write(sptr, v)
            sptr += len(v)

        return envp

    @apihook('exit', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def exit(self, emu, argv, ctx={}):
        """
        void exit(
           int const status
        );
        """

        self.exit_process()

    @apihook('_exit', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _exit(self, emu, argv, ctx={}):
        """
        void _exit(
           int const status
        );
        """

        self.exit_process()

    @apihook('__acrt_iob_func', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def __acrt_iob_func(self, emu, argv, ctx={}):
        """FILE * __acrt_iob_func (fd)"""

        fd, = argv

        return fd

    @apihook('pow', argc=2, conv=e_arch.CALL_CONV_FLOAT)
    def pow(self, emu, argv, ctx={}):
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

    @apihook('floor', argc=1, conv=e_arch.CALL_CONV_FLOAT)
    def floor(self, emu, argv, ctx={}):
        """
        double floor(
           double x
        );
        """
        x, = argv

        y = self.hex_to_double(x)
        z = math.floor(y)
        z = self.double_to_hex(z)

        return z

    @apihook('sin', argc=1, conv=e_arch.CALL_CONV_FLOAT)
    def sin(self, emu, argv, ctx={}):
        """
        double sin(
           double x
        );
        """
        x, = argv

        y = self.hex_to_double(x)
        z = math.sin(y)
        z = self.double_to_hex(z)

        return z

    @apihook('abs', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def abs(self, emu, argv, ctx={}):
        """
        int abs(
           int x
        );
        """
        x, = argv
        y = abs(x)
        return y

    @apihook('strstr', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def strstr(self, emu, argv, ctx={}):
        """
        char *strstr(
           const char *str,
           const char *strSearch
        );
        """
        hay, needle = argv

        if hay:
            _hay = self.read_mem_string(hay, 1)
            argv[0] = _hay

        if needle:
            needle = self.read_mem_string(needle, 1)
            argv[1] = needle

        ret = _hay.find(needle)
        if ret != -1:
            ret = hay + ret
        else:
            ret = 0

        return ret

    @apihook('wcsstr', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def wcsstr(self, emu, argv, ctx={}):
        """
        wchar_t *wcsstr(
            const wchar_t *str,
            const wchar_t *strSearch
        );
        """
        hay, needle = argv

        if hay:
            _hay = self.read_mem_string(hay, 2)
            argv[0] = _hay

        if needle:
            needle = self.read_mem_string(needle, 2)
            argv[1] = needle

        ret = _hay.find(needle)
        if ret != -1:
            ret = hay + ret
        else:
            ret = 0

        return ret

    @apihook('strncat_s', argc=4, conv=e_arch.CALL_CONV_CDECL)
    def strncat_s(self, emu, argv, ctx={}):
        """
        errno_t strncat_s(
           char *strDest,
           size_t numberOfElements,
           const char *strSource,
           size_t count
        );
        """
        strDest, num, src, count = argv
        rv = 0

        is_truncated = (0xFFFFFFFF & count)
        if is_truncated == _TRUNCATE:
            is_truncated = True
        else:
            is_truncated = False

        argv[0] = self.read_mem_string(strDest, 1)
        argv[2] = self.read_mem_string(src, 1)

        slen1 = self.mem_string_len(strDest, 1)
        rem = num - slen1

        if is_truncated:
            if rem < count:
                self.mem_copy(strDest + slen1, src, count-1)
            else:
                self.mem_copy(strDest + slen1, src, count)
        else:
            if rem < count:
                rv = EINVAL
            else:
                self.mem_copy(strDest + slen1, src, count)

        return rv

    @apihook('__stdio_common_vfprintf', argc=e_arch.VAR_ARGS,
             conv=e_arch.CALL_CONV_CDECL)
    def __stdio_common_vfprintf(self, emu, argv, ctx={}):

        arch = emu.get_arch()
        if arch == e_arch.ARCH_AMD64:
            opts, stream, fmt, _, va_list = \
                emu.get_func_argv(e_arch.CALL_CONV_CDECL, 5)[:5]
        else:
            opts, opts2, stream, fmt, _, va_list = \
                emu.get_func_argv(e_arch.CALL_CONV_CDECL, 6)[:6]

        rv = 0

        fmt_str = self.read_mem_string(fmt, 1)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args(va_list, fmt_cnt)
        fin = self.do_str_format(fmt_str, vargs)

        argv[:] = [opts, stream, fin]

        rv = len(fin)
        return rv

    @apihook('memset', argc=3, conv=e_arch.CALL_CONV_CDECL)
    def memset(self, emu, argv, ctx={}):
        """
        void *memset ( void * ptr,
                       int value,
                       size_t num );
        """

        ptr, value, num = argv

        data = value.to_bytes(1, 'little') * num
        self.mem_write(ptr, data)

        return ptr

    @apihook('time', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def time(self, emu, argv, ctx={}):
        """
        time_t time( time_t *destTime );
        """

        destTime, = argv

        out_time = TIME_BASE
        if destTime:
            self.mem_write(destTime, out_time)

        return out_time

    @apihook('clock', argc=0, conv=e_arch.CALL_CONV_CDECL)
    def clock(self, emu, argv, ctx={}):
        '''
        clock_t clock( void );
        '''

        self.tick_counter += 200

        return self.tick_counter

    @apihook('srand', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def srand(self, emu, argv, ctx={}):
        """
        void srand (unsigned int seed);
        """

        seed, = argv

        return

    @apihook('sprintf', argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def sprintf(self, emu, argv, ctx={}):
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
        if not fmt_cnt:
            self.write_string(fmt_str, buf)
            return len(fmt_str)

        _argv = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 2 + fmt_cnt)[2:]
        fin = self.do_str_format(fmt_str, _argv)

        self.write_string(fin, buf)
        argv.clear()
        argv.append(fin)
        return len(fin)

    @apihook('_snprintf', argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def _snprintf(self, emu, argv, ctx={}):
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
        if not fmt_cnt:
            self.write_string(fmt_str, buf)
            return len(fmt_str)

        _argv = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 3 + fmt_cnt)[3:]
        fin = self.do_str_format(fmt_str, _argv)

        self.write_string(fin, buf)
        argv.clear()
        argv.append(fin)
        return len(fin)

    @apihook('atoi', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def atoi(self, emu, argv, ctx={}):
        """
        int atoi(
            const char *str
        );
        """

        _str, = argv

        i = self.read_string(_str)
        argv[0] = i

        try:
            rv = int(i)
        except ValueError:
            rv = 0

        return rv

    @apihook('rand', argc=0, conv=e_arch.CALL_CONV_CDECL)
    def rand(self, emu, argv, ctx={}):
        """
        int rand( void );
        """

        self.rand_int += 1

        return self.rand_int

    @apihook('__set_app_type', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def __set_app_type(self, emu, argv, ctx={}):
        """
        void __set_app_type (
            int at
        )
        """
        return

    @apihook('_set_app_type', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _set_app_type(self, emu, argv, ctx={}):
        return

    @apihook('__p__fmode', argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __p__fmode(self, emu, argv, ctx={}):
        """
        int* __p__fmode();
        """
        _O_TEXT = 0x4000

        ptr = self.mem_alloc(4, tag='api.fmode')
        data = _O_TEXT.to_bytes(4, 'little')
        self.mem_write(ptr, data)
        return ptr

    @apihook('__p__commode', argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __p__commode(self, emu, argv, ctx={}):
        """
        int* __p__commode();
        """
        _IOCOMMIT = 0x4000

        ptr = self.mem_alloc(4, tag='api.commode')
        data = _IOCOMMIT.to_bytes(4, 'little')
        self.mem_write(ptr, data)
        return ptr

    @apihook('_controlfp', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _controlfp(self, emu, argv, ctx={}):
        """
        unsigned int _controlfp(unsigned int new,
                                unsinged int mask)
        """
        return 0

    @apihook('strcpy', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def strcpy(self, emu, argv, ctx={}):
        """
        char *strcpy(
           char *strDestination,
           const char *strSource
        );
        """
        dest, src = argv
        s = self.read_string(src)

        self.write_string(s, dest)
        argv[1] = s
        return dest

    @apihook('wcscpy', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def wcscpy(self, emu, argv, ctx={}):
        """
        wchar_t *wcscpy(
            wchar_t *strDestination,
            const wchar_t *strSource
        );
        """
        dest, src = argv
        ws = self.read_wide_string(src)
        self.write_wide_string(ws, dest)
        argv[1] = ws
        return dest

    @apihook('strncpy', argc=3, conv=e_arch.CALL_CONV_CDECL)
    def strncpy(self, emu, argv, ctx={}):
        """
        char * strncpy(
            char * destination,
            const char * source,
            size_t num
        );
        """
        dest, src, length = argv
        s = self.read_string(src, max_chars=length)
        if len(s) < length:
            s += '\x00'*(length-len(s))
        self.write_string(s, dest)
        argv[1] = s
        return dest

    @apihook('wcsncpy', argc=3, conv=e_arch.CALL_CONV_CDECL)
    def wcsncpy(self, emu, argv, ctx={}):
        """
        wchar_t *wcsncpy(
           wchar_t *strDest,
           const wchar_t *strSource,
           size_t count
        );
        """
        dest, src, count = argv
        ws = self.read_wide_string(src, max_chars=count)
        if len(ws) < count:
            ws += '\x00'*(count-len(ws))
        self.write_wide_string(ws, dest)
        argv[1] = ws
        return dest

    @apihook('memcpy', argc=3, conv=e_arch.CALL_CONV_CDECL)
    def memcpy(self, emu, argv, ctx={}):
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

    @apihook('memmove', argc=3, conv=e_arch.CALL_CONV_CDECL)
    def memmove(self, emu, argv, ctx={}):
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

    @apihook('memcmp', argc=3, conv=e_arch.CALL_CONV_CDECL)
    def memcmp(self, emu, argv, ctx={}):
        """
        int memcmp(
           const void *buffer1,
           const void *buffer2,
           size_t count
        );
        """
        diff = 0
        buff1, buff2, cnt = argv
        for i in range(cnt):
            b1 = self.mem_read(buff1, 1)
            b2 = self.mem_read(buff2, 1)
            if b1 > b2:
                diff = 1
                break
            elif b1 < b2:
                diff = -1
                break

        return diff

    @apihook('_except_handler4_common', argc=6, conv=e_arch.CALL_CONV_CDECL)
    def _except_handler4_common(self, emu, argv, ctx={}):
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
        cookie = int.from_bytes(cookie, 'little')

        thread = emu.get_current_thread()

        # Break down the exception records into something more manageable
        curr_frame = frame
        seh = thread.get_seh()

        _ctx = self.wintypes.CONTEXT(emu.get_ptr_size())
        _ctx = self.mem_cast(_ctx, context)

        seh.set_context(_ctx, address=context)
        seh.set_record(record)

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

            scope_record_offset += (rec.sizeof() * tl)
            rec = self.mem_cast(rec, scope_record_offset)

            seh.add_frame(reg, st, [rec, ])

            curr_frame = reg.Next

        return rv

    @apihook('_seh_filter_exe', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _seh_filter_exe(self, emu, argv, ctx={}):
        """
        int __cdecl _seh_filter_exe(
           unsigned long _ExceptionNum,
           struct _EXCEPTION_POINTERS* _ExceptionPtr
        );
        """
        except_num, exc_ptr = argv
        rv = 1

        return rv

    @apihook('_except_handler3', argc=4, conv=e_arch.CALL_CONV_CDECL)
    def _except_handler3(self, emu, argv, ctx={}):
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

    @apihook('_seh_filter_dll', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _seh_filter_dll(self, emu, argv, ctx={}):
        """
        int __cdecl _seh_filter_dll(
           unsigned long _ExceptionNum,
           struct _EXCEPTION_POINTERS* _ExceptionPtr
        );
        """
        except_num, exc_ptr = argv
        rv = 1

        return rv

    @apihook('puts', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def puts(self, emu, argv, ctx={}):
        """
        int puts(
           const char *str
        );
        """
        s, = argv

        string = self.read_mem_string(s, 1)
        argv[0] = string
        rv = len(string)

        return rv

    @apihook('_initialize_onexit_table', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _initialize_onexit_table(self, emu, argv, ctx={}):
        """
        int _initialize_onexit_table(
            _onexit_table_t* table
            );
        """
        rv = 0

        return rv

    @apihook('_register_onexit_function', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _register_onexit_function(self, emu, argv, ctx={}):
        """
        int _register_onexit_function(
            _onexit_table_t* table,
            _onexit_t        function
            );
        """
        rv = 0

        return rv

    @apihook('malloc', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def malloc(self, emu, argv, ctx={}):
        """
        void *malloc(
        size_t size
        );
        """
        size, = argv

        chunk = self.heap_alloc(size, heap='HeapAlloc')
        return chunk

    @apihook('calloc', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def calloc(self, emu, argv, ctx={}):
        """
        void *calloc(
        size_t num,
        size_t size
        );
        """
        num, size, = argv

        chunk = self.heap_alloc(num*size, heap='HeapAlloc')

        buf = b'\x00' * (num*size)
        self.mem_write(chunk, buf)

        return chunk

    @apihook('free', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def free(self, emu, argv, ctx={}):
        """
        void free(
        void *memblock
        );
        """
        mem, = argv
        self.mem_free(mem)

    @apihook('_beginthreadex', argc=6, conv=e_arch.CALL_CONV_CDECL)
    def _beginthreadex(self, emu, argv, ctx={}):
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
            self.mem_write(thrdaddr, obj.get_id().to_bytes(4, 'little'))

        return handle

    @apihook('_beginthread', argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _beginthread(self, emu, argv, ctx={}):
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

    @apihook('system', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def system(self, emu, argv, ctx={}):
        """
        int system(
           const char *command
        );
        """
        s, = argv

        string = self.read_mem_string(s, 1)
        argv[0] = string
        rv = len(string)

        return rv

    @apihook('toupper', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def toupper(self, emu, argv, ctx={}):
        """
        int toupper(
           int c
        );
        """
        c, = argv
        argv[0] = c
        if 0x00 <= c <= 0x7f:
            c = ord(chr(c).upper())
        else:
            c = 0x00
        return c

    @apihook('strlen', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def strlen(self, emu, argv, ctx={}):
        """
        size_t strlen(
            const char *str
        );
        """
        s, = argv

        string = self.read_mem_string(s, 1)
        argv[0] = string
        rv = len(string)

        return rv

    @apihook('strcat', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def strcat(self, emu, argv, ctx={}):
        '''
        char *strcat(
            char *strDestination,
            const char *strSource
        );
        '''
        _str1, _str2 = argv
        s1 = self.read_mem_string(_str1, 1)
        s2 = self.read_mem_string(_str2, 1)
        argv[0] = s1
        argv[1] = s2
        new = (s1 + s2).encode('utf-8')
        self.mem_write(_str1, new + b'\x00')
        return _str1

    @apihook('wcscat', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def wcscat(self, emu, argv, ctx={}):
        '''
        wchar_t *wcscat(
           wchar_t *strDestination,
           const wchar_t *strSource
        );
        '''
        _str1, _str2 = argv
        s1 = self.read_mem_string(_str1, 2)
        s2 = self.read_mem_string(_str2, 2)
        argv[0] = s1
        argv[1] = s2
        new = (s1 + s2).encode('utf-16le')
        self.mem_write(_str1, new + b'\x00\x00')
        return _str1

    @apihook('wcslen', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def wcslen(self, emu, argv, ctx={}):
        """
        size_t wcslen(
          const wchar_t* wcs
        );
        """
        s, = argv
        string = self.read_wide_string(s)
        argv[0] = string
        rv = len(string)

        return rv

    @apihook('_lock', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _lock(self, emu, argv, ctx={}):
        """
        void __cdecl _lock
            int locknum
        );
        """
        return

    @apihook('_unlock', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _unlock(self, emu, argv, ctx={}):
        """
        void __cdecl _unlock
            int locknum
        );
        """
        return

    @apihook('_ltoa', argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _ltoa(self, emu, argv, ctx={}):
        """
        char *_ltoa(
            long value,
            char *str,
            int radix
        );
        """
        val, out_str, radix, = argv

        v = str(val).encode('utf-8')
        self.mem_write(out_str, v)
        return

    @apihook('__dllonexit', argc=3, conv=e_arch.CALL_CONV_CDECL)
    def __dllonexit(self, emu, argv, ctx={}):
        """
        onexit_t __dllonexit(
            _onexit_t func,
            _PVFV **  pbegin,
            _PVFV **  pend
        )
        """
        func, pbegin, pend, = argv
        return func

    @apihook('strncmp', argc=3, conv=e_arch.CALL_CONV_CDECL)
    def strncmp(self, emu, argv, ctx={}):
        """
        int strncmp(
            const char *string1,
            const char *string2,
            size_t count
        );
        """
        s1, s2, c = argv
        rv = 1

        string1 = self.read_mem_string(s1, 1)
        string2 = self.read_mem_string(s2, 1)
        if string1 == string2:
            rv = 0
        argv[0] = string1
        argv[1] = string2

        return rv

    @apihook('strcmp', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def strcmp(self, emu, argv, ctx={}):
        """
        int strcmp(
            const char *string1,
            const char *string2,
        );
        """
        s1, s2 = argv
        rv = 1

        string1 = self.read_mem_string(s1, 1)
        string2 = self.read_mem_string(s2, 1)
        if string1 == string2:
            rv = 0
        argv[0] = string1
        argv[1] = string2

        return rv

    @apihook('strrchr', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def strrchr(self, emu, argv, ctx={}):
        """
        char *strrchr(
            const char *str,
            int c
            );
        """
        cstr, c = argv
        cs = self.read_string(cstr)
        hay = cs.encode('utf-8')
        needle = c.to_bytes(1, 'little')

        offset = hay.rfind(needle)
        if offset < 0:
            rv = 0
        else:
            rv = cstr + offset

        argv[0] = cs
        argv[1] = needle.decode('utf-8')

        return rv

    @apihook('_ftol', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _ftol(self, emu, argv, ctx={}):
        """
        int _ftol(int);
        """
        f, = argv
        return int(f)

    @apihook('_adjust_fdiv', argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _adjust_fdiv(self, emu, argv, ctx={}):
        """
        void _adjust_fdiv(void)
        """
        return

    @apihook('tolower', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def tolower(self, emu, argv, ctx={}):
        """
        int tolower ( int c );
        """
        c, = argv
        return c | 0x20

    @apihook('sscanf', argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def sscanf(self, emu, argv, ctx={}):
        """
        int sscanf ( const char * s, const char * format, ...);
        """
        return

    @apihook('strchr', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def strchr(self, emu, argv, ctx={}):
        """
        char *strchr(
            const char *str,
            int c
            );
        """
        cstr, c = argv
        cs = self.read_string(cstr)
        hay = cs.encode('utf-8')
        needle = c.to_bytes(1, 'little')

        offset = hay.find(needle)
        if offset < 0:
            rv = 0
        else:
            rv = cstr + offset

        argv[0] = cs
        argv[1] = needle.decode('utf-8')

        return rv

    @apihook('_set_invalid_parameter_handler', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _set_invalid_parameter_handler(self, emu, argv, ctx={}):
        """
        _invalid_parameter_handler _set_invalid_parameter_handler(
        _invalid_parameter_handler pNew
        );
        """
        pNew, = argv

        return 0

    @apihook('__CxxFrameHandler', argc=4, conv=e_arch.CALL_CONV_CDECL)
    def __CxxFrameHandler(self, emu, argv, ctx={}):
        """
        EXCEPTION_DISPOSITION __CxxFrameHandler(
            EHExceptionRecord  *pExcept,
            EHRegistrationNode *pRN,
            void               *pContext,
            DispatcherContext  *pDC
        )
        """
        pExcept, pRN, pContext, pDC, = argv
        return 0

    @apihook('_vsnprintf', argc=4, conv=e_arch.CALL_CONV_CDECL)
    def _vsnprintf(self, emu, argv, ctx={}):
        """
        int _vsnprintf(
            char *buffer,
            size_t count,
            const char *format,
            va_list argptr
        );
        """
        buffer, count, _format, argptr = argv
        rv = 0

        fmt_str = self.read_mem_string(_format, 1)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args(argptr, fmt_cnt)

        fin = self.do_str_format(fmt_str, vargs)
        fin = fin[:count] + '\x00'

        rv = len(fin)
        self.mem_write(buffer, fin.encode('utf-8'))
        argv[0] = fin.replace('\x00', '')
        argv[1] = fmt_str

        return rv

    @apihook('__stdio_common_vsprintf', argc=7, conv=e_arch.CALL_CONV_CDECL)
    def __stdio_common_vsprintf(self, emu, argv, ctx={}):
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
        options_lo, options_hi, buffer, count, _format, locale, argptr = argv
        rv = 0
        fmt_str = self.read_mem_string(_format, 1)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args(argptr, fmt_cnt)

        fin = self.do_str_format(fmt_str, vargs)
        fin = fin[:count] + '\x00'

        rv = len(fin)
        self.mem_write(buffer, fin.encode('utf-8'))
        argv[0] = fin.replace('\x00', '')
        argv[1] = fmt_str

        return rv

    @apihook('_strcmpi', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _strcmpi(self, emu, argv, ctx={}):
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

        cs1 = self.read_string(string1)
        cs2 = self.read_string(string2)

        argv[0] = cs1
        argv[1] = cs2

        if cs1.lower() == cs2.lower():
            rv = 0

        return rv

    @apihook('_wcsicmp', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _wcsicmp(self, emu, argv, ctx={}):
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

        argv[0] = cs1
        argv[1] = cs2

        if cs1.lower() == cs2.lower():
            rv = 0

        return rv

    @apihook('??3@YAXPAX@Z', argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __3_YAXPAX_Z(self, emu, argv, ctx={}):
        return

    @apihook('??2@YAPAXI@Z', argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __2_YAPAXI_Z(self, emu, argv, ctx={}):
        return

    @apihook('__current_exception_context', argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __current_exception_context(self, emu, argv, ctx={}):
        return

    @apihook('__current_exception', argc=0, conv=e_arch.CALL_CONV_CDECL)
    def __current_exception(self, emu, argv, ctx={}):
        return

    @apihook('_set_new_mode', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _set_new_mode(self, emu, argv, ctx={}):
        return

    @apihook('_configthreadlocale', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _configthreadlocale(self, emu, argv, ctx={}):
        return

    @apihook('_setusermatherr', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _setusermatherr(self, emu, argv, ctx={}):
        return

    @apihook('__setusermatherr', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def __setusermatherr(self, emu, argv, ctx={}):
        return

    @apihook('_cexit', argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _cexit(self, emu, argv, ctx={}):
        # TODO: handle atexit flavor functions
        self.exit_process()

    @apihook('_c_exit', argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _c_exit(self, emu, argv, ctx={}):
        self.exit_process()

    @apihook('_register_thread_local_exe_atexit_callback', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _register_thread_local_exe_atexit_callback(self, emu, argv, ctx={}):
        return

    @apihook('_crt_atexit', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _crt_atexit(self, emu, argv, ctx={}):
        return

    @apihook('_controlfp_s', argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _controlfp_s(self, emu, argv, ctx={}):
        return

    @apihook('terminate', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def terminate(self, emu, argv, ctx={}):
        self.exit_process()

    @apihook('_crt_atexit', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _crt_atexit(self, emu, argv, ctx={}):
        return

    @apihook('_initialize_narrow_environment', argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _initialize_narrow_environment(self, emu, argv, ctx={}):
        return

    @apihook('_configure_narrow_argv', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _configure_narrow_argv(self, emu, argv, ctx={}):
        return

    @apihook('_set_fmode', argc=1, conv=e_arch.CALL_CONV_CDECL)
    def _set_fmode(self, emu, argv, ctx={}):
        return

    @apihook('_itoa', argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _itoa(self, emu, argv, ctx={}):
        return

    @apihook('_itow', argc=3, conv=e_arch.CALL_CONV_CDECL)
    def _itow(self, emu, argv, ctx={}):
        return

    @apihook('_EH_prolog', argc=0, conv=e_arch.CALL_CONV_CDECL)
    def _EH_prolog(self, emu, argv, ctx={}):
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
        emu.write_ptr(
            emu.fs_addr + 0,
            emu.reg_read(e_arch.X86_REG_ESP))

        # mov     DWORD PTR [esp+12], ebp
        emu.write_ptr(
            emu.reg_read(e_arch.X86_REG_ESP) + 12,
            emu.reg_read(e_arch.X86_REG_EBP))

        # lea     ebp, DWORD PTR [esp+12]
        emu.reg_write(
            e_arch.X86_REG_EBP,
            emu.reg_read(e_arch.X86_REG_ESP) + 12)

        # push    eax
        # ret     0
        emu.push_stack(eax)
        return

    @apihook('wcstombs', argc=3, conv=e_arch.CALL_CONV_CDECL)
    def wcstombs(self, emu, argv, ctx={}):
        '''
        size_t wcstombs(
            char *mbstr,
            const wchar_t *wcstr,
            size_t count
        );
        '''
        mbstr, wcstr, count = argv

        s = self.read_wide_string(wcstr, count)
        self.write_string(s, mbstr)
        return len(s.encode("ascii"))

    @apihook('_stricmp', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _stricmp(self, emu, argv, ctx={}):
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

        cs1 = self.read_string(string1)
        cs2 = self.read_string(string2)

        argv[0] = cs1
        argv[1] = cs2

        if cs1.lower() == cs2.lower():
            rv = 0

        return rv

    @apihook('_wcsicmp', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def _wcsicmp(self, emu, argv, ctx={}):
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

        argv[0] = ws1
        argv[1] = ws2

        if ws1.lower() == ws2.lower():
            rv = 0

        return rv

    @apihook('wcscmp', argc=2, conv=e_arch.CALL_CONV_CDECL)
    def wcscmp(self, emu, argv, ctx={}):
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
        argv[0] = string1
        argv[1] = string2

        return rv
    
    @apihook('_snwprintf', argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def _snwprintf(self, emu, argv, ctx={}):
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

        if not fmt_cnt:
            self.write_wide_string(fmt_str, buf)
            return len(fmt_str)

        argv = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 3 + fmt_cnt)[3:]
        fin = self.do_str_format(fmt_str, argv)

        self.write_wide_string(fin, buf)

        argv = [buf, cnt, fmt] + argv
        argv[2] = fmt_str
        return len(fin)
