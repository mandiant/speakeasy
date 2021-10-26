# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import os
import ntpath

from .. import api
import speakeasy.winenv.arch as e_arch


class Shlwapi(api.ApiHandler):

    """
    Implements exported functions from shlwapi.dll
    """

    name = 'shlwapi'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Shlwapi, self).__init__(emu)

        self.funcs = {}
        self.data = {}
        self.window_hooks = {}
        self.handle = 0
        self.win = None

        super(Shlwapi, self).__get_hook_attrs__(self)

    def join_windows_path(self, *args, **kwargs):
        args = list(map(lambda x: x.replace('\\', '/'), args))
        return os.path.join(*args, **kwargs).replace('/', '\\')

    @apihook('PathIsRelative', argc=1)
    def PathIsRelative(self, emu, argv, ctx={}):
        '''
        BOOL PathIsRelativeA(
            LPCSTR pszPath
        );
        '''

        pszPath, = argv

        cw = self.get_char_width(ctx)
        pn = ''
        rv = False
        if pszPath:
            pn = self.read_mem_string(pszPath, cw)
            if '..' in pn:
                rv = True

            argv[0] = pn

        return rv
    
    @apihook('StrStr', argc=2)
    def StrStr(self, emu, argv, ctx={}):
        '''
        PCSTR StrStr(
            PCSTR pszFirst,
            PCSTR pszSrch
        );
        '''

        hay, needle = argv

        cw = self.get_char_width(ctx)

        if hay:
            _hay = self.read_mem_string(hay, cw)
            argv[0] = _hay

        if needle:
            needle = self.read_mem_string(needle, cw)
            argv[1] = needle

        ret = _hay.find(needle)
        if ret != -1:
            ret = hay + ret
        else:
            ret = 0

        return ret
    
    @apihook('StrStrI', argc=2)
    def StrStrI(self, emu, argv, ctx={}):
        '''
        PCSTR StrStrI(
            PCSTR pszFirst,
            PCSTR pszSrch
        );
        '''

        hay, needle = argv

        cw = self.get_char_width(ctx)

        if hay:
            _hay = self.read_mem_string(hay, cw)
            argv[0] = _hay
            _hay = _hay.lower()

        if needle:
            needle = self.read_mem_string(needle, cw)
            argv[1] = needle
            needle = needle.lower()

        ret = _hay.find(needle)
        if ret != -1:
            ret = hay + ret
        else:
            ret = 0

        return ret

    @apihook('PathFindExtension', argc=1)
    def PathFindExtension(self, emu, argv, ctx={}):
        """LPCSTR PathFindExtensionA(
          LPCSTR pszPath
        );
        """
        pszPath, = argv
        cw = self.get_char_width(ctx)
        s = self.read_mem_string(pszPath, cw)
        argv[0] = s
        idx1 = s.rfind('\\')
        t = s[idx1 + 1:]
        idx2 = t.rfind('.')
        if idx2 == -1:
            return pszPath + len(s)

        argv[0] = t[idx2:]
        return pszPath + idx1 + 1 + idx2

    @apihook('StrCmpI', argc=2)
    def StrCmpI(self, emu, argv, ctx={}):
        """
        int StrCmpI(
        PCWSTR psz1,
        PCWSTR psz2
        );
        """
        psz1, psz2 = argv

        cw = self.get_char_width(ctx)
        s1 = self.read_mem_string(psz1, cw)
        s2 = self.read_mem_string(psz2, cw)
        rv = 1

        argv[0] = s1
        argv[1] = s2

        if s1.lower() == s2.lower():
            rv = 0

        return rv

    @apihook('PathFindFileName', argc=1)
    def PathFindFileName(self, emu, argv, ctx={}):
        """
        LPCSTR PathFindFileNameA(
          LPCSTR pszPath
        );
        """
        pszPath, = argv
        cw = self.get_char_width(ctx)
        s = self.read_mem_string(pszPath, cw)
        argv[0] = s
        idx = s.rfind('\\')
        if idx == -1:
            return pszPath + len(s)

        argv[0] = s[idx + 1:]
        return pszPath + idx + 1

    @apihook('PathRemoveExtension', argc=1)
    def PathRemoveExtension(self, emu, argv, ctx={}):
        """
        void PathRemoveExtensionA(
          LPSTR pszPath
        );
        """
        pszPath, = argv
        cw = self.get_char_width(ctx)
        s = self.read_mem_string(pszPath, cw)
        argv[0] = s
        idx1 = s.rfind('\\')
        t = s[idx1 + 1:]
        idx2 = t.rfind('.')
        if idx2 == -1:
            return pszPath

        s = s[:idx1 + 1 + idx2]
        argv[0] = s
        self.write_mem_string(s, pszPath, cw)
        return pszPath

    @apihook('PathStripPath', argc=1)
    def PathStripPath(self, emu, argv, ctx={}):
        """
        void PathStripPath(
        LPSTR pszPath
        );
        """
        pszPath, = argv
        cw = self.get_char_width(ctx)
        s = self.read_mem_string(pszPath, cw)
        argv[0] = s
        mod_name = ntpath.basename(s) + '\x00'

        enc = self.get_encoding(cw)
        mod_name = mod_name.encode(enc)
        self.mem_write(pszPath, mod_name)

    @apihook('wvnsprintfA', argc=4)
    def wvnsprintfA(self, emu, argv, ctx={}):
        """
        int wvnsprintfA(
            PSTR    pszDest,
            int     cchDest,
            PCSTR   pszFmt,
            va_list arglist
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

    @apihook('wnsprintf', argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def wnsprintf(self, emu, argv, ctx={}):
        """
        int wnsprintfA(
          PSTR  pszDest,
          int   cchDest,
          PCSTR pszFmt,
          ...
        );
        """
        argv = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 3)
        buf, max_buf_size, fmt = argv

        cw = self.get_char_width(ctx)

        fmt_str = self.read_mem_string(fmt, cw)
        fmt_cnt = self.get_va_arg_count(fmt_str)
        if not fmt_cnt:
            self.write_mem_string(fmt_str, buf, cw)
            return len(fmt_str)

        _argv = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 3 + fmt_cnt)[3:]
        fin = self.do_str_format(fmt_str, _argv)
        rv = len(fin)

        if rv <= max_buf_size:
            self.write_mem_string(fin, buf, cw)
            argv[0] = fin
            argv[2] = fmt_str
            return rv
        else:
            return -1

    @apihook('PathAppend', argc=2)
    def PathAppend(self, emu, argv, ctx={}):
        """
        BOOL PathAppendA(
          LPSTR  pszPath,
          LPCSTR pszMore
        );
        """
        pszPath, pszMore = argv
        cw = self.get_char_width(ctx)
        path = self.read_mem_string(pszPath, cw)
        more = self.read_mem_string(pszMore, cw)
        argv[0] = path
        argv[1] = more
        out = self.join_windows_path(path, more)
        out += '\0'
        self.write_mem_string(out, pszPath, cw)
        return 1
    
    @apihook('PathCanonicalize', argc=2)
    def PathCanonicalize(self, emu, argv, ctx={}):
        """
        BOOL PathCanonicalizeW(
            [out] LPWSTR  pszBuf,
            [in]  LPCWSTR pszPath
        );
        """
        pszBuf, pszPath = argv
        path = self.read_wide_string(pszPath)
        self.write_wide_string(path, pszBuf)
        return 1
