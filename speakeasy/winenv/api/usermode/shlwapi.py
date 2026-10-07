# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ntpath
import os
from typing import Any

import speakeasy.winenv.arch as e_arch

from .. import api

MAX_PATH = 260


class Shlwapi(api.ApiHandler):
    """
    Implements exported functions from shlwapi.dll
    """

    name = "shlwapi"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs: dict[str, Any] = {}
        self.data: dict[str, Any] = {}
        self.window_hooks: dict[int, tuple] = {}
        self.handle: int = 0
        self.win: Any | None = None

        super().__get_hook_attrs__(self)

    def join_windows_path(self, *args, **kwargs):
        args = list(map(lambda x: x.replace("\\", "/"), args))
        return os.path.join(*args, **kwargs).replace("/", "\\")

    @apihook("PathIsRelative", argc=1)
    def PathIsRelative(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PathIsRelativeA(
            LPCSTR pszPath
        );
        """
        (pszPath,) = argv

        cw = self.get_char_width(ctx)
        pn = ""
        rv = True
        if pszPath:
            pn = self.read_mem_string(pszPath, cw)
            if pn.startswith("\\") or pn[1:2] == ":":
                rv = False

            ctx.args["pszPath"].display = pn

        return rv

    @apihook("StrStr", argc=2)
    def StrStr(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PCSTR StrStr(
            PCSTR pszFirst,
            PCSTR pszSrch
        );
        """
        hay, needle = argv

        cw = self.get_char_width(ctx)

        if hay:
            _hay = self.read_mem_string(hay, cw)
            ctx.args["pszFirst"].display = _hay

        if needle:
            needle = self.read_mem_string(needle, cw)
            ctx.args["pszSrch"].display = needle

        if not hay or not needle:
            return 0

        ret = _hay.find(needle)
        if ret != -1:
            ret = hay + ret * cw
        else:
            ret = 0

        return ret

    @apihook("StrStrI", argc=2)
    def StrStrI(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PCSTR StrStrI(
            PCSTR pszFirst,
            PCSTR pszSrch
        );
        """
        hay, needle = argv

        cw = self.get_char_width(ctx)

        if hay:
            _hay = self.read_mem_string(hay, cw)
            ctx.args["pszFirst"].display = _hay
            _hay = _hay.lower()

        if needle:
            needle = self.read_mem_string(needle, cw)
            ctx.args["pszSrch"].display = needle
            needle = needle.lower()

        if not hay or not needle:
            return 0

        ret = _hay.find(needle)
        if ret != -1:
            ret = hay + ret * cw
        else:
            ret = 0

        return ret

    @apihook("PathFindExtension", argc=1)
    def PathFindExtension(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """LPCSTR PathFindExtensionA(
          LPCSTR pszPath
        );
        """
        (pszPath,) = argv
        cw = self.get_char_width(ctx)
        s = self.read_mem_string(pszPath, cw)
        ctx.args["pszPath"].display = s
        idx1 = s.rfind("\\")
        t = s[idx1 + 1 :]
        idx2 = t.rfind(".")
        if idx2 == -1:
            return pszPath + len(s) * cw

        ctx.args["pszPath"].display = t[idx2:]
        return pszPath + (idx1 + 1 + idx2) * cw

    @apihook("StrCmpI", argc=2)
    def StrCmpI(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
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

        ctx.args["psz1"].display = s1
        ctx.args["psz2"].display = s2

        s1, s2 = s1.lower(), s2.lower()
        return (s1 > s2) - (s1 < s2)

    @apihook("PathFindFileName", argc=1)
    def PathFindFileName(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPCSTR PathFindFileNameA(
          LPCSTR pszPath
        );
        """
        (pszPath,) = argv
        cw = self.get_char_width(ctx)
        s = self.read_mem_string(pszPath, cw)
        ctx.args["pszPath"].display = s
        idx = s.rfind("\\")
        if idx == -1:
            return pszPath

        ctx.args["pszPath"].display = s[idx + 1 :]
        return pszPath + (idx + 1) * cw

    @apihook("PathRemoveExtension", argc=1)
    def PathRemoveExtension(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void PathRemoveExtensionA(
          LPSTR pszPath
        );
        """
        (pszPath,) = argv
        cw = self.get_char_width(ctx)
        s = self.read_mem_string(pszPath, cw)
        ctx.args["pszPath"].display = s
        idx1 = s.rfind("\\")
        t = s[idx1 + 1 :]
        idx2 = t.rfind(".")
        if idx2 == -1:
            return pszPath

        s = s[: idx1 + 1 + idx2]
        ctx.args["pszPath"].display = s
        self.write_mem_string(s, pszPath, cw)
        return pszPath

    @apihook("PathStripPath", argc=1)
    def PathStripPath(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void PathStripPath(
        LPSTR pszPath
        );
        """
        (pszPath,) = argv
        cw = self.get_char_width(ctx)
        s = self.read_mem_string(pszPath, cw)
        ctx.args["pszPath"].display = s
        mod_name = ntpath.basename(s) + "\x00"

        enc = self.get_encoding(cw)
        mod_name = mod_name.encode(enc)
        self.mem_write(pszPath, mod_name)

    @apihook("wvnsprintfA", argc=4)
    def wvnsprintfA(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int wvnsprintfA(
            PSTR    pszDest,
            int     cchDest,
            PCSTR   pszFmt,
            va_list arglist
        );
        """
        buffer, count, _format, argptr = argv

        fmt_str = self.read_mem_string(_format, 1)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args(argptr, fmt_cnt)

        fin = self.do_str_format(fmt_str, vargs)
        out = fin[: max(count - 1, 0)]
        if count > 0:
            self.write_mem_string(out, buffer, 1)
        ctx.args["pszDest"].display = out
        ctx.args["pszFmt"].display = fmt_str

        return len(fin) if len(fin) < count else -1

    @apihook("wnsprintf", argc=e_arch.VAR_ARGS, conv=e_arch.CALL_CONV_CDECL)
    def wnsprintf(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
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
        fin = fmt_str
        if fmt_cnt:
            _argv = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 3 + fmt_cnt)[3:]
            fin = self.do_str_format(fmt_str, _argv, wide=cw == 2)

        out = fin[: max(max_buf_size - 1, 0)]
        if max_buf_size > 0:
            self.write_mem_string(out, buf, cw)
        ctx.args.clear()
        ctx.args.append(out)

        return len(fin) if len(fin) < max_buf_size else -1

    @apihook("PathAppend", argc=2)
    def PathAppend(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
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
        ctx.args["pszPath"].display = path
        ctx.args["pszMore"].display = more
        if not more.startswith("\\\\"):
            more = more.lstrip("\\")
        out = self.join_windows_path(path, more)
        out += "\0"
        self.write_mem_string(out, pszPath, cw)
        return 1

    @apihook("PathCanonicalize", argc=2)
    def PathCanonicalize(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PathCanonicalizeW(
            [out] LPWSTR  pszBuf,
            [in]  LPCWSTR pszPath
        );
        """
        pszBuf, pszPath = argv
        cw = self.get_char_width(ctx)
        path = self.read_mem_string(pszPath, cw)
        self.write_mem_string(path, pszBuf, cw)
        return 1

    @apihook("PathRemoveFileSpec", argc=1)
    def PathRemoveFileSpec(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PathRemoveFileSpec(LPTSTR pszPath);
        """
        (pszPath,) = argv
        cw = self.get_char_width(ctx)
        s = self.read_mem_string(pszPath, cw)
        i = cut = len(s[:2]) - len(s[:2].lstrip("\\"))
        while i < len(s):
            if s[i] == "\\":
                cut = i
            elif s[i] == ":":
                i += 1
                cut = i + 1 if s[i : i + 1] == "\\" else i
            i += 1
        if cut >= len(s):
            return 0

        self.write_mem_string(s[:cut], pszPath, cw)
        return 1

    @apihook("PathAddBackslash", argc=1)
    def PathAddBackslash(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPTSTR PathAddBackslash(LPTSTR pszPath);
        """
        (pszPath,) = argv
        cw = self.get_char_width(ctx)
        s = self.read_mem_string(pszPath, cw)
        if not s.endswith("\\"):
            s += "\\"
            if len(s) > MAX_PATH:
                return 0

        self.write_mem_string(s, pszPath, cw)
        return pszPath + len(s) * cw

    @apihook("PathRenameExtension", argc=2)
    def PathRenameExtension(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PathRenameExtension(
          [in, out] LPSTR  pszPath,
          [in]      LPCSTR pszExt
        );
        """
        pszPath, pszExt = argv

        cw = self.get_char_width(ctx)
        path = self.read_mem_string(pszPath, cw)

        ext = self.read_mem_string(pszExt, cw)
        if not ext.startswith("."):
            return 0

        i = path.rfind(".")
        if i == -1 or i < path.rfind("\\"):
            path += ext
        else:
            path = path[:i] + ext

        if len(path) > MAX_PATH:
            return 0

        self.write_mem_string(path, pszPath, cw)
        return 1
