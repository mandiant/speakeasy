# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ntpath
import os
from typing import TYPE_CHECKING
from urllib.parse import urljoin

import speakeasy.winenv.arch as e_arch
import speakeasy.winenv.defs.windows.windows as windefs

from .. import api
from .shell32 import write_dll_version

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator

MAX_PATH = 260
E_INVALIDARG = 0x80070057
E_POINTER = 0x80004003

OS_NT = 1
OS_NT4ORGREATER = 3
OS_WIN2000ORGREATER_ALT = 4
OS_WIN2000ORGREATER = 7
OS_XPORGREATER = 18
OS_PROFESSIONAL = 20
OS_FASTUSERSWITCHING = 26
OS_WELCOMELOGONUI = 27


def get_path_without_file_spec(s: str) -> str | None:
    """
    Remove the last element of a path the way PathRemoveFileSpec does.
    Return None when nothing is removed.
    """
    i = cut = len(s[:2]) - len(s[:2].lstrip("\\"))
    while i < len(s):
        if s[i] == "\\":
            cut = i
        elif s[i] == ":":
            i += 1
            cut = i + 1 if s[i : i + 1] == "\\" else i
        i += 1
    if cut >= len(s):
        return None
    return s[:cut]


def get_path_root(path: str) -> str:
    """
    Get the root of a path the way PathStripToRoot does: a drive, a UNC
    share, a single backslash, or an empty string for a relative path.
    """
    if path[1:2] == ":":
        return path[:3] if path[2:3] == "\\" else path[:2]
    if path.startswith("\\\\"):
        return "\\".join(path.split("\\")[:4])
    return "\\" if path.startswith("\\") else ""


def get_canonical_path(path: str) -> str:
    """
    Remove the "." and ".." elements of a path the way PathCanonicalize does.
    A ".." element at the root is dropped.
    """
    root = path[:3] if path[1:3] == ":\\" else path[: len(path[:2]) - len(path[:2].lstrip("\\"))]
    parts: list[str] = []
    for part in path[len(root) :].split("\\"):
        if part == "..":
            if parts:
                parts.pop()
        elif part != ".":
            parts.append(part)
    return root + "\\".join(parts)


class Shlwapi(api.ApiHandler):
    """
    Implements exported functions from shlwapi.dll
    """

    name = "shlwapi"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs = {}
        self.data = {}
        self.window_hooks: dict[int, tuple] = {}
        self.handle: int = 0

        super().__get_hook_attrs__(self)

    def join_windows_path(self, *args, **kwargs):
        args = list(map(lambda x: x.replace("\\", "/"), args))
        return os.path.join(*args, **kwargs).replace("/", "\\")

    @apihook("PathIsRelative", argc=1)
    def PathIsRelative(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PathIsRelative(
            LPCTSTR pszPath
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

    @apihook("PathFileExists", argc=1)
    def PathFileExists(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PathFileExists(
            LPCTSTR pszPath
        );
        """
        (pszPath,) = argv

        path = ""
        if pszPath:
            path = self.read_mem_string(pszPath, self.get_char_width(ctx))
            ctx.args["pszPath"].display = path
        if path and (emu.get_file_manager().is_directory(path) or self.does_file_exist(path)):
            return 1
        emu.set_last_error(windefs.ERROR_FILE_NOT_FOUND)
        return 0

    @apihook("StrStr", argc=2)
    def StrStr(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PCTSTR StrStr(
            PCTSTR pszFirst,
            PCTSTR pszSrch
        );
        """
        hay, needle = argv

        cw = self.get_char_width(ctx)

        if hay:
            _hay = self.read_mem_string(hay, cw)
            ctx.args["pszFirst"].display = _hay

        if needle:
            _needle = self.read_mem_string(needle, cw)
            ctx.args["pszSrch"].display = _needle

        if not hay or not needle or not _needle:
            return 0

        ret = _hay.find(_needle)
        if ret != -1:
            ret = hay + ret * cw
        else:
            ret = 0

        return ret

    @apihook("StrStrI", argc=2)
    def StrStrI(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PCTSTR StrStrI(
            PCTSTR pszFirst,
            PCTSTR pszSrch
        );
        """
        hay, needle = argv

        cw = self.get_char_width(ctx)

        if hay:
            _hay = self.read_mem_string(hay, cw)
            ctx.args["pszFirst"].display = _hay
            _hay = _hay.lower()

        if needle:
            _needle = self.read_mem_string(needle, cw)
            ctx.args["pszSrch"].display = _needle
            _needle = _needle.lower()

        if not hay or not needle or not _needle:
            return 0

        ret = _hay.find(_needle)
        if ret != -1:
            ret = hay + ret * cw
        else:
            ret = 0

        return ret

    def find_char(self, start, end, match, cw, ignore_case, last):
        """Return the address of the first or last ``match`` in [start, end), or 0."""
        if not start:
            return 0
        match = chr(match & (0xFFFF if cw == 2 else 0xFF))
        if ignore_case:
            match = match.lower()
        found = 0
        addr = start
        while not end or addr < end:
            unit = int.from_bytes(self.mem_read(addr, cw), "little")
            if not unit:
                break
            char = chr(unit).lower() if ignore_case else chr(unit)
            if char == match:
                found = addr
                if not last:
                    break
            addr += cw
        return found

    @apihook("StrChr", argc=2)
    def StrChr(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PTSTR StrChr(
            PCTSTR pszStart,
            TCHAR wMatch
        );
        """
        start, match = argv
        return self.find_char(start, 0, match, self.get_char_width(ctx), False, False)

    @apihook("StrChrI", argc=2)
    def StrChrI(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PTSTR StrChrI(
            PCTSTR pszStart,
            TCHAR wMatch
        );
        """
        start, match = argv
        return self.find_char(start, 0, match, self.get_char_width(ctx), True, False)

    @apihook("StrRChr", argc=3)
    def StrRChr(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PTSTR StrRChr(
            PCTSTR pszStart,
            PCTSTR pszEnd,
            TCHAR wMatch
        );
        """
        start, end, match = argv
        return self.find_char(start, end, match, self.get_char_width(ctx), False, True)

    @apihook("StrRChrI", argc=3)
    def StrRChrI(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PTSTR StrRChrI(
            PCTSTR pszStart,
            PCTSTR pszEnd,
            TCHAR wMatch
        );
        """
        start, end, match = argv
        return self.find_char(start, end, match, self.get_char_width(ctx), True, True)

    @apihook("PathFindExtension", argc=1)
    def PathFindExtension(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPCTSTR PathFindExtension(
            LPCTSTR pszPath
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
    def StrCmpI(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int StrCmpI(
            PCTSTR psz1,
            PCTSTR psz2
        );
        """
        return self.compare_strings(argv, ctx, ignore_case=True)

    @apihook("StrCmpIC", argc=2)
    def StrCmpIC(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int StrCmpIC(
            LPCTSTR pszStr1,
            LPCTSTR pszStr2
        );
        """
        return self.compare_strings(argv, ctx, ignore_case=True)

    @apihook("StrCmpC", argc=2)
    def StrCmpC(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int StrCmpC(
            LPCTSTR pszStr1,
            LPCTSTR pszStr2
        );
        """
        return self.compare_strings(argv, ctx, ignore_case=False)

    def compare_strings(self, argv, ctx, ignore_case):
        psz1, psz2 = argv

        cw = self.get_char_width(ctx)
        s1 = self.read_mem_string(psz1, cw)
        s2 = self.read_mem_string(psz2, cw)

        ctx.args[0].display = s1
        ctx.args[1].display = s2

        if ignore_case:
            s1, s2 = s1.lower(), s2.lower()
        return (s1 > s2) - (s1 < s2)

    @apihook("PathFindFileName", argc=1)
    def PathFindFileName(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPCTSTR PathFindFileName(
            LPCTSTR pszPath
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
    def PathRemoveExtension(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void PathRemoveExtension(
            LPTSTR pszPath
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
    def PathStripPath(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void PathStripPath(
            LPTSTR pszPath
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
    def wvnsprintfA(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int wvnsprintfA(
            PSTR pszDest,
            int cchDest,
            PCSTR pszFmt,
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
    def wnsprintf(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int wnsprintf(
            PTSTR pszDest,
            int cchDest,
            PCTSTR pszFmt,
            ...
        );
        """
        argv = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 3)
        buf, max_buf_size, fmt = argv

        cw = self.get_char_width(ctx)

        fmt_str = self.read_mem_string(fmt, cw)
        fmt_cnt = self.get_va_arg_count(fmt_str)
        _argv = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 3 + fmt_cnt)[3:]
        fin = self.do_str_format(fmt_str, _argv, wide=cw == 2)

        out = fin[: max(max_buf_size - 1, 0)]
        if max_buf_size > 0:
            self.write_mem_string(out, buf, cw)
        ctx.args.clear()
        ctx.args.append(out)

        return len(fin) if len(fin) < max_buf_size else -1

    @apihook("PathAppend", argc=2)
    def PathAppend(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PathAppend(
            LPTSTR pszPath,
            LPCTSTR pszMore
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

    @apihook("PathCombine", argc=3)
    def PathCombine(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPTSTR PathCombine(
            LPTSTR pszDest,
            LPCTSTR pszDir,
            LPCTSTR pszFile
        );
        """
        pszDest, pszDir, pszFile = argv
        if not pszDest:
            return 0
        cw = self.get_char_width(ctx)
        directory = self.read_mem_string(pszDir, cw) if pszDir else ""
        file = self.read_mem_string(pszFile, cw) if pszFile else ""
        if not pszDir and not pszFile:
            path = None
        elif not file:
            path = directory
        elif not directory or file[1:2] == ":" or file.startswith("\\\\"):
            path = file
        else:
            if file.startswith("\\"):
                directory = get_path_root(directory)
                file = file[1:]
            if directory and not directory.endswith("\\"):
                directory += "\\"
            path = directory + file
        if path is None or len(path) >= MAX_PATH:
            self.write_mem_string("\0", pszDest, cw)
            return 0
        self.write_mem_string(get_canonical_path(path) + "\0", pszDest, cw)
        return pszDest

    @apihook("PathCanonicalize", argc=2)
    def PathCanonicalize(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PathCanonicalize(
            LPTSTR pszBuf,
            LPCTSTR pszPath
        );
        """
        pszBuf, pszPath = argv
        cw = self.get_char_width(ctx)
        path = self.read_mem_string(pszPath, cw)
        self.write_mem_string(path, pszBuf, cw)
        return 1

    @apihook("PathRemoveFileSpec", argc=1)
    def PathRemoveFileSpec(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PathRemoveFileSpec(
            LPTSTR pszPath
        );
        """
        (pszPath,) = argv
        cw = self.get_char_width(ctx)
        s = get_path_without_file_spec(self.read_mem_string(pszPath, cw))
        if s is None:
            return 0

        self.write_mem_string(s, pszPath, cw)
        return 1

    @apihook("UrlCombine", argc=5)
    def UrlCombine(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT UrlCombine(
            PCTSTR pszBase,
            PCTSTR pszRelative,
            PTSTR pszCombined,
            DWORD *pcchCombined,
            DWORD dwFlags
        );
        """
        pszBase, pszRelative, pszCombined, pcchCombined, dwFlags = argv
        if not pszBase or not pszRelative or not pcchCombined:
            return E_INVALIDARG
        cw = self.get_char_width(ctx)
        base = self.read_mem_string(pszBase, cw)
        relative = self.read_mem_string(pszRelative, cw)
        ctx.args[0].display = base
        ctx.args[1].display = relative
        combined = urljoin(base, relative)
        size = int.from_bytes(self.mem_read(pcchCombined, 4), "little")
        if not pszCombined or size <= len(combined):
            self.mem_write(pcchCombined, (len(combined) + 1).to_bytes(4, "little"))
            return E_POINTER
        self.write_mem_string(combined + "\0", pszCombined, cw)
        self.mem_write(pcchCombined, len(combined).to_bytes(4, "little"))
        return 0

    @apihook("PathAddBackslash", argc=1)
    def PathAddBackslash(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPTSTR PathAddBackslash(
            LPTSTR pszPath
        );
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
    def PathRenameExtension(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PathRenameExtension(
            LPTSTR pszPath,
            LPCTSTR pszExt
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

    @apihook("DllGetVersion", argc=1)
    def DllGetVersion(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT DllGetVersion(
            DLLVERSIONINFO *pdvi
        );
        """
        (pdvi,) = argv
        ver = emu.config.os_ver
        return write_dll_version(self, pdvi, ver.major or 0, ver.minor or 0, ver.build or 0)

    @apihook("IsOS", argc=1)
    def IsOS(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsOS(
            DWORD dwOS
        );

        The emulated system is a native NT workstation of the configured version,
        not a server and not a WOW64 process.
        """
        (dwOS,) = argv
        ver = emu.config.os_ver
        version = (ver.major or 0, ver.minor or 0)
        minimum = {
            OS_NT: (0, 0),
            OS_NT4ORGREATER: (4, 0),
            OS_WIN2000ORGREATER_ALT: (5, 0),
            OS_WIN2000ORGREATER: (5, 0),
            OS_XPORGREATER: (5, 1),
            OS_PROFESSIONAL: (0, 0),
            OS_FASTUSERSWITCHING: (5, 1),
            OS_WELCOMELOGONUI: (5, 1),
        }.get(dwOS)
        return int(minimum is not None and version >= minimum)
