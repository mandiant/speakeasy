# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
import struct
from typing import TYPE_CHECKING

import speakeasy.winenv.defs.windows.shell32 as shell32_defs
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.errors import FileSystemEmuError
from speakeasy.profiler_events import EventType
from speakeasy.winenv.defs.windows import com as comdefs

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator

DLLVER_PLATFORM_NT = 2


def write_dll_version(handler: api.ApiHandler, pdvi: int, major: int, minor: int, build: int) -> int:
    """
    Fill the DLLVERSIONINFO or DLLVERSIONINFO2 at ``pdvi`` the way DllGetVersion
    does, and return the HRESULT. The size in cbSize selects the structure.
    """
    size = handler.read_dword(pdvi)
    if size not in (20, 32):
        return windefs.E_INVALIDARG
    data = struct.pack("<IIII", major, minor, build, DLLVER_PLATFORM_NT)
    if size == 32:
        data += struct.pack("<IQ", 0, major << 48 | minor << 32 | build << 16)
    handler.mem_write(pdvi + 4, data)
    return windefs.S_OK


def split_command_line(cmdline: str) -> list[str]:
    """
    Split a command line with the rules of CommandLineToArgvW. The program
    name ends at the next quote or whitespace, without escapes. In later
    arguments, 2n backslashes and a quote give n backslashes and toggle
    quoting, 2n+1 backslashes and a quote give n backslashes and a literal
    quote, and other backslashes are literal. In a run of quotes, every
    third quote is a literal quote, as in Wine CommandLineToArgvW.
    """
    blank = " \t"
    if cmdline.startswith('"'):
        end = cmdline.find('"', 1)
        end = len(cmdline) if end == -1 else end
        args = [cmdline[1:end]]
        end += 1
    else:
        end = next((i for i, c in enumerate(cmdline) if c in blank), len(cmdline))
        args = [cmdline[:end]]

    arg: list[str] = []
    started = False
    quotes = backslashes = 0
    i = end
    while i < len(cmdline):
        c = cmdline[i]
        i += 1
        if c == "\\":
            backslashes += 1
            started = True
            continue
        if c == '"':
            arg.append("\\" * (backslashes // 2))
            if backslashes % 2:
                arg.append('"')
            else:
                quotes += 1
            while i < len(cmdline) and cmdline[i] == '"':
                i += 1
                quotes += 1
                if quotes == 3:
                    arg.append('"')
                    quotes = 0
            if quotes == 2:
                quotes = 0
            started = True
        elif c in blank and not quotes:
            arg.append("\\" * backslashes)
            if started:
                args.append("".join(arg))
            arg, started = [], False
        else:
            arg.append("\\" * backslashes + c)
            started = True
        backslashes = 0
    if started:
        args.append("".join(arg) + "\\" * backslashes)
    return args


class Shell32(api.ApiHandler):
    """
    Implements exported functions from shell32.dll
    """

    name = "shell32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs = {}
        self.data = {}
        self.window_hooks: dict[int, tuple] = {}
        self.pidls: dict[int, str] = {}

        super().__get_hook_attrs__(self)

    def get_folder_path(self, emu, csidl):
        path = shell32_defs.CSIDL_PATHS.get(csidl, "C:\\Windows\\Temp")
        if emu.get_ptr_size() == 8:
            path = shell32_defs.CSIDL_PATHS_X64.get(csidl, path)
        return path.format(user=emu.config.user.name)

    def get_known_folder(self, emu, rfid):
        guid = comdefs.convert_guid_bytes_to_str(self.mem_read(rfid, 16)).strip("{}")
        folder = shell32_defs.KNOWN_FOLDERS.get(guid)
        if emu.get_ptr_size() == 8:
            folder = shell32_defs.KNOWN_FOLDERS_X64.get(guid, folder)
        return guid, folder

    def new_pidl(self, path):
        """
        Allocate an ITEMIDLIST with one item that holds the path, and remember
        the path for SHGetPathFromIDList
        """
        item = (path + "\x00").encode("utf-16le")
        cb = 2 + len(item)
        pidl = self.heap_alloc(cb + 2, heap="CoTaskMemAlloc")
        self.mem_write(pidl, cb.to_bytes(2, "little") + item + b"\x00\x00")
        self.pidls[pidl] = path
        return pidl

    def write_folder_pidl(self, emu, csidl, ppidl, ctx):
        csidl &= ~shell32_defs.CSIDL_FLAG_MASK
        pidl = 0
        if csidl in shell32_defs.CSIDL:
            ctx.args["csidl"].display = shell32_defs.CSIDL[csidl]
            pidl = self.new_pidl(self.get_folder_path(emu, csidl))
        if ppidl:
            self.write_ptr(ppidl, pidl)
        return windefs.S_OK if pidl else windefs.E_INVALIDARG

    @apihook("SHCreateDirectoryEx", argc=3)
    def SHCreateDirectoryEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int SHCreateDirectoryEx(
            HWND hwnd,
            LPCTSTR pszPath,
            const SECURITY_ATTRIBUTES *psa
        );
        """
        hwnd, pszPath, psa = argv

        cw = self.get_char_width(ctx)
        dn = ""
        if pszPath:
            dn = self.read_mem_string(pszPath, cw)
            ctx.args["pszPath"].display = dn

            emu.get_file_manager().create_directory(dn)

        return 0

    @apihook("ShellExecute", argc=6)
    def ShellExecute(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HINSTANCE ShellExecute(
            HWND hwnd,
            LPCTSTR lpOperation,
            LPCTSTR lpFile,
            LPCTSTR lpParameters,
            LPCTSTR lpDirectory,
            INT nShowCmd
        );
        """
        hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd = argv

        rv, _ = self.shell_execute(emu, lpOperation, lpFile, lpParameters, lpDirectory, ctx)
        return rv

    def shell_execute(self, emu, lpOperation, lpFile, lpParameters, lpDirectory, ctx):
        """
        Start the program of ``lpFile`` and return the HINSTANCE result
        and the new process, or None when no process starts.
        """
        cw = self.get_char_width(ctx)

        fn = ""
        param = ""
        dn = ""
        if lpOperation:
            op = self.read_mem_string(lpOperation, cw)
            ctx.args["lpOperation"].display = op
        if lpFile:
            fn = self.read_mem_string(lpFile, cw)
            ctx.args["lpFile"].display = fn
        if lpParameters:
            param = self.read_mem_string(lpParameters, cw)
            ctx.args["lpParameters"].display = param
        if lpDirectory:
            dn = self.read_mem_string(lpDirectory, cw)
            ctx.args["lpDirectory"].display = dn

        if dn and fn:
            fn = f"{dn}\\{fn}"

        try:
            proc = emu.create_process(path=fn, cmdline=param)
        except IsADirectoryError:
            # Explorer opens the folder. Any value above 32 means success.
            return 33, None
        except FileSystemEmuError:
            emu.set_last_error(windefs.ERROR_FILE_NOT_FOUND)
            return shell32_defs.SE_ERR_FNF, None
        self.record_process_event(proc, EventType.PROCESS_CREATE)

        return 33, proc

    @apihook("ShellExecuteEx", argc=1)
    def ShellExecuteEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL ShellExecuteEx(
            SHELLEXECUTEINFO *pExecInfo
        );
        """
        (pExecInfo,) = argv

        sei = shell32_defs.SHELLEXECUTEINFOA(emu.get_ptr_size())
        sei_struct = self.mem_cast(sei, pExecInfo)

        rv, proc = self.shell_execute(
            emu, sei_struct.lpVerb, sei_struct.lpFile, sei_struct.lpParameters, sei_struct.lpDirectory, ctx
        )
        sei_struct.hInstApp = rv
        if proc and sei_struct.fMask & shell32_defs.SEE_MASK_NOCLOSEPROCESS:
            sei_struct.handle = self.get_object_handle(proc)
        self.mem_write(pExecInfo, self.get_bytes(sei_struct))

        return rv > 32

    @apihook("SHChangeNotify", argc=4)
    def SHChangeNotify(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void SHChangeNotify(
            LONG wEventId,
            UINT uFlags,
            LPCVOID dwItem1,
            LPCVOID dwItem2
        );
        """
        return

    @apihook("IsUserAnAdmin", argc=0, ordinal=680)
    def IsUserAnAdmin(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsUserAnAdmin();
        """
        return emu.config.user.is_admin

    @apihook("SHGetMalloc", argc=1)
    def SHGetMalloc(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT SHGetMalloc(
            IMalloc **ppMalloc
        );
        """
        (ppMalloc,) = argv

        if ppMalloc:
            ci = emu.com.get_interface(emu, emu.get_ptr_size(), "IMalloc")
            pv = self.mem_alloc(emu.get_ptr_size(), tag="emu.COM.pv_IMalloc")
            self.write_ptr(pv, ci.address)
            self.write_ptr(ppMalloc, pv)
        rv = windefs.S_OK
        return rv

    @apihook("CommandLineToArgv", argc=2)
    def CommandLineToArgv(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPWSTR *CommandLineToArgv(
            LPCWSTR lpCmdLine,
            int *pNumArgs
        );
        """
        lpCmdLine, pNumArgs = argv

        cw = self.get_char_width(ctx)
        cl = self.read_mem_string(lpCmdLine, cw)

        ptrsize = emu.get_ptr_size()

        split = split_command_line(cl)
        nargs = len(split)

        # Get the total size we need
        size = (len(split) + 1) * ptrsize
        size += (len(cl) * cw) + (len(split) * cw)

        # Allocate the array
        buf = self.heap_alloc(size, heap="CommandLineToArgv")
        ptrs = buf
        strs = buf + ((len(split) + 1) * ptrsize)
        for i, p in enumerate(split):
            self.write_ptr(ptrs + (i * ptrsize), strs)

            p += "\x00"
            s = self.encode_string(p, cw)
            self.mem_write(strs, s)

            strs += len(s)

        if pNumArgs:
            self.write_dword(pNumArgs, nargs)

        return buf

    @apihook("ExtractIcon", argc=3)
    def ExtractIcon(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HICON ExtractIcon(
            HINSTANCE hInst,
            LPCTSTR pszExeFileName,
            UINT nIconIndex
        );
        """
        return emu.handle_allocator.allocate_handle()

    @apihook("SHGetFolderPath", argc=5)
    def SHGetFolderPath(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT SHGetFolderPath(
            HWND hwnd,
            int csidl,
            HANDLE hToken,
            DWORD dwFlags,
            LPTSTR pszPath
        );
        """
        hwnd, csidl, hToken, dwFlags, pszPath = argv
        csidl &= ~shell32_defs.CSIDL_FLAG_MASK
        if csidl in shell32_defs.CSIDL:
            ctx.args["csidl"].display = shell32_defs.CSIDL[csidl]
        path = self.get_folder_path(emu, csidl)
        emu.write_mem_string(path, pszPath, self.get_char_width(ctx))
        return 0

    @apihook("SHGetFolderPathAndSubDir", argc=6)
    def SHGetFolderPathAndSubDir(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT SHGetFolderPathAndSubDir(
            HWND hwnd,
            int csidl,
            HANDLE hToken,
            DWORD dwFlags,
            LPCTSTR pszSubDir,
            LPTSTR pszPath
        );
        """
        hwnd, csidl, hToken, dwFlags, pszSubDir, pszPath = argv
        cw = self.get_char_width(ctx)
        csidl &= ~shell32_defs.CSIDL_FLAG_MASK
        if csidl in shell32_defs.CSIDL:
            ctx.args["csidl"].display = shell32_defs.CSIDL[csidl]
        path = self.get_folder_path(emu, csidl)
        if pszSubDir:
            sub_dir = self.read_mem_string(pszSubDir, cw)
            ctx.args["pszSubDir"].display = sub_dir
            path = f"{path}\\{sub_dir}"
        emu.write_mem_string(path, pszPath, cw)
        return windefs.S_OK

    @apihook("SHGetSpecialFolderPath", argc=4)
    def SHGetSpecialFolderPath(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SHGetSpecialFolderPath(
            HWND hwnd,
            LPTSTR pszPath,
            int csidl,
            BOOL fCreate
        );
        """
        hwnd, pszPath, csidl, fCreate = argv
        csidl &= ~shell32_defs.CSIDL_FLAG_MASK
        if csidl not in shell32_defs.CSIDL:
            return 0
        ctx.args["csidl"].display = shell32_defs.CSIDL[csidl]
        path = self.get_folder_path(emu, csidl)
        emu.write_mem_string(path, pszPath, self.get_char_width(ctx))
        return 1

    @apihook("SHGetSpecialFolderLocation", argc=3)
    def SHGetSpecialFolderLocation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT SHGetSpecialFolderLocation(
            HWND hwnd,
            int csidl,
            PIDLIST_ABSOLUTE *ppidl
        );
        """
        hwnd, csidl, ppidl = argv
        return self.write_folder_pidl(emu, csidl, ppidl, ctx)

    @apihook("SHGetFolderLocation", argc=5)
    def SHGetFolderLocation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT SHGetFolderLocation(
            HWND hwnd,
            int csidl,
            HANDLE hToken,
            DWORD dwFlags,
            PIDLIST_ABSOLUTE *ppidl
        );
        """
        hwnd, csidl, hToken, dwFlags, ppidl = argv
        return self.write_folder_pidl(emu, csidl, ppidl, ctx)

    @apihook("SHGetKnownFolderIDList", argc=4)
    def SHGetKnownFolderIDList(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT SHGetKnownFolderIDList(
            REFKNOWNFOLDERID rfid,
            DWORD dwFlags,
            HANDLE hToken,
            PIDLIST_ABSOLUTE *ppidl
        );
        """
        rfid, dwFlags, hToken, ppidl = argv
        guid, folder = self.get_known_folder(emu, rfid)
        ctx.args["rfid"].display = folder[0] if folder else guid
        pidl = self.new_pidl(folder[1].format(user=emu.config.user.name)) if folder else 0
        if ppidl:
            self.write_ptr(ppidl, pidl)
        return windefs.S_OK if folder else windefs.E_FILE_NOT_FOUND

    @apihook("SHGetPathFromIDList", argc=2)
    def SHGetPathFromIDList(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SHGetPathFromIDList(
            PCIDLIST_ABSOLUTE pidl,
            LPTSTR pszPath
        );
        """
        pidl, pszPath = argv
        cw = 2 if ctx.func_name.endswith("W") else 1
        path = self.pidls.get(pidl)
        if pszPath:
            emu.write_mem_string(path or "", pszPath, cw)
        if path is None:
            return 0
        ctx.args["pszPath"].display = path
        return 1

    @apihook("SHGetKnownFolderPath", argc=4)
    def SHGetKnownFolderPath(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT SHGetKnownFolderPath(
            REFKNOWNFOLDERID rfid,
            DWORD dwFlags,
            HANDLE hToken,
            PWSTR *ppszPath
        );
        """
        rfid, dwFlags, hToken, ppszPath = argv
        guid, folder = self.get_known_folder(emu, rfid)
        ctx.args["rfid"].display = folder[0] if folder else guid
        ptr = 0
        if folder:
            path = (folder[1].format(user=emu.config.user.name) + "\x00").encode("utf-16le")
            ptr = self.mem_alloc(len(path), tag="api.SHGetKnownFolderPath")
            self.mem_write(ptr, path)
        if ppszPath:
            self.write_ptr(ppszPath, ptr)
        return windefs.S_OK if folder else windefs.E_FILE_NOT_FOUND

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
