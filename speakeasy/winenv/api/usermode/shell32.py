# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
from typing import Any

import speakeasy.winenv.defs.windows.shell32 as shell32_defs
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.profiler_events import PROC_CREATE

from .. import api


def split_command_line(cmdline: str) -> list[str]:
    """
    Split a command line with the rules of CommandLineToArgvW. The program
    name ends at the next quote or whitespace, without escapes. In later
    arguments, 2n backslashes and a quote give n backslashes and toggle
    quoting, 2n+1 backslashes and a quote give n backslashes and a literal
    quote, and other backslashes are literal.
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
    started = quoted = False
    backslashes = 0
    for c in cmdline[end:]:
        if c == "\\":
            backslashes += 1
            started = True
            continue
        if c == '"':
            arg.append("\\" * (backslashes // 2))
            if backslashes % 2:
                arg.append('"')
            else:
                quoted = not quoted
            started = True
        elif c in blank and not quoted:
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

        self.funcs: dict[str, Any] = {}
        self.data: dict[str, Any] = {}
        self.window_hooks: dict[int, tuple] = {}
        self.handle: int = 0
        self.win: Any | None = None
        self.curr_handle: int = 0x2800

        super().__get_hook_attrs__(self)

    def get_handle(self):
        self.curr_handle += 4
        return self.curr_handle

    @apihook("SHCreateDirectoryEx", argc=3)
    def SHCreateDirectoryEx(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int SHCreateDirectoryExA(
            HWND                      hwnd,
            LPCSTR                    pszPath,
            const SECURITY_ATTRIBUTES *psa
        );
        """
        hwnd, pszPath, psa = argv

        cw = self.get_char_width(ctx)
        dn = ""
        if pszPath:
            dn = self.read_mem_string(pszPath, cw)
            ctx.args["pszPath"].display = dn

            self.record_file_access_event(dn, "directory_create")

        return 0

    @apihook("ShellExecute", argc=6)
    def ShellExecute(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HINSTANCE ShellExecuteA(
            HWND   hwnd,
            LPCSTR lpOperation,
            LPCSTR lpFile,
            LPCSTR lpParameters,
            LPCSTR lpDirectory,
            INT    nShowCmd
        );
        """
        hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd = argv

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

        proc = emu.create_process(path=fn, cmdline=param)
        self.record_process_event(proc, PROC_CREATE)

        return 33

    @apihook("ShellExecuteEx", argc=1)
    def ShellExecuteEx(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL ShellExecuteExA(
            [in, out] SHELLEXECUTEINFOA *pExecInfo
        );
        """
        (lpShellExecuteInfo,) = argv

        sei = shell32_defs.SHELLEXECUTEINFOA(emu.get_ptr_size())
        sei_struct = self.mem_cast(sei, lpShellExecuteInfo)

        self.ShellExecute(
            emu, [0, sei_struct.lpVerb, sei_struct.lpFile, sei_struct.lpParameters, sei_struct.lpDirectory, 0], ctx
        )

        return True

    @apihook("SHChangeNotify", argc=4)
    def SHChangeNotify(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
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
    def IsUserAnAdmin(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsUserAnAdmin();
        """
        return emu.config.user.is_admin

    @apihook("SHGetMalloc", argc=1)
    def SHGetMalloc(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SHSTDAPI SHGetMalloc(
            IMalloc **ppMalloc
        );
        """
        (ppMalloc,) = argv

        if ppMalloc:
            ci = emu.com.get_interface(emu, emu.get_ptr_size(), "IMalloc")
            pv = self.mem_alloc(emu.get_ptr_size(), tag="emu.COM.pv_IMalloc")
            self.mem_write(pv, ci.address.to_bytes(emu.get_ptr_size(), "little"))
            self.mem_write(ppMalloc, pv.to_bytes(emu.get_ptr_size(), "little"))
        rv = windefs.S_OK
        return rv

    @apihook("CommandLineToArgv", argc=2)
    def CommandLineToArgv(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPWSTR * CommandLineToArgv(
            LPCWSTR lpCmdLine,
            int     *pNumArgs
        );
        """
        cmdline, argc = argv

        cw = self.get_char_width(ctx)
        cl = self.read_mem_string(cmdline, cw)

        ptrsize = emu.get_ptr_size()

        split = split_command_line(cl)
        nargs = len(split)

        # Get the total size we need
        size = (len(split) + 1) * ptrsize
        size += (len(cl) * cw) + (len(split) * cw)

        # Allocate the array
        buf = self.mem_alloc(size, tag="api.CommandLineToArgv")
        ptrs = buf
        strs = buf + ((len(split) + 1) * ptrsize)
        for i, p in enumerate(split):
            self.mem_write(ptrs + (i * ptrsize), strs.to_bytes(emu.get_ptr_size(), "little"))

            p += "\x00"
            if cw == 2:
                s = p.encode("utf-16le")
            else:
                s = p.encode("utf-8")
            self.mem_write(strs, s)

            strs += len(s)

        if argc:
            self.mem_write(argc, nargs.to_bytes(4, "little"))

        return buf

    @apihook("ExtractIcon", argc=3)
    def ExtractIcon(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HICON ExtractIconA(
          HINSTANCE hInst,
          LPCSTR    pszExeFileName,
          UINT      nIconIndex
        );
        """

        return self.get_handle()

    @apihook("SHGetFolderPath", argc=5)
    def SHGetFolderPath(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND   hwnd,
        int    csidl,
        HANDLE hToken,
        DWORD  dwFlags,
        LPWSTR pszPath
        """
        hwnd, csidl, hToken, dwFlags, pszPath = argv
        csidl &= ~shell32_defs.CSIDL_FLAG_MASK
        if csidl in shell32_defs.CSIDL:
            ctx.args["csidl"].display = shell32_defs.CSIDL[csidl]
        if csidl == 0x1A:
            # CSIDL_APPDATA
            path = f"C:\\Users\\{emu.config.user.name}\\AppData\\Roaming"
        elif csidl == 0x28:
            # csidl_profile
            path = f"C:\\Users\\{emu.config.user.name}"
        elif csidl == 0 or csidl == 0x10:
            # CSIDL_DESKTOP or CSIDL_DESKTOPDIRECTORY
            path = f"C:\\Users\\{emu.config.user.name}\\Desktop"
        elif csidl == 2:
            # CSIDL_PROGRAMS
            path = f"C:\\Users\\{emu.config.user.name}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs"  # noqa
        elif csidl == 6 or csidl == 0x1F:
            # CSIDL_FAVORITES or CSIDL_COMMON_FAVORITES
            path = f"C:\\Users\\{emu.config.user.name}\\Favorites"
        elif csidl == 7:
            # CSIDL_STARTUP
            path = f"C:\\Users\\{emu.config.user.name}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"  # noqa
        elif csidl == 8:
            # CSIDL_RECENT
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Recent".format(emu.config.user.name)  # noqa
        elif csidl == 9:
            # csidl_sendto
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\SendTo".format(emu.config.user.name)  # noqa
        elif csidl == 0xB:
            # CSIDL_STARTMENU
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu".format(emu.config.user.name)  # noqa
        elif csidl == 0x13:
            # CSIDL_NETHOOD
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Network Shortcuts".format(emu.config.user.name)  # noqa
        elif csidl == 0x15:
            # CSIDL_TEMPLATES
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Templates".format(emu.config.user.name)  # noqa
        elif csidl == 0x1B:
            # CSIDL_PRINTHOOD
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Printer Shortcuts".format(emu.config.user.name)  # noqa
        elif csidl == 0x1C:
            # CSIDL_LOCAL_APPDATA
            path = f"C:\\Users\\{emu.config.user.name}\\AppData\\Local"
        elif csidl == 0x20:
            # CSIDL_INTERNET_CACHE
            path = f"C:\\Users\\{emu.config.user.name}\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet File"  # noqa
        elif csidl == 0x21:
            # CSIDL_COOKIES
            path = "C:\\Users\\{}\\AppData\\AppData\\Roaming\\Microsoft\\Windows\\Cookies".format(emu.config.user.name)  # noqa
        elif csidl == 0x22:
            # CSIDL_HISTORY
            path = "C:\\Users\\{}\\AppData\\Local\\Microsoft\\Windows\\History".format(emu.config.user.name)  # noqa
        elif csidl == 0x27:
            # CSIDL_MYPICTURES
            path = f"C:\\Users\\{emu.config.user.name}\\Pictures"
        elif csidl == 0x2F or csidl == 0x30:
            user = emu.config.user.name
            path = (
                f"C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools"
            )
        elif csidl == 0x1D:
            # CSIDL_ALTSTARTUP
            path = f"C:\\Users\\{emu.config.user.name}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"  # noqa
        elif csidl == 0x1E:
            path = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        elif csidl == 0x2A or csidl == 0x26:
            path = "C:\\Program Files"
        elif csidl == 0x2B or csidl == 0x2C:
            path = "C:\\Program Files\\Common Files"
        elif csidl == 0x24:
            path = "C:\\Windows"
        elif csidl == 0x25:
            path = "C:\\Windows\\System32"
        elif csidl == 0x14:
            path = "C:\\Windows\\Fonts"
        elif csidl == 0x23:
            path = "C:\\ProgramData"
        else:
            # Temp
            path = "C:\\Windows\\Temp"

        emu.write_mem_string(path, pszPath, self.get_char_width(ctx))
        return 0
