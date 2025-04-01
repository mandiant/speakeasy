# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
from speakeasy.const import PROC_CREATE
from .. import api
import shlex
import speakeasy.winenv.defs.windows.windows as windefs
import speakeasy.winenv.defs.windows.shell32 as shell32_defs


class Shell32(api.ApiHandler):

    """
    Implements exported functions from shell32.dll
    """

    name = 'shell32'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Shell32, self).__init__(emu)

        self.funcs = {}
        self.data = {}
        self.window_hooks = {}
        self.handle = 0
        self.win = None
        self.curr_handle = 0x2800

        super(Shell32, self).__get_hook_attrs__(self)

    def get_handle(self):
        self.curr_handle += 4
        return self.curr_handle

    @apihook('SHCreateDirectoryEx', argc=3)
    def SHCreateDirectoryEx(self, emu, argv, ctx={}):
        '''
        int SHCreateDirectoryExA(
            HWND                      hwnd,
            LPCSTR                    pszPath,
            const SECURITY_ATTRIBUTES *psa
        );
        '''

        hwnd, pszPath, psa = argv

        cw = self.get_char_width(ctx)
        dn = ''
        if pszPath:
            dn = self.read_mem_string(pszPath, cw)
            argv[1] = dn

            self.log_file_access(dn, 'directory_create')

        return 0

    @apihook('ShellExecute', argc=6)
    def ShellExecute(self, emu, argv, ctx={}):
        '''
        HINSTANCE ShellExecuteA(
            HWND   hwnd,
            LPCSTR lpOperation,
            LPCSTR lpFile,
            LPCSTR lpParameters,
            LPCSTR lpDirectory,
            INT    nShowCmd
        );
        '''

        hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd = argv

        cw = self.get_char_width(ctx)

        fn = ''
        param = ''
        dn = ''
        if lpOperation:
            op = self.read_mem_string(lpOperation, cw)
            argv[1] = op
        if lpFile:
            fn = self.read_mem_string(lpFile, cw)
            argv[2] = fn
        if lpParameters:
            param = self.read_mem_string(lpParameters, cw)
            argv[3] = param
        if lpDirectory:
            dn = self.read_mem_string(lpDirectory, cw)
            argv[4] = dn

        if dn and fn:
            fn = '%s\\%s' % (dn, fn)

        proc = emu.create_process(path=fn, cmdline=param)
        self.log_process_event(proc, PROC_CREATE)

        return 33

    @apihook('ShellExecuteEx', argc=1)
    def ShellExecuteEx(self, emu, argv, ctx={}):
        '''
        BOOL ShellExecuteExA(
            [in, out] SHELLEXECUTEINFOA *pExecInfo
        );
        '''
        lpShellExecuteInfo, = argv

        sei = shell32_defs.SHELLEXECUTEINFOA(emu.get_ptr_size())
        sei_struct = self.mem_cast(sei, lpShellExecuteInfo)

        self.ShellExecute(
            emu,
            [
                0,
                sei_struct.lpVerb,
                sei_struct.lpFile,
                sei_struct.lpParameters, sei_struct.lpDirectory,
                0
            ],
            ctx
        )

        return True

    @apihook('IsUserAnAdmin', argc=0, ordinal=680)
    def IsUserAnAdmin(self, emu, argv, ctx={}):
        """
        BOOL IsUserAnAdmin();
        """
        return emu.get_user().get('is_admin', False)

    @apihook('SHGetMalloc', argc=1)
    def SHGetMalloc(self, emu, argv, ctx={}):
        """
        SHSTDAPI SHGetMalloc(
            IMalloc **ppMalloc
        );
        """
        ppMalloc, = argv

        if ppMalloc:
            ci = emu.com.get_interface(emu, emu.get_ptr_size(), 'IMalloc')
            self.mem_write(ppMalloc, ci.address.to_bytes(emu.get_ptr_size(), 'little'))
        rv = windefs.S_OK
        return rv

    @apihook('CommandLineToArgv', argc=2)
    def CommandLineToArgv(self, emu, argv, ctx={}):
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

        split = shlex.split(cl)
        nargs = len(split)

        # Get the total size we need
        size = (len(split) + 1) * ptrsize
        size += (len(cl) * cw) + (len(split) * cw)

        # Allocate the array
        buf = self.mem_alloc(size, tag='api.CommandLineToArgv')
        ptrs = buf
        strs = buf + ((len(split) + 1) * ptrsize)
        for i, p in enumerate(split):
            self.mem_write(ptrs + (i * ptrsize), strs.to_bytes(emu.get_ptr_size(), 'little'))

            p += '\x00'
            if cw == 2:
                s = p.encode('utf-16le')
            else:
                s = p.encode('utf-8')
            self.mem_write(strs, s)

            strs += len(s)

        if argc:
            self.mem_write(argc, nargs.to_bytes(4, "little"))

        return buf

    @apihook('ExtractIcon', argc=3)
    def ExtractIcon(self, emu, argv, ctx={}):
        """
        HICON ExtractIconA(
          HINSTANCE hInst,
          LPCSTR    pszExeFileName,
          UINT      nIconIndex
        );
        """

        return self.get_handle()

    @apihook('SHGetFolderPath', argc=5)
    def SHGetFolderPath(self, emu, argv, ctx={}):
        """
        HWND   hwnd,
        int    csidl,
        HANDLE hToken,
        DWORD  dwFlags,
        LPWSTR pszPath
        """
        hwnd, csidl, hToken, dwFlags, pszPath = argv
        if csidl in shell32_defs.CSIDL:
            argv[1] = shell32_defs.CSIDL[csidl]
        if csidl == 0x1a:
            # CSIDL_APPDATA
            path = "C:\\Users\\{}\\AppData\\Roaming".format(emu.get_user()['name'])
        elif csidl == 0x28:
            # csidl_profile
            path = "C:\\Users\\{}".format(emu.get_user()['name'])
        elif csidl == 0 or csidl == 0x10:
            # CSIDL_DESKTOP or CSIDL_DESKTOPDIRECTORY
            path = "C:\\Users\\{}\\Desktop".format(emu.get_user()['name'])
        elif csidl == 2:
            # CSIDL_PROGRAMS
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs".format(emu.get_user()['name']) # noqa
        elif csidl == 6 or csidl == 0x1f:
            # CSIDL_FAVORITES or CSIDL_COMMON_FAVORITES
            path = "C:\\Users\\{}\\Favorites".format(emu.get_user()['name'])
        elif csidl == 7:
            # CSIDL_STARTUP
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup".format(emu.get_user()['name']) # noqa
        elif csidl == 8:
            # CSIDL_RECENT
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Recent".format(emu.get_user()['name']) # noqa
        elif csidl == 9:
            # csidl_sendto
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\SendTo".format(emu.get_user()['name']) # noqa
        elif csidl == 0xb:
            # CSIDL_STARTMENU
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu".format(emu.get_user()['name']) # noqa
        elif csidl == 0x13:
            # CSIDL_NETHOOD
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Network Shortcuts".format(emu.get_user()['name']) # noqa
        elif csidl == 0x15:
            # CSIDL_TEMPLATES
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Templates".format(emu.get_user()['name']) # noqa
        elif csidl == 0x1b:
            # CSIDL_PRINTHOOD
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Printer Shortcuts".format(emu.get_user()['name']) # noqa
        elif csidl == 0x1c:
            # CSIDL_LOCAL_APPDATA
            path = "C:\\Users\\{}\\AppData\\Local".format(emu.get_user()['name'])
        elif csidl == 0x20:
            # CSIDL_INTERNET_CACHE
            path = "C:\\Users\\{}\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet File".format(emu.get_user()['name']) # noqa
        elif csidl == 0x21:
            # CSIDL_COOKIES
            path = "C:\\Users\\{}\\AppData\\AppData\\Roaming\\Microsoft\\Windows\\Cookies".format(emu.get_user()['name']) # noqa
        elif csidl == 0x22:
            # CSIDL_HISTORY
            path = "C:\\Users\\{}\\AppData\\Local\\Microsoft\\Windows\\History".format(emu.get_user()['name']) # noqa
        elif csidl == 0x27:
            # CSIDL_MYPICTURES
            path = "C:\\Users\\{}\\Pictures".format(emu.get_user()['name'])
        elif csidl == 0x2f or csidl == 0x30:
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools".format(emu.get_user()['name']) # noqa
        elif csidl == 0x1d:
            # CSIDL_ALTSTARTUP
            path = "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup".format(emu.get_user()['name']) # noqa
        elif csidl == 0x1e:
            path = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        elif csidl == 0x2a or csidl == 0x26:
            path = "C:\\Program Files"
        elif csidl == 0x2b or csidl == 0x2c:
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
