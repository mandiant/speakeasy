# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.arch as _arch
import speakeasy.windows.sessman as sessman
import speakeasy.winenv.defs.windows.user32 as windefs

from .. import api

IDCANCEL = 2

IDI_APPLICATION = 32512
IDI_ASTERISK = 32516
IDI_ERROR = 32513
IDI_EXCLAMATION = 32515
IDI_HAND = 32513
IDI_INFORMATION = 32516
IDI_QUESTION = 32514
IDI_SHIELD = 32518
IDI_WARNING = 32515
IDI_WINLOGO = 32517


class User32(api.ApiHandler):

    """
    Implements exported functions from user32.dll
    """

    name = 'user32'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(User32, self).__init__(emu)

        self.funcs = {}
        self.data = {}
        self.window_hooks = {}
        self.handle = 0
        self.win = None
        self.sessman = sessman.SessionManager(config=None)

        super(User32, self).__get_hook_attrs__(self)

    def get_handle(self):
        self.handle += 4
        hnd = self.handle
        return hnd

    def find_string_resource_by_id(self, pe, uID):
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if entry.id == 6:  # "String Table"
                for str_entry in entry.directory.entries:
                    s = str_entry.directory.strings.get(uID, None)
                    if s is not None:
                        return s
        return None

    @apihook('GetDesktopWindow', argc=0)
    def GetDesktopWindow(self, emu, argv, ctx={}):
        '''HWND GetDesktopWindow();'''

        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.get_desktop_window()
        hnd = window.get_handle()

        return hnd

    @apihook('ShowWindow', argc=2)
    def ShowWindow(self, emu, argv, ctx={}):
        '''BOOL ShowWindow(
          HWND hWnd,
          int  nCmdShow
        );'''

        rv = 1

        return rv

    @apihook('CreateWindowStation', argc=4)
    def CreateWindowStation(self, emu, argv, ctx={}):
        '''
        HWINSTA CreateWindowStation(
            LPCSTR                lpwinsta,
            DWORD                 dwFlags,
            ACCESS_MASK           dwDesiredAccess,
            LPSECURITY_ATTRIBUTES lpsa
        );
        '''
        winsta, flags, access, sa = argv

        return self.get_handle()

    @apihook('SetProcessWindowStation', argc=1)
    def SetProcessWindowStation(self, emu, argv, ctx={}):
        '''
        BOOL SetProcessWindowStation(
            HWINSTA hWinSta
        );
        '''
        winsta, = argv

        rv = False
        if winsta:
            rv = True

        return rv

    @apihook('GetDC', argc=1)
    def GetDC(self, emu, argv, ctx={}):
        '''
        HDC GetDC(
          HWND hWnd
        );
        '''

        rv = self.sessman.get_device_context()

        return rv

    @apihook('RegisterClassEx', argc=1)
    def RegisterClassEx(self, emu, argv, ctx={}):
        '''
        ATOM RegisterClassEx(
            const WNDCLASSEXA *Arg1
        );
        '''
        Arg1, = argv
        wclass = windefs.WNDCLASSEX(emu.get_ptr_size())
        wclass = self.mem_cast(wclass, Arg1)

        cn = None
        cw = self.get_char_width(ctx)
        if wclass.lpszClassName:
            cn = self.read_mem_string(wclass.lpszClassName, cw)

        atom = self.sessman.create_window_class(wclass, cn)

        return atom

    @apihook('UnregisterClass', argc=2)
    def UnregisterClass(self, emu, argv, ctx={}):
        '''
        BOOL UnregisterClass(
            LPCSTR    lpClassName,
            HINSTANCE hInstance
        );
        '''

        return 1

    @apihook('ChangeWindowMessageFilter', argc=2)
    def ChangeWindowMessageFilter(self, emu, argv, ctx={}):
        '''
        BOOL ChangeWindowMessageFilter(
            UINT  message,
            DWORD dwFlag
        );
        '''
        msg, flag = argv
        emu.enable_code_hook()
        return True

    @apihook('UpdateWindow', argc=1)
    def UpdateWindow(self, emu, argv, ctx={}):
        '''
        BOOL UpdateWindow(
            HWND hWnd
        );
        '''
        hnd, = argv
        window = self.sessman.get_window(hnd)
        if not window:
            return False

        wc = self.sessman.get_window_class(window.class_name)
        return True

    @apihook('DestroyWindow', argc=1)
    def DestroyWindow(self, emu, argv, ctx={}):
        '''
        BOOL DestroyWindow(
            HWND hWnd
        );
        '''
        return True

    @apihook('CreateWindowEx', argc=12)
    def CreateWindowEx(self, emu, argv, ctx={}):
        '''
        HWND CreateWindowExA(
            DWORD     dwExStyle,
            LPCSTR    lpClassName,
            LPCSTR    lpWindowName,
            DWORD     dwStyle,
            int       X,
            int       Y,
            int       nWidth,
            int       nHeight,
            HWND      hWndParent,
            HMENU     hMenu,
            HINSTANCE hInstance,
            LPVOID    lpParam
        );
        '''
        cw = self.get_char_width(ctx)
        _, cn, wn, _, x, y, width, height, parent, menu, inst, param = argv
        if cn:
            cn = self.read_mem_string(cn, cw)
            argv[1] = cn
        else:
            cn = None
        if wn:
            wn = self.read_mem_string(wn, cw)
            argv[2] = wn
        else:
            wn = None
        hnd = self.sessman.create_window(wn, cn)
        return hnd

    @apihook('MessageBox', argc=4)
    def MessageBox(self, emu, argv, ctx={}):
        '''int MessageBox(
          HWND    hWnd,
          LPCTSTR lpText,
          LPCTSTR lpCaption,
          UINT    uType
        );'''
        hWnd, lpText, lpCaption, uType = argv

        cw = self.get_char_width(ctx)

        if lpText:
            text = self.read_mem_string(lpText, cw)
            argv[1] = text
        if lpCaption:
            cap = self.read_mem_string(lpCaption, cw)
            argv[2] = cap
        rv = IDCANCEL

        return rv

    @apihook('MessageBoxEx', argc=5)
    def MessageBoxEx(self, emu, argv, ctx={}):
        '''
        int MessageBoxExA(
            HWND   hWnd,
            LPCSTR lpText,
            LPCSTR lpCaption,
            UINT   uType,
            WORD   wLanguageId
        );
        '''
        av = argv[:-1]
        rv = self.MessageBox(emu, av, ctx)
        argv[:4] = av
        return rv

    @apihook('LoadString', argc=4)
    def LoadString(self, emu, argv, ctx={}):
        """
        int LoadStringW(
          HINSTANCE hInstance,
          UINT      uID,
          LPWSTR    lpBuffer,
          int       cchBufferMax
        );
        """

        hInstance, uID, lpBuffer, ccBufferMax = argv
        cw = self.get_char_width(ctx)
        size = 0

        if hInstance == 0:
            pe = emu.modules[0][0]
        else:
            pe = emu.get_mod_from_addr(hInstance)
            if pe and hInstance != pe.get_base():
                return 0

        s = self.find_string_resource_by_id(pe, uID)
        if s is None:
            # self.logger.info("unable to find resource string id %04X" % uID)
            return 0

        if cw == 2:
            encoded = s.encode('utf-16le')
        elif cw == 1:
            encoded = s.encode('utf-8')

        size = int(len(encoded) / cw)

        if size == 0:
            # self.logger.debug("resource id %04X not found" % uID)
            return 0

        if ccBufferMax == 0:
            # TODO this should be done properly, but requires more research
            offset = pe.get_memory_mapped_image().find(encoded)
            emu.mem_write(lpBuffer, (pe.get_base() + offset).to_bytes(emu.get_ptr_size(),
                                                                      'little'))
            return size

        if len(encoded) > ccBufferMax:
            encoded = encoded[:ccBufferMax * cw]

        emu.mem_write(lpBuffer, encoded)
        if cw == 1:
            argv[2] = s
        else:
            argv[2] = s

        return len(encoded)

    @apihook('GetCursorPos', argc=1)
    def GetCursorPos(self, emu, argv, ctx={}):
        """
        BOOL GetCursorPos(
          LPPOINT lpPoint
        );
        """

        lpPoint, = argv

        rv = 0
        return rv

    @apihook('GetKeyboardType', argc=1)
    def GetKeyboardType(self, emu, argv, ctx={}):
        '''
        int GetKeyboardType(
          int nTypeFlag
        );
        '''
        _type, = argv
        if _type == 0:
            return 4
        elif _type == 1:
            return 0
        elif _type == 2:
            return 12
        return 0

    @apihook('GetSystemMetrics', argc=1)
    def GetSystemMetrics(self, emu, argv, ctx={}):
        """
        int GetSystemMetrics(
          int nIndex
        );
        """

        nIndex, = argv

        rv = 1
        return rv

    @apihook('RegisterWindowMessage', argc=1)
    def RegisterWindowMessage(self, emu, argv, ctx={}):
        '''
        UINT RegisterWindowMessageA(
          LPCSTR lpString
        );
        '''

        lpString, = argv
        rv = 0xc000

        cw = self.get_char_width(ctx)

        s = self.read_mem_string(lpString, cw)
        argv[0] = s

        return rv

    @apihook('wsprintf', argc=_arch.VAR_ARGS, conv=_arch.CALL_CONV_CDECL)
    def wsprintf(self, emu, argv, ctx={}):
        """
        int WINAPIV wsprintf(
          LPSTR  ,
          LPCSTR ,
          ...
        );
        """
        cw = self.get_char_width(ctx)

        buf, fmt = emu.get_func_argv(_arch.CALL_CONV_CDECL, 2)
        fmt_str = self.read_mem_string(fmt, cw)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        if not fmt_cnt:
            self.write_mem_string(fmt_str, buf, cw)
            return len(fmt_str)

        _args = emu.get_func_argv(_arch.CALL_CONV_CDECL, 2 + fmt_cnt)[2:]
        fin = self.do_str_format(fmt_str, _args)

        self.write_mem_string(fin, buf, cw)

        argv.append(fin)
        argv.append(fmt_str)
        return len(fin)

    @apihook('PeekMessage', argc=5)
    def PeekMessage(self, emu, argv, ctx={}):
        '''
        BOOL PeekMessageA(
            LPMSG lpMsg,
            HWND  hWnd,
            UINT  wMsgFilterMin,
            UINT  wMsgFilterMax,
            UINT  wRemoveMsg
        );
        '''
        return False

    @apihook('PostMessage', argc=4)
    def PostMessage(self, emu, argv, ctx={}):
        '''
        BOOL PostMessage(
            HWND   hWnd,
            UINT   Msg,
            WPARAM wParam,
            LPARAM lParam
        );
        '''
        return True

    @apihook('SetWindowsHookEx', argc=4)
    def SetWindowsHookEx(self, emu, argv, ctx={}):
        '''
        HHOOK SetWindowsHookEx(
            int       idHook,
            HOOKPROC  lpfn,
            HINSTANCE hmod,
            DWORD     dwThreadId
        );
        '''
        idHook, lpfn, hmod, dwThreadId = argv

        hname = windefs.get_windowhook_flags(idHook)
        if hname:
            hname = hname[0]
            argv[0] = hname

        hnd = self.get_handle()
        self.window_hooks.update({hnd: (lpfn, hmod)})
        return hnd

    @apihook('MsgWaitForMultipleObjects', argc=5)
    def MsgWaitForMultipleObjects(self, emu, argv, ctx={}):
        '''
        DWORD MsgWaitForMultipleObjects(
            DWORD        nCount,
            const HANDLE *pHandles,
            BOOL         fWaitAll,
            DWORD        dwMilliseconds,
            DWORD        dwWakeMask
        );
        '''
        return 0

    @apihook('GetMessage', argc=4)
    def GetMessage(self, emu, argv, ctx={}):
        '''
        BOOL GetMessage(
            LPMSG lpMsg,
            HWND  hWnd,
            UINT  wMsgFilterMin,
            UINT  wMsgFilterMax
        );
        '''
        lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax = argv

        return True

    @apihook('TranslateMessage', argc=1)
    def TranslateMessage(self, emu, argv, ctx={}):
        '''
        BOOL TranslateMessage(
            const MSG *lpMsg
        );
        '''
        return True

    @apihook('DispatchMessage', argc=1)
    def DispatchMessage(self, emu, argv, ctx={}):
        '''
        LRESULT DispatchMessage(
            const MSG *lpMsg
        );
        '''
        lpMsg, = argv

        msg = windefs.MSG(emu.get_ptr_size())
        msg = self.mem_cast(msg, lpMsg)

        return 0

    @apihook('GetForegroundWindow', argc=0)
    def GetForegroundWindow(self, emu, argv, ctx={}):
        '''
        HWND GetForegroundWindow();
        '''
        return self.get_handle()

    @apihook('FindWindow', argc=2)
    def FindWindow(self, emu, argv, ctx={}):
        '''
        HWND FindWindow(
            LPCSTR lpClassName,
            LPCSTR lpWindowName
        );
        '''
        lpClassName, lpWindowName = argv
        cw = self.get_char_width(ctx)
        if lpClassName:
            cn = self.read_mem_string(lpClassName, cw)
            argv[0] = cn
        if lpWindowName:
            wn = self.read_mem_string(lpWindowName, cw)
            argv[1] = wn
        return 0

    @apihook('GetWindowText', argc=3)
    def GetWindowText(self, emu, argv, ctx={}):
        '''
        int GetWindowText(
            HWND  hWnd,
            LPSTR lpString,
            int   nMaxCount
        );
        '''
        hnd, pstr, maxc = argv

        cw = self.get_char_width(ctx)
        win_text = 'speakeasy window'
        if pstr:
            if cw == 2:
                wt = (win_text).encode('utf-16le')
            else:
                wt = (win_text).encode('utf-8')
            self.mem_write(pstr, wt)

        return len(win_text)

    @apihook('PaintDesktop', argc=1)
    def PaintDesktop(self, emu, argv, ctx={}):
        '''
        BOOL PaintDesktop(
        HDC hdc
        );
        '''
        return 0

    @apihook('wvsprintf', argc=_arch.VAR_ARGS, conv=_arch.CALL_CONV_CDECL)
    def wvsprintf(self, emu, argv, ctx={}):
        buf, fmt, va_list = emu.get_func_argv(_arch.CALL_CONV_CDECL, 3)[:3]
        cw = self.get_char_width(ctx)
        fmt_str = self.read_mem_string(fmt, cw)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args(va_list, fmt_cnt)
        fin = self.do_str_format(fmt_str, vargs)
        self.write_string(fin, buf)
        argv.clear()
        argv.append(fin)
        return len(fin)

    @apihook('ReleaseDC', argc=2)
    def ReleaseDC(self, emu, argv, ctx={}):
        '''
        int ReleaseDC(
          HWND hWnd,
          HDC  hDC
        );
        '''
        return 0

    @apihook('CharNext', argc=1)
    def CharNext(self, emu, argv, ctx={}):
        '''
        LPSTR CharNext(
            LPCSTR lpsz
        );
        '''
        s, = argv
        rv = 0
        cw = self.get_char_width(ctx)
        if s:
            rv = s + cw
        return rv

    @apihook('EnumWindows', argc=2)
    def EnumWindows(self, emu, argv, ctx={}):
        '''
        BOOL EnumWindows(
            WNDENUMPROC lpEnumFunc,
            LPARAM      lParam
        );
        '''
        lpEnumFunc, lParam = argv
        rv = 1

        return rv

    @apihook('LoadIcon', argc=2)
    def LoadIcon(self, emu, argv, ctx={}):
        '''
        HICON LoadIcon(
            HINSTANCE hInstance,
            LPCSTR    lpIconName
        );
        '''
        inst, name, = argv

        if name not in (IDI_APPLICATION, IDI_ASTERISK, IDI_ERROR, IDI_EXCLAMATION, IDI_HAND,
                        IDI_INFORMATION, IDI_QUESTION, IDI_SHIELD, IDI_WARNING, IDI_WINLOGO):
            return 0
        return 1
