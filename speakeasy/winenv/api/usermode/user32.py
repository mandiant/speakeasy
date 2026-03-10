# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from typing import Any

import speakeasy.windows.sessman as sessman
import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.windows.user32 as windefs
import speakeasy.winenv.defs.windows.windef as windef

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

UOI_FLAGS = 1


class User32(api.ApiHandler):
    """
    Implements exported functions from user32.dll
    """

    name = "user32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super().__init__(emu)

        self.funcs: dict[str, Any] = {}
        self.data: dict[str, Any] = {}
        self.window_hooks: dict[int, tuple] = {}
        self.handle: int = 0
        self.win: Any | None = None
        self.handles: list[int] = []
        self.wndprocs: dict[int, int] = {}
        self.timer_count: int = 0
        self.sessman = sessman.SessionManager(config=None)
        self.synthetic_async_keys = [0x41, 0x42, 0x43]
        self.synthetic_async_key_index = 0
        self.synthetic_hook_keys = [0x41, 0x42, 0x43]
        self.synthetic_hook_key_index = 0

        super().__get_hook_attrs__(self)

    def get_handle(self):
        self.handle += 4
        hnd = self.handle
        self.handles.append(hnd)
        return hnd

    def get_synthetic_async_key_state(self, vkey):
        if self.synthetic_async_key_index >= len(self.synthetic_async_keys):
            return 0

        if vkey != self.synthetic_async_keys[self.synthetic_async_key_index]:
            return 0

        self.synthetic_async_key_index += 1
        return 0x8001

    def get_synthetic_keyboard_hook(self):
        for _, hook in self.window_hooks.items():
            if len(hook) == 3 and hook[0] == windefs.WH_KEYBOARD_LL:
                return hook
        return None

    def emit_synthetic_keyboard_hook_event(self, emu, caller_argv):
        hook = self.get_synthetic_keyboard_hook()
        if not hook:
            return None

        if self.synthetic_hook_key_index >= len(self.synthetic_hook_keys):
            return None

        hook_index = self.synthetic_hook_key_index
        vkey = self.synthetic_hook_keys[hook_index]
        self.synthetic_hook_key_index += 1

        wparam = windefs.WM_KEYDOWN if (hook_index % 2 == 0) else windefs.WM_SYSKEYDOWN

        kbd = windefs.KBDLLHOOKSTRUCT(emu.get_ptr_size())
        kbd.vkCode = vkey
        kbd.scanCode = 0
        kbd.flags = 0
        kbd.time = 0
        kbd.dwExtraInfo = 0

        kbd_ptr = self.mem_alloc(kbd.sizeof(), tag="api.user32.kbdllhook")
        self.mem_write(kbd_ptr, kbd.get_bytes())

        _, lpfn, _ = hook
        self.setup_callback(lpfn, (0, wparam, kbd_ptr), caller_argv=caller_argv)
        return wparam, vkey

    def find_string_resource_by_id(self, pe, uID):
        pe_metadata = pe.get_pe_metadata()
        if not pe_metadata:
            return None
        return pe_metadata.string_table.get(uID)

    @apihook("GetDesktopWindow", argc=0)
    def GetDesktopWindow(self, emu, argv, ctx: api.ApiContext = None):
        """HWND GetDesktopWindow();"""
        ctx = ctx or {}

        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("ShowWindow", argc=2)
    def ShowWindow(self, emu, argv, ctx: api.ApiContext = None):
        """BOOL ShowWindow(
          HWND hWnd,
          int  nCmdShow
        );"""
        ctx = ctx or {}

        rv = 1

        return rv

    @apihook("CreateWindowStation", argc=4)
    def CreateWindowStation(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWINSTA CreateWindowStation(
            LPCSTR                lpwinsta,
            DWORD                 dwFlags,
            ACCESS_MASK           dwDesiredAccess,
            LPSECURITY_ATTRIBUTES lpsa
        );
        """
        ctx = ctx or {}
        winsta, flags, access, sa = argv

        return self.get_handle()

    @apihook("SetProcessWindowStation", argc=1)
    def SetProcessWindowStation(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL SetProcessWindowStation(
            HWINSTA hWinSta
        );
        """
        ctx = ctx or {}
        (winsta,) = argv

        rv = False
        if winsta:
            rv = True

        return rv

    @apihook("GetDC", argc=1)
    def GetDC(self, emu, argv, ctx: api.ApiContext = None):
        """
        HDC GetDC(
          HWND hWnd
        );
        """
        ctx = ctx or {}

        rv = self.sessman.get_device_context()

        return rv

    @apihook("RegisterClassEx", argc=1)
    def RegisterClassEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        ATOM RegisterClassEx(
            const WNDCLASSEXA *Arg1
        );
        """
        ctx = ctx or {}
        (Arg1,) = argv
        wclass = windefs.WNDCLASSEX(emu.get_ptr_size())
        wclass = self.mem_cast(wclass, Arg1)

        cn = None
        cw = self.get_char_width(ctx)
        if wclass.lpszClassName:
            cn = self.read_mem_string(wclass.lpszClassName, cw)

        atom = self.sessman.create_window_class(wclass, cn)

        return atom

    @apihook("UnregisterClass", argc=2)
    def UnregisterClass(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL UnregisterClass(
            LPCSTR    lpClassName,
            HINSTANCE hInstance
        );
        """
        ctx = ctx or {}

        return 1

    @apihook("SetCursorPos", argc=2)
    def SetCursorPos(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL SetCursorPos(
        int X,
        int Y
        );
        """
        ctx = ctx or {}
        return 1

    @apihook("CloseDesktop", argc=1)
    def CloseDesktop(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL CloseDesktop(
        HDESK hDesktop
        );
        """
        ctx = ctx or {}
        return 1

    @apihook("CloseWindowStation", argc=1)
    def CloseWindowStation(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL CloseWindowStation(
        HWINSTA hWinSta
        );
        """
        ctx = ctx or {}
        return 1

    @apihook("GetThreadDesktop", argc=1)
    def GetThreadDesktop(self, emu, argv, ctx: api.ApiContext = None):
        """
        HDESK GetThreadDesktop(
        DWORD dwThreadId
        );
        """
        ctx = ctx or {}
        return 1

    @apihook("OpenWindowStation", argc=3)
    def OpenWindowStation(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWINSTA OpenWindowStation(
        LPCSTR      lpszWinSta,
        BOOL        fInherit,
        ACCESS_MASK dwDesiredAccess
        );
        """
        ctx = ctx or {}
        return 1

    @apihook("ChangeWindowMessageFilter", argc=2)
    def ChangeWindowMessageFilter(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL ChangeWindowMessageFilter(
            UINT  message,
            DWORD dwFlag
        );
        """
        ctx = ctx or {}
        msg, flag = argv
        emu.enable_code_hook()
        return True

    @apihook("UpdateWindow", argc=1)
    def UpdateWindow(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL UpdateWindow(
            HWND hWnd
        );
        """
        ctx = ctx or {}
        (hnd,) = argv
        window = self.sessman.get_window(hnd)
        if not window:
            return False

        wc = self.sessman.get_window_class(window.class_name)
        if wc.wclass.lpfnWndProc:
            cb_args = (hnd, windefs.WM_PAINT, 0, 0)
            self.setup_callback(wc.wclass.lpfnWndProc, cb_args, caller_argv=argv)

        return True

    @apihook("PostQuitMessage", argc=1)
    def PostQuitMessage(self, emu, argv, ctx: api.ApiContext = None):
        """
        void PostQuitMessage(
            int nExitCode
        );
        """
        ctx = ctx or {}
        return

    @apihook("DestroyWindow", argc=1)
    def DestroyWindow(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL DestroyWindow(
            HWND hWnd
        );
        """
        ctx = ctx or {}
        return True

    @apihook("DefWindowProc", argc=4)
    def DefWindowProc(self, emu, argv, ctx: api.ApiContext = None):
        """
        LRESULT LRESULT DefWindowProc(
            HWND   hWnd,
            UINT   Msg,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        ctx = ctx or {}
        return 0

    @apihook("CreateWindowEx", argc=12)
    def CreateWindowEx(self, emu, argv, ctx: api.ApiContext = None):
        """
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
        """
        ctx = ctx or {}
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

    @apihook("SetLayeredWindowAttributes", argc=4)
    def SetLayeredWindowAttributes(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL SetLayeredWindowAttributes(
          [in] HWND     hwnd,
          [in] COLORREF crKey,
          [in] BYTE     bAlpha,
          [in] DWORD    dwFlags
        );
        """
        ctx = ctx or {}
        hwnd, crKey, bAlpha, dwFlags = argv
        return 1

    @apihook("MessageBox", argc=4)
    def MessageBox(self, emu, argv, ctx: api.ApiContext = None):
        """int MessageBox(
          HWND    hWnd,
          LPCTSTR lpText,
          LPCTSTR lpCaption,
          UINT    uType
        );"""
        ctx = ctx or {}
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

    @apihook("MessageBoxEx", argc=5)
    def MessageBoxEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        int MessageBoxExA(
            HWND   hWnd,
            LPCSTR lpText,
            LPCSTR lpCaption,
            UINT   uType,
            WORD   wLanguageId
        );
        """
        ctx = ctx or {}
        av = argv[:-1]
        rv = self.MessageBox(emu, av, ctx)
        argv[:4] = av
        return rv

    @apihook("LoadString", argc=4)
    def LoadString(self, emu, argv, ctx: api.ApiContext = None):
        """
        int LoadStringW(
          HINSTANCE hInstance,
          UINT      uID,
          LPWSTR    lpBuffer,
          int       cchBufferMax
        );
        """
        ctx = ctx or {}

        hInstance, uID, lpBuffer, ccBufferMax = argv
        cw = self.get_char_width(ctx)
        size = 0

        if hInstance == 0:
            pe = emu.modules[0] if emu.modules else None
        else:
            pe = emu.get_mod_from_addr(hInstance)
            if pe and hInstance != pe.base:
                return 0

        if not pe:
            return 0

        s = self.find_string_resource_by_id(pe, uID)
        if s is None:
            # self.logger.info("unable to find resource string id %04X" % uID)
            return 0

        if cw == 2:
            encoded = s.encode("utf-16le")
        elif cw == 1:
            encoded = s.encode("utf-8")

        size = int(len(encoded) / cw)

        if size == 0:
            # self.logger.debug("resource id %04X not found" % uID)
            return 0

        if ccBufferMax == 0:
            # Returning a pointer to the resource string is not supported without raw access
            return 0

        if len(encoded) > ccBufferMax:
            encoded = encoded[: ccBufferMax * cw]

        emu.mem_write(lpBuffer, encoded)
        if cw == 1:
            argv[2] = s
        else:
            argv[2] = s

        return len(encoded)

    @apihook("GetCursorPos", argc=1)
    def GetCursorPos(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetCursorPos(
          LPPOINT lpPoint
        );
        """
        ctx = ctx or {}

        (lpPoint,) = argv

        rv = 0
        return rv

    @apihook("GetAsyncKeyState", argc=1)
    def GetAsyncKeyState(self, emu, argv, ctx: api.ApiContext = None):
        """
        SHORT GetAsyncKeyState(
          [in] int vKey
        );
        """
        ctx = ctx or {}

        (vkey,) = argv
        return self.get_synthetic_async_key_state(vkey)

    @apihook("GetKeyboardType", argc=1)
    def GetKeyboardType(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetKeyboardType(
          int nTypeFlag
        );
        """
        ctx = ctx or {}
        (_type,) = argv
        if _type == 0:
            return 4
        elif _type == 1:
            return 0
        elif _type == 2:
            return 12
        return 0

    @apihook("GetSystemMetrics", argc=1)
    def GetSystemMetrics(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetSystemMetrics(
          int nIndex
        );
        """
        ctx = ctx or {}

        (nIndex,) = argv

        rv = 1
        return rv

    @apihook("LoadBitmap", argc=2)
    def LoadBitmap(self, emu, argv, ctx: api.ApiContext = None):
        """
        HBITMAP LoadBitmap(
            HINSTANCE hInstance,
            LPCSTR    lpBitmapName
        );
        """
        ctx = ctx or {}
        hInstance, lpBitmapName = argv
        rv = self.get_handle()
        return rv

    @apihook("GetClientRect", argc=2)
    def GetClientRect(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetClientRect(
          [in]  HWND   hWnd,
          [out] LPRECT lpRect
        );
        """
        ctx = ctx or {}
        return 0

    @apihook("RegisterWindowMessage", argc=1)
    def RegisterWindowMessage(self, emu, argv, ctx: api.ApiContext = None):
        """
        UINT RegisterWindowMessageA(
          LPCSTR lpString
        );
        """
        ctx = ctx or {}

        (lpString,) = argv
        rv = 0xC000

        cw = self.get_char_width(ctx)

        s = self.read_mem_string(lpString, cw)
        argv[0] = s

        return rv

    @apihook("wsprintf", argc=_arch.VAR_ARGS, conv=_arch.CALL_CONV_CDECL)
    def wsprintf(self, emu, argv, ctx: api.ApiContext = None):
        """
        int WINAPIV wsprintf(
          LPSTR  ,
          LPCSTR ,
          ...
        );
        """
        ctx = ctx or {}
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

    @apihook("PeekMessage", argc=5)
    def PeekMessage(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL PeekMessageA(
            LPMSG lpMsg,
            HWND  hWnd,
            UINT  wMsgFilterMin,
            UINT  wMsgFilterMax,
            UINT  wRemoveMsg
        );
        """
        ctx = ctx or {}
        return False

    @apihook("PostMessage", argc=4)
    def PostMessage(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL PostMessage(
            HWND   hWnd,
            UINT   Msg,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        ctx = ctx or {}
        return True

    @apihook("SendMessage", argc=4)
    def SendMessage(self, emu, argv, ctx: api.ApiContext = None):
        """
        LRESULT SendMessage(
            HWND   hWnd,
            UINT   Msg,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        ctx = ctx or {}
        hWnd, Msg, wParam, lParam = argv
        if hWnd in self.wndprocs:
            emu.set_pc(self.wndprocs[hWnd])

        return False

    @apihook("CallNextHookEx", argc=4)
    def CallNextHookEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        LRESULT CallNextHookEx(
            HHOOK  hhk,
            int    nCode,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        ctx = ctx or {}
        hhk, nCode, wParam, lParam = argv
        return 0

    @apihook("SetWindowsHookEx", argc=4)
    def SetWindowsHookEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        HHOOK SetWindowsHookEx(
            int       idHook,
            HOOKPROC  lpfn,
            HINSTANCE hmod,
            DWORD     dwThreadId
        );
        """
        ctx = ctx or {}
        idHook, lpfn, hmod, dwThreadId = argv

        hname = windefs.get_windowhook_flags(idHook)
        if hname:
            hname = hname[0]
            argv[0] = hname

        hnd = self.get_handle()
        self.window_hooks.update({hnd: (idHook, lpfn, hmod)})
        return hnd

    @apihook("UnhookWindowsHookEx", argc=1)
    def UnhookWindowsHookEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL UnhookWindowsHookEx(
            HHOOK hhk
        );
        """
        ctx = ctx or {}
        (hhk,) = argv

        rv = False
        if self.window_hooks.get(hhk):
            self.window_hooks.pop(hhk)
            rv = True
        return rv

    @apihook("MsgWaitForMultipleObjects", argc=5)
    def MsgWaitForMultipleObjects(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD MsgWaitForMultipleObjects(
            DWORD        nCount,
            const HANDLE *pHandles,
            BOOL         fWaitAll,
            DWORD        dwMilliseconds,
            DWORD        dwWakeMask
        );
        """
        ctx = ctx or {}
        return 0

    @apihook("GetMessage", argc=4)
    def GetMessage(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetMessage(
            LPMSG lpMsg,
            HWND  hWnd,
            UINT  wMsgFilterMin,
            UINT  wMsgFilterMax
        );
        """
        ctx = ctx or {}
        lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax = argv

        t = emu.get_current_thread()
        msg = None

        try:
            msg = t.message_queue.pop(0)
        except IndexError:
            if self.timer_count > 0:
                msg = windefs.MSG(emu.get_ptr_size())
                msg.hwnd = hWnd
                msg.message = windefs.WM_TIMER
            else:
                synthetic = self.emit_synthetic_keyboard_hook_event(emu, argv)
                if synthetic is None:
                    return False
                if lpMsg:
                    wparam, vkey = synthetic
                    msg = windefs.MSG(emu.get_ptr_size())
                    msg.hwnd = hWnd
                    msg.message = wparam
                    msg.wParam = vkey
                    msg.lParam = 0
                else:
                    return True

        if lpMsg:
            self.mem_write(lpMsg, msg.get_bytes())

        return True

    @apihook("TranslateMessage", argc=1)
    def TranslateMessage(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL TranslateMessage(
            const MSG *lpMsg
        );
        """
        ctx = ctx or {}
        return True

    @apihook("DispatchMessage", argc=1)
    def DispatchMessage(self, emu, argv, ctx: api.ApiContext = None):
        """
        LRESULT DispatchMessage(
            const MSG *lpMsg
        );
        """
        ctx = ctx or {}
        (lpMsg,) = argv

        msg = windefs.MSG(emu.get_ptr_size())
        msg = self.mem_cast(msg, lpMsg)

        return 0

    @apihook("GetForegroundWindow", argc=0)
    def GetForegroundWindow(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND GetForegroundWindow();
        """
        ctx = ctx or {}
        return self.get_handle()

    @apihook("LoadCursor", argc=2)
    def LoadCursor(self, emu, argv, ctx: api.ApiContext = None):
        """
        HCURSOR LoadCursor(
        HINSTANCE hInstance,
        LPCSTR    lpCursorName
        );
        """
        ctx = ctx or {}
        return self.get_handle()

    @apihook("FindWindow", argc=2)
    def FindWindow(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND FindWindow(
            LPCSTR lpClassName,
            LPCSTR lpWindowName
        );
        """
        ctx = ctx or {}
        lpClassName, lpWindowName = argv
        cw = self.get_char_width(ctx)
        if lpClassName:
            cn = self.read_mem_string(lpClassName, cw)
            argv[0] = cn
        if lpWindowName:
            wn = self.read_mem_string(lpWindowName, cw)
            argv[1] = wn
        return 0

    @apihook("GetWindowText", argc=3)
    def GetWindowText(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetWindowText(
            HWND  hWnd,
            LPSTR lpString,
            int   nMaxCount
        );
        """
        ctx = ctx or {}
        hnd, pstr, maxc = argv

        cw = self.get_char_width(ctx)
        win_text = "speakeasy window"
        if pstr:
            if cw == 2:
                wt = (win_text).encode("utf-16le")
            else:
                wt = (win_text).encode("utf-8")
            self.mem_write(pstr, wt)

        return len(win_text)

    @apihook("PaintDesktop", argc=1)
    def PaintDesktop(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL PaintDesktop(
        HDC hdc
        );
        """
        ctx = ctx or {}
        return 0

    @apihook("wvsprintf", argc=_arch.VAR_ARGS, conv=_arch.CALL_CONV_CDECL)
    def wvsprintf(self, emu, argv, ctx: api.ApiContext = None):
        ctx = ctx or {}
        buf, fmt, va_list = emu.get_func_argv(_arch.CALL_CONV_CDECL, 3)[:3]
        cw = self.get_char_width(ctx)
        fmt_str = self.read_mem_string(fmt, cw)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args(va_list, fmt_cnt)
        fin = self.do_str_format(fmt_str, vargs)
        self.write_string(fin, buf)
        argv.clear()
        argv.append(fin)
        argv.append(fmt_str)
        return len(fin)

    @apihook("ReleaseDC", argc=2)
    def ReleaseDC(self, emu, argv, ctx: api.ApiContext = None):
        """
        int ReleaseDC(
          HWND hWnd,
          HDC  hDC
        );
        """
        ctx = ctx or {}
        return 0

    @apihook("CharNext", argc=1)
    def CharNext(self, emu, argv, ctx: api.ApiContext = None):
        """
        LPSTR CharNext(
            LPCSTR lpsz
        );
        """
        ctx = ctx or {}
        (s,) = argv
        rv = 0
        cw = self.get_char_width(ctx)
        if s:
            rv = s + cw
        return rv

    @apihook("CharPrev", argc=2)
    def CharPrev(self, emu, argv, ctx: api.ApiContext = None):
        """
        LPSTR CharPrev(
            LPCSTR lpszStart,
            LPCSTR lpszCurrent
        );
        """
        ctx = ctx or {}
        """
        Got this from wine.          
        https://github.com/wine-mirror/wine/blob/a8c1d5c108fc57e4d78e9db126f395c89083a83d/dlls/kernelbase/string.c
        """
        s, c = argv
        cw = self.get_char_width(ctx)
        while s < c:
            n = s + cw
            if n >= c:
                break
            s = n

        return s

    @apihook("EnumWindows", argc=2)
    def EnumWindows(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL EnumWindows(
            WNDENUMPROC lpEnumFunc,
            LPARAM      lParam
        );
        """
        ctx = ctx or {}
        lpEnumFunc, lParam = argv
        rv = 1

        return rv

    @apihook("GetSysColor", argc=1)
    def GetSysColor(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD GetSysColor(
            int nIndex
        );
        """
        ctx = ctx or {}
        (nIndex,) = argv
        rv = 1

        return rv

    @apihook("GetParent", argc=1)
    def GetParent(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND GetParent(
            HWND hWnd
        );
        """
        ctx = ctx or {}
        return self.get_handle()

    @apihook("GetSysColorBrush", argc=1)
    def GetSysColorBrush(self, emu, argv, ctx: api.ApiContext = None):
        """
        HBRUSH GetSysColorBrush(
            int nIndex
        );
        """
        ctx = ctx or {}
        (nIndex,) = argv
        rv = 1

        return rv

    @apihook("GetWindowLong", argc=2)
    def GetWindowLong(self, emu, argv, ctx: api.ApiContext = None):
        """
        LONG GetWindowLongA(
            HWND hWnd,
            int  nIndex
        );
        """
        ctx = ctx or {}
        (
            hWnd,
            nIndex,
        ) = argv
        rv = 2

        return rv

    @apihook("SetWindowLong", argc=3)
    def SetWindowLong(self, emu, argv, ctx: api.ApiContext = None):
        """
        LONG SetWindowLongA(
          HWND hWnd,
          int  nIndex,
          LONG dwNewLong
        );
        """
        ctx = ctx or {}
        hWnd, nIndex, dwNewLong = argv
        if (self.get_ptr_size() == 4 and nIndex == 0xFFFFFFFC) or (
            self.get_ptr_size() == 8 and nIndex == 0xFFFFFFFFFFFFFFFC
        ):
            self.wndprocs[hWnd] = dwNewLong

        return 1

    @apihook("DialogBoxParam", argc=5)
    def DialogBoxParam(self, emu, argv, ctx: api.ApiContext = None):
        """
        INT_PTR DialogBoxParam(
            HINSTANCE hInstance,
            LPCSTR    lpTemplateName,
            HWND      hWndParent,
            DLGPROC   lpDialogFunc,
            LPARAM    dwInitParam
        );
        """
        ctx = ctx or {}
        hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam = argv
        rv = self.get_handle()
        cw = self.get_char_width(ctx)
        if lpTemplateName:
            tname = self.read_mem_string(lpTemplateName, cw)
            argv[1] = tname

        return rv

    @apihook("CreateDialogIndirectParam", argc=5)
    def CreateDialogIndirectParam(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND CreateDialogIndirectParam(
        HINSTANCE       hInstance,
        LPCDLGTEMPLATEA lpTemplate,
        HWND            hWndParent,
        DLGPROC         lpDialogFunc,
        LPARAM          dwInitParam
        );
        """
        ctx = ctx or {}

        (
            hnd,
            template,
            hnd_parent,
            func,
            param,
        ) = argv

        cb_args = (hnd_parent, windefs.WM_INITDIALOG, param, 0)
        self.setup_callback(func, cb_args, caller_argv=argv)
        return self.get_handle()

    @apihook("GetMenuInfo", argc=2)
    def GetMenuInfo(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetMenuInfo(
            HMENU,
            LPMENUINFO
        );
        """
        ctx = ctx or {}
        return 1

    @apihook("GetProcessWindowStation", argc=0)
    def GetProcessWindowStation(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWINSTA GetProcessWindowStation();
        """
        ctx = ctx or {}
        sta = self.sessman.get_current_station()
        return sta.get_handle()

    @apihook("LoadAccelerators", argc=2)
    def LoadAccelerators(self, emu, argv, ctx: api.ApiContext = None):
        """
        HACCEL LoadAccelerators(
        HINSTANCE hInstance,
        LPCSTR    lpTableName
        );
        """
        ctx = ctx or {}
        return self.get_handle()

    @apihook("IsWindowVisible", argc=1)
    def IsWindowVisible(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL IsWindowVisible(
        HWND hWnd
        );
        """
        ctx = ctx or {}
        return True

    @apihook("BeginPaint", argc=2)
    def BeginPaint(self, emu, argv, ctx: api.ApiContext = None):
        """
        HDC BeginPaint(
        HWND          hWnd,
        LPPAINTSTRUCT lpPaint
        );
        """
        ctx = ctx or {}
        return self.get_handle()

    @apihook("LookupIconIdFromDirectory", argc=2)
    def LookupIconIdFromDirectory(self, emu, argv, ctx: api.ApiContext = None):
        """
        int LookupIconIdFromDirectory(
        PBYTE presbits,
        BOOL  fIcon
        );
        """
        ctx = ctx or {}
        return 1

    @apihook("GetActiveWindow", argc=0)
    def GetActiveWindow(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND GetActiveWindow();
        """
        ctx = ctx or {}
        return self.get_handle()

    @apihook("GetLastActivePopup", argc=1)
    def GetLastActivePopup(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND GetLastActivePopup(
        HWND hWnd
        );
        """
        ctx = ctx or {}
        (hWnd,) = argv
        return self.get_handle()

    @apihook("GetUserObjectInformation", argc=5)
    def GetUserObjectInformation(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetUserObjectInformation(
            HANDLE  hObj,
            int     nIndex,
            PVOID   pvInfo,
            DWORD   nLength,
            LPDWORD lpnLengthNeeded
        );
        """
        ctx = ctx or {}
        obj, index, info, length, needed = argv

        if index == UOI_FLAGS:
            uoi = windefs.USEROBJECTFLAGS(emu.get_ptr_size())
            uoi.fInherit = 1
            uoi.dwFlags = 1

            if info:
                self.mem_write(info, uoi.get_bytes())

        return True

    @apihook("LoadIcon", argc=2)
    def LoadIcon(self, emu, argv, ctx: api.ApiContext = None):
        """
        HICON LoadIcon(
            HINSTANCE hInstance,
            LPCSTR    lpIconName
        );
        """
        ctx = ctx or {}
        (
            inst,
            name,
        ) = argv

        if name not in (
            IDI_APPLICATION,
            IDI_ASTERISK,
            IDI_ERROR,
            IDI_EXCLAMATION,
            IDI_HAND,
            IDI_INFORMATION,
            IDI_QUESTION,
            IDI_SHIELD,
            IDI_WARNING,
            IDI_WINLOGO,
        ):
            return 0
        return 1

    @apihook("GetRawInputDeviceList", argc=3)
    def GetRawInputDeviceList(self, emu, argv, ctx: api.ApiContext = None):
        """
        UINT GetRawInputDeviceList(
          PRAWINPUTDEVICELIST pRawInputDeviceList,
          PUINT               puiNumDevices,
          UINT                cbSize
        );
        """
        ctx = ctx or {}
        pRawInputDeviceList, puiNumDevices, cbSize = argv
        num_devices = 4
        self.mem_write(puiNumDevices, num_devices.to_bytes(4, "little"))
        return num_devices

    @apihook("GetNextDlgTabItem", argc=3)
    def GetNextDlgTabItem(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND GetNextDlgTabItem(
          HWND hDlg,
          HWND hCtl,
          BOOL bPrevious
        );
        """
        ctx = ctx or {}
        return 0

    @apihook("GetCaretPos", argc=1)
    def GetCaretPos(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetCaretPos(
          LPPOINT lpPoint
        );
        """
        ctx = ctx or {}
        lpPoint = argv[0]
        point = windef.POINT(emu.get_ptr_size())
        point.x = 0
        point.y = 0
        self.mem_write(lpPoint, self.get_bytes(point))
        return 1

    @apihook("GetMonitorInfo", argc=2)
    def GetMonitorInfo(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetMonitorInfo(
          HMONITOR      hMonitor,
          LPMONITORINFO lpmi
        );
        """
        ctx = ctx or {}
        hMonitor, lpmi = argv
        mi = windef.MONITORINFO(emu.get_ptr_size())
        mi = self.mem_cast(mi, lpmi)
        # just a stub for now
        self.mem_write(lpmi, self.get_bytes(mi))
        return 1

    @apihook("EndPaint", argc=2)
    def EndPaint(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL EndPaint(
          HWND              hWnd,
          const PAINTSTRUCT *lpPaint
        );
        """
        ctx = ctx or {}
        return 1

    @apihook("GetDlgCtrlID", argc=1)
    def GetDlgCtrlID(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetDlgCtrlID(
          HWND hWnd
        );
        """
        ctx = ctx or {}
        return 1

    @apihook("GetUpdateRect", argc=3)
    def GetUpdateRect(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetUpdateRect(
          HWND   hWnd,
          LPRECT lpRect,
          BOOL   bErase
        );
        """
        ctx = ctx or {}
        return 0

    @apihook("GetAltTabInfo", argc=5)
    def GetAltTabInfo(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL GetAltTabInfoA(
          HWND        hwnd,
          int         iItem,
          PALTTABINFO pati,
          LPSTR       pszItemText,
          UINT        cchItemText
        );
        """
        ctx = ctx or {}
        return 0

    @apihook("GetUpdateRgn", argc=3)
    def GetUpdateRgn(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetUpdateRgn(
          HWND hWnd,
          HRGN hRgn,
          BOOL bErase
        );
        """
        ctx = ctx or {}
        return 0

    @apihook("FlashWindow", argc=2)
    def FlashWindow(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL FlashWindow(
          HWND hWnd,
          BOOL bInvert
        );
        """
        ctx = ctx or {}
        return 1

    @apihook("IsClipboardFormatAvailable", argc=1)
    def IsClipboardFormatAvailable(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL IsClipboardFormatAvailable(
          UINT format
        );
        """
        ctx = ctx or {}
        return 0

    @apihook("IsWindow", argc=1)
    def IsWindow(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL IsWindow(
            HWND hWnd
        );
        """
        ctx = ctx or {}
        (hnd,) = argv

        return True

    @apihook("EnableWindow", argc=2)
    def EnableWindow(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL EnableWindow(
        HWND hWnd,
        BOOL bEnable
        );
        """
        ctx = ctx or {}
        hnd, bEnable = argv

        return False

    @apihook("CharLowerBuff", argc=2)
    def CharLowerBuff(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD CharLowerBuffA(
            LPSTR lpsz,
            DWORD cchLength
        );
        """
        ctx = ctx or {}
        _str, cchLength = argv
        cw = self.get_char_width(ctx)
        val = self.read_mem_string(_str, cw, max_chars=cchLength)
        argv[0] = val
        argv[1] = cchLength
        self.write_mem_string(val.lower(), _str, cw)
        return cchLength

    @apihook("CharUpperBuff", argc=2)
    def CharUpperBuff(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD CharUpperBuffA(
            LPSTR lpsz,
            DWORD cchLength
        );
        """
        ctx = ctx or {}
        _str, cchLength = argv
        cw = self.get_char_width(ctx)
        val = self.read_mem_string(_str, cw, max_chars=cchLength)
        argv[0] = val
        argv[1] = cchLength
        self.write_mem_string(val.upper(), _str, cw)
        return cchLength

    @apihook("CharLower", argc=1)
    def CharLower(self, emu, argv, ctx: api.ApiContext = None):
        """
        LPSTR CharLowerA(
            LPSTR lpsz
        );
        """
        ctx = ctx or {}
        (_str,) = argv
        cw = self.get_char_width(ctx)
        bits = _str.bit_length()
        if bits <= 16:
            if cw == 1:
                val = chr(_str).lower().encode("ascii")
            else:
                val = chr(_str).lower().encode("utf-16le")
            return int.from_bytes(val, byteorder="little")
        else:
            val = self.read_mem_string(_str, cw)
            self.write_mem_string(val.lower(), _str, cw)
            return _str

    @apihook("CharUpper", argc=1)
    def CharUpper(self, emu, argv, ctx: api.ApiContext = None):
        """
        LPSTR CharUpperA(
            LPSTR lpsz
        );
        """
        ctx = ctx or {}
        (_str,) = argv
        cw = self.get_char_width(ctx)
        bits = _str.bit_length()
        if bits <= 16:
            if cw == 1:
                val = chr(_str).upper().encode("ascii")
            else:
                val = chr(_str).upper().encode("utf-16le")
            return int.from_bytes(val, byteorder="little")
        else:
            val = self.read_mem_string(_str, cw)
            self.write_mem_string(val.upper(), _str, cw)
            return _str

    @apihook("SetTimer", argc=4)
    def SetTimer(self, emu, argv, ctx: api.ApiContext = None):
        """
        UINT_PTR SetTimer(
          HWND      hWnd,
          UINT_PTR  nIDEvent,
          UINT      uElapse,
          TIMERPROC lpTimerFunc
        );
        """
        ctx = ctx or {}
        self.timer_count += 1

        return self.get_handle()

    @apihook("KillTimer", argc=2)
    def KillTimer(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL KillTimer(
          HWND     hWnd,
          UINT_PTR uIDEvent
        );
        """
        ctx = ctx or {}
        self.timer_count -= 1

        return True

    @apihook("OpenDesktop", argc=4)
    def OpenDesktop(self, emu, argv, ctx: api.ApiContext = None):
        """
        HDESK OpenDesktopA(
            LPCSTR      lpszDesktop,
            DWORD       dwFlags,
            BOOL        fInherit,
            ACCESS_MASK dwDesiredAccess
        );
        """
        ctx = ctx or {}
        lpszDesktop, dwFlags, fInherit, dwDesiredAccess = argv
        cw = self.get_char_width(ctx)
        desktop = self.read_mem_string(lpszDesktop, cw)
        argv[0] = desktop
        return self.get_handle()

    @apihook("SetThreadDesktop", argc=1)
    def SetThreadDesktop(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL SetThreadDesktop(
            HDESK hDesktop
        );
        """
        ctx = ctx or {}
        return 0

    @apihook("GetKeyboardLayoutList", argc=2)
    def GetKeyboardLayoutList(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetKeyboardLayoutList(
          int nBuff,
          HKL *lpList
        );
        """
        ctx = ctx or {}
        nBuff, lpList = argv
        if not nBuff:
            # number of items
            return 1
        locale = 0x409  # English - United States
        self.mem_write(lpList, locale.to_bytes(2, "little"))
        self.mem_write(lpList + 4, locale.to_bytes(2, "little"))

        return 1

    @apihook("GetKBCodePage", argc=0)
    def GetKBCodePage(self, emu, argv, ctx: api.ApiContext = None):
        """
        INT GetKBCodePage();
        """
        ctx = ctx or {}
        # >>> ctypes.windll.user32.GetKBCodePage()
        # 437
        # https://docs.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
        return 437  # OEM United States

    @apihook("GetClipboardViewer", argc=0)
    def GetClipboardViewer(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND GetClipboardViewer();
        """
        ctx = ctx or {}
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetClipboardOwner", argc=0)
    def GetClipboardOwner(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND GetClipboardOwner();
        """
        ctx = ctx or {}
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetMenuCheckMarkDimensions", argc=0)
    def GetMenuCheckMarkDimensions(self, emu, argv, ctx: api.ApiContext = None):
        """
        LONG GetMenuCheckMarkDimensions();
        """
        ctx = ctx or {}
        # >>> ctypes.windll.user32.GetMenuCheckMarkDimensions()
        # 983055
        return 983055

    @apihook("GetOpenClipboardWindow", argc=0)
    def GetOpenClipboardWindow(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND GetOpenClipboardWindow();
        """
        ctx = ctx or {}
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetFocus", argc=0)
    def GetFocus(self, emu, argv, ctx: api.ApiContext = None):
        """
        HWND GetFocus();
        """
        ctx = ctx or {}
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetCursor", argc=0)
    def GetCursor(self, emu, argv, ctx: api.ApiContext = None):
        """
        HCURSOR GetCursor();
        """
        ctx = ctx or {}
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetClipboardSequenceNumber", argc=0)
    def GetClipboardSequenceNumber(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD GetClipboardSequenceNumber();
        """
        ctx = ctx or {}
        # >>> ctypes.windll.user32.GetClipboardSequenceNumber()
        # 295
        return 295

    @apihook("GetCaretBlinkTime", argc=0)
    def GetCaretBlinkTime(self, emu, argv, ctx: api.ApiContext = None):
        """
        UINT GetCaretBlinkTime();
        """
        ctx = ctx or {}
        # >>> ctypes.windll.user32.GetCaretBlinkTime()
        # 530
        return 530

    @apihook("GetDoubleClickTime", argc=0)
    def GetDoubleClickTime(self, emu, argv, ctx: api.ApiContext = None):
        """
        UINT GetDoubleClickTime();
        """
        ctx = ctx or {}
        # >>> ctypes.windll.user32.GetDoubleClickTime()
        # 500
        return 500

    @apihook("RegisterClipboardFormatA", argc=1)
    def RegisterClipboardFormatA(self, emu, argv, ctx: api.ApiContext = None):
        """
        UINT RegisterClipboardFormatA(
            LPCSTR lpszFormat
        );
        """
        ctx = ctx or {}
        # Return a fake clipboard format ID.
        # Clipboard format IDs start at 0xC000 for custom formats.
        return 0xC000

    @apihook("SystemParametersInfoA", argc=4)
    def SystemParametersInfoA(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL SystemParametersInfoA(
            UINT  uiAction,
            UINT  uiParam,
            PVOID pvParam,
            UINT  fWinIni
        );
        """
        ctx = ctx or {}
        uiAction, uiParam, pvParam, fWinIni = argv

        # Many callers expect pvParam to be filled with something.
        # We return success without writing anything unless needed.
        return 1

    @apihook("GetKeyboardLayout", argc=1)
    def GetKeyboardLayout(self, emu, argv, ctx: api.ApiContext = None):
        """
        HKL GetKeyboardLayout(
            DWORD idThread
        );
        """
        ctx = ctx or {}
        # Return a fake HKL (keyboard layout handle).
        # Real HKLs are typically like 0x04090409 (LANG + device id).
        return 0x04090409

    @apihook("EnumDisplayMonitors", argc=4)
    def EnumDisplayMonitors(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL EnumDisplayMonitors(
            HDC             hdc,
            LPCRECT         lprcClip,
            MONITORENUMPROC lpfnEnum,
            LPARAM          dwData
        );
        """
        ctx = ctx or {}
        hdc, lprcClip, lpfnEnum, dwData = argv

        # Most callers expect TRUE to indicate success.
        # We do not invoke the callback — Speakeasy doesn't emulate monitor enumeration.
        return 1

    @apihook("OemToCharA", argc=2)
    def OemToCharA(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL OemToCharA(
            LPCSTR lpszSrc,
            LPSTR  lpszDst
        );
        """
        ctx = ctx or {}
        src, dst = argv

        # If destination buffer exists, copy source bytes into it.
        if src and dst:
            try:
                data = emu.mem_read(src, 256)
                try:
                    emu.mem_write(dst, data)
                except Exception:
                    base_addr = dst & ~0xFFF
                    emu.mem_map(base_addr, 0x1000)
                    emu.mem_write(dst, data)
            except Exception:
                pass

        # Return TRUE
        return 1

    @apihook("CharPrevW", argc=2)
    def CharPrevW(self, emu, argv, ctx: api.ApiContext = None):
        """
        LPWSTR CharPrevW(
            LPCWSTR lpszStart,
            LPCWSTR lpszCurrent
        );
        """
        ctx = ctx or {}
        start, current = argv

        # If current > start, return current - 2 (one WCHAR back)
        try:
            if current and start and current > start:
                return current - 2
        except Exception:
            pass

        # Otherwise return start
        return start
