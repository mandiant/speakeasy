# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes
from typing import Any

import speakeasy.windows.guest_callbacks as guest_callbacks
import speakeasy.windows.sessman as sessman
import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.windows.user32 as windefs
import speakeasy.winenv.defs.windows.windef as windef
import speakeasy.winenv.defs.windows.windows as windows
from speakeasy.windows.guest_callbacks import GuestCall

from .. import api

IDOK = 1
IDCANCEL = 2
IDABORT = 3
IDYES = 6

MB_TYPEMASK = 0xF
MB_OK = 0x0
MB_ABORTRETRYIGNORE = 0x2
MB_YESNO = 0x4

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

GWL_WNDPROC = -4
GWL_STYLE = -16

RT_STRING = 6

WS_POPUP = 0x80000000
WS_CHILD = 0x40000000

SCREEN_WIDTH = 1920
SCREEN_HEIGHT = 1080

# Windows 10 at 96 DPI with a 40 pixel taskbar. Indexes that are not here return 0.
SYSTEM_METRICS = {
    0: SCREEN_WIDTH,  # SM_CXSCREEN
    1: SCREEN_HEIGHT,  # SM_CYSCREEN
    2: 17,  # SM_CXVSCROLL
    3: 17,  # SM_CYHSCROLL
    4: 23,  # SM_CYCAPTION
    5: 1,  # SM_CXBORDER
    6: 1,  # SM_CYBORDER
    7: 3,  # SM_CXDLGFRAME
    8: 3,  # SM_CYDLGFRAME
    9: 17,  # SM_CYVTHUMB
    10: 17,  # SM_CXHTHUMB
    11: 32,  # SM_CXICON
    12: 32,  # SM_CYICON
    13: 32,  # SM_CXCURSOR
    14: 32,  # SM_CYCURSOR
    15: 20,  # SM_CYMENU
    16: SCREEN_WIDTH,  # SM_CXFULLSCREEN
    17: SCREEN_HEIGHT - 63,  # SM_CYFULLSCREEN
    19: 1,  # SM_MOUSEPRESENT
    20: 17,  # SM_CYVSCROLL
    21: 17,  # SM_CXHSCROLL
    28: 136,  # SM_CXMIN
    29: 39,  # SM_CYMIN
    30: 36,  # SM_CXSIZE
    31: 22,  # SM_CYSIZE
    32: 4,  # SM_CXFRAME
    33: 4,  # SM_CYFRAME
    34: 136,  # SM_CXMINTRACK
    35: 39,  # SM_CYMINTRACK
    36: 4,  # SM_CXDOUBLECLK
    37: 4,  # SM_CYDOUBLECLK
    38: 75,  # SM_CXICONSPACING
    39: 75,  # SM_CYICONSPACING
    43: 3,  # SM_CMOUSEBUTTONS
    45: 2,  # SM_CXEDGE
    46: 2,  # SM_CYEDGE
    47: 160,  # SM_CXMINSPACING
    48: 28,  # SM_CYMINSPACING
    49: 16,  # SM_CXSMICON
    50: 16,  # SM_CYSMICON
    51: 23,  # SM_CYSMCAPTION
    52: 22,  # SM_CXSMSIZE
    53: 22,  # SM_CYSMSIZE
    54: 19,  # SM_CXMENUSIZE
    55: 19,  # SM_CYMENUSIZE
    56: 8,  # SM_ARRANGE
    57: 160,  # SM_CXMINIMIZED
    58: 28,  # SM_CYMINIMIZED
    59: SCREEN_WIDTH + 20,  # SM_CXMAXTRACK
    60: SCREEN_HEIGHT + 20,  # SM_CYMAXTRACK
    61: SCREEN_WIDTH + 16,  # SM_CXMAXIMIZED
    62: SCREEN_HEIGHT - 24,  # SM_CYMAXIMIZED
    63: 3,  # SM_NETWORK
    68: 4,  # SM_CXDRAG
    69: 4,  # SM_CYDRAG
    71: 15,  # SM_CXMENUCHECK
    72: 15,  # SM_CYMENUCHECK
    75: 1,  # SM_MOUSEWHEELPRESENT
    78: SCREEN_WIDTH,  # SM_CXVIRTUALSCREEN
    79: SCREEN_HEIGHT,  # SM_CYVIRTUALSCREEN
    80: 1,  # SM_CMONITORS
    81: 1,  # SM_SAMEDISPLAYFORMAT
    83: 1,  # SM_CXFOCUSBORDER
    84: 1,  # SM_CYFOCUSBORDER
    92: 4,  # SM_CXPADDEDBORDER
}

# Windows 10 default colors as COLORREF (0x00BBGGRR). Indexes that are not here return 0.
SYS_COLORS = {
    0: 0xC8C8C8,  # COLOR_SCROLLBAR
    2: 0xD1B499,  # COLOR_ACTIVECAPTION
    3: 0xDBCDBF,  # COLOR_INACTIVECAPTION
    4: 0xF0F0F0,  # COLOR_MENU
    5: 0xFFFFFF,  # COLOR_WINDOW
    6: 0x646464,  # COLOR_WINDOWFRAME
    10: 0xB4B4B4,  # COLOR_ACTIVEBORDER
    11: 0xFCF7F4,  # COLOR_INACTIVEBORDER
    12: 0xABABAB,  # COLOR_APPWORKSPACE
    13: 0xD77800,  # COLOR_HIGHLIGHT
    14: 0xFFFFFF,  # COLOR_HIGHLIGHTTEXT
    15: 0xF0F0F0,  # COLOR_BTNFACE
    16: 0xA0A0A0,  # COLOR_BTNSHADOW
    17: 0x6D6D6D,  # COLOR_GRAYTEXT
    20: 0xFFFFFF,  # COLOR_BTNHIGHLIGHT
    21: 0x696969,  # COLOR_3DDKSHADOW
    22: 0xE3E3E3,  # COLOR_3DLIGHT
    24: 0xE1FFFF,  # COLOR_INFOBK
    26: 0xCC6600,  # COLOR_HOTLIGHT
    27: 0xEAD1B9,  # COLOR_GRADIENTACTIVECAPTION
    28: 0xF2E4D7,  # COLOR_GRADIENTINACTIVECAPTION
    29: 0xD77800,  # COLOR_MENUHILIGHT
    30: 0xF0F0F0,  # COLOR_MENUBAR
}


def map_char_case(raw: bytes, width: int, upper: bool) -> bytes:
    """
    Change the case of a buffer of characters without changing its length.
    ANSI buffers change only ASCII letters. A wide character keeps its case
    when the mapped form is more than one UTF-16 unit.
    """
    if width == 1:
        return raw.upper() if upper else raw.lower()
    out = []
    for ch in raw.decode("utf-16le", "surrogatepass"):
        mapped = ch.upper() if upper else ch.lower()
        out.append(mapped if len(mapped) == 1 and ord(mapped) <= 0xFFFF else ch)
    return "".join(out).encode("utf-16le", "surrogatepass")


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
        self.window_longs: dict[int, dict[int, int]] = {}
        self.window_messages: dict[str, int] = {}
        self.dialog_results: dict[int, int] = {}
        self.timers: list[tuple[int, int, int]] = []
        self.next_timer: int = 0
        self.sessman = sessman.SessionManager(config=None, allocator=emu.handle_allocator)
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

    def emit_synthetic_keyboard_hook_event(self, emu):
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
        self.setup_callback(lpfn, (0, wparam, kbd_ptr))
        return wparam, vkey

    def find_string_resource_by_id(self, pe, uID):
        """Read string uID from its RT_STRING block in the mapped image, which a packer may have written."""
        pe_metadata = pe.get_pe_metadata()
        if not pe_metadata:
            return None
        block = uID // 16 + 1
        entry = next((r for r in pe_metadata.resources if r.type_id == RT_STRING and r.id == block), None)
        if not entry:
            return None
        data = self.mem_read(pe.base + entry.data_rva, entry.size)
        offset = 0
        for _ in range(uID % 16):
            if offset + 2 > len(data):
                return None
            offset += 2 + int.from_bytes(data[offset : offset + 2], "little") * 2
        if offset + 2 > len(data):
            return None
        length = int.from_bytes(data[offset : offset + 2], "little")
        return data[offset + 2 : offset + 2 + length * 2].decode("utf-16le", errors="replace")

    @apihook("GetDesktopWindow", argc=0)
    def GetDesktopWindow(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """HWND GetDesktopWindow();"""

        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("ShowWindow", argc=2)
    def ShowWindow(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """BOOL ShowWindow(
          HWND hWnd,
          int  nCmdShow
        );"""

        rv = 1

        return rv

    @apihook("CreateWindowStation", argc=4)
    def CreateWindowStation(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWINSTA CreateWindowStation(
            LPCSTR                lpwinsta,
            DWORD                 dwFlags,
            ACCESS_MASK           dwDesiredAccess,
            LPSECURITY_ATTRIBUTES lpsa
        );
        """
        winsta, flags, access, sa = argv

        return self.get_handle()

    @apihook("SetProcessWindowStation", argc=1)
    def SetProcessWindowStation(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetProcessWindowStation(
            HWINSTA hWinSta
        );
        """
        (winsta,) = argv

        rv = False
        if winsta:
            rv = True

        return rv

    @apihook("GetDC", argc=1)
    def GetDC(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HDC GetDC(
          HWND hWnd
        );
        """

        rv = self.sessman.get_device_context()

        return rv

    @apihook("GetWindowDC", argc=1)
    def GetWindowDC(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HDC GetWindowDC(
          HWND hWnd
        );
        """
        return self.sessman.get_device_context()

    @apihook("RegisterClassEx", argc=1)
    def RegisterClassEx(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        ATOM RegisterClassEx(
            const WNDCLASSEXA *Arg1
        );
        """
        (Arg1,) = argv
        return self.register_window_class(windefs.WNDCLASSEX(emu.get_ptr_size()), Arg1, ctx)

    @apihook("RegisterClass", argc=1)
    def RegisterClass(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        ATOM RegisterClass(
            const WNDCLASSA *lpWndClass
        );
        """
        (lpWndClass,) = argv
        return self.register_window_class(windefs.WNDCLASS(emu.get_ptr_size()), lpWndClass, ctx)

    def register_window_class(self, wclass, address, ctx):
        wclass = self.mem_cast(wclass, address)

        cn = None
        cw = self.get_char_width(ctx)
        if wclass.lpszClassName > 0xFFFF:
            cn = self.read_mem_string(wclass.lpszClassName, cw)

        return self.sessman.create_window_class(wclass, cn)

    @apihook("UnregisterClass", argc=2)
    def UnregisterClass(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL UnregisterClass(
            LPCSTR    lpClassName,
            HINSTANCE hInstance
        );
        """

        return 1

    @apihook("SetCursorPos", argc=2)
    def SetCursorPos(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetCursorPos(
        int X,
        int Y
        );
        """
        return 1

    @apihook("CloseDesktop", argc=1)
    def CloseDesktop(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CloseDesktop(
        HDESK hDesktop
        );
        """
        return 1

    @apihook("CloseWindowStation", argc=1)
    def CloseWindowStation(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CloseWindowStation(
        HWINSTA hWinSta
        );
        """
        return 1

    @apihook("GetThreadDesktop", argc=1)
    def GetThreadDesktop(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HDESK GetThreadDesktop(
        DWORD dwThreadId
        );
        """
        return 1

    @apihook("OpenWindowStation", argc=3)
    def OpenWindowStation(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWINSTA OpenWindowStation(
        LPCSTR      lpszWinSta,
        BOOL        fInherit,
        ACCESS_MASK dwDesiredAccess
        );
        """
        return 1

    @apihook("ChangeWindowMessageFilter", argc=2)
    def ChangeWindowMessageFilter(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL ChangeWindowMessageFilter(
            UINT  message,
            DWORD dwFlag
        );
        """
        msg, flag = argv
        emu.enable_code_hook()
        return True

    @apihook("UpdateWindow", argc=1)
    def UpdateWindow(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL UpdateWindow(
            HWND hWnd
        );
        """
        (hnd,) = argv
        window = self.sessman.get_window(hnd)
        if not window:
            return False

        wc = self.sessman.get_window_class(window.class_name)
        if wc and wc.wclass.lpfnWndProc:
            cb_args = (hnd, windefs.WM_PAINT, 0, 0)
            self.setup_callback(wc.wclass.lpfnWndProc, cb_args)

        return True

    @apihook("PostQuitMessage", argc=1)
    def PostQuitMessage(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void PostQuitMessage(
            int nExitCode
        );
        """
        return

    @apihook("DestroyWindow", argc=1)
    def DestroyWindow(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL DestroyWindow(
            HWND hWnd
        );
        """
        return True

    @apihook("DefWindowProc", argc=4)
    def DefWindowProc(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LRESULT LRESULT DefWindowProc(
            HWND   hWnd,
            UINT   Msg,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        hWnd, Msg, wParam, lParam = argv
        return int(Msg == windefs.WM_NCCREATE)

    @apihook("CallWindowProc", argc=5)
    def CallWindowProc(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LRESULT CallWindowProcA(
            WNDPROC lpPrevWndFunc,
            HWND    hWnd,
            UINT    Msg,
            WPARAM  wParam,
            LPARAM  lParam
        );
        """
        lpPrevWndFunc, hWnd, Msg, wParam, lParam = argv
        if not lpPrevWndFunc:
            return 0
        return (yield GuestCall(lpPrevWndFunc, (hWnd, Msg, wParam, lParam)))

    @apihook("CreateWindowEx", argc=12)
    def CreateWindowEx(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
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
        cw = self.get_char_width(ctx)
        ex_style, class_arg, name_arg, style, x, y, width, height, parent, menu, inst, param = argv
        cn, wn = class_arg, name_arg
        if cn > 0xFFFF:
            cn = self.read_mem_string(cn, cw)
            ctx.args["lpClassName"].display = cn
        elif not cn:
            cn = None
        if wn:
            wn = self.read_mem_string(wn, cw)
            ctx.args["lpWindowName"].display = wn
        else:
            wn = None
        thread = emu.get_current_thread()
        proc = emu.get_current_process()
        hnd = self.sessman.create_window(wn, cn, style, parent, thread.id if thread else 0, proc.pid if proc else 0)
        wc = self.sessman.get_window_class(cn) if cn else None
        if not wc or not wc.wclass.lpfnWndProc:
            return hnd
        cs = windefs.CREATESTRUCT(emu.get_ptr_size())
        cs.lpCreateParams, cs.hInstance, cs.hMenu, cs.hwndParent = param, inst, menu, parent
        cs.cy, cs.cx, cs.y, cs.x = height, width, y, x
        cs.style, cs.lpszName, cs.lpszClass, cs.dwExStyle = style, name_arg, class_arg, ex_style
        return self.send_create_messages(emu, hnd, wc.wclass.lpfnWndProc, cs)

    def send_create_messages(self, emu, hnd, wndproc, cs):
        """Send WM_NCCREATE and WM_CREATE as CreateWindowEx does; either can refuse the window."""
        lparam = guest_callbacks.alloca(emu, cs.get_bytes())
        if not (yield GuestCall(wndproc, (hnd, windefs.WM_NCCREATE, 0, lparam))):
            return 0
        if (yield GuestCall(wndproc, (hnd, windefs.WM_CREATE, 0, lparam))) == (1 << emu.get_ptr_size() * 8) - 1:
            return 0
        return hnd

    @apihook("SetLayeredWindowAttributes", argc=4)
    def SetLayeredWindowAttributes(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetLayeredWindowAttributes(
          [in] HWND     hwnd,
          [in] COLORREF crKey,
          [in] BYTE     bAlpha,
          [in] DWORD    dwFlags
        );
        """
        hwnd, crKey, bAlpha, dwFlags = argv
        return 1

    @apihook("MessageBox", argc=4)
    def MessageBox(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """int MessageBox(
          HWND    hWnd,
          LPCTSTR lpText,
          LPCTSTR lpCaption,
          UINT    uType
        );"""
        hWnd, lpText, lpCaption, uType = argv

        cw = self.get_char_width(ctx)

        if lpText:
            text = self.read_mem_string(lpText, cw)
            ctx.args["lpText"].display = text
        if lpCaption:
            cap = self.read_mem_string(lpCaption, cw)
            ctx.args["lpCaption"].display = cap

        # Dismiss the box with Cancel, or press the first button if it has no Cancel button
        return {MB_OK: IDOK, MB_ABORTRETRYIGNORE: IDABORT, MB_YESNO: IDYES}.get(uType & MB_TYPEMASK, IDCANCEL)

    @apihook("MessageBoxEx", argc=5)
    def MessageBoxEx(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int MessageBoxExA(
            HWND   hWnd,
            LPCSTR lpText,
            LPCSTR lpCaption,
            UINT   uType,
            WORD   wLanguageId
        );
        """
        av = argv[:-1]
        rv = self.MessageBox(emu, av, ctx)
        return rv

    @apihook("LoadString", argc=4)
    def LoadString(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
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

        if not s:
            # self.logger.debug("resource id %04X not found" % uID)
            return 0

        if ccBufferMax == 0:
            # Returning a pointer to the resource string is not supported without raw access
            return 0

        s = s[: ccBufferMax - 1]
        self.write_mem_string(s, lpBuffer, cw)
        ctx.args["lpBuffer"].display = s

        return len(s)

    @apihook("GetCursorPos", argc=1)
    def GetCursorPos(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetCursorPos(
          LPPOINT lpPoint
        );
        """

        (lpPoint,) = argv
        if not lpPoint:
            return False

        pt = windef.POINT(emu.get_ptr_size())
        pt.x = SCREEN_WIDTH // 2
        pt.y = SCREEN_HEIGHT // 2
        self.mem_write(lpPoint, self.get_bytes(pt))
        return True

    @apihook("WindowFromPoint", argc=2)
    def WindowFromPoint(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND WindowFromPoint(
          POINT Point
        );

        Point is passed by value: two stack slots on x86, one register on x64.
        argc=2 covers the x86 layout.
        """
        return self.sessman.get_current_desktop().desktop_window.get_handle()

    @apihook("GetAsyncKeyState", argc=1)
    def GetAsyncKeyState(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SHORT GetAsyncKeyState(
          [in] int vKey
        );
        """

        (vkey,) = argv
        return self.get_synthetic_async_key_state(vkey)

    @apihook("GetKeyboardType", argc=1)
    def GetKeyboardType(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetKeyboardType(
          int nTypeFlag
        );
        """
        (_type,) = argv
        if _type == 0:
            return 4
        elif _type == 1:
            return 0
        elif _type == 2:
            return 12
        return 0

    @apihook("GetSystemMetrics", argc=1)
    def GetSystemMetrics(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetSystemMetrics(
          int nIndex
        );
        """

        (nIndex,) = argv
        return SYSTEM_METRICS.get(nIndex, 0)

    @apihook("LoadBitmap", argc=2)
    def LoadBitmap(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HBITMAP LoadBitmap(
            HINSTANCE hInstance,
            LPCSTR    lpBitmapName
        );
        """
        hInstance, lpBitmapName = argv
        self.read_res_identifier(emu, ctx, "lpBitmapName", self.get_char_width(ctx), lpBitmapName)
        rv = self.get_handle()
        return rv

    @apihook("GetClientRect", argc=2)
    def GetClientRect(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetClientRect(
          [in]  HWND   hWnd,
          [out] LPRECT lpRect
        );
        """
        return 0

    @apihook("RegisterWindowMessage", argc=1)
    def RegisterWindowMessage(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT RegisterWindowMessageA(
          LPCSTR lpString
        );
        """
        (lpString,) = argv
        if not lpString:
            return 0

        cw = self.get_char_width(ctx)

        s = self.read_mem_string(lpString, cw)
        ctx.args["lpString"].display = s

        return self.window_messages.setdefault(s.lower(), 0xC000 + len(self.window_messages))

    @apihook("wsprintf", argc=_arch.VAR_ARGS, conv=_arch.CALL_CONV_CDECL)
    def wsprintf(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
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

        _args = emu.get_func_argv(_arch.CALL_CONV_CDECL, 2 + fmt_cnt)[2:]
        fin = self.do_str_format(fmt_str, _args, wide=cw == 2)

        self.write_mem_string(fin, buf, cw)

        ctx.args.clear()
        ctx.args.append(fin)
        ctx.args.append(fmt_str)
        return len(fin)

    @apihook("PeekMessage", argc=5)
    def PeekMessage(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PeekMessageA(
            LPMSG lpMsg,
            HWND  hWnd,
            UINT  wMsgFilterMin,
            UINT  wMsgFilterMax,
            UINT  wRemoveMsg
        );
        """
        return False

    @apihook("PostMessage", argc=4)
    def PostMessage(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PostMessage(
            HWND   hWnd,
            UINT   Msg,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        return True

    @apihook("SendMessage", argc=4)
    def SendMessage(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LRESULT SendMessage(
            HWND   hWnd,
            UINT   Msg,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        hWnd, Msg, wParam, lParam = argv
        if hWnd in self.wndprocs:
            emu.set_pc(self.wndprocs[hWnd])

        return False

    @apihook("CallNextHookEx", argc=4)
    def CallNextHookEx(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LRESULT CallNextHookEx(
            HHOOK  hhk,
            int    nCode,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        hhk, nCode, wParam, lParam = argv
        return 0

    @apihook("SetWindowsHookEx", argc=4)
    def SetWindowsHookEx(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HHOOK SetWindowsHookEx(
            int       idHook,
            HOOKPROC  lpfn,
            HINSTANCE hmod,
            DWORD     dwThreadId
        );
        """
        idHook, lpfn, hmod, dwThreadId = argv

        hname = windefs.get_windowhook_flags(idHook)
        if hname:
            hname = hname[0]
            ctx.args["idHook"].display = hname

        hnd = self.get_handle()
        self.window_hooks.update({hnd: (idHook, lpfn, hmod)})
        return hnd

    @apihook("UnhookWindowsHookEx", argc=1)
    def UnhookWindowsHookEx(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL UnhookWindowsHookEx(
            HHOOK hhk
        );
        """
        (hhk,) = argv

        rv = False
        if self.window_hooks.get(hhk):
            self.window_hooks.pop(hhk)
            rv = True
        return rv

    @apihook("MsgWaitForMultipleObjects", argc=5)
    def MsgWaitForMultipleObjects(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD MsgWaitForMultipleObjects(
            DWORD        nCount,
            const HANDLE *pHandles,
            BOOL         fWaitAll,
            DWORD        dwMilliseconds,
            DWORD        dwWakeMask
        );
        """
        return 0

    @apihook("GetMessage", argc=4)
    def GetMessage(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetMessage(
            LPMSG lpMsg,
            HWND  hWnd,
            UINT  wMsgFilterMin,
            UINT  wMsgFilterMax
        );
        """
        lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax = argv

        t = emu.get_current_thread()
        msg = None

        try:
            msg = t.message_queue.pop(0)
        except IndexError:
            if self.timers:
                hwnd, tid, proc = self.timers[self.next_timer % len(self.timers)]
                self.next_timer += 1
                msg = windefs.MSG(emu.get_ptr_size())
                msg.hwnd = hwnd
                msg.message = windefs.WM_TIMER
                msg.wParam = tid
                msg.lParam = proc
            else:
                synthetic = self.emit_synthetic_keyboard_hook_event(emu)
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
    def TranslateMessage(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL TranslateMessage(
            const MSG *lpMsg
        );
        """
        return True

    @apihook("DispatchMessage", argc=1)
    def DispatchMessage(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LRESULT DispatchMessage(
            const MSG *lpMsg
        );
        """
        (lpMsg,) = argv

        msg = windefs.MSG(emu.get_ptr_size())
        msg = self.mem_cast(msg, lpMsg)

        if msg.message == windefs.WM_TIMER and msg.lParam:
            self.setup_callback(msg.lParam, (msg.hwnd, msg.message, msg.wParam, msg.time))
            return 0
        wndproc = self.wndprocs.get(msg.hwnd)
        window = self.sessman.get_window(msg.hwnd)
        if not wndproc and window:
            wc = self.sessman.get_window_class(window.class_name)
            wndproc = wc.wclass.lpfnWndProc if wc else 0
        if wndproc:
            self.setup_callback(wndproc, (msg.hwnd, msg.message, msg.wParam, msg.lParam))
        return 0

    @apihook("GetForegroundWindow", argc=0)
    def GetForegroundWindow(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetForegroundWindow();
        """
        return self.get_handle()

    @apihook("LoadCursor", argc=2)
    def LoadCursor(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HCURSOR LoadCursor(
        HINSTANCE hInstance,
        LPCSTR    lpCursorName
        );
        """
        _, lpCursorName = argv
        self.read_res_identifier(emu, ctx, "lpCursorName", self.get_char_width(ctx), lpCursorName)
        return self.get_handle()

    @apihook("FindWindow", argc=2)
    def FindWindow(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND FindWindow(
            LPCSTR lpClassName,
            LPCSTR lpWindowName
        );
        """
        lpClassName, lpWindowName = argv
        cw = self.get_char_width(ctx)
        if lpClassName > 0xFFFF:
            cn = self.read_mem_string(lpClassName, cw)
            ctx.args["lpClassName"].display = cn
        if lpWindowName:
            wn = self.read_mem_string(lpWindowName, cw)
            ctx.args["lpWindowName"].display = wn
        return 0

    @apihook("GetWindowText", argc=3)
    def GetWindowText(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetWindowText(
            HWND  hWnd,
            LPSTR lpString,
            int   nMaxCount
        );
        """
        hnd, pstr, maxc = argv

        cw = self.get_char_width(ctx)
        win_text = "speakeasy window"
        if not pstr or not 0 < maxc <= 0x7FFFFFFF:
            return 0
        win_text = win_text[: maxc - 1]
        self.write_mem_string(win_text, pstr, cw)

        return len(win_text)

    @apihook("PaintDesktop", argc=1)
    def PaintDesktop(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PaintDesktop(
        HDC hdc
        );
        """
        return 0

    @apihook("wvsprintf", argc=3)
    def wvsprintf(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int wvsprintf(
          LPSTR   lpOutput,
          LPCSTR  lpFmt,
          va_list arglist
        );
        """
        buf, fmt, va_list = argv
        cw = self.get_char_width(ctx)
        fmt_str = self.read_mem_string(fmt, cw)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args(va_list, fmt_cnt)
        fin = self.do_str_format(fmt_str, vargs, wide=cw == 2)
        self.write_mem_string(fin, buf, cw)
        ctx.args.clear()
        ctx.args.append(fin)
        ctx.args.append(fmt_str)
        return len(fin)

    @apihook("ReleaseDC", argc=2)
    def ReleaseDC(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int ReleaseDC(
          HWND hWnd,
          HDC  hDC
        );
        """
        hWnd, hDC = argv
        return int(hDC == self.sessman.get_device_context())

    @apihook("CharNext", argc=1)
    def CharNext(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPSTR CharNext(
            LPCSTR lpsz
        );
        """
        (s,) = argv
        rv = s
        cw = self.get_char_width(ctx)
        if s and int.from_bytes(self.mem_read(s, cw), "little"):
            rv = s + cw
        return rv

    @apihook("CharPrev", argc=2)
    def CharPrev(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPSTR CharPrev(
            LPCSTR lpszStart,
            LPCSTR lpszCurrent
        );
        """
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
    def EnumWindows(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnumWindows(
            WNDENUMPROC lpEnumFunc,
            LPARAM      lParam
        );
        """
        lpEnumFunc, lParam = argv
        desktop = self.sessman.get_current_desktop().desktop_window.get_handle()
        windows = [hnd for hnd, w in self.sessman.windows.items() if isinstance(hnd, int) and w.parent in (0, desktop)]
        for hnd in windows:
            if not (yield GuestCall(lpEnumFunc, (hnd, lParam))) & 0xFFFFFFFF:
                return 0
        return 1

    @apihook("GetSysColor", argc=1)
    def GetSysColor(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetSysColor(
            int nIndex
        );
        """
        (nIndex,) = argv
        return SYS_COLORS.get(nIndex, 0)

    @apihook("GetParent", argc=1)
    def GetParent(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetParent(
            HWND hWnd
        );
        """
        (hnd,) = argv
        window = self.sessman.get_window(hnd)
        if not window:
            if hnd != self.sessman.get_current_desktop().desktop_window.get_handle():
                emu.set_last_error(windows.ERROR_INVALID_WINDOW_HANDLE)
            return 0
        if window.style & (WS_POPUP | WS_CHILD):
            return window.parent
        return 0

    def get_prop_key(self, lpString, ctx: api.ApiContext) -> int | str:
        if lpString <= 0xFFFF:
            return lpString
        name = self.read_mem_string(lpString, self.get_char_width(ctx))
        ctx.args["lpString"].display = name
        return name.upper()

    def get_prop_window(self, emu, hnd):
        window = self.sessman.get_window(hnd)
        if not window:
            emu.set_last_error(windows.ERROR_INVALID_WINDOW_HANDLE)
        return window

    @apihook("SetProp", argc=3)
    def SetProp(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetPropA(
          HWND   hWnd,
          LPCSTR lpString,
          HANDLE hData
        );
        """
        hnd, lpString, hData = argv
        key = self.get_prop_key(lpString, ctx)
        window = self.get_prop_window(emu, hnd)
        if not window:
            return False
        window.props[key] = hData
        return True

    @apihook("GetProp", argc=2)
    def GetProp(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE GetPropA(
          HWND   hWnd,
          LPCSTR lpString
        );
        """
        hnd, lpString = argv
        key = self.get_prop_key(lpString, ctx)
        window = self.get_prop_window(emu, hnd)
        if not window:
            return 0
        return window.props.get(key, 0)

    @apihook("RemoveProp", argc=2)
    def RemoveProp(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE RemovePropA(
          HWND   hWnd,
          LPCSTR lpString
        );
        """
        hnd, lpString = argv
        key = self.get_prop_key(lpString, ctx)
        window = self.get_prop_window(emu, hnd)
        if not window:
            return 0
        return window.props.pop(key, 0)

    @apihook("GetWindowThreadProcessId", argc=2)
    def GetWindowThreadProcessId(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetWindowThreadProcessId(
          HWND    hWnd,
          LPDWORD lpdwProcessId
        );
        """
        hnd, lpdwProcessId = argv
        desktop_window = self.sessman.get_current_desktop().desktop_window
        if hnd == desktop_window.get_handle():
            window = desktop_window
            if not window.thread_id:
                csrss = next((p for p in emu.get_processes() if p.name.lower() == "csrss"), None)
                window.process_id = csrss.pid if csrss else 0
                window.thread_id = emu.handle_allocator.allocate_kernel_object_id()
        else:
            window = self.sessman.get_window(hnd)
        if not window:
            emu.set_last_error(windows.ERROR_INVALID_WINDOW_HANDLE)
            return 0
        if lpdwProcessId:
            self.mem_write(lpdwProcessId, window.process_id.to_bytes(4, "little"))
        return window.thread_id

    @apihook("GetSysColorBrush", argc=1)
    def GetSysColorBrush(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HBRUSH GetSysColorBrush(
            int nIndex
        );
        """
        (nIndex,) = argv
        rv = 1

        return rv

    def get_window_longs(self, emu, hWnd):
        """
        Get the values that SetWindowLong stored for ``hWnd``. For an unknown
        window, set ERROR_INVALID_WINDOW_HANDLE and return None.
        """
        desktop = self.sessman.get_current_desktop().desktop_window.get_handle()
        if not self.sessman.get_window(hWnd) and hWnd not in self.handles and hWnd != desktop:
            emu.set_last_error(windows.ERROR_INVALID_WINDOW_HANDLE)
            return None
        return self.window_longs.setdefault(hWnd, {})

    def get_window_long(self, hWnd, index, longs):
        if index == GWL_WNDPROC and hWnd in self.wndprocs:
            return self.wndprocs[hWnd]
        window = self.sessman.get_window(hWnd)
        if index == GWL_WNDPROC and window:
            wc = self.sessman.get_window_class(window.class_name)
            return wc.wclass.lpfnWndProc if wc else 0
        if index == GWL_STYLE and window:
            return window.style
        return longs.get(index, 0)

    @apihook("GetWindowLong", argc=2)
    def GetWindowLong(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG GetWindowLongA(
            HWND hWnd,
            int  nIndex
        );
        """
        hWnd, nIndex = argv
        longs = self.get_window_longs(emu, hWnd)
        if longs is None:
            return 0
        return self.get_window_long(hWnd, ctypes.c_int32(nIndex).value, longs)

    @apihook("GetWindowLongPtr", argc=2)
    def GetWindowLongPtr(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG_PTR GetWindowLongPtrA(
            HWND hWnd,
            int  nIndex
        );
        """
        return self.GetWindowLong(emu, argv, ctx)

    @apihook("SetWindowLong", argc=3)
    def SetWindowLong(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG SetWindowLongA(
          HWND hWnd,
          int  nIndex,
          LONG dwNewLong
        );
        """
        hWnd, nIndex, dwNewLong = argv
        longs = self.get_window_longs(emu, hWnd)
        if longs is None:
            return 0
        index = ctypes.c_int32(nIndex).value
        rv = self.get_window_long(hWnd, index, longs)
        window = self.sessman.get_window(hWnd)
        if index == GWL_WNDPROC:
            self.wndprocs[hWnd] = dwNewLong
        elif index == GWL_STYLE and window:
            window.style = dwNewLong
        else:
            longs[index] = dwNewLong
        return rv

    @apihook("SetWindowLongPtr", argc=3)
    def SetWindowLongPtr(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG_PTR SetWindowLongPtrA(
          HWND     hWnd,
          int      nIndex,
          LONG_PTR dwNewLong
        );
        """
        return self.SetWindowLong(emu, argv, ctx)

    @apihook("DialogBoxParam", argc=5)
    def DialogBoxParam(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        INT_PTR DialogBoxParam(
            HINSTANCE hInstance,
            LPCSTR    lpTemplateName,
            HWND      hWndParent,
            DLGPROC   lpDialogFunc,
            LPARAM    dwInitParam
        );
        """
        hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam = argv
        self.read_res_identifier(emu, ctx, "lpTemplateName", self.get_char_width(ctx), lpTemplateName)
        if not lpDialogFunc:
            return IDCANCEL
        return self.run_dialog(self.get_handle(), lpDialogFunc, dwInitParam)

    def run_dialog(self, hdlg, func, param):
        # No user input arrives, so the dialog ends when the procedure calls EndDialog
        # during WM_INITDIALOG, or else as if the user closed it
        yield GuestCall(func, (hdlg, windefs.WM_INITDIALOG, 0, param))
        return self.dialog_results.pop(hdlg, IDCANCEL)

    @apihook("EndDialog", argc=2)
    def EndDialog(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EndDialog(
            HWND    hDlg,
            INT_PTR nResult
        );
        """
        hDlg, nResult = argv
        self.dialog_results[hDlg] = nResult
        return 1

    @apihook("CreateDialogIndirectParam", argc=5)
    def CreateDialogIndirectParam(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND CreateDialogIndirectParam(
        HINSTANCE       hInstance,
        LPCDLGTEMPLATEA lpTemplate,
        HWND            hWndParent,
        DLGPROC         lpDialogFunc,
        LPARAM          dwInitParam
        );
        """

        (
            hnd,
            template,
            hnd_parent,
            func,
            param,
        ) = argv

        hdlg = self.get_handle()
        cb_args = (hdlg, windefs.WM_INITDIALOG, 0, param)
        self.setup_callback(func, cb_args)
        return hdlg

    @apihook("GetMenuInfo", argc=2)
    def GetMenuInfo(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetMenuInfo(
            HMENU,
            LPMENUINFO
        );
        """
        return 1

    @apihook("GetProcessWindowStation", argc=0)
    def GetProcessWindowStation(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWINSTA GetProcessWindowStation();
        """
        sta = self.sessman.get_current_station()
        return sta.get_handle()

    @apihook("LoadAccelerators", argc=2)
    def LoadAccelerators(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HACCEL LoadAccelerators(
        HINSTANCE hInstance,
        LPCSTR    lpTableName
        );
        """
        _, lpTableName = argv
        self.read_res_identifier(emu, ctx, "lpTableName", self.get_char_width(ctx), lpTableName)
        return self.get_handle()

    @apihook("IsWindowVisible", argc=1)
    def IsWindowVisible(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsWindowVisible(
        HWND hWnd
        );
        """
        return True

    @apihook("BeginPaint", argc=2)
    def BeginPaint(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HDC BeginPaint(
        HWND          hWnd,
        LPPAINTSTRUCT lpPaint
        );
        """
        return self.get_handle()

    @apihook("LookupIconIdFromDirectory", argc=2)
    def LookupIconIdFromDirectory(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int LookupIconIdFromDirectory(
        PBYTE presbits,
        BOOL  fIcon
        );
        """
        return 1

    @apihook("GetActiveWindow", argc=0)
    def GetActiveWindow(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetActiveWindow();
        """
        return self.get_handle()

    @apihook("GetLastActivePopup", argc=1)
    def GetLastActivePopup(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetLastActivePopup(
        HWND hWnd
        );
        """
        (hWnd,) = argv
        return self.get_handle()

    @apihook("GetUserObjectInformation", argc=5)
    def GetUserObjectInformation(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetUserObjectInformation(
            HANDLE  hObj,
            int     nIndex,
            PVOID   pvInfo,
            DWORD   nLength,
            LPDWORD lpnLengthNeeded
        );
        """
        obj, index, info, length, needed = argv

        if index == UOI_FLAGS:
            uoi = windefs.USEROBJECTFLAGS(emu.get_ptr_size())
            uoi.fInherit = 1
            uoi.dwFlags = 1

            if info:
                self.mem_write(info, uoi.get_bytes())

        return True

    @apihook("LoadIcon", argc=2)
    def LoadIcon(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HICON LoadIcon(
            HINSTANCE hInstance,
            LPCSTR    lpIconName
        );
        """
        (
            inst,
            name,
        ) = argv
        self.read_res_identifier(emu, ctx, "lpIconName", self.get_char_width(ctx), name)

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
    def GetRawInputDeviceList(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetRawInputDeviceList(
          PRAWINPUTDEVICELIST pRawInputDeviceList,
          PUINT               puiNumDevices,
          UINT                cbSize
        );
        """
        pRawInputDeviceList, puiNumDevices, cbSize = argv
        types = (windefs.RIM_TYPEKEYBOARD, windefs.RIM_TYPEMOUSE, windefs.RIM_TYPEHID, windefs.RIM_TYPEHID)
        num_devices = len(types)
        if not pRawInputDeviceList:
            self.mem_write(puiNumDevices, num_devices.to_bytes(4, "little"))
            return 0

        if int.from_bytes(self.mem_read(puiNumDevices, 4), "little") < num_devices:
            self.mem_write(puiNumDevices, num_devices.to_bytes(4, "little"))
            emu.set_last_error(windows.ERROR_INSUFFICIENT_BUFFER)
            return 0xFFFFFFFF

        ptr_size = self.get_ptr_size()
        for i, dev_type in enumerate(types):
            entry = self.get_handle().to_bytes(ptr_size, "little") + dev_type.to_bytes(ptr_size, "little")
            self.mem_write(pRawInputDeviceList + i * 2 * ptr_size, entry)
        return num_devices

    @apihook("GetNextDlgTabItem", argc=3)
    def GetNextDlgTabItem(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetNextDlgTabItem(
          HWND hDlg,
          HWND hCtl,
          BOOL bPrevious
        );
        """
        return 0

    @apihook("GetCaretPos", argc=1)
    def GetCaretPos(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetCaretPos(
          LPPOINT lpPoint
        );
        """
        lpPoint = argv[0]
        point = windef.POINT(emu.get_ptr_size())
        point.x = 0
        point.y = 0
        self.mem_write(lpPoint, self.get_bytes(point))
        return 1

    @apihook("GetMonitorInfo", argc=2)
    def GetMonitorInfo(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetMonitorInfo(
          HMONITOR      hMonitor,
          LPMONITORINFO lpmi
        );
        """
        hMonitor, lpmi = argv
        mi = windef.MONITORINFO(emu.get_ptr_size())
        mi = self.mem_cast(mi, lpmi)
        # just a stub for now
        self.mem_write(lpmi, self.get_bytes(mi))
        return 1

    @apihook("EndPaint", argc=2)
    def EndPaint(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EndPaint(
          HWND              hWnd,
          const PAINTSTRUCT *lpPaint
        );
        """
        return 1

    @apihook("GetDlgCtrlID", argc=1)
    def GetDlgCtrlID(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetDlgCtrlID(
          HWND hWnd
        );
        """
        return 1

    @apihook("GetUpdateRect", argc=3)
    def GetUpdateRect(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetUpdateRect(
          HWND   hWnd,
          LPRECT lpRect,
          BOOL   bErase
        );
        """
        return 0

    @apihook("GetAltTabInfo", argc=5)
    def GetAltTabInfo(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetAltTabInfoA(
          HWND        hwnd,
          int         iItem,
          PALTTABINFO pati,
          LPSTR       pszItemText,
          UINT        cchItemText
        );
        """
        return 0

    @apihook("GetUpdateRgn", argc=3)
    def GetUpdateRgn(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetUpdateRgn(
          HWND hWnd,
          HRGN hRgn,
          BOOL bErase
        );
        """
        return 0

    @apihook("FlashWindow", argc=2)
    def FlashWindow(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL FlashWindow(
          HWND hWnd,
          BOOL bInvert
        );
        """
        return 1

    @apihook("IsClipboardFormatAvailable", argc=1)
    def IsClipboardFormatAvailable(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsClipboardFormatAvailable(
          UINT format
        );
        """
        return 0

    @apihook("GetClipboardData", argc=1)
    def GetClipboardData(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE GetClipboardData(
          [in] UINT uFormat
        );
        """
        return 0

    @apihook("IsWindow", argc=1)
    def IsWindow(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsWindow(
            HWND hWnd
        );
        """
        (hnd,) = argv

        return True

    @apihook("EnableWindow", argc=2)
    def EnableWindow(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnableWindow(
        HWND hWnd,
        BOOL bEnable
        );
        """
        hnd, bEnable = argv

        return False

    @apihook("CharLowerBuff", argc=2)
    def CharLowerBuff(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD CharLowerBuffA(
            LPSTR lpsz,
            DWORD cchLength
        );
        """
        _str, cchLength = argv
        cw = self.get_char_width(ctx)
        if not cchLength:
            return 0
        raw = self.mem_read(_str, cchLength * cw)
        ctx.args["lpsz"].display = raw.decode("utf-8" if cw == 1 else "utf-16le", "ignore").replace("\x00", "")
        self.mem_write(_str, map_char_case(raw, cw, upper=False))
        return cchLength

    @apihook("CharUpperBuff", argc=2)
    def CharUpperBuff(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD CharUpperBuffA(
            LPSTR lpsz,
            DWORD cchLength
        );
        """
        _str, cchLength = argv
        cw = self.get_char_width(ctx)
        if not cchLength:
            return 0
        raw = self.mem_read(_str, cchLength * cw)
        ctx.args["lpsz"].display = raw.decode("utf-8" if cw == 1 else "utf-16le", "ignore").replace("\x00", "")
        self.mem_write(_str, map_char_case(raw, cw, upper=True))
        return cchLength

    @apihook("CharLower", argc=1)
    def CharLower(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPSTR CharLowerA(
            LPSTR lpsz
        );
        """
        (_str,) = argv
        cw = self.get_char_width(ctx)
        bits = _str.bit_length()
        if bits <= 16:
            if cw == 1 and _str > 0xFF:
                return _str
            val = map_char_case(_str.to_bytes(cw, "little"), cw, upper=False)
            return int.from_bytes(val, byteorder="little")
        else:
            raw = self.mem_read(_str, self.mem_string_len(_str, cw) * cw)
            self.mem_write(_str, map_char_case(raw, cw, upper=False))
            return _str

    @apihook("CharUpper", argc=1)
    def CharUpper(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPSTR CharUpperA(
            LPSTR lpsz
        );
        """
        (_str,) = argv
        cw = self.get_char_width(ctx)
        bits = _str.bit_length()
        if bits <= 16:
            if cw == 1 and _str > 0xFF:
                return _str
            val = map_char_case(_str.to_bytes(cw, "little"), cw, upper=True)
            return int.from_bytes(val, byteorder="little")
        else:
            raw = self.mem_read(_str, self.mem_string_len(_str, cw) * cw)
            self.mem_write(_str, map_char_case(raw, cw, upper=True))
            return _str

    @apihook("SetTimer", argc=4)
    def SetTimer(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT_PTR SetTimer(
          HWND      hWnd,
          UINT_PTR  nIDEvent,
          UINT      uElapse,
          TIMERPROC lpTimerFunc
        );
        """
        hWnd, nIDEvent, uElapse, lpTimerFunc = argv
        if hWnd:
            self.timers = [t for t in self.timers if t[:2] != (hWnd, nIDEvent)]
            self.timers.append((hWnd, nIDEvent, lpTimerFunc))
            return nIDEvent
        tid = self.get_handle()
        self.timers.append((0, tid, lpTimerFunc))
        return tid

    @apihook("KillTimer", argc=2)
    def KillTimer(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL KillTimer(
          HWND     hWnd,
          UINT_PTR uIDEvent
        );
        """
        hWnd, uIDEvent = argv
        self.timers = [t for t in self.timers if t[:2] != (hWnd, uIDEvent)]
        return True

    @apihook("OpenDesktop", argc=4)
    def OpenDesktop(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HDESK OpenDesktopA(
            LPCSTR      lpszDesktop,
            DWORD       dwFlags,
            BOOL        fInherit,
            ACCESS_MASK dwDesiredAccess
        );
        """
        lpszDesktop, dwFlags, fInherit, dwDesiredAccess = argv
        cw = self.get_char_width(ctx)
        desktop = self.read_mem_string(lpszDesktop, cw)
        ctx.args["lpszDesktop"].display = desktop
        return self.get_handle()

    @apihook("SetThreadDesktop", argc=1)
    def SetThreadDesktop(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetThreadDesktop(
            HDESK hDesktop
        );
        """
        return 0

    @apihook("GetKeyboardLayoutList", argc=2)
    def GetKeyboardLayoutList(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetKeyboardLayoutList(
          int nBuff,
          HKL *lpList
        );
        """
        nBuff, lpList = argv
        if not nBuff:
            # number of items
            return 1
        hkl = 0x04090409  # English - United States
        self.mem_write(lpList, hkl.to_bytes(self.get_ptr_size(), "little"))

        return 1

    @apihook("GetKBCodePage", argc=0)
    def GetKBCodePage(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        INT GetKBCodePage();
        """
        # >>> ctypes.windll.user32.GetKBCodePage()
        # 437
        # https://docs.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
        return 437  # OEM United States

    @apihook("GetClipboardViewer", argc=0)
    def GetClipboardViewer(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetClipboardViewer();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetClipboardOwner", argc=0)
    def GetClipboardOwner(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetClipboardOwner();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetMenuCheckMarkDimensions", argc=0)
    def GetMenuCheckMarkDimensions(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG GetMenuCheckMarkDimensions();
        """
        # >>> ctypes.windll.user32.GetMenuCheckMarkDimensions()
        # 983055
        return 983055

    @apihook("GetOpenClipboardWindow", argc=0)
    def GetOpenClipboardWindow(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetOpenClipboardWindow();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetFocus", argc=0)
    def GetFocus(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetFocus();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetCursor", argc=0)
    def GetCursor(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HCURSOR GetCursor();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetClipboardSequenceNumber", argc=0)
    def GetClipboardSequenceNumber(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetClipboardSequenceNumber();
        """
        # >>> ctypes.windll.user32.GetClipboardSequenceNumber()
        # 295
        return 295

    @apihook("GetCaretBlinkTime", argc=0)
    def GetCaretBlinkTime(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetCaretBlinkTime();
        """
        # >>> ctypes.windll.user32.GetCaretBlinkTime()
        # 530
        return 530

    @apihook("GetDoubleClickTime", argc=0)
    def GetDoubleClickTime(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetDoubleClickTime();
        """
        # >>> ctypes.windll.user32.GetDoubleClickTime()
        # 500
        return 500

    @apihook("RegisterClipboardFormatA", argc=1)
    def RegisterClipboardFormatA(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT RegisterClipboardFormatA(
            LPCSTR lpszFormat
        );
        """
        # Return a fake clipboard format ID.
        # Clipboard format IDs start at 0xC000 for custom formats.
        return 0xC000

    @apihook("SystemParametersInfoA", argc=4)
    def SystemParametersInfoA(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SystemParametersInfoA(
            UINT  uiAction,
            UINT  uiParam,
            PVOID pvParam,
            UINT  fWinIni
        );
        """
        uiAction, uiParam, pvParam, fWinIni = argv

        # Many callers expect pvParam to be filled with something.
        # We return success without writing anything unless needed.
        return 1

    @apihook("GetKeyboardLayout", argc=1)
    def GetKeyboardLayout(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HKL GetKeyboardLayout(
            DWORD idThread
        );
        """
        # Return a fake HKL (keyboard layout handle).
        # Real HKLs are typically like 0x04090409 (LANG + device id).
        return 0x04090409

    @apihook("EnumDisplayMonitors", argc=4)
    def EnumDisplayMonitors(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnumDisplayMonitors(
            HDC             hdc,
            LPCRECT         lprcClip,
            MONITORENUMPROC lpfnEnum,
            LPARAM          dwData
        );
        """
        hdc, lprcClip, lpfnEnum, dwData = argv

        # Most callers expect TRUE to indicate success.
        # We do not invoke the callback — Speakeasy doesn't emulate monitor enumeration.
        return 1

    @apihook("OemToCharA", argc=2)
    def OemToCharA(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL OemToCharA(
            LPCSTR lpszSrc,
            LPSTR  lpszDst
        );
        """
        src, dst = argv

        # If destination buffer exists, copy source bytes into it.
        if src and dst:
            try:
                data = emu.mem_read(src, self.mem_string_len(src, 1) + 1)
                try:
                    emu.mem_write(dst, data)
                except Exception:
                    base_addr = dst & ~0xFFF
                    emu.mem_map(0x1000, base=base_addr)
                    emu.mem_write(dst, data)
            except Exception:
                pass

        # Return TRUE
        return 1

    @apihook("CharPrevW", argc=2)
    def CharPrevW(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPWSTR CharPrevW(
            LPCWSTR lpszStart,
            LPCWSTR lpszCurrent
        );
        """
        start, current = argv

        # If current > start, return current - 2 (one WCHAR back)
        try:
            if current and start and current > start:
                return current - 2
        except Exception:
            pass

        # Otherwise return start
        return start
