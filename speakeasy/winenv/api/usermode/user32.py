# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes
from typing import TYPE_CHECKING

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.windows.user32 as u32defs
from speakeasy.windows import guest_callbacks, sessman
from speakeasy.windows.guest_callbacks import GuestCall
from speakeasy.winenv.defs.enums import WINDOWS_HOOK_ID
from speakeasy.winenv.defs.lookup import decode
from speakeasy.winenv.defs.windows import windef
from speakeasy.winenv.defs.windows import windows as windefs

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator

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

LIST_VIEW_COLUMN_MESSAGES = (
    u32defs.LVM_INSERTCOLUMNA,
    u32defs.LVM_INSERTCOLUMNW,
    u32defs.LVM_GETCOLUMNA,
    u32defs.LVM_GETCOLUMNW,
    u32defs.LVM_GETCOLUMNWIDTH,
    u32defs.LVM_SETCOLUMNWIDTH,
    u32defs.LVM_DELETECOLUMN,
)

GWL_WNDPROC = -4
GWL_STYLE = -16

RT_STRING = 6

WS_POPUP = 0x80000000
WS_CHILD = 0x40000000

# The devices that EnumDisplayDevices lists under each parent device name: one Intel adapter, as in an
# OptiPlex 7090, with one monitor. Each entry gives DeviceName, DeviceString, StateFlags, DeviceID and DeviceKey.
DISPLAY_DEVICES = {
    None: (
        "\\\\.\\DISPLAY1",
        "Intel(R) UHD Graphics 750",
        u32defs.DISPLAY_DEVICE_ATTACHED_TO_DESKTOP | u32defs.DISPLAY_DEVICE_PRIMARY_DEVICE,
        "PCI\\VEN_8086&DEV_4C8A&SUBSYS_0A6F1028&REV_04",
        "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Video\\{6E5A3F42-9C1B-4D7E-8F20-3B1A5C7D9E04}\\0000",
    ),
    "\\\\.\\DISPLAY1": (
        "\\\\.\\DISPLAY1\\Monitor0",
        "Generic PnP Monitor",
        u32defs.DISPLAY_DEVICE_ACTIVE | u32defs.DISPLAY_DEVICE_ATTACHED,
        "MONITOR\\DELA1A8\\{4d36e96e-e325-11ce-bfc1-08002be10318}\\0000",
        "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class\\{4d36e96e-e325-11ce-bfc1-08002be10318}\\0000",
    ),
}

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

        self.funcs = {}
        self.data = {}
        self.window_hooks: dict[int, tuple[int, int, int]] = {}
        self.wndprocs: dict[int, int] = {}
        self.window_longs: dict[int, dict[int, int]] = {}
        self.window_messages: dict[str, int] = {}
        self.dialog_results: dict[int, int] = {}
        self.timers: list[tuple[int, int, int]] = []
        self.next_timer: int = 0
        self.sessman: sessman.SessionManager = emu.get_session_manager()
        self.foreground_window: int = 0
        self.synthetic_async_keys: list[int] = [0x41, 0x42, 0x43]
        self.synthetic_async_key_index: int = 0
        self.synthetic_hook_keys: list[int] = [0x41, 0x42, 0x43]
        self.synthetic_hook_key_index: int = 0

        super().__get_hook_attrs__(self)

    def new_window_handle(self):
        """Get the handle of a new window that EnumWindows does not give."""
        return sessman.Window(self.sessman.handles).get_handle()

    def get_synthetic_async_key_state(self, vkey):
        if self.synthetic_async_key_index >= len(self.synthetic_async_keys):
            return 0

        if vkey != self.synthetic_async_keys[self.synthetic_async_key_index]:
            return 0

        self.synthetic_async_key_index += 1
        return 0x8001

    def get_synthetic_keyboard_hook(self):
        for _, hook in self.window_hooks.items():
            if len(hook) == 3 and hook[0] == WINDOWS_HOOK_ID.WH_KEYBOARD_LL:
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

        wparam = u32defs.WM_KEYDOWN if (hook_index % 2 == 0) else u32defs.WM_SYSKEYDOWN

        kbd = u32defs.KBDLLHOOKSTRUCT(emu.get_ptr_size())
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
        """
        Find string uID in its RT_STRING block in the mapped image, which a packer may have written.
        Return the address of its characters and the string, or None.
        """
        pe_metadata = pe.get_pe_metadata()
        if not pe_metadata:
            return None
        block = uID // 16 + 1
        entry = next((r for r in pe_metadata.resources if r.type_id == RT_STRING and r.id == block), None)
        if not entry:
            return None
        address = pe.base + entry.data_rva
        data = self.mem_read(address, entry.size)
        offset = 0
        for _ in range(uID % 16):
            if offset + 2 > len(data):
                return None
            offset += 2 + int.from_bytes(data[offset : offset + 2], "little") * 2
        if offset + 2 > len(data):
            return None
        length = int.from_bytes(data[offset : offset + 2], "little")
        string = data[offset + 2 : offset + 2 + length * 2].decode("utf-16le", errors="replace")
        return address + offset + 2, string

    @apihook("GetDesktopWindow", argc=0)
    def GetDesktopWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetDesktopWindow();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("ShowWindow", argc=2)
    def ShowWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL ShowWindow(
            HWND hWnd,
            int nCmdShow
        );
        """
        rv = 1

        return rv

    @apihook("CreateWindowStation", argc=4)
    def CreateWindowStation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWINSTA CreateWindowStation(
            LPCTSTR lpwinsta,
            DWORD dwFlags,
            ACCESS_MASK dwDesiredAccess,
            LPSECURITY_ATTRIBUTES lpsa
        );
        """
        lpwinsta, dwFlags, dwDesiredAccess, lpsa = argv

        return emu.handle_allocator.allocate_handle()

    @apihook("SetProcessWindowStation", argc=1)
    def SetProcessWindowStation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetProcessWindowStation(
            HWINSTA hWinSta
        );
        """
        (hWinSta,) = argv

        rv = False
        if hWinSta:
            rv = True

        return rv

    @apihook("GetDC", argc=1)
    def GetDC(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HDC GetDC(
            HWND hWnd
        );
        """
        rv = self.sessman.get_device_context()

        return rv

    @apihook("GetWindowDC", argc=1)
    def GetWindowDC(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HDC GetWindowDC(
            HWND hWnd
        );
        """
        return self.sessman.get_device_context()

    @apihook("RegisterClassEx", argc=1)
    def RegisterClassEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        ATOM RegisterClassEx(
            const WNDCLASSEX *lpwcx
        );
        """
        (lpwcx,) = argv
        return self.register_window_class(u32defs.WNDCLASSEX(emu.get_ptr_size()), lpwcx, ctx)

    @apihook("RegisterClass", argc=1)
    def RegisterClass(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        ATOM RegisterClass(
            const WNDCLASS *lpWndClass
        );
        """
        (lpWndClass,) = argv
        return self.register_window_class(u32defs.WNDCLASS(emu.get_ptr_size()), lpWndClass, ctx)

    def register_window_class(self, wclass, address, ctx):
        wclass = self.mem_cast(wclass, address)

        cn = None
        cw = self.get_char_width(ctx)
        if wclass.lpszClassName > 0xFFFF:
            cn = self.read_mem_string(wclass.lpszClassName, cw)

        return self.sessman.create_window_class(wclass, cn)

    @apihook("UnregisterClass", argc=2)
    def UnregisterClass(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL UnregisterClass(
            LPCTSTR lpClassName,
            HINSTANCE hInstance
        );
        """
        return 1

    @apihook("SetCursorPos", argc=2)
    def SetCursorPos(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetCursorPos(
            int X,
            int Y
        );
        """
        return 1

    @apihook("CloseDesktop", argc=1)
    def CloseDesktop(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CloseDesktop(
            HDESK hDesktop
        );
        """
        return 1

    @apihook("CloseWindowStation", argc=1)
    def CloseWindowStation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CloseWindowStation(
            HWINSTA hWinSta
        );
        """
        return 1

    @apihook("GetThreadDesktop", argc=1)
    def GetThreadDesktop(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HDESK GetThreadDesktop(
            DWORD dwThreadId
        );
        """
        return 1

    @apihook("OpenWindowStation", argc=3)
    def OpenWindowStation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWINSTA OpenWindowStation(
            LPCTSTR lpszWinSta,
            BOOL fInherit,
            ACCESS_MASK dwDesiredAccess
        );
        """
        return 1

    @apihook("ChangeWindowMessageFilter", argc=2)
    def ChangeWindowMessageFilter(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL ChangeWindowMessageFilter(
            UINT message,
            DWORD dwFlag
        );
        """
        message, dwFlag = argv
        emu.enable_deferred_work_hook()
        return True

    @apihook("UpdateWindow", argc=1)
    def UpdateWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL UpdateWindow(
            HWND hWnd
        );
        """
        (hWnd,) = argv
        window = self.sessman.get_window(hWnd)
        if not window:
            emu.set_last_error(windefs.ERROR_INVALID_WINDOW_HANDLE)
            return False

        wc = self.sessman.get_window_class(window.class_name)
        if wc and wc.wclass.lpfnWndProc:
            cb_args = (hWnd, u32defs.WM_PAINT, 0, 0)
            self.setup_callback(wc.wclass.lpfnWndProc, cb_args)

        return True

    @apihook("PostQuitMessage", argc=1)
    def PostQuitMessage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID PostQuitMessage(
            int nExitCode
        );

        Speakeasy does not post WM_QUIT. A message loop ends when no message or timer is pending, or at a run limit.
        """
        return

    @apihook("DestroyWindow", argc=1)
    def DestroyWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL DestroyWindow(
            HWND hWnd
        );

        Speakeasy does not model the lifetime of windows, so the window and its timers stay.
        """
        return True

    @apihook("DefWindowProc", argc=4)
    def DefWindowProc(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LRESULT LRESULT DefWindowProc(
            HWND hWnd,
            UINT Msg,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        hWnd, Msg, wParam, lParam = argv
        return int(Msg == u32defs.WM_NCCREATE)

    @apihook("CallWindowProc", argc=5)
    def CallWindowProc(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LRESULT CallWindowProc(
            WNDPROC lpPrevWndFunc,
            HWND hWnd,
            UINT Msg,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        lpPrevWndFunc, hWnd, Msg, wParam, lParam = argv
        if not lpPrevWndFunc:
            return 0
        return (yield GuestCall(lpPrevWndFunc, (hWnd, Msg, wParam, lParam)))

    @apihook("CreateWindowEx", argc=12)
    def CreateWindowEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND CreateWindowEx(
            DWORD dwExStyle,
            LPCTSTR lpClassName,
            LPCTSTR lpWindowName,
            DWORD dwStyle,
            int X,
            int Y,
            int nWidth,
            int nHeight,
            HWND hWndParent,
            HMENU hMenu,
            HINSTANCE hInstance,
            LPVOID lpParam
        );
        """
        cw = self.get_char_width(ctx)
        dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam = (
            argv
        )
        cn: int | str | None = lpClassName
        if lpClassName > 0xFFFF:
            cn = self.read_mem_string(lpClassName, cw)
            ctx.args["lpClassName"].display = cn
        elif not lpClassName:
            cn = None
        wn = None
        if lpWindowName:
            wn = self.read_mem_string(lpWindowName, cw)
            ctx.args["lpWindowName"].display = wn
        thread = emu.get_current_thread()
        proc = emu.get_current_process()
        hnd = self.sessman.create_window(
            wn, cn, dwStyle, hWndParent, thread.id if thread else 0, proc.pid if proc else 0
        )
        wc = self.sessman.get_window_class(cn) if cn else None
        if not wc or not wc.wclass.lpfnWndProc:
            return hnd
        cs = u32defs.CREATESTRUCT(emu.get_ptr_size())
        cs.lpCreateParams, cs.hInstance, cs.hMenu, cs.hwndParent = lpParam, hInstance, hMenu, hWndParent
        cs.cy, cs.cx, cs.y, cs.x = nHeight, nWidth, Y, X
        cs.style, cs.lpszName, cs.lpszClass, cs.dwExStyle = dwStyle, lpWindowName, lpClassName, dwExStyle
        return self.send_create_messages(emu, hnd, wc.wclass.lpfnWndProc, cs)

    def send_create_messages(self, emu, hnd, wndproc, cs):
        """Send WM_NCCREATE and WM_CREATE as CreateWindowEx does; either can refuse the window."""
        lparam = guest_callbacks.alloca(emu, cs.get_bytes())
        if not (yield GuestCall(wndproc, (hnd, u32defs.WM_NCCREATE, 0, lparam))):
            return 0
        if (yield GuestCall(wndproc, (hnd, u32defs.WM_CREATE, 0, lparam))) == (1 << emu.get_ptr_size() * 8) - 1:
            return 0
        return hnd

    @apihook("SetLayeredWindowAttributes", argc=4)
    def SetLayeredWindowAttributes(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetLayeredWindowAttributes(
            HWND hwnd,
            COLORREF crKey,
            BYTE bAlpha,
            DWORD dwFlags
        );
        """
        hwnd, crKey, bAlpha, dwFlags = argv
        return 1

    @apihook("MessageBox", argc=4)
    def MessageBox(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int MessageBox(
            HWND hWnd,
            LPCTSTR lpText,
            LPCTSTR lpCaption,
            UINT uType
        );
        """
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
    def MessageBoxEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int MessageBoxEx(
            HWND hWnd,
            LPCTSTR lpText,
            LPCTSTR lpCaption,
            UINT uType,
            WORD wLanguageId
        );
        """
        av = argv[:-1]
        rv = self.MessageBox(emu, av, ctx)
        return rv

    @apihook("LoadString", argc=4)
    def LoadString(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int LoadString(
            HINSTANCE hInstance,
            UINT uID,
            LPTSTR lpBuffer,
            int cchBufferMax
        );

        When cchBufferMax is 0, LoadStringW writes a pointer to the string resource,
        which has no terminator, into lpBuffer.
        """
        hInstance, uID, lpBuffer, cchBufferMax = argv
        cw = self.get_char_width(ctx)

        if hInstance == 0:
            pe = emu.modules[0] if emu.modules else None
        else:
            pe = emu.get_mod_from_addr(hInstance)
            if pe and hInstance != pe.base:
                return 0

        if not pe:
            return 0

        found = self.find_string_resource_by_id(pe, uID)
        if not found or not found[1]:
            return 0
        address, s = found

        if cchBufferMax == 0:
            if cw != 2:
                return 0
            self.write_ptr(lpBuffer, address)
            ctx.args["lpBuffer"].display = s
            return len(s)

        s = s[: cchBufferMax - 1]
        self.write_mem_string(s, lpBuffer, cw)
        ctx.args["lpBuffer"].display = s

        return len(s)

    @apihook("GetCursorPos", argc=1)
    def GetCursorPos(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
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
    def WindowFromPoint(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND WindowFromPoint(
            POINT Point
        );

        Point is passed by value: two stack slots on x86, one register on x64.
        argc=2 covers the x86 layout.
        """
        return self.sessman.get_current_desktop().desktop_window.get_handle()

    @apihook("GetAsyncKeyState", argc=1)
    def GetAsyncKeyState(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SHORT GetAsyncKeyState(
            int vKey
        );
        """
        (vKey,) = argv
        return self.get_synthetic_async_key_state(vKey)

    @apihook("GetKeyboardType", argc=1)
    def GetKeyboardType(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetKeyboardType(
            int nTypeFlag
        );
        """
        (nTypeFlag,) = argv
        if nTypeFlag == 0:
            return 4
        if nTypeFlag == 1:
            return 0
        if nTypeFlag == 2:
            return 12
        return 0

    @apihook("GetSystemMetrics", argc=1)
    def GetSystemMetrics(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetSystemMetrics(
            int nIndex
        );
        """
        (nIndex,) = argv
        return SYSTEM_METRICS.get(nIndex, 0)

    @apihook("LoadBitmap", argc=2)
    def LoadBitmap(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HBITMAP LoadBitmap(
            HINSTANCE hInstance,
            LPCTSTR lpBitmapName
        );
        """
        hInstance, lpBitmapName = argv
        self.read_res_identifier(emu, ctx, "lpBitmapName", self.get_char_width(ctx), lpBitmapName)
        rv = emu.handle_allocator.allocate_handle()
        return rv

    @apihook("GetClientRect", argc=2)
    def GetClientRect(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetClientRect(
            HWND hWnd,
            LPRECT lpRect
        );
        """
        return 0

    @apihook("RegisterWindowMessage", argc=1)
    def RegisterWindowMessage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT RegisterWindowMessage(
            LPCTSTR lpString
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
    def wsprintf(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int wsprintf(
            LPTSTR unnamedParam1,
            LPCTSTR unnamedParam2,
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
    def PeekMessage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PeekMessage(
            LPMSG lpMsg,
            HWND hWnd,
            UINT wMsgFilterMin,
            UINT wMsgFilterMax,
            UINT wRemoveMsg
        );
        """
        return False

    @apihook("PostMessage", argc=4)
    def PostMessage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PostMessage(
            HWND hWnd,
            UINT Msg,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        return True

    @apihook("SendMessage", argc=4)
    def SendMessage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LRESULT SendMessage(
            HWND hWnd,
            UINT Msg,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        hWnd, Msg, wParam, lParam = argv
        window = self.sessman.windows.get(hWnd)
        if window and isinstance(window.class_name, str) and window.class_name.lower() == "syslistview32":
            if Msg in LIST_VIEW_COLUMN_MESSAGES:
                return self.send_list_view_column_message(emu, window, Msg, wParam, lParam)
        if hWnd in self.wndprocs:
            emu.set_pc(self.wndprocs[hWnd])

        return False

    def send_list_view_column_message(self, emu, window, msg, wparam, lparam):
        """Keep the columns of a list-view control as comctl32 does for the LVM_*COLUMN* messages."""
        columns = window.lv_columns
        index = ctypes.c_int32(wparam).value
        if msg in (u32defs.LVM_INSERTCOLUMNA, u32defs.LVM_INSERTCOLUMNW):
            if not lparam or index < 0:
                return -1
            col = self.mem_cast(u32defs.LVCOLUMN(emu.get_ptr_size()), lparam)
            index = min(index, len(columns))
            text = ""
            if col.mask & u32defs.LVCF_TEXT and col.pszText:
                text = self.read_mem_string(col.pszText, 1 if msg == u32defs.LVM_INSERTCOLUMNA else 2)
            columns.insert(
                index,
                sessman.ListViewColumn(
                    fmt=col.fmt if col.mask & u32defs.LVCF_FMT else 0,
                    cx=col.cx if col.mask & u32defs.LVCF_WIDTH else 0,
                    text=text,
                    sub_item=col.iSubItem if col.mask & u32defs.LVCF_SUBITEM else index,
                ),
            )
            return index
        if not 0 <= index < len(columns):
            return 0
        column = columns[index]
        if msg in (u32defs.LVM_GETCOLUMNA, u32defs.LVM_GETCOLUMNW):
            if not lparam:
                return False
            col = self.mem_cast(u32defs.LVCOLUMN(emu.get_ptr_size()), lparam)
            if col.mask & u32defs.LVCF_FMT:
                col.fmt = column.fmt
            if col.mask & u32defs.LVCF_WIDTH:
                col.cx = column.cx
            if col.mask & u32defs.LVCF_SUBITEM:
                col.iSubItem = column.sub_item
            self.mem_write(lparam, col.get_bytes())
            if col.mask & u32defs.LVCF_TEXT and col.pszText and col.cchTextMax > 0:
                cw = 1 if msg == u32defs.LVM_GETCOLUMNA else 2
                self.write_mem_string(column.text[: col.cchTextMax - 1], col.pszText, cw)
            return True
        if msg == u32defs.LVM_GETCOLUMNWIDTH:
            return column.cx
        if msg == u32defs.LVM_SETCOLUMNWIDTH:
            column.cx = ctypes.c_int16(lparam).value
            return True
        del columns[index]
        return True

    @apihook("CallNextHookEx", argc=4)
    def CallNextHookEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LRESULT CallNextHookEx(
            HHOOK hhk,
            int nCode,
            WPARAM wParam,
            LPARAM lParam
        );
        """
        hhk, nCode, wParam, lParam = argv
        return 0

    @apihook("SetWindowsHookEx", argc=4)
    def SetWindowsHookEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HHOOK SetWindowsHookEx(
            int idHook,
            HOOKPROC lpfn,
            HINSTANCE hmod,
            DWORD dwThreadId
        );
        """
        idHook, lpfn, hmod, dwThreadId = argv

        ctx.args["idHook"].display = decode(WINDOWS_HOOK_ID, idHook)

        hnd = emu.handle_allocator.allocate_handle()
        self.window_hooks.update({hnd: (idHook, lpfn, hmod)})
        return hnd

    @apihook("UnhookWindowsHookEx", argc=1)
    def UnhookWindowsHookEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
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
    def MsgWaitForMultipleObjects(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD MsgWaitForMultipleObjects(
            DWORD nCount,
            const HANDLE *pHandles,
            BOOL fWaitAll,
            DWORD dwMilliseconds,
            DWORD dwWakeMask
        );
        """
        return 0

    @apihook("GetMessage", argc=4)
    def GetMessage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetMessage(
            LPMSG lpMsg,
            HWND hWnd,
            UINT wMsgFilterMin,
            UINT wMsgFilterMax
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
                msg = u32defs.MSG(emu.get_ptr_size())
                msg.hwnd = hwnd
                msg.message = u32defs.WM_TIMER
                msg.wParam = tid
                msg.lParam = proc
            else:
                synthetic = self.emit_synthetic_keyboard_hook_event(emu)
                if synthetic is None:
                    return False
                if lpMsg:
                    wparam, vkey = synthetic
                    msg = u32defs.MSG(emu.get_ptr_size())
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
    def TranslateMessage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL TranslateMessage(
            const MSG *lpMsg
        );
        """
        return True

    @apihook("DispatchMessage", argc=1)
    def DispatchMessage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LRESULT DispatchMessage(
            const MSG *lpMsg
        );
        """
        (lpMsg,) = argv

        msg = u32defs.MSG(emu.get_ptr_size())
        msg = self.mem_cast(msg, lpMsg)

        if msg.message == u32defs.WM_TIMER and msg.lParam:
            self.setup_callback(msg.lParam, (msg.hwnd, msg.message, msg.wParam, msg.time))
            return 0
        wndproc = self.wndprocs.get(msg.hwnd)
        window = self.sessman.windows.get(msg.hwnd)
        if not wndproc and window:
            wc = self.sessman.get_window_class(window.class_name)
            wndproc = wc.wclass.lpfnWndProc if wc else 0
        if wndproc:
            self.setup_callback(wndproc, (msg.hwnd, msg.message, msg.wParam, msg.lParam))
        return 0

    @apihook("GetForegroundWindow", argc=0)
    def GetForegroundWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetForegroundWindow();
        """
        if not self.foreground_window:
            explorer = next((p for p in emu.get_processes() if p.name.lower() == "explorer"), None)
            self.foreground_window = self.sessman.create_window(
                window_name="Program Manager",
                class_name="Progman",
                thread_id=emu.handle_allocator.allocate_kernel_object_id(),
                process_id=explorer.pid if explorer else 0,
            )
        return self.foreground_window

    @apihook("LoadCursor", argc=2)
    def LoadCursor(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HCURSOR LoadCursor(
            HINSTANCE hInstance,
            LPCTSTR lpCursorName
        );
        """
        hInstance, lpCursorName = argv
        self.read_res_identifier(emu, ctx, "lpCursorName", self.get_char_width(ctx), lpCursorName)
        return emu.handle_allocator.allocate_handle()

    @apihook("FindWindow", argc=2)
    def FindWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND FindWindow(
            LPCTSTR lpClassName,
            LPCTSTR lpWindowName
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

    @apihook("FindWindowEx", argc=4)
    def FindWindowEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND FindWindowEx(
            HWND hWndParent,
            HWND hWndChildAfter,
            LPCTSTR lpszClass,
            LPCTSTR lpszWindow
        );
        """
        hWndParent, hWndChildAfter, lpszClass, lpszWindow = argv
        cw = self.get_char_width(ctx)
        if lpszClass > 0xFFFF:
            ctx.args["lpszClass"].display = self.read_mem_string(lpszClass, cw)
        if lpszWindow:
            ctx.args["lpszWindow"].display = self.read_mem_string(lpszWindow, cw)
        return 0

    @apihook("GetWindowText", argc=3)
    def GetWindowText(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetWindowText(
            HWND hWnd,
            LPTSTR lpString,
            int nMaxCount
        );
        """
        hWnd, lpString, nMaxCount = argv

        cw = self.get_char_width(ctx)
        win_text = "speakeasy window"
        if not lpString or not 0 < nMaxCount <= 0x7FFFFFFF:
            return 0
        win_text = win_text[: nMaxCount - 1]
        self.write_mem_string(win_text, lpString, cw)

        return len(win_text)

    @apihook("PaintDesktop", argc=1)
    def PaintDesktop(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PaintDesktop(
            HDC hdc
        );
        """
        return 0

    @apihook("wvsprintf", argc=3)
    def wvsprintf(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int wvsprintf(
            LPTSTR lpOutput,
            LPCTSTR lpFmt,
            va_list arglist
        );
        """
        lpOutput, lpFmt, arglist = argv
        cw = self.get_char_width(ctx)
        fmt_str = self.read_mem_string(lpFmt, cw)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args(arglist, fmt_cnt)
        fin = self.do_str_format(fmt_str, vargs, wide=cw == 2)
        self.write_mem_string(fin, lpOutput, cw)
        ctx.args.clear()
        ctx.args.append(fin)
        ctx.args.append(fmt_str)
        return len(fin)

    @apihook("ReleaseDC", argc=2)
    def ReleaseDC(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int ReleaseDC(
            HWND hWnd,
            HDC hDC
        );
        """
        hWnd, hDC = argv
        return int(hDC == self.sessman.get_device_context())

    @apihook("CharNext", argc=1)
    def CharNext(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPTSTR CharNext(
            LPCTSTR lpsz
        );
        """
        (lpsz,) = argv
        rv = lpsz
        cw = self.get_char_width(ctx)
        if lpsz and int.from_bytes(self.mem_read(lpsz, cw), "little"):
            rv = lpsz + cw
        return rv

    @apihook("CharPrev", argc=2)
    def CharPrev(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPTSTR CharPrev(
            LPCTSTR lpszStart,
            LPCTSTR lpszCurrent
        );
        """
        """
        Got this from wine.          
        https://github.com/wine-mirror/wine/blob/a8c1d5c108fc57e4d78e9db126f395c89083a83d/dlls/kernelbase/string.c
        """
        lpszStart, lpszCurrent = argv
        cw = self.get_char_width(ctx)
        while lpszStart < lpszCurrent:
            n = lpszStart + cw
            if n >= lpszCurrent:
                break
            lpszStart = n

        return lpszStart

    @apihook("EnumWindows", argc=2)
    def EnumWindows(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnumWindows(
            WNDENUMPROC lpEnumFunc,
            LPARAM lParam
        );
        """
        lpEnumFunc, lParam = argv
        desktop = self.sessman.get_current_desktop().desktop_window.get_handle()
        hwnds = [hnd for hnd, w in self.sessman.windows.items() if isinstance(hnd, int) and w.parent in (0, desktop)]
        for hnd in hwnds:
            if not (yield GuestCall(lpEnumFunc, (hnd, lParam))) & 0xFFFFFFFF:
                return 0
        return 1

    @apihook("GetSysColor", argc=1)
    def GetSysColor(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetSysColor(
            int nIndex
        );
        """
        (nIndex,) = argv
        return SYS_COLORS.get(nIndex, 0)

    @apihook("GetParent", argc=1)
    def GetParent(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetParent(
            HWND hWnd
        );
        """
        (hWnd,) = argv
        window = self.sessman.get_window(hWnd)
        if not window:
            if hWnd != self.sessman.get_current_desktop().desktop_window.get_handle():
                emu.set_last_error(windefs.ERROR_INVALID_WINDOW_HANDLE)
            return 0
        if window.style & (WS_POPUP | WS_CHILD):
            return window.parent
        return 0

    def get_prop_key(self, lpString: int, ctx: api.ApiContext) -> int | str:
        if lpString <= 0xFFFF:
            return lpString
        name = self.read_mem_string(lpString, self.get_char_width(ctx))
        ctx.args["lpString"].display = name
        return name.upper()

    def get_prop_window(self, emu, hnd):
        window = self.sessman.get_window(hnd)
        if not window:
            emu.set_last_error(windefs.ERROR_INVALID_WINDOW_HANDLE)
        return window

    @apihook("SetProp", argc=3)
    def SetProp(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetProp(
            HWND hWnd,
            LPCTSTR lpString,
            HANDLE hData
        );
        """
        hWnd, lpString, hData = argv
        key = self.get_prop_key(lpString, ctx)
        window = self.get_prop_window(emu, hWnd)
        if not window:
            return False
        window.props[key] = hData
        return True

    @apihook("GetProp", argc=2)
    def GetProp(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE GetProp(
            HWND hWnd,
            LPCTSTR lpString
        );
        """
        hWnd, lpString = argv
        key = self.get_prop_key(lpString, ctx)
        window = self.get_prop_window(emu, hWnd)
        if not window:
            return 0
        return window.props.get(key, 0)

    @apihook("RemoveProp", argc=2)
    def RemoveProp(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE RemoveProp(
            HWND hWnd,
            LPCTSTR lpString
        );
        """
        hWnd, lpString = argv
        key = self.get_prop_key(lpString, ctx)
        window = self.get_prop_window(emu, hWnd)
        if not window:
            return 0
        return window.props.pop(key, 0)

    @apihook("GetWindowThreadProcessId", argc=2)
    def GetWindowThreadProcessId(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetWindowThreadProcessId(
            HWND hWnd,
            LPDWORD lpdwProcessId
        );
        """
        hWnd, lpdwProcessId = argv
        desktop_window = self.sessman.get_current_desktop().desktop_window
        if hWnd == desktop_window.get_handle():
            window = desktop_window
            if not window.thread_id:
                csrss = next((p for p in emu.get_processes() if p.name.lower() == "csrss"), None)
                window.process_id = csrss.pid if csrss else 0
                window.thread_id = emu.handle_allocator.allocate_kernel_object_id()
        else:
            window = self.sessman.get_window(hWnd)
            if not window:
                emu.set_last_error(windefs.ERROR_INVALID_WINDOW_HANDLE)
                return 0
            if window.process_id and not window.thread_id:
                # The console window reports the first thread of the process that owns the console
                owner = next((p for p in emu.get_processes() if p.pid == window.process_id), None)
                if owner and owner.threads:
                    window.thread_id = owner.threads[0].tid
        if lpdwProcessId:
            self.write_dword(lpdwProcessId, window.process_id)
        return window.thread_id

    @apihook("GetSysColorBrush", argc=1)
    def GetSysColorBrush(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
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
        if not self.sessman.get_window(hWnd):
            emu.set_last_error(windefs.ERROR_INVALID_WINDOW_HANDLE)
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
    def GetWindowLong(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG GetWindowLong(
            HWND hWnd,
            int nIndex
        );
        """
        hWnd, nIndex = argv
        longs = self.get_window_longs(emu, hWnd)
        if longs is None:
            return 0
        return self.get_window_long(hWnd, ctypes.c_int32(nIndex).value, longs)

    @apihook("GetWindowLongPtr", argc=2)
    def GetWindowLongPtr(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG_PTR GetWindowLongPtr(
            HWND hWnd,
            int nIndex
        );
        """
        return self.GetWindowLong(emu, argv, ctx)

    @apihook("SetWindowLong", argc=3)
    def SetWindowLong(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG SetWindowLong(
            HWND hWnd,
            int nIndex,
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
    def SetWindowLongPtr(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG_PTR SetWindowLongPtr(
            HWND hWnd,
            int nIndex,
            LONG_PTR dwNewLong
        );
        """
        return self.SetWindowLong(emu, argv, ctx)

    @apihook("DialogBoxParam", argc=5)
    def DialogBoxParam(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        INT_PTR DialogBoxParam(
            HINSTANCE hInstance,
            LPCTSTR lpTemplateName,
            HWND hWndParent,
            DLGPROC lpDialogFunc,
            LPARAM dwInitParam
        );
        """
        hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam = argv
        self.read_res_identifier(emu, ctx, "lpTemplateName", self.get_char_width(ctx), lpTemplateName)
        if not lpDialogFunc:
            return IDCANCEL
        return self.run_dialog(self.new_window_handle(), lpDialogFunc, dwInitParam)

    def run_dialog(self, hdlg, func, param):
        # No user input arrives, so the dialog ends when the procedure calls EndDialog
        # during WM_INITDIALOG, or else as if the user closed it
        yield GuestCall(func, (hdlg, u32defs.WM_INITDIALOG, 0, param))
        return self.dialog_results.pop(hdlg, IDCANCEL)

    @apihook("EndDialog", argc=2)
    def EndDialog(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EndDialog(
            HWND hDlg,
            INT_PTR nResult
        );
        """
        hDlg, nResult = argv
        self.dialog_results[hDlg] = nResult
        return 1

    @apihook("CreateDialogIndirectParam", argc=5)
    def CreateDialogIndirectParam(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND CreateDialogIndirectParam(
            HINSTANCE hInstance,
            LPCDLGTEMPLATE lpTemplate,
            HWND hWndParent,
            DLGPROC lpDialogFunc,
            LPARAM dwInitParam
        );
        """
        (
            hInstance,
            lpTemplate,
            hWndParent,
            lpDialogFunc,
            dwInitParam,
        ) = argv

        hdlg = self.new_window_handle()
        cb_args = (hdlg, u32defs.WM_INITDIALOG, 0, dwInitParam)
        self.setup_callback(lpDialogFunc, cb_args)
        return hdlg

    @apihook("GetMenuInfo", argc=2)
    def GetMenuInfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetMenuInfo(
            HMENU hmenu,
            LPMENUINFO lpcmi
        );
        """
        return 1

    @apihook("GetProcessWindowStation", argc=0)
    def GetProcessWindowStation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWINSTA GetProcessWindowStation();
        """
        sta = self.sessman.get_current_station()
        return sta.get_handle()

    @apihook("LoadAccelerators", argc=2)
    def LoadAccelerators(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HACCEL LoadAccelerators(
            HINSTANCE hInstance,
            LPCTSTR lpTableName
        );
        """
        hInstance, lpTableName = argv
        self.read_res_identifier(emu, ctx, "lpTableName", self.get_char_width(ctx), lpTableName)
        return emu.handle_allocator.allocate_handle()

    @apihook("IsWindowVisible", argc=1)
    def IsWindowVisible(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsWindowVisible(
            HWND hWnd
        );
        """
        return True

    @apihook("BeginPaint", argc=2)
    def BeginPaint(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HDC BeginPaint(
            HWND hWnd,
            LPPAINTSTRUCT lpPaint
        );
        """
        return emu.handle_allocator.allocate_handle()

    @apihook("LookupIconIdFromDirectory", argc=2)
    def LookupIconIdFromDirectory(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int LookupIconIdFromDirectory(
            PBYTE presbits,
            BOOL fIcon
        );
        """
        return 1

    @apihook("GetActiveWindow", argc=0)
    def GetActiveWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetActiveWindow();
        """
        return self.new_window_handle()

    @apihook("GetLastActivePopup", argc=1)
    def GetLastActivePopup(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetLastActivePopup(
            HWND hWnd
        );
        """
        (hWnd,) = argv
        return self.new_window_handle()

    @apihook("GetUserObjectInformation", argc=5)
    def GetUserObjectInformation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetUserObjectInformation(
            HANDLE hObj,
            int nIndex,
            PVOID pvInfo,
            DWORD nLength,
            LPDWORD lpnLengthNeeded
        );
        """
        hObj, nIndex, pvInfo, nLength, lpnLengthNeeded = argv

        if nIndex == UOI_FLAGS:
            uoi = u32defs.USEROBJECTFLAGS(emu.get_ptr_size())
            uoi.fInherit = 1
            uoi.dwFlags = 1

            if pvInfo:
                self.mem_write(pvInfo, uoi.get_bytes())

        return True

    @apihook("LoadIcon", argc=2)
    def LoadIcon(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HICON LoadIcon(
            HINSTANCE hInstance,
            LPCTSTR lpIconName
        );
        """
        (
            hInstance,
            lpIconName,
        ) = argv
        self.read_res_identifier(emu, ctx, "lpIconName", self.get_char_width(ctx), lpIconName)

        if lpIconName not in (
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
    def GetRawInputDeviceList(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetRawInputDeviceList(
            PRAWINPUTDEVICELIST pRawInputDeviceList,
            PUINT puiNumDevices,
            UINT cbSize
        );
        """
        pRawInputDeviceList, puiNumDevices, cbSize = argv
        types = (u32defs.RIM_TYPEKEYBOARD, u32defs.RIM_TYPEMOUSE, u32defs.RIM_TYPEHID, u32defs.RIM_TYPEHID)
        num_devices = len(types)
        if not pRawInputDeviceList:
            self.write_dword(puiNumDevices, num_devices)
            return 0

        if self.read_dword(puiNumDevices) < num_devices:
            self.write_dword(puiNumDevices, num_devices)
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
            return 0xFFFFFFFF

        ptr_size = self.get_ptr_size()
        for i, dev_type in enumerate(types):
            hnd = emu.handle_allocator.allocate_handle()
            entry = hnd.to_bytes(ptr_size, "little") + dev_type.to_bytes(ptr_size, "little")
            self.mem_write(pRawInputDeviceList + i * 2 * ptr_size, entry)
        return num_devices

    @apihook("GetNextDlgTabItem", argc=3)
    def GetNextDlgTabItem(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetNextDlgTabItem(
            HWND hDlg,
            HWND hCtl,
            BOOL bPrevious
        );
        """
        return 0

    @apihook("GetCaretPos", argc=1)
    def GetCaretPos(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetCaretPos(
            LPPOINT lpPoint
        );
        """
        (lpPoint,) = argv
        point = windef.POINT(emu.get_ptr_size())
        point.x = 0
        point.y = 0
        self.mem_write(lpPoint, self.get_bytes(point))
        return 1

    @apihook("GetMonitorInfo", argc=2)
    def GetMonitorInfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetMonitorInfo(
            HMONITOR hMonitor,
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
    def EndPaint(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EndPaint(
            HWND hWnd,
            const PAINTSTRUCT *lpPaint
        );
        """
        return 1

    @apihook("GetDlgCtrlID", argc=1)
    def GetDlgCtrlID(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetDlgCtrlID(
            HWND hWnd
        );
        """
        return 1

    @apihook("GetUpdateRect", argc=3)
    def GetUpdateRect(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetUpdateRect(
            HWND hWnd,
            LPRECT lpRect,
            BOOL bErase
        );
        """
        return 0

    @apihook("GetAltTabInfo", argc=5)
    def GetAltTabInfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetAltTabInfo(
            HWND hwnd,
            int iItem,
            PALTTABINFO pati,
            LPTSTR pszItemText,
            UINT cchItemText
        );
        """
        return 0

    @apihook("GetUpdateRgn", argc=3)
    def GetUpdateRgn(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetUpdateRgn(
            HWND hWnd,
            HRGN hRgn,
            BOOL bErase
        );
        """
        return 0

    @apihook("FlashWindow", argc=2)
    def FlashWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL FlashWindow(
            HWND hWnd,
            BOOL bInvert
        );
        """
        return 1

    @apihook("IsClipboardFormatAvailable", argc=1)
    def IsClipboardFormatAvailable(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsClipboardFormatAvailable(
            UINT format
        );
        """
        return 0

    @apihook("GetClipboardData", argc=1)
    def GetClipboardData(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE GetClipboardData(
            UINT uFormat
        );
        """
        return 0

    @apihook("IsWindow", argc=1)
    def IsWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsWindow(
            HWND hWnd
        );
        """
        (hWnd,) = argv

        return True

    @apihook("EnableWindow", argc=2)
    def EnableWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnableWindow(
            HWND hWnd,
            BOOL bEnable
        );
        """
        hWnd, bEnable = argv

        return False

    @apihook("CharLowerBuff", argc=2)
    def CharLowerBuff(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD CharLowerBuff(
            LPTSTR lpsz,
            DWORD cchLength
        );
        """
        lpsz, cchLength = argv
        cw = self.get_char_width(ctx)
        if not cchLength:
            return 0
        raw = self.mem_read(lpsz, cchLength * cw)
        ctx.args["lpsz"].display = self.decode_string(raw, cw).replace("\x00", "")
        self.mem_write(lpsz, map_char_case(raw, cw, upper=False))
        return cchLength

    @apihook("CharUpperBuff", argc=2)
    def CharUpperBuff(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD CharUpperBuff(
            LPTSTR lpsz,
            DWORD cchLength
        );
        """
        lpsz, cchLength = argv
        cw = self.get_char_width(ctx)
        if not cchLength:
            return 0
        raw = self.mem_read(lpsz, cchLength * cw)
        ctx.args["lpsz"].display = self.decode_string(raw, cw).replace("\x00", "")
        self.mem_write(lpsz, map_char_case(raw, cw, upper=True))
        return cchLength

    @apihook("CharLower", argc=1)
    def CharLower(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPTSTR CharLower(
            LPTSTR lpsz
        );
        """
        (lpsz,) = argv
        cw = self.get_char_width(ctx)
        bits = lpsz.bit_length()
        if bits <= 16:
            if cw == 1 and lpsz > 0xFF:
                return lpsz
            val = map_char_case(lpsz.to_bytes(cw, "little"), cw, upper=False)
            return int.from_bytes(val, byteorder="little")
        raw = self.mem_read(lpsz, self.mem_string_len(lpsz, cw) * cw)
        self.mem_write(lpsz, map_char_case(raw, cw, upper=False))
        return lpsz

    @apihook("CharUpper", argc=1)
    def CharUpper(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPTSTR CharUpper(
            LPTSTR lpsz
        );
        """
        (lpsz,) = argv
        cw = self.get_char_width(ctx)
        bits = lpsz.bit_length()
        if bits <= 16:
            if cw == 1 and lpsz > 0xFF:
                return lpsz
            val = map_char_case(lpsz.to_bytes(cw, "little"), cw, upper=True)
            return int.from_bytes(val, byteorder="little")
        raw = self.mem_read(lpsz, self.mem_string_len(lpsz, cw) * cw)
        self.mem_write(lpsz, map_char_case(raw, cw, upper=True))
        return lpsz

    @apihook("SetTimer", argc=4)
    def SetTimer(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT_PTR SetTimer(
            HWND hWnd,
            UINT_PTR nIDEvent,
            UINT uElapse,
            TIMERPROC lpTimerFunc
        );
        """
        hWnd, nIDEvent, uElapse, lpTimerFunc = argv
        if hWnd:
            self.timers = [t for t in self.timers if t[:2] != (hWnd, nIDEvent)]
            self.timers.append((hWnd, nIDEvent, lpTimerFunc))
            return nIDEvent
        tid = emu.handle_allocator.allocate_handle()
        self.timers.append((0, tid, lpTimerFunc))
        return tid

    @apihook("KillTimer", argc=2)
    def KillTimer(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL KillTimer(
            HWND hWnd,
            UINT_PTR uIDEvent
        );
        """
        hWnd, uIDEvent = argv
        self.timers = [t for t in self.timers if t[:2] != (hWnd, uIDEvent)]
        return True

    @apihook("OpenDesktop", argc=4)
    def OpenDesktop(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HDESK OpenDesktop(
            LPCTSTR lpszDesktop,
            DWORD dwFlags,
            BOOL fInherit,
            ACCESS_MASK dwDesiredAccess
        );
        """
        lpszDesktop, dwFlags, fInherit, dwDesiredAccess = argv
        cw = self.get_char_width(ctx)
        desktop = self.read_mem_string(lpszDesktop, cw)
        ctx.args["lpszDesktop"].display = desktop
        return emu.handle_allocator.allocate_handle()

    @apihook("SetThreadDesktop", argc=1)
    def SetThreadDesktop(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetThreadDesktop(
            HDESK hDesktop
        );
        """
        return 0

    @apihook("GetKeyboardLayoutList", argc=2)
    def GetKeyboardLayoutList(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
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
        self.write_ptr(lpList, hkl)

        return 1

    @apihook("GetKBCodePage", argc=0)
    def GetKBCodePage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetKBCodePage();
        """
        # >>> ctypes.windll.user32.GetKBCodePage()
        # 437
        # https://docs.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
        return 437  # OEM United States

    @apihook("GetClipboardViewer", argc=0)
    def GetClipboardViewer(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetClipboardViewer();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetClipboardOwner", argc=0)
    def GetClipboardOwner(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetClipboardOwner();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetMenuCheckMarkDimensions", argc=0)
    def GetMenuCheckMarkDimensions(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG GetMenuCheckMarkDimensions();
        """
        # >>> ctypes.windll.user32.GetMenuCheckMarkDimensions()
        # 983055
        return 983055

    @apihook("GetOpenClipboardWindow", argc=0)
    def GetOpenClipboardWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetOpenClipboardWindow();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetFocus", argc=0)
    def GetFocus(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetFocus();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetCursor", argc=0)
    def GetCursor(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HCURSOR GetCursor();
        """
        hnd = 0

        desk = self.sessman.get_current_desktop()
        window = desk.desktop_window
        hnd = window.get_handle()

        return hnd

    @apihook("GetClipboardSequenceNumber", argc=0)
    def GetClipboardSequenceNumber(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetClipboardSequenceNumber();
        """
        # >>> ctypes.windll.user32.GetClipboardSequenceNumber()
        # 295
        return 295

    @apihook("GetCaretBlinkTime", argc=0)
    def GetCaretBlinkTime(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetCaretBlinkTime();
        """
        # >>> ctypes.windll.user32.GetCaretBlinkTime()
        # 530
        return 530

    @apihook("GetDoubleClickTime", argc=0)
    def GetDoubleClickTime(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetDoubleClickTime();
        """
        # >>> ctypes.windll.user32.GetDoubleClickTime()
        # 500
        return 500

    @apihook("RegisterClipboardFormatA", argc=1)
    def RegisterClipboardFormatA(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT RegisterClipboardFormatA(
            LPCSTR lpszFormat
        );
        """
        # Return a fake clipboard format ID.
        # Clipboard format IDs start at 0xC000 for custom formats.
        return 0xC000

    @apihook("SystemParametersInfoA", argc=4)
    def SystemParametersInfoA(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SystemParametersInfoA(
            UINT uiAction,
            UINT uiParam,
            PVOID pvParam,
            UINT fWinIni
        );
        """
        uiAction, uiParam, pvParam, fWinIni = argv

        # Many callers expect pvParam to be filled with something.
        # We return success without writing anything unless needed.
        return 1

    @apihook("GetKeyboardLayout", argc=1)
    def GetKeyboardLayout(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HKL GetKeyboardLayout(
            DWORD idThread
        );
        """
        # Return a fake HKL (keyboard layout handle).
        # Real HKLs are typically like 0x04090409 (LANG + device id).
        return 0x04090409

    @apihook("EnumDisplayMonitors", argc=4)
    def EnumDisplayMonitors(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnumDisplayMonitors(
            HDC hdc,
            LPCRECT lprcClip,
            MONITORENUMPROC lpfnEnum,
            LPARAM dwData
        );
        """
        hdc, lprcClip, lpfnEnum, dwData = argv

        # Most callers expect TRUE to indicate success.
        # We do not invoke the callback — Speakeasy doesn't emulate monitor enumeration.
        return 1

    @apihook("EnumDisplayDevices", argc=4)
    def EnumDisplayDevices(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnumDisplayDevices(
            LPCTSTR lpDevice,
            DWORD iDevNum,
            PDISPLAY_DEVICE lpDisplayDevice,
            DWORD dwFlags
        );

        Older callers set cb to the size of the struct without DeviceID and DeviceKey, so the handler writes only
        cb bytes.
        """
        lpDevice, iDevNum, lpDisplayDevice, dwFlags = argv

        cw = self.get_char_width(ctx)
        parent = self.read_mem_string(lpDevice, cw).upper() if lpDevice else None
        if iDevNum or not lpDisplayDevice or parent not in DISPLAY_DEVICES:
            return 0

        dd = u32defs.DISPLAY_DEVICE(emu.get_ptr_size(), cw)
        cb = self.read_dword(lpDisplayDevice)
        if cb < dd.get_cstruct().DeviceID.offset:
            return 0

        name, text, flags, device_id, key = DISPLAY_DEVICES[parent]
        dd.cb = cb
        dd.DeviceName = self.encode_string(name, cw)
        dd.DeviceString = self.encode_string(text, cw)
        dd.StateFlags = flags
        dd.DeviceID = self.encode_string(device_id, cw)
        dd.DeviceKey = self.encode_string(key, cw)
        self.mem_write(lpDisplayDevice, dd.get_bytes()[:cb])
        return 1

    @apihook("OemToCharA", argc=2)
    def OemToCharA(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL OemToCharA(
            LPCSTR pSrc,
            LPSTR pDst
        );
        """
        pSrc, pDst = argv

        # If destination buffer exists, copy source bytes into it.
        if pSrc and pDst:
            data = emu.mem_read(pSrc, self.mem_string_len(pSrc, 1) + 1)
            emu.mem_write(pDst, data)

        # Return TRUE
        return 1

    @apihook("CharPrevW", argc=2)
    def CharPrevW(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPWSTR CharPrevW(
            LPCWSTR lpszStart,
            LPCWSTR lpszCurrent
        );
        """
        lpszStart, lpszCurrent = argv

        # If current > start, return current - 2 (one WCHAR back)
        try:
            if lpszCurrent and lpszStart and lpszCurrent > lpszStart:
                return lpszCurrent - 2
        except Exception:
            pass

        # Otherwise return start
        return lpszStart
