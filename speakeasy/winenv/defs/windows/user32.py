# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct

from speakeasy.struct import EmuStruct, Ptr

WH_CALLWNDPROC = 4
WH_CALLWNDPROCRET = 12
WH_CBT = 5
WH_DEBUG = 9
WH_FOREGROUNDIDLE = 11
WH_GETMESSAGE = 3
WH_JOURNALPLAYBACK = 1
WH_JOURNALRECORD = 0
WH_KEYBOARD = 2
WH_KEYBOARD_LL = 13
WH_MOUSE = 7
WH_MOUSE_LL = 14
WH_MSGFILTER = -1
WH_SHELL = 10
WH_SYSMSGFILTER = 6
WM_KEYDOWN = 0x0100
WM_SYSKEYDOWN = 0x0104
WM_TIMER = 0x0113

WM_CREATE = 0x01
WM_PAINT = 0x0F
WM_NCCREATE = 0x81

WM_INITDIALOG = 0x0110

LVM_GETCOLUMNA = 0x1019
LVM_INSERTCOLUMNA = 0x101B
LVM_DELETECOLUMN = 0x101C
LVM_GETCOLUMNWIDTH = 0x101D
LVM_SETCOLUMNWIDTH = 0x101E
LVM_GETCOLUMNW = 0x105F
LVM_INSERTCOLUMNW = 0x1061

LVCF_FMT = 0x1
LVCF_WIDTH = 0x2
LVCF_TEXT = 0x4
LVCF_SUBITEM = 0x8

RIM_TYPEMOUSE = 0
RIM_TYPEKEYBOARD = 1
RIM_TYPEHID = 2


class MSG(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.hwnd = Ptr
        self.message = ct.c_uint32
        self.wParam = Ptr
        self.lParam = Ptr
        self.time = ct.c_uint32
        self.pt_x = ct.c_int32
        self.pt_y = ct.c_int32


class CREATESTRUCT(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.lpCreateParams = Ptr
        self.hInstance = Ptr
        self.hMenu = Ptr
        self.hwndParent = Ptr
        self.cy = ct.c_int32
        self.cx = ct.c_int32
        self.y = ct.c_int32
        self.x = ct.c_int32
        self.style = ct.c_uint32
        self.lpszName = Ptr
        self.lpszClass = Ptr
        self.dwExStyle = ct.c_uint32


class LVCOLUMN(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.mask = ct.c_uint32
        self.fmt = ct.c_int32
        self.cx = ct.c_int32
        self.pszText = Ptr
        self.cchTextMax = ct.c_int32
        self.iSubItem = ct.c_int32


class KBDLLHOOKSTRUCT(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.vkCode = ct.c_uint32
        self.scanCode = ct.c_uint32
        self.flags = ct.c_uint32
        self.time = ct.c_uint32
        self.dwExtraInfo = Ptr


class USEROBJECTFLAGS(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.fInherit = ct.c_uint32
        self.fReserved = ct.c_uint32
        self.dwFlags = ct.c_uint32


class WNDCLASS(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.style = ct.c_uint32
        self.lpfnWndProc = Ptr
        self.cbClsExtra = ct.c_uint32
        self.cbWndExtra = ct.c_uint32
        self.hInstance = Ptr
        self.hIcon = Ptr
        self.hCursor = Ptr
        self.hbrBackground = Ptr
        self.lpszMenuName = Ptr
        self.lpszClassName = Ptr


class WNDCLASSEX(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.cbSize = ct.c_uint32
        self.style = ct.c_uint32
        self.lpfnWndProc = Ptr
        self.cbClsExtra = ct.c_uint32
        self.cbWndExtra = ct.c_uint32
        self.hInstance = Ptr
        self.hIcon = Ptr
        self.hCursor = Ptr
        self.hbrBackground = Ptr
        self.lpszMenuName = Ptr
        self.lpszClassName = Ptr
        self.hIconSm = Ptr


def get_flag_defines(flags, prefix=""):
    defs = []
    for k, v in globals().items():
        if not isinstance(v, int):
            continue
        if v == flags:
            if prefix and k.startswith(prefix):
                defs.append(k)
    return defs


def get_windowhook_flags(flags):
    return get_flag_defines(flags, prefix="WH_")
