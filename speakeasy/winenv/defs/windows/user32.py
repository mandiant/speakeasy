# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from speakeasy.struct import EmuStruct, Ptr
import ctypes as ct

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
WM_TIMER = 0x0113

WM_PAINT = 0x0F

WM_INITDIALOG = 0x0110


class MSG(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.hwnd = Ptr
        self.message = ct.c_uint32
        self.wParam = Ptr
        self.lParam = Ptr
        self.time = ct.c_uint32
        self.pt_x = Ptr
        self.pt_y = Ptr
        self.lPrivate = ct.c_uint32


class USEROBJECTFLAGS(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.fInherit = ct.c_uint32
        self.fReserved = ct.c_uint32
        self.dwFlags = ct.c_uint32


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


def get_flag_defines(flags, prefix=''):
    defs = []
    for k, v in globals().items():
        if not isinstance(v, int):
            continue
        if v == flags:
            if prefix and k.startswith(prefix):
                defs.append(k)
    return defs


def get_windowhook_flags(flags):
    return get_flag_defines(flags, prefix='WH_')
