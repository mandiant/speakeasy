# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from typing import Annotated

from speakeasy.struct import EmuStruct, Ptr

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

DISPLAY_DEVICE_ATTACHED_TO_DESKTOP = 0x1
DISPLAY_DEVICE_PRIMARY_DEVICE = 0x4
DISPLAY_DEVICE_ACTIVE = 0x1
DISPLAY_DEVICE_ATTACHED = 0x2


class DISPLAY_DEVICE(EmuStruct):
    cb: Annotated[int, ct.c_uint32]

    def __init__(self, ptr_size, width):
        super().__init__(ptr_size)
        self.DeviceName = ct.c_uint8 * (32 * width)
        self.DeviceString = ct.c_uint8 * (128 * width)
        self.StateFlags = ct.c_uint32
        self.DeviceID = ct.c_uint8 * (128 * width)
        self.DeviceKey = ct.c_uint8 * (128 * width)


class MSG(EmuStruct):
    hwnd: Annotated[int, Ptr]
    message: Annotated[int, ct.c_uint32]
    wParam: Annotated[int, Ptr]
    lParam: Annotated[int, Ptr]
    time: Annotated[int, ct.c_uint32]
    pt_x: Annotated[int, ct.c_int32]
    pt_y: Annotated[int, ct.c_int32]


class CREATESTRUCT(EmuStruct):
    lpCreateParams: Annotated[int, Ptr]
    hInstance: Annotated[int, Ptr]
    hMenu: Annotated[int, Ptr]
    hwndParent: Annotated[int, Ptr]
    cy: Annotated[int, ct.c_int32]
    cx: Annotated[int, ct.c_int32]
    y: Annotated[int, ct.c_int32]
    x: Annotated[int, ct.c_int32]
    style: Annotated[int, ct.c_uint32]
    lpszName: Annotated[int, Ptr]
    lpszClass: Annotated[int, Ptr]
    dwExStyle: Annotated[int, ct.c_uint32]


class LVCOLUMN(EmuStruct):
    mask: Annotated[int, ct.c_uint32]
    fmt: Annotated[int, ct.c_int32]
    cx: Annotated[int, ct.c_int32]
    pszText: Annotated[int, Ptr]
    cchTextMax: Annotated[int, ct.c_int32]
    iSubItem: Annotated[int, ct.c_int32]
    iImage: Annotated[int, ct.c_int32]
    iOrder: Annotated[int, ct.c_int32]
    cxMin: Annotated[int, ct.c_int32]
    cxDefault: Annotated[int, ct.c_int32]
    cxIdeal: Annotated[int, ct.c_int32]


class KBDLLHOOKSTRUCT(EmuStruct):
    vkCode: Annotated[int, ct.c_uint32]
    scanCode: Annotated[int, ct.c_uint32]
    flags: Annotated[int, ct.c_uint32]
    time: Annotated[int, ct.c_uint32]
    dwExtraInfo: Annotated[int, Ptr]


class USEROBJECTFLAGS(EmuStruct):
    fInherit: Annotated[int, ct.c_uint32]
    fReserved: Annotated[int, ct.c_uint32]
    dwFlags: Annotated[int, ct.c_uint32]


class WNDCLASS(EmuStruct):
    style: Annotated[int, ct.c_uint32]
    lpfnWndProc: Annotated[int, Ptr]
    cbClsExtra: Annotated[int, ct.c_uint32]
    cbWndExtra: Annotated[int, ct.c_uint32]
    hInstance: Annotated[int, Ptr]
    hIcon: Annotated[int, Ptr]
    hCursor: Annotated[int, Ptr]
    hbrBackground: Annotated[int, Ptr]
    lpszMenuName: Annotated[int, Ptr]
    lpszClassName: Annotated[int, Ptr]


class WNDCLASSEX(EmuStruct):
    cbSize: Annotated[int, ct.c_uint32]
    style: Annotated[int, ct.c_uint32]
    lpfnWndProc: Annotated[int, Ptr]
    cbClsExtra: Annotated[int, ct.c_uint32]
    cbWndExtra: Annotated[int, ct.c_uint32]
    hInstance: Annotated[int, Ptr]
    hIcon: Annotated[int, Ptr]
    hCursor: Annotated[int, Ptr]
    hbrBackground: Annotated[int, Ptr]
    lpszMenuName: Annotated[int, Ptr]
    lpszClassName: Annotated[int, Ptr]
    hIconSm: Annotated[int, Ptr]
