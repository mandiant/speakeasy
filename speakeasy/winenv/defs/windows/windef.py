# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from speakeasy.struct import EmuStruct
import ctypes as ct


class POINT(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.x = ct.c_uint32
        self.y = ct.c_uint32


class RECT(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.left = ct.c_int32
        self.top = ct.c_int32
        self.right = ct.c_int32
        self.bottom = ct.c_int32


class MONITORINFO(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.cbSize = ct.c_uint32
        self.rcMonitor = RECT
        self.rcWORK = RECT
        self.dwFlags = ct.c_uint32
