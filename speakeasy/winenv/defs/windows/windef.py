# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from typing import Annotated

from speakeasy.struct import EmuStruct


class POINT(EmuStruct):
    x: Annotated[int, ct.c_uint32]
    y: Annotated[int, ct.c_uint32]


class RECT(EmuStruct):
    left: Annotated[int, ct.c_int32]
    top: Annotated[int, ct.c_int32]
    right: Annotated[int, ct.c_int32]
    bottom: Annotated[int, ct.c_int32]


class MONITORINFO(EmuStruct):
    cbSize: Annotated[int, ct.c_uint32]
    rcMonitor: RECT
    rcWORK: RECT
    dwFlags: Annotated[int, ct.c_uint32]
