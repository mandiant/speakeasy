# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from typing import Annotated

from speakeasy.struct import EmuStruct
from speakeasy.winenv.defs.nt import ddk

from . import kernel_mod as km


class DISK_EXTENT(EmuStruct):
    DiskNumber: Annotated[int, ct.c_uint32]
    StartingOffset: Annotated[int, ct.c_uint64]
    ExtentLength: Annotated[int, ct.c_uint64]


class VOLUME_DISK_EXTENTS(EmuStruct):
    NumberOfDiskExtents: Annotated[int, ct.c_uint32]
    Extents: Annotated[list[DISK_EXTENT], DISK_EXTENT * 1]


class DriverModule(km.KernelModule):
    """The volmgr driver. Each IOCTL gets one disk extent, as for IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS."""

    def __init__(self):
        super().__init__()
        self.name = "volmgr"

    def ioctl(self, arch, code, inbuf):
        vde = VOLUME_DISK_EXTENTS(arch)
        vde.NumberOfDiskExtents = 1
        vde.Extents[0].DiskNumber = 0
        vde.Extents[0].StartingOffset = 0
        vde.Extents[0].ExtentLength = 0x1000

        return (ddk.STATUS_SUCCESS, vde.get_bytes())
