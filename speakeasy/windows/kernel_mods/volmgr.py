# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from . import kernel_mod as km

from speakeasy.struct import EmuStruct
import ctypes as ct

import speakeasy.winenv.defs.nt.ddk as ddk


class DISK_EXTENT(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.DiskNumber = ct.c_uint32
        self.StartingOffset = ct.c_uint64
        self.ExtentLength = ct.c_uint64


class VOLUME_DISK_EXTENTS(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.NumberOfDiskExtents = ct.c_uint32
        self.Extents = DISK_EXTENT * 1


class DriverModule(km.KernelModule):
    '''Class for emulation of specific drivers (e.g. their ioctl handlers)'''
    def __init__(self):
        super(DriverModule, self).__init__()
        self.name = 'volmgr'

    def ioctl(self, ptr_size, code, inbuf):
        vde = VOLUME_DISK_EXTENTS(ptr_size)
        vde.NumberOfDiskExtents = 1
        vde.Extents[0].DiskNumber = 0
        vde.Extents[0].StartingOffset = 0
        vde.Extents[0].ExtentLength = 0x1000

        return (ddk.STATUS_SUCCESS, vde.get_bytes())
