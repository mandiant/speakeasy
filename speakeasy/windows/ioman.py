# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.windows.kernel_mods as km
from speakeasy.windows.kernel_mods.kernel_mod import KernelModule
from speakeasy.winenv.defs.nt import ddk


class IoManager:
    """Send device I/O control requests to the emulated kernel module of the device driver."""

    def __init__(self):
        super().__init__()
        self.emu_kmods: list[KernelModule] = [m.DriverModule() for m in km._get_kmods()]

    def dev_ioctl(self, arch, dev, ioctl, inbuf):
        rv = ddk.STATUS_INVALID_DEVICE_REQUEST
        outbuf = b""

        drv = dev.driver
        bn = drv.get_basename()

        mods = [m for m in self.emu_kmods if bn == m.get_mod_name()]
        if not mods:
            rv = ddk.STATUS_INVALID_DEVICE_REQUEST
            return (rv, outbuf)
        mod = mods[0]

        return mod.ioctl(arch, ioctl, inbuf)
