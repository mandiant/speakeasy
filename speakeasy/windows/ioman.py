# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.defs.nt.ddk as ddk
import speakeasy.windows.kernel_mods as km


class IoManager(object):
    """
    Directs IO requests to a module handler. For example, if a user mode application
    sends an ioctl to a device this can be handled here.
    """
    def __init__(self):
        super(IoManager, self).__init__()
        self.emu_kmods = [m.DriverModule() for m in km._get_kmods()]

    def dev_ioctl(self, arch, dev, ioctl, inbuf):
        rv = ddk.STATUS_INVALID_DEVICE_REQUEST
        outbuf = b''

        # Get parent driver for you
        drv = dev.get_parent_driver()
        bn = drv.get_basename()

        # Find the emulated kernel module (if any)
        mod = [m for m in self.emu_kmods if bn == m.get_mod_name()]
        if not mod:
            rv = ddk.STATUS_INVALID_DEVICE_REQUEST
            return (rv, outbuf)
        mod = mod[0]

        return mod.ioctl(arch, ioctl, inbuf)
