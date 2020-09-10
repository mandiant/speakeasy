# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.defs.windows.com as com


class COM(object):
    """
    The Component Object Model (COM) manager for the emulator. This will manage COM interfaces.
    """
    def __init__(self, config):
        super(COM, self).__init__()
        self.interfaces = {}
        self.config = config

    def get_interface(self, name, ptr_size):
        """
        Get COM interface
        """
        iface = com.IFACE_TYPES.get(name)
        if iface:
            ci = com.ComInterface(iface, name, ptr_size)
            return ci
