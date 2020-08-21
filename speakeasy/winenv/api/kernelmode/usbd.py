# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.defs.nt.ddk as ddk
from speakeasy.winenv.api import api


class Usbd(api.ApiHandler):
    """
    Implements the USB stack driver (USBD.sys)
    """

    name = 'usbd'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    class ApiEmuError(Exception):
        pass

    def __init__(self, emu):

        super(Usbd, self).__init__(emu)

        self.funcs = {}
        self.data = {}

        super(Usbd, self).__get_hook_attrs__(self)

    @apihook('USBD_ValidateConfigurationDescriptor', argc=5)
    def USBD_ValidateConfigurationDescriptor(self, emu, argv, ctx={}):
        """
        USBD_STATUS USBD_ValidateConfigurationDescriptor(
          PUSB_CONFIGURATION_DESCRIPTOR ConfigDesc,
          ULONG                         BufferLength,
          USHORT                        Level,
          PUCHAR                        *Offset,
          ULONG                         Tag
        );
        """
        rv = ddk.STATUS_SUCCESS
        ConfigDesc, BufferLength, Level, Offset, Tag = argv

        return rv
