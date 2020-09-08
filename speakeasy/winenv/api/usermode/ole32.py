# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.defs.windows.windows as windefs

from .. import api


class Ole32(api.ApiHandler):

    name = 'ole32'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Ole32, self).__init__(emu)
        self.funcs = {}
        self.data = {}
        super(Ole32, self).__get_hook_attrs__(self)
        self.netman = emu.get_network_manager()
        self.names = {}

    @apihook('OleInitialize', argc=1)
    def OleInitialize(self, emu, argv, ctx={}):
        """
        HRESULT OleInitialize(
            IN LPVOID pvReserved
        );
        """

        rv = windefs.S_OK

        return rv
