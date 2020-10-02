# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import uuid

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

    @apihook('StringFromCLSID', argc=2)
    def StringFromCLSID(self, emu, argv, ctx={}):
        """
        HRESULT StringFromCLSID(
        REFCLSID rclsid,
        LPOLESTR *lplpsz
        );
        """

        rclsid, lplpsz = argv
        rv = windefs.S_OK

        guid = self.mem_read(rclsid, self.sizeof(windefs.GUID()))
        u = uuid.UUID(bytes_le=guid)
        u = ('{%s}' % (u)).upper()
        argv[1] = u
        u = (u + '\x00').encode('utf-16le')

        ptr = self.mem_alloc(len(u), tag='api.StringFromCLSID')

        if lplpsz:
            self.mem_write(lplpsz, ptr.to_bytes(emu.get_ptr_size(), 'little'))

        return rv
