# Copyright (C) 2021 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.defs.windows.netapi32 as netapi32defs
import speakeasy.winenv.arch as _arch

from .. import api


class Wkscli(api.ApiHandler):
    """
    Implements exported functions from wkscli.dll
    """
    name = 'wkscli'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super(Wkscli, self).__init__(emu)
        super(Wkscli, self).__get_hook_attrs__(self)

    @apihook('NetGetJoinInformation', argc=3)
    def NetGetJoinInformation(self, emu, argv, ctx={}):
        """
        NET_API_STATUS NET_API_FUNCTION NetGetJoinInformation(
          LPCWSTR lpServer,
          LPWSTR *lpNameBuffer,
          PNETSETUP_JOIN_STATUS BufferType
        );
        """
        lpServer, lpNameBuffer, BufferType = argv

        if lpServer:
            server = self.read_wide_string(lpServer)
            argv[0] = server

        # Assumes the server being queried is the local computer
        domain = emu.get_domain()
        argv[1] = domain
        namebuf = self.mem_alloc(emu.get_ptr_size())
        self.write_wide_string(domain, namebuf)
        self.mem_write(lpNameBuffer, namebuf.to_bytes(emu.get_ptr_size(), 'little'))

        argv[2] = netapi32defs.NetSetupDomainName
        self.mem_write(BufferType, netapi32defs.NetSetupDomainName.to_bytes(4, 'little'))

        return netapi32defs.NERR_Success
