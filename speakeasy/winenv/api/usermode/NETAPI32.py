# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.defs.windows.kernel32 as k32types
import speakeasy.winenv.arch as _arch
from .. import api

PAGE_SIZE = 0x1000


class net32api(api.ApiHandler):
    name = 'NETAPI32'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super(net32api, self).__init__(emu)
        super(net32api, self).__get_hook_attrs__(self)

    @apihook('NetGetJoinInformation', argc=3, conv=_arch.CALL_CONV_STDCALL)
    def NetGetJoinInformation(self, emu, argv, ctx={}):
        """
        NET_API_STATUS NET_API_FUNCTION NetGetJoinInformation(
         LPCWSTR lpServer,
         LPWSTR *lpNameBuffer,
         PNETSETUP_JOIN_STATUS BufferType
         );
            lpServer: Pointer to a constant string that specifies the DNS or NetBIOS name of the computer on which to call the function.
            If this parameter is NULL, the local computer is used.

            lpNameBuffer: Pointer to the buffer that receives the NetBIOS name of the domain or workgroup to which the computer is joined.
            This buffer is allocated by the system and must be freed using the NetApiBufferFree function.

            BufferType: Receives the join status of the specified computer. This parameter can have one of the following values.
        """
        lpServer, lpNameBuffer, BufferType = argv

        name = 'FLARE_Test_Domain'
        name_bytes = str.encode(name)

        lpServer = 0
        lpNameBuffer = name_bytes
        BufferType = k32types.NetSetupWorkgroupName

        return 0  # NERR_Success
