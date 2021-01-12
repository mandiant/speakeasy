# Copyright (C) 2021 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.defs.windows.netapi32 as netapi32defs

from .. import api


class NetUtils(api.ApiHandler):

    name = 'netutils'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(NetUtils, self).__init__(emu)
        super(NetUtils, self).__get_hook_attrs__(self)

    @apihook('NetApiBufferFree', argc=1)
    def NetApiBufferFree(self, emu, argv, ctx={}):
        """
        NET_API_STATUS NET_API_FUNCTION NetApiBufferFree(
          _Frees_ptr_opt_ LPVOID Buffer
        );
        """
        return netapi32defs.NERR_Success
