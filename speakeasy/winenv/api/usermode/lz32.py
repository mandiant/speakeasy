# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.arch as _arch

from .. import api


class Lz32(api.ApiHandler):

    name = 'lz32'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Lz32, self).__init__(emu)
        super(Lz32, self).__get_hook_attrs__(self)

    @apihook('LZSeek', argc=3, conv=_arch.CALL_CONV_STDCALL)
    def LZSeek(self, emu, argv, ctx={}):
        """
        LONG LZSeek(
          INT  hFile,
          LONG lOffset,
          INT  iOrigin
        );
        """
        return -1
