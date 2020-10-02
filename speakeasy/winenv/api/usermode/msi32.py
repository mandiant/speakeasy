# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.arch as _arch

from .. import api


class Msi32(api.ApiHandler):

    name = 'msi32'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Msi32, self).__init__(emu)
        super(Msi32, self).__get_hook_attrs__(self)

    @apihook('MsiDatabaseMergeA', argc=3, conv=_arch.CALL_CONV_STDCALL, ordinal=29)
    def MsiDatabaseMergeA(self, emu, argv, ctx={}):
        """
        UINT MsiDatabaseMergeA(
          MSIHANDLE hDatabase,
          MSIHANDLE hDatabaseMerge,
          LPCSTR    szTableName
        );
        """
        return 0
