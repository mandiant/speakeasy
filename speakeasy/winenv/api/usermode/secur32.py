# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.windows.secur32 as sec32defs

from .. import api


class Secur32(api.ApiHandler):

    name = 'secur32'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Secur32, self).__init__(emu)
        super(Secur32, self).__get_hook_attrs__(self)

    @apihook('GetUserNameEx', argc=3, conv=_arch.CALL_CONV_STDCALL)
    def GetUserNameEx(self, emu, argv, ctx={}):
        """
        BOOLEAN SEC_ENTRY GetUserNameExA(
          EXTENDED_NAME_FORMAT NameFormat,
          LPSTR                lpNameBuffer,
          PULONG               nSize
        );
        """
        NameFormat, lpNameBuffer, nSize = argv

        cw = self.get_char_width(ctx)

        name_format = sec32defs.get_define(NameFormat, prefix='Name')
        if name_format:
            argv[0] = name_format

        user = emu.get_user()
        user_name = user.get('name')
        user_name_len = len(user_name)

        argv[1] = user_name
        argv[2] = user_name_len

        self.write_mem_string(user_name, lpNameBuffer, cw)
        self.mem_write(nSize, user_name_len.to_bytes(4, 'little'))

        return 1

    @apihook('EncryptMessage', argc=4)
    def EncryptMessage(self, emu, argv, ctx={}):
        """
        SECURITY_STATUS SEC_ENTRY EncryptMessage(
        PCtxtHandle    phContext,
        unsigned long  fQOP,
        PSecBufferDesc pMessage,
        unsigned long  MessageSeqNo
        );
        """

        PCtxtHandle, fQOP, pMessage, MessageSeqNo = argv

        return sec32defs.SEC_E_INVALID_HANDLE
