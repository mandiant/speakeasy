# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import base64
from .. import api

ERROR_MORE_DATA = 234

CRYPT_STRING_BASE64 = 1


class Crypt32(api.ApiHandler):

    """
    Implements exported functions from user32.dll
    """

    name = 'crypt32'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Crypt32, self).__init__(emu)

        self.funcs = {}
        self.data = {}

        super(Crypt32, self).__get_hook_attrs__(self)

    @apihook('CryptStringToBinary', argc=7)
    def CryptStringToBinary(self, emu, argv, ctx={}):
        '''
        BOOL CryptStringToBinaryA(
        LPCSTR pszString,
        DWORD  cchString,
        DWORD  dwFlags,
        BYTE   *pbBinary,
        DWORD  *pcbBinary,
        DWORD  *pdwSkip,
        DWORD  *pdwFlags
        );
        '''

        cw = self.get_char_width(ctx)

        pszString, cchString, dwFlags, pbBinary, pcbBinary, pdwSkip, pdwFlags = argv

        if cchString:
            s = self.mem_read(pszString, cchString * cw)
        else:
            s = self.read_mem_string(pszString, cw)

        if dwFlags != CRYPT_STRING_BASE64:
            # self.logger.info("%s: currently unsupported flags (%08X)" % (api_name, dwFlags))
            return 1

        if type(s) != str:
            s = s.decode('utf8')

        argv[0] = s

        try:
            decoded = base64.b64decode(s)
        except Exception:
            return 0

        cbBinary = int.from_bytes(self.mem_read(pcbBinary, 4), 'little')
        out_len = len(decoded)

        if pbBinary == 0:
            return out_len

        if out_len > cbBinary:
            emu.set_last_error(ERROR_MORE_DATA)
            return 0

        self.mem_write(pbBinary, decoded)
        self.mem_write(pcbBinary, out_len.to_bytes(4, 'little'))

        if pdwSkip:
            self.mem_write(pdwSkip, b"\x00" * 4)

        return 1
