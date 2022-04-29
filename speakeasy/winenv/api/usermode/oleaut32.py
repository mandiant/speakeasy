# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import struct

from .. import api


class OleAut32(api.ApiHandler):

    name = 'oleaut32'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(OleAut32, self).__init__(emu)
        super(OleAut32, self).__get_hook_attrs__(self)

    @apihook('SysAllocString', argc=1, ordinal=2)
    def SysAllocString(self, emu, argv, ctx={}):
        """
        BSTR SysAllocString(
            const OLECHAR *psz
        );
        """
        psz, = argv
        alloc_str = self.read_mem_string(psz, 2)
        if alloc_str:
            argv[0] = alloc_str
            alloc_str += '\x00'
            ws = alloc_str.encode('utf-16le')
            ws_len = len(ws)

            # https://docs.microsoft.com/en-us/previous-versions/windows/desktop/automat/bstr
            bstr_len = 4 + ws_len
            bstr = self.mem_alloc(bstr_len)
            bstr_bytes = struct.pack('<I', ws_len - 2) + ws

            self.mem_write(bstr, bstr_bytes)

            return bstr + 4

        return 0

    @apihook('SysAllocStringLen', argc=2, ordinal=4)
    def SysAllocStringLen(self, emu, argv, ctx={}):
        """
        BSTR SysAllocStringLen(
          [in] const OLECHAR *strIn,
          [in] UINT          ui
        );
        """
        strin, ui = argv

        ws_len = (ui + 1) * 2
        bstr = self.mem_alloc(4 + ws_len)

        if not strin:
            bstr_bytes = struct.pack('<I', ui * 2)
        else:
            alloc_str = self.read_mem_string(strin, 2)
            if alloc_str:
                argv[0] = alloc_str
                alloc_str = alloc_str[:ui]
                alloc_str += '\x00'
                ws = alloc_str.encode('utf-16le')
                bstr_bytes = struct.pack('<I', ui * 2) + ws
            else:
                return 0

        self.mem_write(bstr, bstr_bytes)

        return bstr + 4

    @apihook('SysFreeString', argc=1, ordinal=6)
    def SysFreeString(self, emu, argv, ctx={}):
        """
        void SysFreeString(
            BSTR bstrString
        );
        """
        argv[0] = self.read_wide_string(argv[0])
        return
