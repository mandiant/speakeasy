# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import struct

from .. import api


class OleAut32(api.ApiHandler):
    name = "oleaut32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        super().__get_hook_attrs__(self)

    @apihook("SysAllocString", argc=1, ordinal=2)
    def SysAllocString(self, emu, argv, ctx: api.ApiContext = None):
        """
        BSTR SysAllocString(
            const OLECHAR *psz
        );
        """
        (psz,) = argv
        alloc_str = self.read_mem_string(psz, 2)
        if alloc_str:
            argv[0] = alloc_str
            alloc_str += "\x00"
            ws = alloc_str.encode("utf-16le")
            ws_len = len(ws)

            # https://docs.microsoft.com/en-us/previous-versions/windows/desktop/automat/bstr
            bstr_len = 4 + ws_len
            bstr = self.mem_alloc(bstr_len)
            bstr_bytes = struct.pack("<I", ws_len - 2) + ws

            self.mem_write(bstr, bstr_bytes)

            return bstr + 4

        return 0

    @apihook("SysAllocStringLen", argc=2, ordinal=4)
    def SysAllocStringLen(self, emu, argv, ctx: api.ApiContext = None):
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
            bstr_bytes = struct.pack("<I", ui * 2)
        else:
            alloc_str = self.read_mem_string(strin, 2)
            if alloc_str:
                argv[0] = alloc_str
                alloc_str = alloc_str[:ui]
                alloc_str += "\x00"
                ws = alloc_str.encode("utf-16le")
                bstr_bytes = struct.pack("<I", ui * 2) + ws
            else:
                return 0

        self.mem_write(bstr, bstr_bytes)

        return bstr + 4

    @apihook("SysReAllocStringLen", argc=3, ordinal=5)
    def SysReAllocStringLen(self, emu, argv, ctx: api.ApiContext = None):
        """
        INT SysReAllocStringLen(
          [in, out]      BSTR          *pbstr,
          [in, optional] const OLECHAR *psz,
          [in]           unsigned int  len
        );
        """
        pbstr, psz, ui = argv
        if not pbstr:
            return 0

        ws = b"\x00" * (ui * 2)
        if psz:
            ws = self.mem_read(psz, ui * 2)
            argv[1] = ws.decode("utf-16le", errors="replace")

        bstr = self.mem_alloc(4 + ui * 2 + 2)
        self.mem_write(bstr, struct.pack("<I", ui * 2) + ws + b"\x00\x00")
        self.mem_write(pbstr, (bstr + 4).to_bytes(self.get_ptr_size(), "little"))

        return 1

    @apihook("SysFreeString", argc=1, ordinal=6)
    def SysFreeString(self, emu, argv, ctx: api.ApiContext = None):
        """
        void SysFreeString(
            BSTR bstrString
        );
        """
        argv[0] = self.read_wide_string(argv[0])
        return

    @apihook("VariantInit", argc=1, ordinal=8)
    def VariantInit(self, emu, argv, ctx: api.ApiContext = None):
        """
        void VariantInit(
            VARIANTARG *pvarg
        );
        """
        (pvarg,) = argv
        if pvarg:
            size = 0x18 if emu.get_ptr_size() == 8 else 0x10
            self.mem_write(pvarg, b"\x00" * size)
        return
