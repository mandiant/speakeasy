# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import struct
from typing import TYPE_CHECKING

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator


class OleAut32(api.ApiHandler):
    name = "oleaut32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        super().__get_hook_attrs__(self)

    @apihook("SysAllocString", argc=1, ordinal=2)
    def SysAllocString(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BSTR SysAllocString(
            const OLECHAR *psz
        );
        """
        (psz,) = argv
        if not psz:
            return 0

        alloc_str = self.read_mem_string(psz, 2)
        ctx.args["psz"].display = alloc_str
        alloc_str += "\x00"
        ws = alloc_str.encode("utf-16le")
        ws_len = len(ws)

        # https://docs.microsoft.com/en-us/previous-versions/windows/desktop/automat/bstr
        bstr_len = 4 + ws_len
        bstr = self.mem_alloc(bstr_len)
        bstr_bytes = struct.pack("<I", ws_len - 2) + ws

        self.mem_write(bstr, bstr_bytes)

        return bstr + 4

    @apihook("SysAllocStringLen", argc=2, ordinal=4)
    def SysAllocStringLen(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BSTR SysAllocStringLen(
            const OLECHAR *strIn,
            UINT ui
        );
        """
        strIn, ui = argv

        ws_len = (ui + 1) * 2
        bstr = self.mem_alloc(4 + ws_len)

        if not strIn:
            bstr_bytes = struct.pack("<I", ui * 2)
        else:
            ws = self.mem_read(strIn, ui * 2)
            ctx.args["strIn"].display = ws.decode("utf-16le", errors="replace")
            bstr_bytes = struct.pack("<I", ui * 2) + ws + b"\x00\x00"

        self.mem_write(bstr, bstr_bytes)

        return bstr + 4

    @apihook("SysAllocStringByteLen", argc=2, ordinal=150)
    def SysAllocStringByteLen(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BSTR SysAllocStringByteLen(
            LPCSTR psz,
            UINT len
        );
        """
        psz, len = argv

        data = self.mem_read(psz, len) if psz else b"\x00" * len
        bstr = self.mem_alloc(4 + len + 2)
        self.mem_write(bstr, struct.pack("<I", len) + data + b"\x00\x00")

        return bstr + 4

    @apihook("SysReAllocStringLen", argc=3, ordinal=5)
    def SysReAllocStringLen(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        INT SysReAllocStringLen(
            BSTR *pbstr,
            const OLECHAR *psz,
            unsigned int len
        );
        """
        pbstr, psz, len = argv
        if not pbstr:
            return 0

        ws = b"\x00" * (len * 2)
        if psz:
            ws = self.mem_read(psz, len * 2)
            ctx.args["psz"].display = ws.decode("utf-16le", errors="replace")

        bstr = self.mem_alloc(4 + len * 2 + 2)
        self.mem_write(bstr, struct.pack("<I", len * 2) + ws + b"\x00\x00")
        self.mem_write(pbstr, (bstr + 4).to_bytes(self.get_ptr_size(), "little"))

        return 1

    @apihook("SysFreeString", argc=1, ordinal=6)
    def SysFreeString(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void SysFreeString(
            BSTR bstrString
        );
        """
        if argv[0]:
            ctx.args["bstrString"].display = self.read_wide_string(argv[0])

    @apihook("SysStringLen", argc=1, ordinal=7)
    def SysStringLen(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT SysStringLen(
            BSTR pbstr
        );
        """
        return self.SysStringByteLen(emu, argv, ctx) // 2

    @apihook("SysStringByteLen", argc=1, ordinal=149)
    def SysStringByteLen(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT SysStringByteLen(
            BSTR bstr
        );
        """
        (bstr,) = argv
        if not bstr:
            return 0
        return struct.unpack("<I", self.mem_read(bstr - 4, 4))[0]

    @apihook("VariantInit", argc=1, ordinal=8)
    def VariantInit(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void VariantInit(
            VARIANTARG *pvarg
        );
        """
        (pvarg,) = argv
        if pvarg:
            size = 0x18 if emu.get_ptr_size() == 8 else 0x10
            self.mem_write(pvarg, b"\x00" * size)
