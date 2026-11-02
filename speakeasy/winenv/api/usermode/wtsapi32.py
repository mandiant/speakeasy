# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from typing import TYPE_CHECKING, Annotated

import speakeasy.winenv.arch as _arch
from speakeasy.struct import EmuStruct, Ptr

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator


class WTS_SESSION_INFO(EmuStruct):
    SessionId: Annotated[int, ct.c_uint32]
    pWinStationName: Annotated[int, Ptr]
    State: Annotated[int, ct.c_uint32]


class WtsApi32(api.ApiHandler):
    name = "wtsapi32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        self.funcs = {}
        self.data = {}
        super().__get_hook_attrs__(self)

    @apihook("WTSEnumerateSessions", argc=5, conv=_arch.CALL_CONV_STDCALL)
    def WTSEnumerateSessions(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL WTSEnumerateSessions(
            HANDLE hServer,
            DWORD Reserved,
            DWORD Version,
            PWTS_SESSION_INFO *ppSessionInfo,
            DWORD *pCount
        );
        """
        hServer, Reserved, Version, ppSessionInfo, pCount = argv
        rv = 0

        fn = ctx.func_name
        cw = self.get_char_width(ctx)

        sn = self.encode_string("RDP-Tcp#1\x00", cw)

        wsi = WTS_SESSION_INFO(emu.get_ptr_size())

        size = len(sn) + wsi.sizeof()
        buf = self.mem_alloc(size=size, tag=f"api.{fn}")

        wsi.SessionId = 1
        # Write the string at the end of the structure
        wsi.pWinStationName = buf + wsi.sizeof()
        wsi.State = 0

        # Write the structure into memory
        self.mem_write(buf, self.get_bytes(wsi))
        # Write the string at the end of the structure
        self.mem_write(buf + wsi.sizeof(), sn)

        # Write the total session count
        if ppSessionInfo and pCount:
            self.write_dword(pCount, 1)
            # Write the session buffer
            self.write_ptr(ppSessionInfo, buf)

            rv = 1

        return rv

    @apihook("WTSFreeMemory", argc=1, conv=_arch.CALL_CONV_STDCALL)
    def WTSFreeMemory(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID WTSFreeMemory(
            PVOID pMemory
        );
        """
        (pMemory,) = argv
        rv = 1

        self.mem_free(pMemory)

        return rv
