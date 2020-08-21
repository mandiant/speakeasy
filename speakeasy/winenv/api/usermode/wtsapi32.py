# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
import speakeasy.winenv.arch as _arch
from speakeasy.struct import EmuStruct, Ptr

from .. import api


class WTS_SESSION_INFO(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.SessionId = ct.c_uint32
        self.pWinStationName = Ptr
        self.State = ct.c_uint32


class WtsApi32(api.ApiHandler):

    name = 'wtsapi32'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(WtsApi32, self).__init__(emu)
        self.funcs = {}
        self.data = {}
        super(WtsApi32, self).__get_hook_attrs__(self)

    @apihook('WTSEnumerateSessions', argc=5, conv=_arch.CALL_CONV_STDCALL)
    def WTSEnumerateSessions(self, emu, argv, ctx={}):
        """
        BOOL WTSEnumerateSessions(
          IN HANDLE          hServer,
          IN DWORD           Reserved,
          IN DWORD           Version,
          PWTS_SESSION_INFO *ppSessionInfo,
          DWORD              *pCount
        );
        """

        hServer, res, ver, ppSessionInfo, pCount = argv
        rv = 0

        fn = ctx['func_name']
        cw = self.get_char_width(ctx)

        winstatname = 'RDP-Tcp#1' + '\x00'
        if cw == 2:
            sn = winstatname.encode('utf-16le')
        elif cw == 1:
            sn = winstatname.encode('utf-8')

        wsi = WTS_SESSION_INFO(emu.get_ptr_size())

        size = len(sn) + wsi.sizeof()
        buf = self.mem_alloc(size=size, tag='api.%s' % (fn))

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
            self.mem_write(pCount, (1).to_bytes(4, 'little'))
            # Write the session buffer
            self.mem_write(ppSessionInfo, (buf).to_bytes(self.get_ptr_size(), 'little'))

            rv = 1

        return rv

    @apihook('WTSFreeMemory', argc=1, conv=_arch.CALL_CONV_STDCALL)
    def WTSFreeMemory(self, emu, argv, ctx={}):
        """
        void WTSFreeMemory(
          IN PVOID pMemory
        );
        """
        pMemory, = argv
        rv = 1

        self.mem_free(pMemory)

        return rv
