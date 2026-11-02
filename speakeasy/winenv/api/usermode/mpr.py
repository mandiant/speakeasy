# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from typing import TYPE_CHECKING

import speakeasy.winenv.arch as _arch
from speakeasy.winenv.defs.windows import mpr

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator


class Mpr(api.ApiHandler):
    name = "mpr"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        super().__get_hook_attrs__(self)

    @apihook("WNetOpenEnum", argc=5, conv=_arch.CALL_CONV_STDCALL)
    def WNetOpenEnum(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD WNetOpenEnum(
            DWORD dwScope,
            DWORD dwType,
            DWORD dwUsage,
            LPNETRESOURCE lpNetResource,
            LPHANDLE lphEnum
        );
        """
        dwScope, dwType, dwUsage, lpNetResource, lphEnum = argv

        scope = mpr.get_define_int(dwScope, "RESOURCE_")
        if scope:
            ctx.args["dwScope"].display = scope

        type = mpr.get_define_int(dwType, "RESOURCETYPE_")
        if type:
            ctx.args["dwType"].display = type

        usage = mpr.get_define_int(dwUsage, "RESOURCEUSAGE_")
        if usage:
            ctx.args["dwUsage"].display = usage

        return mpr.ERROR_NO_NETWORK

    @apihook("WNetEnumResource", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def WNetEnumResource(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD WNetEnumResource(
            HANDLE hEnum,
            LPDWORD lpcCount,
            LPVOID lpBuffer,
            LPDWORD lpBufferSize
        );
        """
        return mpr.ERROR_NO_NETWORK

    @apihook("WNetAddConnection2", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def WNetAddConnection2(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD WNetAddConnection2(
            LPNETRESOURCE lpNetResource,
            LPCTSTR lpPassword,
            LPCTSTR lpUserName,
            DWORD dwFlags
        );
        """
        return mpr.ERROR_NO_NETWORK

    @apihook("WNetGetConnection", argc=3, conv=_arch.CALL_CONV_STDCALL)
    def WNetGetConnection(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD WNetGetConnection(
            LPCTSTR lpLocalName,
            LPTSTR lpRemoteName,
            LPDWORD lpnLength
        );
        """
        lpLocalName, lpRemoteName, lpnLength = argv

        cw = self.get_char_width(ctx)

        local_name = self.read_mem_string(lpLocalName, cw)
        if local_name:
            ctx.args["lpLocalName"].display = local_name

        return mpr.ERROR_NO_NETWORK
