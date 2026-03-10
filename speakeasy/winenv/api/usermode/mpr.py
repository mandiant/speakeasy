# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.windows.mpr as mpr

from .. import api


class Mpr(api.ApiHandler):
    name = "mpr"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super().__init__(emu)
        super().__get_hook_attrs__(self)

    @apihook("WNetOpenEnum", argc=5, conv=_arch.CALL_CONV_STDCALL)
    def WNetOpenEnum(self, emu, argv, ctx: dict[str, str] | None = None):
        """
        DWORD WNetOpenEnum(
          DWORD          dwScope,
          DWORD          dwType,
          DWORD          dwUsage,
          LPNETRESOURCEW lpNetResource,
          LPHANDLE       lphEnum
        );
        """
        ctx = ctx or {}
        dwScope, dwType, dwUsage, lpNetResource, lphEnum = argv

        scope = mpr.get_define_int(dwScope, "RESOURCE_")
        if scope:
            argv[0] = scope

        type = mpr.get_define_int(dwType, "RESOURCETYPE_")
        if type:
            argv[1] = type

        usage = mpr.get_define_int(dwUsage, "RESOURCEUSAGE_")
        if usage:
            argv[2] = usage

        return mpr.ERROR_NO_NETWORK

    @apihook("WNetEnumResource", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def WNetEnumResource(self, emu, argv, ctx: dict[str, str] | None = None):
        """
        DWORD WNetEnumResourceA(
          HANDLE  hEnum,
          LPDWORD lpcCount,
          LPVOID  lpBuffer,
          LPDWORD lpBufferSize
        );
        """
        ctx = ctx or {}
        return mpr.ERROR_NO_NETWORK

    @apihook("WNetAddConnection2", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def WNetAddConnection2(self, emu, argv, ctx: dict[str, str] | None = None):
        """
        DWORD WNetAddConnection2W(
          LPNETRESOURCEW lpNetResource,
          LPCWSTR        lpPassword,
          LPCWSTR        lpUserName,
          DWORD          dwFlags
        );
        """
        ctx = ctx or {}
        return mpr.ERROR_NO_NETWORK

    @apihook("WNetGetConnection", argc=3, conv=_arch.CALL_CONV_STDCALL)
    def WNetGetConnection(self, emu, argv, ctx: dict[str, str] | None = None):
        """
        DWORD WNetGetConnectionA(
          LPCSTR  lpLocalName,
          LPSTR   lpRemoteName,
          LPDWORD lpnLength
        );
        """
        ctx = ctx or {}
        lpLocalName, lpRemoteName, lpnLength = argv

        cw = self.get_char_width(ctx)

        local_name = self.read_mem_string(lpLocalName, cw)
        if local_name:
            argv[0] = local_name

        return mpr.ERROR_NO_NETWORK
