# Copyright (C) 2026 Mandiant, Inc. All Rights Reserved.

import speakeasy.winenv.defs.windows.windows as windefs

from .. import api


class Version(api.ApiHandler):
    """
    Implements exported functions from version.dll

    Version resources are not modeled: every file reports that it has none.
    Without a handler, the signature fallback reports a zero size with
    ERROR_SUCCESS and a successful VerQueryValue with a NULL buffer, which
    callers dereference. The documented "no version resource" failure keeps
    callers on their own error path instead.
    """

    name = "version"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        self.funcs = {}
        self.data = {}
        super().__get_hook_attrs__(self)

    @apihook("GetFileVersionInfoSize", argc=2)
    def GetFileVersionInfoSize(self, emu, argv, ctx={}):
        """
        DWORD GetFileVersionInfoSize(LPCSTR lptstrFilename, LPDWORD lpdwHandle);
        """
        lptstrFilename, lpdwHandle = argv
        if lpdwHandle:
            self.mem_write(lpdwHandle, (0).to_bytes(4, "little"))
        emu.set_last_error(windefs.ERROR_RESOURCE_TYPE_NOT_FOUND)
        return 0

    @apihook("GetFileVersionInfoSizeEx", argc=3)
    def GetFileVersionInfoSizeEx(self, emu, argv, ctx={}):
        """
        DWORD GetFileVersionInfoSizeEx(DWORD dwFlags, LPCSTR lpwstrFilename, LPDWORD lpdwHandle);
        """
        dwFlags, lpwstrFilename, lpdwHandle = argv
        if lpdwHandle:
            self.mem_write(lpdwHandle, (0).to_bytes(4, "little"))
        emu.set_last_error(windefs.ERROR_RESOURCE_TYPE_NOT_FOUND)
        return 0

    @apihook("GetFileVersionInfo", argc=4)
    def GetFileVersionInfo(self, emu, argv, ctx={}):
        """
        BOOL GetFileVersionInfo(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
        """
        emu.set_last_error(windefs.ERROR_RESOURCE_TYPE_NOT_FOUND)
        return 0

    @apihook("GetFileVersionInfoEx", argc=5)
    def GetFileVersionInfoEx(self, emu, argv, ctx={}):
        """
        BOOL GetFileVersionInfoEx(DWORD dwFlags, LPCSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
        """
        emu.set_last_error(windefs.ERROR_RESOURCE_TYPE_NOT_FOUND)
        return 0

    @apihook("VerQueryValue", argc=4)
    def VerQueryValue(self, emu, argv, ctx={}):
        """
        BOOL VerQueryValue(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen);
        """
        # No version block can exist, so no value is available.
        return 0
