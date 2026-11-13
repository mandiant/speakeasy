# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from typing import TYPE_CHECKING

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator


class Advpack(api.ApiHandler):
    """
    Emulates functions from advpack.dll
    """

    name = "advpack"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs = {}
        self.data = {}

        super().__get_hook_attrs__(self)

    @apihook("IsNTAdmin", argc=2)
    def IsNTAdmin(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsNTAdmin(
            DWORD dwReserved,
            DWORD *lpdwReserved
        );
        """
        return emu.config.user.admin
