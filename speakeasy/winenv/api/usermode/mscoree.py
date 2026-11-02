# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from typing import TYPE_CHECKING

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator


class Mscoree(api.ApiHandler):
    """
    Implements exported functions from mscoree.dll.
    """

    name = "mscoree"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs = {}
        self.data = {}

        super().__get_hook_attrs__(self)

    @apihook("CorExitProcess", argc=1)
    def CorExitProcess(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void STDMETHODCALLTYPE CorExitProcess(
            int exitCode
        );
        """
        return 0
