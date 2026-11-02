# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.


from typing import TYPE_CHECKING

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator


class Msimg32(api.ApiHandler):
    """
    Implements exported functions from msimg.dll
    """

    name = "msimg32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        super().__get_hook_attrs__(self)

    @apihook("TransparentBlt", argc=11)
    def TransparentBlt(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL TransparentBlt(
            HDC hdcDest,
            int xoriginDest,
            int yoriginDest,
            int wDest,
            int hDest,
            HDC hdcSrc,
            int xoriginSrc,
            int yoriginSrc,
            int wSrc,
            int hSrc,
            UINT crTransparent
        );
        """
        return 1
