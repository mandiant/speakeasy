from typing import TYPE_CHECKING

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator


class Msvfw32(api.ApiHandler):
    """Implements exported functions from msvfw32.dll."""

    name = "msvfw32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        self.funcs = {}
        self.data = {}
        super().__get_hook_attrs__(self)

    @apihook("ICOpen", argc=3)
    def ICOpen(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HIC ICOpen(
            DWORD fccType,
            DWORD fccHandler,
            UINT wMode
        );
        """
        fccType, fccHandler, wMode = argv
        return emu.handle_allocator.allocate_handle()

    @apihook("ICSendMessage", argc=4)
    def ICSendMessage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LRESULT ICSendMessage(
            HIC hic,
            UINT msg,
            DWORD_PTR dw1,
            DWORD_PTR dw2
        );
        """
        hic, msg, dw1, dw2 = argv
        return 1

    @apihook("ICClose", argc=1)
    def ICClose(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LRESULT ICClose(
            HIC hic
        );
        """
        return 1

    @apihook("DrawDibOpen", argc=0)
    def DrawDibOpen(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HDRAWDIB DrawDibOpen();
        """
        return emu.handle_allocator.allocate_handle()

    @apihook("DrawDibClose", argc=1)
    def DrawDibClose(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL DrawDibClose(
            HDRAWDIB hdd
        );
        """
        return 1

    @apihook("DrawDibDraw", argc=13)
    def DrawDibDraw(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL DrawDibDraw(
            HDRAWDIB hdd,
            HDC hdc,
            int xDst,
            int yDst,
            int dxDst,
            int dyDst,
            LPBITMAPINFOHEADER lpbi,
            LPVOID lpBits,
            int xSrc,
            int ySrc,
            int dxSrc,
            int dySrc,
            UINT wFlags
        );
        """
        return 1
