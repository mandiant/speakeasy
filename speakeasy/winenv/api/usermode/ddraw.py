from typing import TYPE_CHECKING

from speakeasy.winenv.defs.windows.ddraw import DDERR_NODIRECTDRAWHW

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator


class Ddraw(api.ApiHandler):
    """
    Emulates functions from ddraw.dll. The emulator has no display driver,
    so object creation reports that no DirectDraw hardware is present.
    """

    name = "ddraw"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        super().__get_hook_attrs__(self)

    @apihook("DirectDrawCreate", argc=3)
    def DirectDrawCreate(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT DirectDrawCreate(
            GUID *lpGUID,
            LPDIRECTDRAW *lplpDD,
            IUnknown *pUnkOuter
        );
        """
        lpGUID, lplpDD, pUnkOuter = argv
        if lplpDD:
            self.write_ptr(lplpDD, 0)
        return DDERR_NODIRECTDRAWHW

    @apihook("DirectDrawCreateEx", argc=4)
    def DirectDrawCreateEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT DirectDrawCreateEx(
            GUID *lpGuid,
            LPVOID *lplpDD,
            REFIID iid,
            IUnknown *pUnkOuter
        );
        """
        lpGuid, lplpDD, iid, pUnkOuter = argv
        if lplpDD:
            self.write_ptr(lplpDD, 0)
        return DDERR_NODIRECTDRAWHW
