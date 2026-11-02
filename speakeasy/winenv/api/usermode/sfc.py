from typing import TYPE_CHECKING

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator


class sfc(api.ApiHandler):
    """
    Emulates functions from sfc.dll
    """

    name = "sfc"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        super().__get_hook_attrs__(self)

    @apihook("SfcIsFileProtected", argc=2)
    def SfcIsFileProtected(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SfcIsFileProtected(
            HANDLE RpcHandle,
            LPCWSTR ProtFileName
        );
        """
        return False

    @apihook("SfcTerminateWatcherThread", argc=0, ordinal=2)
    def SfcTerminateWatcherThread(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void SfcTerminateWatcherThread();
        """
        return 0
