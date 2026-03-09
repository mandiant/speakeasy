import time

from .. import api


class Winmm(api.ApiHandler):
    """
    Emulates functions from winmm.dll
    """

    name = "winmm"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super().__init__(emu)
        super().__get_hook_attrs__(self)

    @apihook("timeGetTime", argc=0)
    def timeGetTime(self, emu, argv, ctx={}):
        """
        DWORD timeGetTime(); // return the system time, in milliseconds
        """
        return int(time.monotonic() * 1000) & 0xFFFFFFFF
