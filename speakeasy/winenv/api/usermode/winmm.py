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

    @apihook("timeBeginPeriod", argc=1)
    def timeBeginPeriod(self, emu, argv, ctx={}):
        """
        MMRESULT timeBeginPeriod(UINT uPeriod);
        """
        return 0  # TIMERR_NOERROR

    @apihook("timeEndPeriod", argc=1)
    def timeEndPeriod(self, emu, argv, ctx={}):
        """
        MMRESULT timeEndPeriod(UINT uPeriod);
        """
        return 0  # TIMERR_NOERROR

    @apihook("timeGetTime", argc=0)
    def timeGetTime(self, emu, argv, ctx={}):
        """
        DWORD timeGetTime(); // return the system time, in milliseconds
        """
        return int(time.monotonic() * 1000) & 0xFFFFFFFF
