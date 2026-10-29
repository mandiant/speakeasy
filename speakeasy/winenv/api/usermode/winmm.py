from .. import api

DRV_LOAD = 0x0001
DRV_ENABLE = 0x0002
DRV_DISABLE = 0x0005
DRV_FREE = 0x0006
DRV_INSTALL = 0x0009
DRV_REMOVE = 0x000A


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

    @apihook("DefDriverProc", argc=5)
    def DefDriverProc(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LRESULT DefDriverProc(DWORD_PTR dwDriverIdentifier, HDRVR hdrvr, UINT uMsg, LPARAM lParam1, LPARAM lParam2);
        """
        _, _, msg, _, _ = argv
        if msg in (DRV_LOAD, DRV_ENABLE, DRV_DISABLE, DRV_FREE, DRV_INSTALL, DRV_REMOVE):
            return 1
        return 0

    @apihook("timeBeginPeriod", argc=1)
    def timeBeginPeriod(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        MMRESULT timeBeginPeriod(UINT uPeriod);
        """
        return 0  # TIMERR_NOERROR

    @apihook("timeEndPeriod", argc=1)
    def timeEndPeriod(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        MMRESULT timeEndPeriod(UINT uPeriod);
        """
        return 0  # TIMERR_NOERROR

    @apihook("timeGetTime", argc=0)
    def timeGetTime(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD timeGetTime(); // return the system time, in milliseconds
        """
        return emu.api.load_api_handler("kernel32").get_tick_count() & 0xFFFFFFFF
