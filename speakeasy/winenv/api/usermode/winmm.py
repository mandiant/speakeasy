from .. import api

import time

class Winmm(api.ApiHandler):
    """
    Emulates functions from winmm.dll
    """

    name = 'winmm'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        
        super(Winmm, self).__init__(emu)
        super(Winmm, self).__get_hook_attrs__(self)

    @apihook('timeGetTime', argc=0)
    def timeGetTime(self, emu, argv, ctx={}):        
        '''
        DWORD timeGetTime(); // return the system time, in milliseconds
        '''
        return int(time.monotonic() * 1000) & 0xffffffff
        

        
