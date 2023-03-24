from .. import api

import time

class sfc(api.ApiHandler):
    """
    Emulates functions from sfc.dll
    """

    name = 'sfc'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super(sfc, self).__init__(emu)
        super(sfc, self).__get_hook_attrs__(self)

    @apihook('SfcIsFileProtected', argc=2)
    def SfcIsFileProtected(self, emu, argv, ctx={}):
        return False
