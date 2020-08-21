# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from .. import api


class Mscoree(api.ApiHandler):

    """
    Implements exported functions from mscoree.dll.
    """

    name = 'mscoree'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Mscoree, self).__init__(emu)

        self.funcs = {}
        self.data = {}

        super(Mscoree, self).__get_hook_attrs__(self)

    @apihook('CorExitProcess', argc=1)
    def CorExitProcess(self, emu, argv, ctx={}):
        '''
        void STDMETHODCALLTYPE CorExitProcess (
            int  exitCode
        );
        '''

        return 0
