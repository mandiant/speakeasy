# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from .. import api


class Shlwapi(api.ApiHandler):

    """
    Implements exported functions from shlwapi.dll
    """

    name = 'shlwapi'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Shlwapi, self).__init__(emu)

        self.funcs = {}
        self.data = {}
        self.window_hooks = {}
        self.handle = 0
        self.win = None

        super(Shlwapi, self).__get_hook_attrs__(self)

    @apihook('PathIsRelative', argc=1)
    def PathIsRelative(self, emu, argv, ctx={}):
        '''
        BOOL PathIsRelativeA(
            LPCSTR pszPath
        );
        '''

        pszPath, = argv

        cw = self.get_char_width(ctx)
        pn = ''
        rv = False
        if pszPath:
            pn = self.read_mem_string(pszPath, cw)
            if '..' in pn:
                rv = True

            argv[0] = pn

        return rv
