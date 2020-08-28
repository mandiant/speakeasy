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

    @apihook('PathFindExtension', argc=1)
    def PathFindExtension(self, emu, argv, ctx={}):
        """LPCSTR PathFindExtensionA(
          LPCSTR pszPath
        );
        """
        pszPath, = argv
        cw = self.get_char_width(ctx)
        s = self.read_mem_string(pszPath, cw)
        argv[0] = s
        idx1 = s.rfind('\\')
        t = s[idx1 + 1:]
        idx2 = t.rfind('.')
        if idx2 == -1:
            return pszPath + len(s)

        argv[0] = t[idx2:]
        return pszPath + idx1 + 1 + idx2

    @apihook('PathFindFileName', argc=1)
    def PathFindFileName(self, emu, argv, ctx={}):
        """
        LPCSTR PathFindFileNameA(
          LPCSTR pszPath
        );
        """
        pszPath, = argv
        cw = self.get_char_width(ctx)
        s = self.read_mem_string(pszPath, cw)
        argv[0] = s
        idx = s.rfind('\\')
        if idx == -1:
            return pszPath + len(s)

        argv[0] = s[idx + 1:]
        return pszPath + idx + 1

    @apihook('PathRemoveExtension', argc=1)
    def PathRemoveExtension(self, emu, argv, ctx={}):
        """
        void PathRemoveExtensionA(
          LPSTR pszPath
        );
        """
        pszPath, = argv
        cw = self.get_char_width(ctx)
        s = self.read_mem_string(pszPath, cw)
        argv[0] = s
        idx1 = s.rfind('\\')
        t = s[idx1 + 1:]
        idx2 = t.rfind('.')
        if idx2 == -1:
            return pszPath

        s = s[:idx1 + 1 + idx2]
        argv[0] = s
        self.write_mem_string(s, pszPath, cw)
        return pszPath
