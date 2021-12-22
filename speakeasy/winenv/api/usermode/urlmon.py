# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from urllib.parse import urlparse

import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.const import FILE_WRITE, FILE_CREATE

from .. import api


class Urlmon(api.ApiHandler):

    name = 'urlmon'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Urlmon, self).__init__(emu)
        self.funcs = {}
        self.data = {}
        super(Urlmon, self).__get_hook_attrs__(self)
        self.netman = emu.get_network_manager()
        self.names = {}

    @apihook('URLDownloadToFile', argc=5)
    def URLDownloadToFile(self, emu, argv, ctx={}):
        """
        HRESULT URLDownloadToFile(
                    LPUNKNOWN            pCaller,
                    LPCTSTR              szURL,
                    LPCTSTR              szFileName,
                    DWORD                dwReserved,
                    LPBINDSTATUSCALLBACK lpfnCB
        );
        """

        pCaller, szURL, szFileName, dwReserved, lpfnCB = argv
        rv = windefs.ERROR_SUCCESS

        cw = self.get_char_width(ctx)

        if szURL:
            url = self.read_mem_string(szURL, cw)
            argv[1] = url
            url = urlparse(url)
            if url.netloc:
                self.log_dns(url.netloc)

        if szFileName:
            name = self.read_mem_string(szFileName, cw)
            argv[2] = name
            self.log_file_access(name, FILE_CREATE)
            self.log_file_access(name, FILE_WRITE)

        return rv
