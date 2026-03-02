# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from urllib.parse import urlparse

import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.const import FILE_CREATE, FILE_WRITE

from .. import api


class Urlmon(api.ApiHandler):
    name = "urlmon"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super().__init__(emu)
        self.funcs = {}
        self.data = {}
        super().__get_hook_attrs__(self)
        self.netman = emu.get_network_manager()
        self.names = {}

    @apihook("URLDownloadToFile", argc=5)
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
            parsed = urlparse(url)
            if parsed.netloc:
                self.record_dns_event(parsed.netloc)

        if szFileName:
            name = self.read_mem_string(szFileName, cw)
            argv[2] = name
            self.record_file_access_event(name, FILE_CREATE)
            self.record_file_access_event(name, FILE_WRITE)

        return rv

    @apihook("URLDownloadToCacheFile", argc=6)
    def URLDownloadToCacheFile(self, emu, argv, ctx={}):
        """
        HRESULT URLDownloadToCacheFileA(
          LPUNKNOWN            pCaller,
          LPCSTR               szURL,
          LPSTR                szFileName,
          DWORD                cchFileName,
          DWORD                dwReserved,
          LPBINDSTATUSCALLBACK lpfnCB
        );
        """
        pCaller, szURL, szFileName, cchFileName, dwReserved, lpfnCB = argv
        rv = windefs.ERROR_SUCCESS
        cw = self.get_char_width(ctx)

        cache_name = "C:\\Windows\\Temp\\urlcache.bin"

        if szURL:
            url = self.read_mem_string(szURL, cw)
            argv[1] = url
            parsed = urlparse(url)
            if parsed.netloc:
                self.record_dns_event(parsed.netloc)
            tail = parsed.path.rsplit("/", 1)[-1]
            if tail:
                cache_name = f"C:\\Windows\\Temp\\{tail}"

        if szFileName:
            required = len(cache_name) + 1
            argv[2] = cache_name
            argv[3] = cchFileName
            if cchFileName >= required:
                self.write_mem_string(cache_name, szFileName, cw)
                self.record_file_access_event(cache_name, FILE_CREATE)
                self.record_file_access_event(cache_name, FILE_WRITE)
            else:
                rv = windefs.ERROR_INSUFFICIENT_BUFFER

        return rv
