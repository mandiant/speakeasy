# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct

from speakeasy.struct import EmuStruct, Ptr
import speakeasy.winenv.defs.windows.windows as windefs

from .. import api

DNS_TYPE_TEXT = 0x0010


class _DnsRecord(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.pNext = Ptr
        self.pName = Ptr
        self.wType = ct.c_uint16
        self.wDataLength = ct.c_uint16
        self.Flags = ct.c_uint32
        self.dwTtl = ct.c_uint32
        self.dwReserved = ct.c_uint32


class DNS_TXT_DATA(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.dwStringCount = Ptr
        self.pStringArray = Ptr


class DnsApi(api.ApiHandler):

    name = 'dnsapi'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(DnsApi, self).__init__(emu)
        self.funcs = {}
        self.data = {}
        super(DnsApi, self).__get_hook_attrs__(self)
        self.netman = emu.get_network_manager()
        self.names = {}

    @apihook('DnsQuery_', argc=6)
    def DnsQuery_(self, emu, argv, ctx={}):
        """
        DNS_STATUS DnsQuery_A(
            PCSTR       pszName,
            WORD        wType,
            DWORD       Options,
            PVOID       pExtra,
            PDNS_RECORD *ppQueryResults,
            PVOID       *pReserved
        );
        """

        pszName, wType, Options, pExtra, ppQueryResults, pReserved = argv
        rv = windefs.ERROR_INVALID_PARAMETER
        rr = None

        cw = self.get_char_width(ctx)
        if pszName:
            name = self.read_mem_string(pszName, cw)
            ip = self.netman.name_lookup(name)
            self.log_dns(name, ip)

            rec = _DnsRecord(emu.get_ptr_size())
            rec.pName = pszName
            rec.wType = wType
            if wType == DNS_TYPE_TEXT:
                argv[1] = 'DNS_TYPE_TEXT'

                text = self.netman.get_dns_txt(name)
                if not text:
                    text = b'\x00'*12

                ts = DNS_TXT_DATA(emu.get_ptr_size())
                size = len(text) + ts.sizeof()

                rr = self.mem_alloc(rec.sizeof() + size, tag='api.DnsQuery._DnsRecord')
                ts.dwStringCount = 1
                ts.pStringArray = rr + rec.sizeof() + ts.sizeof()
                rec.wDataLength = size

                self.mem_write(rr, rec.get_bytes() + ts.get_bytes())
                self.mem_write(ts.pStringArray, text)

            if ppQueryResults and rr:
                out = rr.to_bytes(self.get_ptr_size(), 'little')
                self.mem_write(ppQueryResults, out)
                rv = windefs.ERROR_SUCCESS

        return rv
