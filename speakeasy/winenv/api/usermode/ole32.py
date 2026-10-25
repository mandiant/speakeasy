# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import logging
import random
import uuid

import speakeasy.winenv.defs.windows.com as com
import speakeasy.winenv.defs.windows.windows as windefs

from .. import api

logger = logging.getLogger(__name__)


class Ole32(api.ApiHandler):
    name = "ole32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        self.funcs = {}
        self.data = {}
        super().__get_hook_attrs__(self)
        self.netman = emu.get_network_manager()
        self.names = {}
        self.rng = random.Random(0)

    @apihook("OleInitialize", argc=1)
    def OleInitialize(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT OleInitialize(
            IN LPVOID pvReserved
        );
        """

        rv = windefs.S_OK

        return rv

    @apihook("CoInitialize", argc=1)
    def CoInitialize(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CoInitialize(
          LPVOID pvReserved
        );
        """

        rv = windefs.S_OK

        return rv

    @apihook("CoInitializeEx", argc=2)
    def CoInitializeEx(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CoInitializeEx(
          LPVOID pvReserved,
          DWORD  dwCoInit
        );
        """

        rv = windefs.S_OK

        return rv

    @apihook("CoUninitialize", argc=0)
    def CoUninitialize(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void CoUninitialize();
        """

    @apihook("CoInitializeSecurity", argc=9)
    def CoInitializeSecurity(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CoInitializeSecurity(
          PSECURITY_DESCRIPTOR        pSecDesc,
          LONG                        cAuthSvc,
          SOLE_AUTHENTICATION_SERVICE *asAuthSvc,
          void                        *pReserved1,
          DWORD                       dwAuthnLevel,
          DWORD                       dwImpLevel,
          void                        *pAuthList,
          DWORD                       dwCapabilities,
          void                        *pReserved3
        );
        """

        rv = windefs.S_OK

        authn_level = com.get_define_int(argv[4])
        if authn_level:
            ctx.args["dwAuthnLevel"].display = authn_level

        imp_level = com.get_define_int(argv[5])
        if imp_level:
            ctx.args["dwImpLevel"].display = imp_level

        return rv

    @apihook("CoCreateInstance", argc=5)
    def CoCreateInstance(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CoCreateInstance(
          REFCLSID  rclsid,
          LPUNKNOWN pUnkOuter,
          DWORD     dwClsContext,
          REFIID    riid,
          LPVOID    *ppv
        );
        """
        rclsid, pUnkOuter, dwClsContext, riid, ppv = argv
        rv = windefs.S_OK

        clsid_bytes = self.mem_read(rclsid, self.sizeof(windefs.GUID()))
        clsid_str = com.convert_guid_bytes_to_str(clsid_bytes)
        clsid_name = com.get_clsid(clsid_str)
        if clsid_name:
            ctx.args["rclsid"].display = clsid_name
            riid_bytes = self.mem_read(riid, self.sizeof(windefs.GUID()))
            riid_str = com.convert_guid_bytes_to_str(riid_bytes)
            iid_name = com.get_iid(riid_str)
            if iid_name:
                ctx.args["riid"].display = iid_name
                if ppv:
                    ci = emu.com.get_interface(emu, emu.get_ptr_size(), iid_name.replace("IID_", ""))
                    pv = self.mem_alloc(emu.get_ptr_size(), tag=f"emu.COM.pv_{iid_name}")
                    self.mem_write(pv, ci.address.to_bytes(emu.get_ptr_size(), "little"))
                    self.mem_write(ppv, pv.to_bytes(emu.get_ptr_size(), "little"))
                return rv
            logger.info("Unsupported COM IID %s", riid_str)
            rv = com.E_NOINTERFACE
        else:
            logger.info("Unsupported COM CLSID %s", clsid_str)
            rv = com.REGDB_E_CLASSNOTREG

        if ppv:
            self.mem_write(ppv, b"\x00" * emu.get_ptr_size())
        return rv

    @apihook("CoSetProxyBlanket", argc=8)
    def CoSetProxyBlanket(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CoSetProxyBlanket(
            IUnknown                 *pProxy,
            DWORD                    dwAuthnSvc,
            DWORD                    dwAuthzSvc,
            OLECHAR                  *pServerPrincName,
            DWORD                    dwAuthnLevel,
            DWORD                    dwImpLevel,
            RPC_AUTH_IDENTITY_HANDLE pAuthInfo,
            DWORD                    dwCapabilities
        );
        """
        return windefs.S_OK

    @apihook("StringFromCLSID", argc=2)
    def StringFromCLSID(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT StringFromCLSID(
        REFCLSID rclsid,
        LPOLESTR *lplpsz
        );
        """

        rclsid, lplpsz = argv
        rv = windefs.S_OK

        guid = self.mem_read(rclsid, self.sizeof(windefs.GUID()))
        u = com.convert_guid_bytes_to_str(guid)
        ctx.args["lplpsz"].display = u
        u = (u + "\x00").encode("utf-16le")

        ptr = self.mem_alloc(len(u), tag="api.StringFromCLSID")
        self.mem_write(ptr, u)

        if lplpsz:
            self.mem_write(lplpsz, ptr.to_bytes(emu.get_ptr_size(), "little"))

        return rv

    @apihook("CLSIDFromProgID", argc=2)
    def CLSIDFromProgID(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CLSIDFromProgID(
          LPCOLESTR lpszProgID,
          LPCLSID   lpclsid
        );
        """
        lpszProgID, lpclsid = argv

        progid = self.read_mem_string(lpszProgID, 2) if lpszProgID else ""
        clsid = com.PROGID_CLSIDS.get(progid.lower())
        if clsid is None:
            self.mem_write(lpclsid, b"\x00" * 16)
            return com.CO_E_CLASSSTRING

        self.mem_write(lpclsid, uuid.UUID(clsid).bytes_le)
        ctx.args["lpclsid"].display = clsid
        return windefs.S_OK

    @apihook("CLSIDFromProgIDEx", argc=2)
    def CLSIDFromProgIDEx(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CLSIDFromProgIDEx(
          LPCOLESTR lpszProgID,
          LPCLSID   lpclsid
        );
        """
        return self.CLSIDFromProgID(emu, argv, ctx)

    @apihook("StringFromGUID2", argc=3)
    def StringFromGUID2(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int StringFromGUID2(
          REFGUID  rguid,
          LPOLESTR lpsz,
          int      cchMax
        );
        """
        rguid, lpsz, cchMax = argv

        guid = self.mem_read(rguid, self.sizeof(windefs.GUID()))
        u = com.convert_guid_bytes_to_str(guid) + "\x00"
        if cchMax < len(u):
            return 0

        self.write_mem_string(u, lpsz, 2)
        ctx.args["lpsz"].display = u[:-1]
        return len(u)

    @apihook("CoTaskMemAlloc", argc=1)
    def CoTaskMemAlloc(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPVOID CoTaskMemAlloc(
          SIZE_T cb
        );
        """
        (cb,) = argv
        return self.heap_alloc(max(cb, 1), heap="CoTaskMemAlloc")

    @apihook("CoTaskMemRealloc", argc=2)
    def CoTaskMemRealloc(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPVOID CoTaskMemRealloc(
          LPVOID pv,
          SIZE_T cb
        );
        """
        pv, cb = argv
        if pv and not cb:
            self.heap_free(pv)
            return 0
        new = self.heap_alloc(max(cb, 1), heap="CoTaskMemAlloc")
        if pv:
            old = self.heap_size(pv)
            if old is None:
                self.heap_free(new)
                return 0
            self.mem_write(new, self.mem_read(pv, min(old, cb)))
            self.heap_free(pv)
        return new

    @apihook("CoTaskMemFree", argc=1)
    def CoTaskMemFree(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void CoTaskMemFree(
          LPVOID pv
        );
        """
        (pv,) = argv
        if pv:
            self.heap_free(pv)

    @apihook("CoCreateGuid", argc=1)
    def CoCreateGuid(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CoCreateGuid(
          GUID *pguid
        );
        """
        (pguid,) = argv
        if not pguid:
            return windefs.E_INVALIDARG
        guid = bytearray(self.rng.randbytes(16))
        guid[7] = guid[7] & 0x0F | 0x40
        guid[8] = guid[8] & 0x3F | 0x80
        self.mem_write(pguid, bytes(guid))
        return windefs.S_OK
