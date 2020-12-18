# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.defs.windows.com as com
import speakeasy.winenv.defs.windows.windows as windefs

from .. import api


class Ole32(api.ApiHandler):

    name = 'ole32'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Ole32, self).__init__(emu)
        self.funcs = {}
        self.data = {}
        super(Ole32, self).__get_hook_attrs__(self)
        self.netman = emu.get_network_manager()
        self.names = {}

    @apihook('OleInitialize', argc=1)
    def OleInitialize(self, emu, argv, ctx={}):
        """
        HRESULT OleInitialize(
            IN LPVOID pvReserved
        );
        """

        rv = windefs.S_OK

        return rv

    @apihook('CoInitialize', argc=1)
    def CoInitialize(self, emu, argv, ctx={}):
        """
        HRESULT CoInitialize(
          LPVOID pvReserved
        );
        """

        rv = windefs.S_OK

        return rv

    @apihook('CoInitializeEx', argc=2)
    def CoInitializeEx(self, emu, argv, ctx={}):
        """
        HRESULT CoInitializeEx(
          LPVOID pvReserved,
          DWORD  dwCoInit
        );
        """

        rv = windefs.S_OK

        return rv

    @apihook('CoUninitialize', argc=0)
    def CoUninitialize(self, emu, argv, ctx={}):
        """
        void CoUninitialize();
        """

    @apihook('CoInitializeSecurity', argc=9)
    def CoInitializeSecurity(self, emu, argv, ctx={}):
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
            argv[4] = authn_level

        imp_level = com.get_define_int(argv[5])
        if imp_level:
            argv[5] = imp_level

        return rv

    @apihook('CoCreateInstance', argc=5)
    def CoCreateInstance(self, emu, argv, ctx={}):
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
            argv[0] = clsid_name
            riid_bytes = self.mem_read(riid, self.sizeof(windefs.GUID()))
            riid_str = com.convert_guid_bytes_to_str(riid_bytes)
            iid_name = com.get_iid(riid_str)
            if iid_name:
                argv[3] = iid_name
                if ppv:
                    ci = emu.com.get_interface(emu, emu.get_ptr_size(), iid_name.replace('IID_', ''))
                    pv = self.mem_alloc(emu.get_ptr_size(), tag='emu.COM.pv_%s' % iid_name)
                    self.mem_write(pv, ci.address.to_bytes(emu.get_ptr_size(), 'little'))
                    self.mem_write(ppv, pv.to_bytes(emu.get_ptr_size(), 'little'))
            else:
                self.emu.logger.info('Unsupported COM IID %s', riid)
        else:
            self.emu.logger.info('Unsupported COM CLSID %s', clsid_str)

        return rv

    @apihook('CoSetProxyBlanket', argc=8)
    def CoSetProxyBlanket(self, emu, argv, ctx={}):
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
        return 1

    @apihook('StringFromCLSID', argc=2)
    def StringFromCLSID(self, emu, argv, ctx={}):
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
        argv[1] = u
        u = (u + '\x00').encode('utf-16le')

        ptr = self.mem_alloc(len(u), tag='api.StringFromCLSID')

        if lplpsz:
            self.mem_write(lplpsz, ptr.to_bytes(emu.get_ptr_size(), 'little'))

        return rv
