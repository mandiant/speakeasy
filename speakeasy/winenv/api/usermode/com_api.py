# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from .. import api
import speakeasy.winenv.defs.windows.com as comdefs


class ComApi(api.ApiHandler):
    """
    Implements COM interfaces
    """
    name = 'com_api'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(ComApi, self).__init__(emu)

        self.funcs = {}
        self.data = {}

        super(ComApi, self).__get_hook_attrs__(self)

    # First argument (self) is not reflected in method definitions; note this increases argc by 1
    @apihook('IUnknown.QueryInterface', argc=3)
    def IUnknown_QueryInterface(self, emu, argv, ctx={}):
        """
        HRESULT QueryInterface(
            REFIID riid,
            void   **ppvObject
        );
        """
        # not implemented
        return comdefs.S_OK

    @apihook('IUnknown.AddRef', argc=1)
    def IUnknown_AddRef(self, emu, argv, ctx={}):
        """
        ULONG AddRef();
        """
        # not implemented
        return 1

    @apihook('IUnknown.Release', argc=1)
    def IUnknown_Release(self, emu, argv, ctx={}):
        """
        ULONG Release();
        """
        # not implemented
        return 0

    @apihook('IWbemLocator.ConnectServer', argc=9)
    def IWbemLocator_ConnectServer(self, emu, argv, ctx={}):
        """
        HRESULT ConnectServer(
            const BSTR    strNetworkResource,
            const BSTR    strUser,
            const BSTR    strPassword,
            const BSTR    strLocale,
            long          lSecurityFlags,
            const BSTR    strAuthority,
            IWbemContext  *pCtx,
            IWbemServices **ppNamespace
        );
        """
        ptr, strNetworkResource, strUser, strPassword, strLocale, lSecurityFlags, strAuthority, \
            pCtx, ppNamespace = argv
        argv[1] = self.read_wide_string(strNetworkResource)

        if ppNamespace:
            ci = emu.com.get_interface(emu, emu.get_ptr_size(), 'IWbemServices')
            pNamespace = self.mem_alloc(emu.get_ptr_size(),
                                        tag='emu.COM.ppNamespace_IWbemServices')
            self.mem_write(pNamespace, ci.address.to_bytes(emu.get_ptr_size(), 'little'))
            self.mem_write(ppNamespace, pNamespace.to_bytes(emu.get_ptr_size(), 'little'))

        return comdefs.S_OK

    @apihook('IWbemServices.ExecQuery', argc=6)
    def IWbemServices_ExecQuery(self, emu, argv, ctx={}):
        """
        HRESULT ExecQuery(
            const BSTR           strQueryLanguage,
            const BSTR           strQuery,
            long                 lFlags,
            IWbemContext         *pCtx,
            IEnumWbemClassObject **ppEnum
        );
        """
        ptr, strQueryLanguage, strQuery, lFlags, pCtx, ppEnum = argv
        argv[1] = self.read_wide_string(strQueryLanguage)
        argv[2] = self.read_wide_string(strQuery)

        # not implemented so returning -1
        return -1
