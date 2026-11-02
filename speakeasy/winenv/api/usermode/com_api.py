# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from typing import TYPE_CHECKING

import speakeasy.winenv.defs.windows.com as comdefs

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator


class ComApi(api.ApiHandler):
    """
    Implements COM interfaces
    """

    name = "com_api"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs = {}
        self.data = {}

        super().__get_hook_attrs__(self)

    # First argument (self) is not reflected in method definitions; note this increases argc by 1
    @apihook("IUnknown.QueryInterface", argc=3)
    def IUnknown_QueryInterface(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT IUnknown::QueryInterface(
            REFIID riid,
            void **ppvObject
        );

        argv[0] is the interface pointer (this).
        """
        ptr, riid, ppvObject = argv
        if not ppvObject:
            return comdefs.E_POINTER

        iid = comdefs.convert_guid_bytes_to_str(self.mem_read(riid, 16))
        iid_name = comdefs.get_iid(iid)
        if iid_name:
            ctx.args[1].display = iid_name
            self.mem_write(ppvObject, ptr.to_bytes(emu.get_ptr_size(), "little"))
            return comdefs.S_OK

        self.mem_write(ppvObject, b"\x00" * emu.get_ptr_size())
        return comdefs.E_NOINTERFACE

    @apihook("IUnknown.AddRef", argc=1)
    def IUnknown_AddRef(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        ULONG IUnknown::AddRef();

        argv[0] is the interface pointer (this).
        """
        # not implemented
        return 1

    @apihook("IUnknown.Release", argc=1)
    def IUnknown_Release(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        ULONG IUnknown::Release();

        argv[0] is the interface pointer (this).
        """
        # not implemented
        return 0

    @apihook("IMalloc.Alloc", argc=2)
    def IMalloc_Alloc(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void *IMalloc::Alloc(
            SIZE_T cb
        );

        argv[0] is the interface pointer (this).
        """
        ptr, cb = argv
        return self.heap_alloc(max(cb, 1), heap="CoTaskMemAlloc")

    @apihook("IMalloc.Realloc", argc=3)
    def IMalloc_Realloc(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void *IMalloc::Realloc(
            void *pv,
            SIZE_T cb
        );

        argv[0] is the interface pointer (this).
        """
        ptr, pv, cb = argv
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

    @apihook("IMalloc.Free", argc=2)
    def IMalloc_Free(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void IMalloc::Free(
            void *pv
        );

        argv[0] is the interface pointer (this).
        """
        ptr, pv = argv
        if pv:
            self.heap_free(pv)

    @apihook("IMalloc.GetSize", argc=2)
    def IMalloc_GetSize(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SIZE_T IMalloc::GetSize(
            void *pv
        );

        argv[0] is the interface pointer (this).
        """
        ptr, pv = argv
        size = self.heap_size(pv) if pv else None
        if size is None:
            return (1 << (8 * emu.get_ptr_size())) - 1
        return size

    @apihook("IMalloc.DidAlloc", argc=2)
    def IMalloc_DidAlloc(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int IMalloc::DidAlloc(
            void *pv
        );

        argv[0] is the interface pointer (this).
        """
        ptr, pv = argv
        if not pv:
            return 0xFFFFFFFF
        return int(self.heap_size(pv) is not None)

    @apihook("IMalloc.HeapMinimize", argc=1)
    def IMalloc_HeapMinimize(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void IMalloc::HeapMinimize();

        argv[0] is the interface pointer (this).
        """

    @apihook("IWbemLocator.ConnectServer", argc=9)
    def IWbemLocator_ConnectServer(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT IWbemLocator::ConnectServer(
            const BSTR strNetworkResource,
            const BSTR strUser,
            const BSTR strPassword,
            const BSTR strLocale,
            long lSecurityFlags,
            const BSTR strAuthority,
            IWbemContext *pCtx,
            IWbemServices **ppNamespace
        );

        argv[0] is the interface pointer (this).
        """
        ptr, strNetworkResource, strUser, strPassword, strLocale, lSecurityFlags, strAuthority, pCtx, ppNamespace = argv
        ctx.args[1].display = self.read_wide_string(strNetworkResource)

        if ppNamespace:
            ci = emu.com.get_interface(emu, emu.get_ptr_size(), "IWbemServices")
            pNamespace = self.mem_alloc(emu.get_ptr_size(), tag="emu.COM.ppNamespace_IWbemServices")
            self.mem_write(pNamespace, ci.address.to_bytes(emu.get_ptr_size(), "little"))
            self.mem_write(ppNamespace, pNamespace.to_bytes(emu.get_ptr_size(), "little"))

        return comdefs.S_OK

    @apihook("IWbemServices.GetObject", argc=6)
    def IWbemServices_GetObject(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT IWbemServices::GetObject(
            const BSTR strObjectPath,
            long lFlags,
            IWbemContext *pCtx,
            IWbemClassObject **ppObject,
            IWbemCallResult **ppCallResult
        );

        argv[0] is the interface pointer (this).
        """
        ptr, strObjectPath, lFlags, pCtx, ppObject, ppCallResult = argv
        if strObjectPath:
            ctx.args[1].display = self.read_wide_string(strObjectPath)

        for out in (ppObject, ppCallResult):
            if out:
                self.mem_write(out, b"\x00" * emu.get_ptr_size())

        return comdefs.WBEM_E_NOT_FOUND

    @apihook("IWbemServices.ExecQuery", argc=6)
    def IWbemServices_ExecQuery(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT IWbemServices::ExecQuery(
            const BSTR strQueryLanguage,
            const BSTR strQuery,
            long lFlags,
            IWbemContext *pCtx,
            IEnumWbemClassObject **ppEnum
        );

        argv[0] is the interface pointer (this).
        """
        ptr, strQueryLanguage, strQuery, lFlags, pCtx, ppEnum = argv
        ctx.args[1].display = self.read_wide_string(strQueryLanguage)
        ctx.args[2].display = self.read_wide_string(strQuery)

        # not implemented so returning -1
        return -1
