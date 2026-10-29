# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import uuid

import speakeasy.winenv.defs.registry.reg as regdefs
import speakeasy.winenv.defs.windows.com as comdefs
import speakeasy.winenv.defs.windows.windows as windefs

from .. import api


class RPCRT4(api.ApiHandler):
    """
    Implements exported functions from rpcrt4.dll
    """

    name = "rpcrt4"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

    @apihook("UuidCreate", argc=1)
    def UuidCreate(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        RPC_STATUS UuidCreate(
          UUID *Uuid
        );
        """
        (uuidp,) = argv

        if not uuidp:
            return 1

        self.mem_write(uuidp, uuid.UUID(bytes=emu.rng.randbytes(16), version=4).bytes_le)

        return 0

    @apihook("UuidToStringA", argc=2)
    def UuidToStringA(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        RPC_STATUS UuidToStringA(
          const UUID *Uuid,
          RPC_CSTR   *StringUuid
        );
        """
        uuidp, stringp = argv

        if not uuidp or not stringp:
            return 1

        uuid_bytes = self.mem_read(uuidp, windefs.GUID().sizeof())
        uuid_obj = uuid.UUID(bytes_le=uuid_bytes)

        string = str(uuid_obj) + "\0"

        buf = self.mem_alloc(len(string), tag="api.UuidToStringA")
        self.mem_write(buf, string.encode("utf-8"))
        self.mem_write(stringp, buf.to_bytes(self.get_ptr_size(), "little"))

        return 0

    def read_guid_string(self, addr):
        guid = uuid.UUID(bytes_le=bytes(self.mem_read(addr, 16)))
        return f"{{{str(guid).upper()}}}"

    def get_proxy_interfaces(self, proxy_file_list):
        """
        Walk a NULL terminated list of ProxyFileInfo structures and get the
        IID, name and method count of each interface
        """
        ptr_size = self.get_ptr_size()
        interfaces = []
        while info := self.emu.read_ptr(proxy_file_list):
            stubs = self.emu.read_ptr(info + ptr_size)
            names = self.emu.read_ptr(info + ptr_size * 2)
            table_size = int.from_bytes(self.mem_read(info + ptr_size * 5, 2), "little")
            for i in range(table_size):
                stub = self.emu.read_ptr(stubs + i * ptr_size)
                iid = self.read_guid_string(self.emu.read_ptr(stub))
                method_count = int.from_bytes(self.mem_read(stub + ptr_size * 2, 4), "little")
                name_ptr = self.emu.read_ptr(names + i * ptr_size) if names else 0
                name = self.read_mem_string(name_ptr, 1) if name_ptr else ""
                interfaces.append((iid, name, method_count))
            proxy_file_list += ptr_size
        return interfaces

    @apihook("NdrDllRegisterProxy", argc=3)
    def NdrDllRegisterProxy(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT NdrDllRegisterProxy(
          HMODULE              hDll,
          const ProxyFileInfo **pProxyFileList,
          const CLSID          *pclsid
        );
        """
        hDll, pProxyFileList, pclsid = argv

        interfaces = self.get_proxy_interfaces(pProxyFileList)
        if pclsid:
            clsid = self.read_guid_string(pclsid)
        elif interfaces:
            clsid = interfaces[0][0]
        else:
            return comdefs.S_OK

        for iid, name, method_count in interfaces:
            key = emu.regman.create_key(f"HKEY_CLASSES_ROOT\\Interface\\{iid}")
            if name:
                key.create_value("", regdefs.REG_SZ, name)
            key = emu.regman.create_key(f"HKEY_CLASSES_ROOT\\Interface\\{iid}\\NumMethods")
            key.create_value("", regdefs.REG_SZ, str(method_count))
            key = emu.regman.create_key(f"HKEY_CLASSES_ROOT\\Interface\\{iid}\\ProxyStubClsid32")
            key.create_value("", regdefs.REG_SZ, clsid)

        key = emu.regman.create_key(f"HKEY_CLASSES_ROOT\\CLSID\\{clsid}")
        key.create_value("", regdefs.REG_SZ, "PSFactoryBuffer")
        mod = emu.get_mod_from_addr(hDll)
        if mod:
            key = emu.regman.create_key(f"HKEY_CLASSES_ROOT\\CLSID\\{clsid}\\InprocServer32")
            key.create_value("", regdefs.REG_SZ, mod.emu_path)
            key.create_value("ThreadingModel", regdefs.REG_SZ, "Both")

        return comdefs.S_OK

    @apihook("NdrDllUnregisterProxy", argc=3)
    def NdrDllUnregisterProxy(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT NdrDllUnregisterProxy(
          HMODULE              hDll,
          const ProxyFileInfo **pProxyFileList,
          const CLSID          *pclsid
        );
        """
        return comdefs.S_OK

    @apihook("NdrDllGetClassObject", argc=6)
    def NdrDllGetClassObject(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT NdrDllGetClassObject(
          REFCLSID             rclsid,
          REFIID               riid,
          void                 **ppv,
          const ProxyFileInfo  **pProxyFileList,
          const CLSID          *pclsid,
          CStdPSFactoryBuffer  *pPSFactoryBuffer
        );
        """
        _rclsid, _riid, ppv, _proxy_file_list, _pclsid, _factory = argv

        if ppv:
            self.mem_write(ppv, b"\x00" * self.get_ptr_size())
        return comdefs.CLASS_E_CLASSNOTAVAILABLE

    @apihook("NdrDllCanUnloadNow", argc=1)
    def NdrDllCanUnloadNow(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT NdrDllCanUnloadNow(
          CStdPSFactoryBuffer *pPSFactoryBuffer
        );
        """
        (factory,) = argv

        ref_count = int.from_bytes(self.mem_read(factory + self.get_ptr_size(), 4), "little")
        return comdefs.S_FALSE if ref_count else comdefs.S_OK
