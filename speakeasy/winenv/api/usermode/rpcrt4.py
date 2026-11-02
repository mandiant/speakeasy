# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import uuid
from typing import TYPE_CHECKING

import speakeasy.winenv.defs.windows.com as comdefs
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.winenv.defs.registry.reg import REG_VALUE_TYPE

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator


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
    def UuidCreate(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        RPC_STATUS UuidCreate(
            UUID *Uuid
        );
        """
        (Uuid,) = argv

        if not Uuid:
            return 1

        self.mem_write(Uuid, uuid.UUID(bytes=emu.rng.randbytes(16), version=4).bytes_le)

        return 0

    @apihook("UuidToStringA", argc=2)
    def UuidToStringA(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        RPC_STATUS UuidToStringA(
            const UUID *Uuid,
            RPC_CSTR *StringUuid
        );
        """
        Uuid, StringUuid = argv

        if not Uuid or not StringUuid:
            return 1

        uuid_bytes = self.mem_read(Uuid, windefs.GUID().sizeof())
        uuid_obj = uuid.UUID(bytes_le=uuid_bytes)

        string = str(uuid_obj) + "\0"

        buf = self.mem_alloc(len(string), tag="api.UuidToStringA")
        self.mem_write(buf, string.encode("utf-8"))
        self.write_ptr(StringUuid, buf)

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
        while info := self.read_ptr(proxy_file_list):
            stubs = self.read_ptr(info + ptr_size)
            names = self.read_ptr(info + ptr_size * 2)
            table_size = int.from_bytes(self.mem_read(info + ptr_size * 5, 2), "little")
            for i in range(table_size):
                stub = self.read_ptr(stubs + i * ptr_size)
                iid = self.read_guid_string(self.read_ptr(stub))
                method_count = self.read_dword(stub + ptr_size * 2)
                name_ptr = self.read_ptr(names + i * ptr_size) if names else 0
                name = self.read_mem_string(name_ptr, 1) if name_ptr else ""
                interfaces.append((iid, name, method_count))
            proxy_file_list += ptr_size
        return interfaces

    @apihook("NdrDllRegisterProxy", argc=3)
    def NdrDllRegisterProxy(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT NdrDllRegisterProxy(
            HMODULE hDll,
            const ProxyFileInfo **pProxyFileList,
            const CLSID *pclsid
        );
        """
        hDll, pProxyFileList, pclsid = argv

        interfaces = self.get_proxy_interfaces(pProxyFileList)
        if pclsid:
            clsid = self.read_guid_string(pclsid)
        elif interfaces:
            clsid = interfaces[0][0]
        else:
            return windefs.S_OK

        for iid, name, method_count in interfaces:
            key = emu.regman.create_key(f"HKEY_CLASSES_ROOT\\Interface\\{iid}")
            if name:
                key.create_value("", REG_VALUE_TYPE.REG_SZ, name)
            key = emu.regman.create_key(f"HKEY_CLASSES_ROOT\\Interface\\{iid}\\NumMethods")
            key.create_value("", REG_VALUE_TYPE.REG_SZ, str(method_count))
            key = emu.regman.create_key(f"HKEY_CLASSES_ROOT\\Interface\\{iid}\\ProxyStubClsid32")
            key.create_value("", REG_VALUE_TYPE.REG_SZ, clsid)

        key = emu.regman.create_key(f"HKEY_CLASSES_ROOT\\CLSID\\{clsid}")
        key.create_value("", REG_VALUE_TYPE.REG_SZ, "PSFactoryBuffer")
        mod = emu.get_mod_from_addr(hDll)
        if mod:
            key = emu.regman.create_key(f"HKEY_CLASSES_ROOT\\CLSID\\{clsid}\\InprocServer32")
            key.create_value("", REG_VALUE_TYPE.REG_SZ, mod.emu_path)
            key.create_value("ThreadingModel", REG_VALUE_TYPE.REG_SZ, "Both")

        return windefs.S_OK

    @apihook("NdrDllUnregisterProxy", argc=3)
    def NdrDllUnregisterProxy(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT NdrDllUnregisterProxy(
            HMODULE hDll,
            const ProxyFileInfo **pProxyFileList,
            const CLSID *pclsid
        );
        """
        return windefs.S_OK

    @apihook("NdrDllGetClassObject", argc=6)
    def NdrDllGetClassObject(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT NdrDllGetClassObject(
            REFCLSID rclsid,
            REFIID riid,
            void **ppv,
            const ProxyFileInfo **pProxyFileList,
            const CLSID *pclsid,
            CStdPSFactoryBuffer *pPSFactoryBuffer
        );
        """
        rclsid, riid, ppv, pProxyFileList, pclsid, pPSFactoryBuffer = argv

        if ppv:
            self.mem_write(ppv, b"\x00" * self.get_ptr_size())
        return comdefs.CLASS_E_CLASSNOTAVAILABLE

    @apihook("NdrDllCanUnloadNow", argc=1)
    def NdrDllCanUnloadNow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT NdrDllCanUnloadNow(
            CStdPSFactoryBuffer *pPSFactoryBuffer
        );
        """
        (pPSFactoryBuffer,) = argv

        ref_count = self.read_dword(pPSFactoryBuffer + self.get_ptr_size())
        return comdefs.S_FALSE if ref_count else windefs.S_OK
