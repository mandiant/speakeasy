# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import base64
from typing import TYPE_CHECKING

import speakeasy.winenv.defs.windows.advapi32 as adv32defs
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.windows.cryptman import CryptContext, CryptKey

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator


class Ncrypt(api.ApiHandler):
    """
    Implements exported functions from ncrypt.dll
    """

    name = "ncrypt"
    sets_last_error = False
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs = {}
        self.data = {}

        super().__get_hook_attrs__(self)

    @apihook("NCryptOpenStorageProvider", argc=3)
    def NCryptOpenStorageProvider(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SECURITY_STATUS NCryptOpenStorageProvider(
            NCRYPT_PROV_HANDLE *phProvider,
            LPCWSTR pszProviderName,
            DWORD dwFlags
        );
        """
        phProvider, pszProviderName, dwFlags = argv
        prov_str = ""
        if pszProviderName:
            prov_str = self.read_wide_string(pszProviderName)
            ctx.args["pszProviderName"].display = prov_str

        cm = emu.get_crypt_manager()
        hnd = cm.crypt_open(pname=prov_str, flags=dwFlags)
        if hnd:
            self.write_ptr(phProvider, hnd)

        return windefs.ERROR_SUCCESS

    @apihook("NCryptImportKey", argc=8, fail=adv32defs.NTE_INVALID_HANDLE)
    def NCryptImportKey(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SECURITY_STATUS NCryptImportKey(
            NCRYPT_PROV_HANDLE hProvider,
            NCRYPT_KEY_HANDLE hImportKey,
            LPCWSTR pszBlobType,
            NCryptBufferDesc *pParameterList,
            NCRYPT_KEY_HANDLE *phKey,
            PBYTE pbData,
            DWORD cbData,
            DWORD dwFlags
        );
        """
        hProvider, hImportKey, pszBlobType, pParameterList, phKey, pbData, cbData, dwFlags = argv
        blob_type = self.read_wide_string(pszBlobType)
        ctx.args["pszBlobType"].display = blob_type

        cbData = cbData & 0xFFFFFFFF
        blob = self.mem_read(pbData, cbData)
        ctx.args["pbData"].display = base64.b64encode(blob).decode("utf-8")

        cm = emu.get_crypt_manager()
        if hProvider and phKey:
            prov_ctx = cm.get_context(hProvider)
            hnd = prov_ctx.import_key(
                blob_type=blob_type,
                blob=blob,
                blob_len=cbData,
                hnd_import_key=hImportKey,
                param_list=pParameterList,
                flags=dwFlags,
            )
            if hnd:
                self.write_ptr(phKey, hnd)

        return windefs.ERROR_SUCCESS

    @apihook("NCryptDeleteKey", argc=2, fail=adv32defs.NTE_INVALID_HANDLE)
    def NCryptDeleteKey(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SECURITY_STATUS NCryptDeleteKey(
            NCRYPT_KEY_HANDLE hKey,
            DWORD dwFlags
        );
        """
        hKey, dwFlags = argv
        emu.get_crypt_manager().delete_key(hKey)

        return windefs.ERROR_SUCCESS

    @apihook("NCryptFreeObject", argc=1, fail=adv32defs.NTE_INVALID_HANDLE)
    def NCryptFreeObject(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SECURITY_STATUS NCryptFreeObject(
            NCRYPT_HANDLE hObject
        );
        """
        (hObject,) = argv
        cm = emu.get_crypt_manager()

        # hObject can be a handle to a provider or key
        if isinstance(cm.handles.get(hObject, CryptContext, CryptKey), CryptContext):
            cm.crypt_close(hObject)
        else:
            cm.delete_key(hObject)

        return windefs.ERROR_SUCCESS
