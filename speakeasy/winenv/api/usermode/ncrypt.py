# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import base64

import speakeasy.winenv.defs.windows.windows as windefs

from .. import api


class Ncrypt(api.ApiHandler):
    """
    Implements exported functions from ncrypt.dll
    """
    name = 'ncrypt'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Ncrypt, self).__init__(emu)

        self.funcs = {}
        self.data = {}

        super(Ncrypt, self).__get_hook_attrs__(self)

    @apihook('NCryptOpenStorageProvider', argc=3)
    def NCryptOpenStorageProvider(self, emu, argv, ctx={}):
        """
        SECURITY_STATUS NCryptOpenStorageProvider(
            NCRYPT_PROV_HANDLE *phProvider,
            LPCWSTR            pszProviderName,
            DWORD              dwFlags
        );
        """
        phProvider, pszProviderName, dwFlags = argv
        if pszProviderName:
            prov_str = self.read_wide_string(pszProviderName)
            argv[1] = prov_str

            cm = emu.get_crypt_manager()
            hnd = cm.crypt_open(pname=prov_str, flags=dwFlags)
            if hnd:
                self.mem_write(phProvider, hnd.to_bytes(emu.get_ptr_size(), 'little'))

        return windefs.ERROR_SUCCESS

    @apihook('NCryptImportKey', argc=8)
    def NCryptImportKey(self, emu, argv, ctx={}):
        """
        SECURITY_STATUS NCryptImportKey(
            NCRYPT_PROV_HANDLE hProvider,
            NCRYPT_KEY_HANDLE  hImportKey,
            LPCWSTR            pszBlobType,
            NCryptBufferDesc   *pParameterList,
            NCRYPT_KEY_HANDLE  *phKey,
            PBYTE              pbData,
            DWORD              cbData,
            DWORD              dwFlags
        );
        """
        hProvider, hImportKey, pszBlobType, pParameterList, phKey, pbData, cbData, dwFlags = argv
        blob_type = self.read_wide_string(pszBlobType)
        argv[2] = blob_type

        blob = self.mem_read(pbData, cbData)
        argv[5] = base64.b64encode(blob).decode('utf-8')

        cm = emu.get_crypt_manager()
        if hProvider and phKey:
            ctx = cm.crypt_get(hProvider)
            hnd = ctx.import_key(blob_type=blob_type,
                                 blob=blob,
                                 blob_len=cbData,
                                 hnd_import_key=hImportKey,
                                 param_list=pParameterList,
                                 flags=dwFlags)
            if hnd:
                self.mem_write(phKey, hnd.to_bytes(emu.get_ptr_size(), 'little'))

        return windefs.ERROR_SUCCESS

    @apihook('NCryptDeleteKey', argc=2)
    def NCryptDeleteKey(self, emu, argv, ctx={}):
        """
        SECURITY_STATUS NCryptDeleteKey(
            NCRYPT_KEY_HANDLE hKey,
            DWORD             dwFlags
        );
        """
        hKey, dwFlags = argv
        cm = emu.get_crypt_manager()
        for hnd, ctx in cm.ctx_handles.items():
            hnd_key = ctx.get_key(hKey)
            if hnd_key:
                ctx.delete_key(hKey)
                break

        return windefs.ERROR_SUCCESS

    @apihook('NCryptFreeObject', argc=1)
    def NCryptFreeObject(self, emu, argv, ctx={}):
        """
        SECURITY_STATUS NCryptFreeObject(
            NCRYPT_HANDLE hObject
        );
        """
        hObject = argv[0]
        cm = emu.get_crypt_manager()

        # hObject can be a handle to a provider or key
        for hnd, ctx in cm.ctx_handles.items():
            if hnd == hObject:
                cm.crypt_close(hObject)
                break
            elif ctx.get_key(hObject):
                ctx.delete_key(hObject)
                break

        return windefs.ERROR_SUCCESS
