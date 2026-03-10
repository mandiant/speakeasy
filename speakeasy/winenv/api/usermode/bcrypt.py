# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import base64

import speakeasy.winenv.defs.nt.ddk as ntdefs

from .. import api


class Bcrypt(api.ApiHandler):
    """
    Implements exported functions from bcrypt.dll
    """

    name = "bcrypt"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super().__init__(emu)

        self.funcs = {}
        self.data = {}

        super().__get_hook_attrs__(self)

    @apihook("BCryptOpenAlgorithmProvider", argc=4)
    def BCryptOpenAlgorithmProvider(self, emu, argv, ctx: api.ApiContext = None):
        """
        NTSTATUS BCryptOpenAlgorithmProvider(
          BCRYPT_ALG_HANDLE *phAlgorithm,
          LPCWSTR           pszAlgId,
          LPCWSTR           pszImplementation,
          ULONG             dwFlags
        );
        """
        ctx = ctx or {}
        phAlgorithm, pszAlgId, pszImplementation, dwFlags = argv

        algid = self.read_wide_string(pszAlgId)
        if algid:
            argv[1] = algid

        implementation = ""
        if pszImplementation:
            implementation = self.read_wide_string(pszImplementation)
            if implementation:
                argv[2] = implementation

        cm = emu.get_crypt_manager()
        hnd = cm.crypt_open(pname=implementation, ptype=algid, flags=dwFlags)
        if hnd:
            self.mem_write(phAlgorithm, hnd.to_bytes(emu.get_ptr_size(), "little"))
            argv[0] = hnd

        return ntdefs.STATUS_SUCCESS

    @apihook("BCryptImportKeyPair", argc=7)
    def BCryptImportKeyPair(self, emu, argv, ctx: api.ApiContext = None):
        """
        NTSTATUS BCryptImportKeyPair(
          BCRYPT_ALG_HANDLE hAlgorithm,
          BCRYPT_KEY_HANDLE hImportKey,
          LPCWSTR           pszBlobType,
          BCRYPT_KEY_HANDLE *phKey,
          PUCHAR            pbInput,
          ULONG             cbInput,
          ULONG             dwFlags
        );
        """
        ctx = ctx or {}
        hAlgorithm, hImportKey, pszBlobType, phKey, pbInput, cbInput, dwFlags = argv

        blob_type = self.read_wide_string(pszBlobType)
        argv[2] = blob_type

        cbInput = cbInput & 0xFFFFFFFF
        blob = self.mem_read(pbInput, cbInput)
        argv[4] = base64.b64encode(blob).decode("utf-8")

        cm = emu.get_crypt_manager()
        if hAlgorithm and phKey:
            ctx = cm.crypt_get(hAlgorithm)
            hnd = ctx.import_key(blob_type=blob_type, blob=blob, blob_len=cbInput, flags=dwFlags)
            if hnd:
                self.mem_write(phKey, hnd.to_bytes(emu.get_ptr_size(), "little"))
                argv[3] = hnd

        return ntdefs.STATUS_SUCCESS

    @apihook("BCryptCloseAlgorithmProvider", argc=2)
    def BCryptCloseAlgorithmProvider(self, emu, argv, ctx: api.ApiContext = None):
        """
        NTSTATUS BCryptCloseAlgorithmProvider(
          BCRYPT_ALG_HANDLE hAlgorithm,
          ULONG             dwFlags
        );
        """
        ctx = ctx or {}
        hAlgorithm, dwFlags = argv

        cm = emu.get_crypt_manager()
        if hAlgorithm:
            cm.crypt_close(hAlgorithm)

        return ntdefs.STATUS_SUCCESS

    @apihook("BCryptGetProperty", argc=6)
    def BCryptGetProperty(self, emu, argv, ctx: api.ApiContext = None):
        """
        NTSTATUS BCryptGetProperty(
          BCRYPT_HANDLE hObject,
          LPCWSTR       pszProperty,
          PUCHAR        pbOutput,
          ULONG         cbOutput,
          ULONG         *pcbResult,
          ULONG         dwFlags
        );
        """
        ctx = ctx or {}
        hObject, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags = argv

        property = self.read_wide_string(pszProperty)
        if property:
            argv[1] = property

        # TODO: implement property retrieval

        return ntdefs.STATUS_SUCCESS

    @apihook("BCryptDestroyKey", argc=1)
    def BCryptDestroyKey(self, emu, argv, ctx: api.ApiContext = None):
        """
        NTSTATUS BCryptDestroyKey(
          BCRYPT_KEY_HANDLE hKey
        );
        """
        ctx = ctx or {}
        (hKey,) = argv
        cm = emu.get_crypt_manager()
        for hnd, ctx in cm.ctx_handles.items():
            hnd_key = ctx.get_key(hKey)
            if hnd_key:
                ctx.delete_key(hKey)
                return ntdefs.STATUS_SUCCESS

        return ntdefs.STATUS_INVALID_HANDLE
