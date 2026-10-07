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
    def BCryptOpenAlgorithmProvider(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS BCryptOpenAlgorithmProvider(
          BCRYPT_ALG_HANDLE *phAlgorithm,
          LPCWSTR           pszAlgId,
          LPCWSTR           pszImplementation,
          ULONG             dwFlags
        );
        """
        phAlgorithm, pszAlgId, pszImplementation, dwFlags = argv

        algid = self.read_wide_string(pszAlgId)
        if algid:
            ctx.args["pszAlgId"].display = algid

        implementation = ""
        if pszImplementation:
            implementation = self.read_wide_string(pszImplementation)
            if implementation:
                ctx.args["pszImplementation"].display = implementation

        cm = emu.get_crypt_manager()
        hnd = cm.crypt_open(pname=implementation, ptype=algid, flags=dwFlags)
        if hnd:
            self.mem_write(phAlgorithm, hnd.to_bytes(emu.get_ptr_size(), "little"))
            ctx.args["phAlgorithm"].display = hex(hnd)

        return ntdefs.STATUS_SUCCESS

    @apihook("BCryptImportKeyPair", argc=7)
    def BCryptImportKeyPair(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
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
        hAlgorithm, hImportKey, pszBlobType, phKey, pbInput, cbInput, dwFlags = argv

        blob_type = self.read_wide_string(pszBlobType)
        ctx.args["pszBlobType"].display = blob_type

        cbInput = cbInput & 0xFFFFFFFF
        blob = self.mem_read(pbInput, cbInput)
        ctx.args["pbInput"].display = base64.b64encode(blob).decode("utf-8")

        cm = emu.get_crypt_manager()
        if hAlgorithm and phKey:
            alg_ctx = cm.crypt_get(hAlgorithm)
            hnd = alg_ctx.import_key(blob_type=blob_type, blob=blob, blob_len=cbInput, flags=dwFlags)
            if hnd:
                self.mem_write(phKey, hnd.to_bytes(emu.get_ptr_size(), "little"))
                ctx.args["phKey"].display = hex(hnd)

        return ntdefs.STATUS_SUCCESS

    @apihook("BCryptCloseAlgorithmProvider", argc=2)
    def BCryptCloseAlgorithmProvider(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS BCryptCloseAlgorithmProvider(
          BCRYPT_ALG_HANDLE hAlgorithm,
          ULONG             dwFlags
        );
        """
        hAlgorithm, dwFlags = argv

        cm = emu.get_crypt_manager()
        if hAlgorithm:
            cm.crypt_close(hAlgorithm)

        return ntdefs.STATUS_SUCCESS

    @apihook("BCryptGetProperty", argc=6)
    def BCryptGetProperty(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
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
        hObject, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags = argv

        property = self.read_wide_string(pszProperty)
        if property:
            ctx.args["pszProperty"].display = property

        # TODO: implement property retrieval

        return ntdefs.STATUS_SUCCESS

    @apihook("BCryptDestroyKey", argc=1)
    def BCryptDestroyKey(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS BCryptDestroyKey(
          BCRYPT_KEY_HANDLE hKey
        );
        """
        (hKey,) = argv
        cm = emu.get_crypt_manager()
        for hnd, crypt_ctx in cm.ctx_handles.items():
            hnd_key = crypt_ctx.get_key(hKey)
            if hnd_key:
                crypt_ctx.delete_key(hKey)
                return ntdefs.STATUS_SUCCESS

        return ntdefs.STATUS_INVALID_HANDLE
