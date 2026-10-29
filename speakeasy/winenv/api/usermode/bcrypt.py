# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import base64
import struct

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import speakeasy.winenv.defs.nt.ddk as ntdefs

from .. import api

BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x2
BCRYPT_BLOCK_PADDING = 0x1
BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG = 0x1
STATUS_DATA_ERROR = 0xC000003E
STATUS_INVALID_BUFFER_SIZE = 0xC0000206
STATUS_AUTH_TAG_MISMATCH = 0xC000A002

CHAINING_MODES = (
    "ChainingModeN/A",
    "ChainingModeCBC",
    "ChainingModeECB",
    "ChainingModeCFB",
    "ChainingModeCCM",
    "ChainingModeGCM",
)
AES_OBJECT_LENGTH = 654
AES_BLOCK_LENGTH = 16
AES_KEY_LENGTHS = (16, 24, 32)
GCM_NONCE_LENGTH = 12
GCM_TAG_LENGTHS = (12, 16, 1)


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
            if not alg_ctx:
                return ntdefs.STATUS_INVALID_HANDLE
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
        if not cm.crypt_get(hAlgorithm):
            return ntdefs.STATUS_INVALID_HANDLE
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

        alg_ctx = emu.get_crypt_manager().crypt_get(hObject)
        key = None
        if not alg_ctx:
            alg_ctx, key = self.get_key(emu, hObject)
        # Properties of other algorithms are not emulated
        if not alg_ctx or not is_aes(alg_ctx):
            return ntdefs.STATUS_SUCCESS

        value = get_aes_property(property, key or alg_ctx, key)
        if value is None:
            return ntdefs.STATUS_NOT_SUPPORTED
        self.write_result_size(pcbResult, len(value))
        if not pbOutput:
            return ntdefs.STATUS_SUCCESS
        if cbOutput & 0xFFFFFFFF < len(value):
            return ntdefs.STATUS_BUFFER_TOO_SMALL
        self.mem_write(pbOutput, value)
        return ntdefs.STATUS_SUCCESS

    @apihook("BCryptSetProperty", argc=5)
    def BCryptSetProperty(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS BCryptSetProperty(
          BCRYPT_HANDLE hObject,
          LPCWSTR       pszProperty,
          PUCHAR        pbInput,
          ULONG         cbInput,
          ULONG         dwFlags
        );
        """
        hObject, pszProperty, pbInput, cbInput, dwFlags = argv

        property = self.read_wide_string(pszProperty)
        ctx.args["pszProperty"].display = property

        obj = emu.get_crypt_manager().crypt_get(hObject) or self.get_key(emu, hObject)[1]
        if not obj:
            return ntdefs.STATUS_INVALID_HANDLE

        if property == "ChainingMode":
            mode = self.read_wide_string(pbInput, max_chars=(cbInput & 0xFFFFFFFF) // 2)
            ctx.args["pbInput"].display = mode
            if mode not in CHAINING_MODES:
                return ntdefs.STATUS_NOT_SUPPORTED
            obj.chaining_mode = mode

        return ntdefs.STATUS_SUCCESS

    @apihook("BCryptGenerateSymmetricKey", argc=7)
    def BCryptGenerateSymmetricKey(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS BCryptGenerateSymmetricKey(
          BCRYPT_ALG_HANDLE hAlgorithm,
          BCRYPT_KEY_HANDLE *phKey,
          PUCHAR            pbKeyObject,
          ULONG             cbKeyObject,
          PUCHAR            pbSecret,
          ULONG             cbSecret,
          ULONG             dwFlags
        );
        """
        hAlgorithm, phKey, pbKeyObject, cbKeyObject, pbSecret, cbSecret, dwFlags = argv

        alg_ctx = emu.get_crypt_manager().crypt_get(hAlgorithm)
        if not alg_ctx:
            return ntdefs.STATUS_INVALID_HANDLE
        cbSecret &= 0xFFFFFFFF
        if not phKey or (is_aes(alg_ctx) and cbSecret not in AES_KEY_LENGTHS):
            return ntdefs.STATUS_INVALID_PARAMETER

        secret = self.mem_read(pbSecret, cbSecret) if cbSecret else b""
        ctx.args["pbSecret"].display = secret.hex()
        hnd = alg_ctx.import_key(blob=secret, blob_len=cbSecret, flags=dwFlags)
        alg_ctx.get_key(hnd).chaining_mode = alg_ctx.chaining_mode
        self.mem_write(phKey, hnd.to_bytes(emu.get_ptr_size(), "little"))
        ctx.args["phKey"].display = hex(hnd)
        return ntdefs.STATUS_SUCCESS

    @apihook("BCryptEncrypt", argc=10)
    def BCryptEncrypt(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS BCryptEncrypt(
          BCRYPT_KEY_HANDLE hKey,
          PUCHAR            pbInput,
          ULONG             cbInput,
          VOID              *pPaddingInfo,
          PUCHAR            pbIV,
          ULONG             cbIV,
          PUCHAR            pbOutput,
          ULONG             cbOutput,
          ULONG             *pcbResult,
          ULONG             dwFlags
        );
        """
        return self.aes_crypt(emu, argv, ctx, encrypt=True)

    @apihook("BCryptDecrypt", argc=10)
    def BCryptDecrypt(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS BCryptDecrypt(
          BCRYPT_KEY_HANDLE hKey,
          PUCHAR            pbInput,
          ULONG             cbInput,
          VOID              *pPaddingInfo,
          PUCHAR            pbIV,
          ULONG             cbIV,
          PUCHAR            pbOutput,
          ULONG             cbOutput,
          ULONG             *pcbResult,
          ULONG             dwFlags
        );
        """
        return self.aes_crypt(emu, argv, ctx, encrypt=False)

    def write_result_size(self, pcbResult, size):
        if pcbResult:
            self.mem_write(pcbResult, size.to_bytes(4, "little"))

    def get_key(self, emu, hKey):
        """Get the algorithm context and the key of a key handle, or (None, None)."""
        for alg_ctx in emu.get_crypt_manager().ctx_handles.values():
            key = alg_ctx.get_key(hKey)
            if key:
                return alg_ctx, key
        return None, None

    def read_auth_info(self, addr):
        """
        Read the nonce, the authenticated data, the tag address and size, and the flags of a
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.
        """
        fmt = "<IIQI4xQI4xQI4xQIIQI" if self.get_ptr_size() == 8 else "<IIIIIIIIIII4xQI"
        fields = struct.unpack(fmt, self.mem_read(addr, struct.calcsize(fmt)))
        _, _, nonce, nonce_len, aad, aad_len, tag, tag_len = fields[:8]
        nonce = self.mem_read(nonce, nonce_len) if nonce_len else b""
        aad = self.mem_read(aad, aad_len) if aad_len else b""
        return nonce, aad, tag, tag_len, fields[-1]

    def aes_crypt(self, emu, argv, ctx, encrypt):
        """
        Encrypt or decrypt with an AES key in ECB, CBC or GCM mode. A NULL pbOutput
        asks for the output size. CBC writes the last cipher block back to pbIV.
        """
        hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags = argv
        cbInput, cbIV, cbOutput = (n & 0xFFFFFFFF for n in (cbInput, cbIV, cbOutput))

        alg_ctx, key = self.get_key(emu, hKey)
        if not key:
            return ntdefs.STATUS_INVALID_HANDLE
        if not is_aes(alg_ctx) or key.chaining_mode not in ("ChainingModeCBC", "ChainingModeECB", "ChainingModeGCM"):
            return ntdefs.STATUS_NOT_SUPPORTED

        data = self.mem_read(pbInput, cbInput) if cbInput else b""
        if encrypt:
            ctx.args["pbInput"].display = base64.b64encode(data).decode("utf-8")

        if key.chaining_mode == "ChainingModeGCM":
            if not pPaddingInfo:
                return ntdefs.STATUS_INVALID_PARAMETER
            nonce, aad, tag, tag_len, flags = self.read_auth_info(pPaddingInfo)
            if flags & BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG:
                return ntdefs.STATUS_NOT_SUPPORTED
            if len(nonce) != GCM_NONCE_LENGTH or not GCM_TAG_LENGTHS[0] <= tag_len <= GCM_TAG_LENGTHS[1]:
                return ntdefs.STATUS_INVALID_PARAMETER
            if not pbOutput:
                self.write_result_size(pcbResult, len(data))
                return ntdefs.STATUS_SUCCESS
            if cbOutput < len(data):
                return ntdefs.STATUS_BUFFER_TOO_SMALL
            cipher = AES.new(key.blob, AES.MODE_GCM, nonce=nonce, mac_len=tag_len)
            cipher.update(aad)
            if encrypt:
                out, digest = cipher.encrypt_and_digest(data)
                self.mem_write(tag, digest)
            else:
                try:
                    out = cipher.decrypt_and_verify(data, self.mem_read(tag, tag_len))
                except ValueError:
                    return STATUS_AUTH_TAG_MISMATCH
        else:
            padding = dwFlags & BCRYPT_BLOCK_PADDING
            if encrypt and padding:
                data = pad(data, AES_BLOCK_LENGTH)
            elif len(data) % AES_BLOCK_LENGTH:
                return STATUS_INVALID_BUFFER_SIZE
            if not pbOutput:
                self.write_result_size(pcbResult, len(data))
                return ntdefs.STATUS_SUCCESS

            iv = b"\x00" * AES_BLOCK_LENGTH
            if key.chaining_mode == "ChainingModeCBC" and pbIV:
                if cbIV != AES_BLOCK_LENGTH:
                    return ntdefs.STATUS_INVALID_PARAMETER
                iv = self.mem_read(pbIV, cbIV)
            if key.chaining_mode == "ChainingModeCBC":
                cipher = AES.new(key.blob, AES.MODE_CBC, iv=iv)
            else:
                cipher = AES.new(key.blob, AES.MODE_ECB)
            out = cipher.encrypt(data) if encrypt else cipher.decrypt(data)
            next_iv = (out if encrypt else data)[-AES_BLOCK_LENGTH:]
            if not encrypt and padding:
                try:
                    out = unpad(out, AES_BLOCK_LENGTH)
                except ValueError:
                    return STATUS_DATA_ERROR
            if cbOutput < len(out):
                self.write_result_size(pcbResult, len(out))
                return ntdefs.STATUS_BUFFER_TOO_SMALL
            if key.chaining_mode == "ChainingModeCBC" and pbIV and next_iv:
                self.mem_write(pbIV, next_iv)

        if out:
            self.mem_write(pbOutput, out)
        if not encrypt:
            ctx.args["pbOutput"].display = base64.b64encode(out).decode("utf-8")
        self.write_result_size(pcbResult, len(out))
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

    @apihook("BCryptGenRandom", argc=4)
    def BCryptGenRandom(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS BCryptGenRandom(
          BCRYPT_ALG_HANDLE hAlgorithm,
          PUCHAR            pbBuffer,
          ULONG             cbBuffer,
          ULONG             dwFlags
        );
        """
        hAlgorithm, pbBuffer, cbBuffer, dwFlags = argv

        if dwFlags & BCRYPT_USE_SYSTEM_PREFERRED_RNG:
            if hAlgorithm:
                return ntdefs.STATUS_INVALID_PARAMETER
        elif not emu.get_crypt_manager().crypt_get(hAlgorithm):
            return ntdefs.STATUS_INVALID_HANDLE
        cbBuffer &= 0xFFFFFFFF
        if not cbBuffer:
            return ntdefs.STATUS_SUCCESS
        if not pbBuffer:
            return ntdefs.STATUS_INVALID_PARAMETER
        self.mem_write(pbBuffer, emu.rng.randbytes(cbBuffer))
        return ntdefs.STATUS_SUCCESS


def is_aes(alg_ctx):
    return (alg_ctx.ptype or "").upper() == "AES"


def get_aes_property(name, obj, key):
    """Get the value of an AES algorithm or key property, or None for a property that is not supported."""
    if name == "ObjectLength":
        return AES_OBJECT_LENGTH.to_bytes(4, "little")
    if name == "BlockLength":
        return AES_BLOCK_LENGTH.to_bytes(4, "little")
    if name == "ChainingMode":
        return (obj.chaining_mode + "\x00").encode("utf-16le")
    if name == "KeyLengths":
        return struct.pack("<III", 128, 256, 64)
    if name == "KeyLength" and key:
        return (len(key.blob) * 8).to_bytes(4, "little")
    if name == "AuthTagLength" and obj.chaining_mode == "ChainingModeGCM":
        return struct.pack("<III", *GCM_TAG_LENGTHS)
    return None
