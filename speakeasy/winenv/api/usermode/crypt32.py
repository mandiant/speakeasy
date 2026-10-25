# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import base64
import hashlib
import hmac
import struct

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import speakeasy.winenv.defs.windows.windows as windefs

from .. import api

ERROR_MORE_DATA = 234

CRYPT_STRING_BASE64 = 1

DPAPI_VERSION = 1
DPAPI_PROVIDER = bytes.fromhex("d08c9ddf0115d1118c7a00c04fc297eb")
DPAPI_MASTER_KEY = bytes.fromhex("5c7b0e3a9d6f4e21b3a8c4d2e1f09a77")
DPAPI_KEY = hashlib.sha256(b"speakeasy dpapi master key").digest()
DPAPI_HEADER = struct.Struct("<I16sI16sII")


class Crypt32(api.ApiHandler):
    """
    Implements exported functions from user32.dll
    """

    name = "crypt32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs = {}
        self.data = {}

        super().__get_hook_attrs__(self)

    @apihook("CryptStringToBinary", argc=7)
    def CryptStringToBinary(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CryptStringToBinaryA(
        LPCSTR pszString,
        DWORD  cchString,
        DWORD  dwFlags,
        BYTE   *pbBinary,
        DWORD  *pcbBinary,
        DWORD  *pdwSkip,
        DWORD  *pdwFlags
        );
        """
        cw = self.get_char_width(ctx)

        pszString, cchString, dwFlags, pbBinary, pcbBinary, pdwSkip, pdwFlags = argv

        if cchString:
            s = self.mem_read(pszString, cchString * cw)
        else:
            s = self.read_mem_string(pszString, cw)

        if dwFlags != CRYPT_STRING_BASE64:
            # self.logger.info("%s: currently unsupported flags (%08X)" % (api_name, dwFlags))
            return 1

        if not isinstance(s, str):
            s = s.decode("utf8")

        ctx.args["pszString"].display = s

        try:
            decoded = base64.b64decode(s)
        except Exception:
            return 0

        cbBinary = int.from_bytes(self.mem_read(pcbBinary, 4), "little")
        out_len = len(decoded)

        if pbBinary == 0:
            self.mem_write(pcbBinary, out_len.to_bytes(4, "little"))
            return 1

        if out_len > cbBinary:
            emu.set_last_error(ERROR_MORE_DATA)
            return 0

        self.mem_write(pbBinary, decoded)
        self.mem_write(pcbBinary, out_len.to_bytes(4, "little"))

        if pdwSkip:
            self.mem_write(pdwSkip, b"\x00" * 4)

        return 1

    def read_data_blob(self, addr):
        ptr_size = self.get_ptr_size()
        size = int.from_bytes(self.mem_read(addr, 4), "little")
        data = int.from_bytes(self.mem_read(addr + ptr_size, ptr_size), "little")
        return self.mem_read(data, size) if size else b""

    def write_data_blob(self, addr, data):
        ptr_size = self.get_ptr_size()
        buf = self.heap_alloc(max(len(data), 1), heap="LocalAlloc")
        self.mem_write(buf, data)
        self.mem_write(addr, len(data).to_bytes(4, "little"))
        self.mem_write(addr + ptr_size, buf.to_bytes(ptr_size, "little"))

    def get_dpapi_keys(self, pOptionalEntropy):
        entropy = self.read_data_blob(pOptionalEntropy) if pOptionalEntropy else b""
        key = hashlib.sha256(DPAPI_KEY + entropy).digest()
        return key[:16], key[16:]

    @apihook("CryptProtectData", argc=7)
    def CryptProtectData(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CryptProtectData(
          DATA_BLOB                 *pDataIn,
          LPCWSTR                   szDataDescr,
          DATA_BLOB                 *pOptionalEntropy,
          PVOID                     pvReserved,
          CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
          DWORD                     dwFlags,
          DATA_BLOB                 *pDataOut
        );
        """
        pDataIn, szDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut = argv

        if not pDataIn or not pDataOut:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        data = self.read_data_blob(pDataIn)
        descr = self.read_mem_string(szDataDescr, 2) if szDataDescr else ""
        descr_bytes = (descr + "\x00").encode("utf-16le")
        enc_key, mac_key = self.get_dpapi_keys(pOptionalEntropy)
        cipher = AES.new(enc_key, AES.MODE_CBC, iv=b"\x00" * 16).encrypt(pad(data, 16))
        blob = DPAPI_HEADER.pack(
            DPAPI_VERSION, DPAPI_PROVIDER, 1, DPAPI_MASTER_KEY, dwFlags & 0xFFFFFFFF, len(descr_bytes)
        )
        blob += descr_bytes + struct.pack("<I", len(cipher)) + cipher
        sign = hmac.new(mac_key, blob, hashlib.sha256).digest()
        self.write_data_blob(pDataOut, blob + struct.pack("<I", len(sign)) + sign)
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return 1

    @apihook("CryptUnprotectData", argc=7)
    def CryptUnprotectData(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CryptUnprotectData(
          DATA_BLOB                 *pDataIn,
          LPWSTR                    *ppszDataDescr,
          DATA_BLOB                 *pOptionalEntropy,
          PVOID                     pvReserved,
          CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
          DWORD                     dwFlags,
          DATA_BLOB                 *pDataOut
        );
        """
        pDataIn, ppszDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut = argv

        if not pDataIn or not pDataOut:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        blob = self.read_data_blob(pDataIn)
        enc_key, mac_key = self.get_dpapi_keys(pOptionalEntropy)
        try:
            version, provider, _, _, _, descr_len = DPAPI_HEADER.unpack_from(blob)
            if (version, provider) != (DPAPI_VERSION, DPAPI_PROVIDER):
                raise ValueError("not a DPAPI blob")
            off = DPAPI_HEADER.size + descr_len
            (cipher_len,) = struct.unpack_from("<I", blob, off)
            off += 4 + cipher_len
            (sign_len,) = struct.unpack_from("<I", blob, off)
            sign = hmac.new(mac_key, blob[:off], hashlib.sha256).digest()
            if blob[off + 4 :] != sign or sign_len != len(sign):
                raise ValueError("bad DPAPI signature")
            cipher = blob[off - cipher_len : off]
            data = unpad(AES.new(enc_key, AES.MODE_CBC, iv=b"\x00" * 16).decrypt(cipher), 16)
        except (ValueError, struct.error):
            emu.set_last_error(windefs.ERROR_INVALID_DATA)
            return 0

        self.write_data_blob(pDataOut, data)
        if ppszDataDescr:
            descr = blob[DPAPI_HEADER.size : DPAPI_HEADER.size + descr_len]
            buf = self.heap_alloc(max(len(descr), 2), heap="LocalAlloc")
            self.mem_write(buf, descr)
            self.mem_write(ppszDataDescr, buf.to_bytes(self.get_ptr_size(), "little"))
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return 1
