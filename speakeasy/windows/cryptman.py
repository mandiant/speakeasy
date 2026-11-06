# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

import struct
from collections.abc import Callable
from typing import Any

from Crypto.Cipher import AES, ARC4, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Util.Padding import pad, unpad

import speakeasy.winenv.defs.windows.advapi32 as adv32defs
from speakeasy.windows.handles import HANDLE_MASK, HandleTable

AES_KEY_LENGTHS = {adv32defs.CALG_AES_128: 16, adv32defs.CALG_AES_192: 24, adv32defs.CALG_AES_256: 32}
CIPHER_MODES = (adv32defs.CRYPT_MODE_CBC, adv32defs.CRYPT_MODE_ECB, adv32defs.CRYPT_MODE_CFB)


class CryptKey:
    def __init__(self, context, blob_type, blob, blob_len, hnd_import_key, param_list, flags):
        self.context: CryptContext = context
        self.blob_type: str | None = blob_type
        self.blob: bytes | None = blob
        self.blob_len: int | None = blob_len
        self.import_key: int | None = hnd_import_key
        self.param_list: int | None = param_list
        self.flags: int | None = flags
        self.chaining_mode: str | None = None


class CryptoApiError(Exception):
    """A CryptoAPI call failed with the last error in code."""

    def __init__(self, code: int):
        super().__init__(hex(code))
        self.code = code


class CryptoApiKey:
    """
    Represents a key of the CryptoAPI key functions (HCRYPTKEY), with the cipher state of the current message.

    An RC4 or AES key has its key bytes in secret. An RSA key has only the public key, in rsa. A
    40-bit RC4 key gets 11 zero bytes of salt unless CRYPT_NO_SALT is set. A call with Final set ends
    the message, and the next call starts again from the IV or from the start of the RC4 key stream.
    """

    def __init__(self, context, algid: int, flags: int, secret: bytes = b"", rsa: RsaKey | None = None):
        self.context: CryptContext = context
        self.algid = algid
        self.flags = flags
        self.secret = secret
        self.rsa = rsa
        no_salt = algid != adv32defs.CALG_RC4 or len(secret) != 5 or flags & adv32defs.CRYPT_NO_SALT
        self.salt = b"" if no_salt else bytes(11)
        self.mode = adv32defs.CRYPT_MODE_CBC
        self.iv = bytes(self.block_len)
        self.cipher: Any = None
        self.encrypting = False

    @classmethod
    def from_blob(cls, context, blob: bytes, flags: int) -> CryptoApiKey:
        """
        Make a key from the PLAINTEXTKEYBLOB of an RC4 or AES key, or from the PUBLICKEYBLOB of an RSA key.

        Raises:
            CryptoApiError: NTE_BAD_PUBLIC_KEY for a SIMPLEBLOB, because no key has the private part
                that decrypts it. NTE_BAD_TYPE for another blob type, NTE_BAD_ALGID for another
                algorithm, and NTE_BAD_DATA for a blob that is too short or has a bad size.
        """
        if len(blob) < 8:
            raise CryptoApiError(adv32defs.NTE_BAD_DATA)
        blob_type, _, _, algid = struct.unpack_from("<BBHI", blob)
        if blob_type == adv32defs.SIMPLEBLOB:
            raise CryptoApiError(adv32defs.NTE_BAD_PUBLIC_KEY)
        if blob_type == adv32defs.PLAINTEXTKEYBLOB:
            if algid != adv32defs.CALG_RC4 and algid not in AES_KEY_LENGTHS:
                raise CryptoApiError(adv32defs.NTE_BAD_ALGID)
            size = struct.unpack_from("<I", blob, 8)[0] if len(blob) >= 12 else 0
            secret = blob[12 : 12 + size]
            if not size or len(secret) != size or AES_KEY_LENGTHS.get(algid, size) != size:
                raise CryptoApiError(adv32defs.NTE_BAD_DATA)
            return cls(context, algid, flags, secret=secret)
        if blob_type == adv32defs.PUBLICKEYBLOB:
            if algid not in (adv32defs.CALG_RSA_KEYX, adv32defs.CALG_RSA_SIGN):
                raise CryptoApiError(adv32defs.NTE_BAD_ALGID)
            magic, bits, exponent = struct.unpack_from("<III", blob, 8) if len(blob) >= 20 else (0, 0, 0)
            modulus = blob[20 : 20 + bits // 8]
            if magic != adv32defs.RSA1 or not modulus or len(modulus) != bits // 8:
                raise CryptoApiError(adv32defs.NTE_BAD_DATA)
            try:
                rsa = RSA.construct((int.from_bytes(modulus, "little"), exponent))
            except ValueError:
                raise CryptoApiError(adv32defs.NTE_BAD_DATA) from None
            return cls(context, algid, flags, rsa=rsa)
        raise CryptoApiError(adv32defs.NTE_BAD_TYPE)

    @classmethod
    def from_random(cls, context, algid: int, flags: int, randbytes: Callable[[int], bytes]) -> CryptoApiKey:
        """
        Make an RC4 or AES key with random key bytes.

        The upper 16 bits of flags give the key length in bits. An RC4 key without a length gets
        the default length of the provider.

        Raises:
            CryptoApiError: NTE_BAD_ALGID for another algorithm, NTE_BAD_FLAGS for a key length that
                the algorithm does not have.
        """
        bits = flags >> 16
        if algid in AES_KEY_LENGTHS:
            size = AES_KEY_LENGTHS[algid]
            if bits not in (0, size * 8):
                raise CryptoApiError(adv32defs.NTE_BAD_FLAGS)
        elif algid == adv32defs.CALG_RC4:
            bits = bits or context.get_default_rc4_bits()
            if bits % 8 or not 40 <= bits <= 128:
                raise CryptoApiError(adv32defs.NTE_BAD_FLAGS)
            size = bits // 8
        else:
            raise CryptoApiError(adv32defs.NTE_BAD_ALGID)
        return cls(context, algid, flags, secret=randbytes(size))

    def get_blob(self, blob_type: int) -> bytes:
        """
        Get the PLAINTEXTKEYBLOB of an RC4 or AES key.

        Raises:
            CryptoApiError: NTE_BAD_TYPE for another blob type or for an RSA key, and
                NTE_BAD_KEY_STATE for a key without CRYPT_EXPORTABLE.
        """
        if blob_type != adv32defs.PLAINTEXTKEYBLOB or self.rsa is not None:
            raise CryptoApiError(adv32defs.NTE_BAD_TYPE)
        if not self.flags & adv32defs.CRYPT_EXPORTABLE:
            raise CryptoApiError(adv32defs.NTE_BAD_KEY_STATE)
        header = struct.pack("<BBHII", blob_type, adv32defs.CUR_BLOB_VERSION, 0, self.algid, len(self.secret))
        return header + self.secret

    @property
    def block_len(self) -> int:
        return AES.block_size if self.algid in AES_KEY_LENGTHS else 0

    def reset(self) -> None:
        self.cipher = None

    def get_cipher(self, encrypting: bool) -> Any:
        """Get the cipher of the current message. A block cipher starts a new message if the direction changes."""
        changed = self.encrypting != encrypting and self.algid != adv32defs.CALG_RC4
        if self.cipher is None or changed:
            key = self.secret + self.salt
            if self.algid == adv32defs.CALG_RC4:
                self.cipher = ARC4.new(key)
            elif self.mode == adv32defs.CRYPT_MODE_ECB:
                self.cipher = AES.new(key, AES.MODE_ECB)
            elif self.mode == adv32defs.CRYPT_MODE_CFB:
                self.cipher = AES.new(key, AES.MODE_CFB, iv=self.iv, segment_size=8)
            else:
                self.cipher = AES.new(key, AES.MODE_CBC, iv=self.iv)
            self.encrypting = encrypting
        return self.cipher

    def get_encrypted_size(self, size: int, final: bool) -> int:
        """
        Get the size of the cipher text of size bytes of plain text.

        Raises:
            CryptoApiError: NTE_BAD_DATA if the data of a block cipher is not whole blocks and final is False.
        """
        if self.rsa is not None:
            return self.rsa.size_in_bytes()
        if not self.block_len:
            return size
        if final:
            return (size // self.block_len + 1) * self.block_len
        if size % self.block_len:
            raise CryptoApiError(adv32defs.NTE_BAD_DATA)
        return size

    def encrypt(self, data: bytes, final: bool, randbytes: Callable[[int], bytes]) -> bytes:
        """
        Encrypt data.

        A block cipher adds PKCS#5 padding when final is True. RSA uses PKCS#1 v1.5 padding, with
        random bytes from randbytes, and gives the cipher text in little-endian order.

        Raises:
            CryptoApiError: NTE_BAD_KEY for a signature key, NTE_BAD_LEN for data too long for RSA,
                NTE_BAD_DATA for a block cipher as get_encrypted_size describes.
        """
        if self.rsa is not None:
            if self.algid != adv32defs.CALG_RSA_KEYX:
                raise CryptoApiError(adv32defs.NTE_BAD_KEY)
            if len(data) > self.rsa.size_in_bytes() - 11:
                raise CryptoApiError(adv32defs.NTE_BAD_LEN)
            return PKCS1_v1_5.new(self.rsa, randfunc=randbytes).encrypt(data)[::-1]
        self.get_encrypted_size(len(data), final)
        if final and self.block_len:
            data = pad(data, self.block_len)
        out: bytes = self.get_cipher(encrypting=True).encrypt(data)
        if final:
            self.reset()
        return out

    def decrypt(self, data: bytes, final: bool) -> bytes:
        """
        Decrypt data. A block cipher removes the PKCS#5 padding when final is True.

        Raises:
            CryptoApiError: NTE_BAD_KEY for an RSA key, because the key has no private part.
                NTE_BAD_DATA if the data of a block cipher is not whole blocks or has bad padding.
        """
        if self.rsa is not None:
            raise CryptoApiError(adv32defs.NTE_BAD_KEY)
        if self.block_len and len(data) % self.block_len:
            raise CryptoApiError(adv32defs.NTE_BAD_DATA)
        out: bytes = self.get_cipher(encrypting=False).decrypt(data)
        if final:
            self.reset()
            if self.block_len:
                try:
                    out = unpad(out, self.block_len)
                except ValueError:
                    raise CryptoApiError(adv32defs.NTE_BAD_DATA) from None
        return out


class CryptHash:
    """Represents a hash object of CryptCreateHash, with the hashlib object that keeps its state."""

    def __init__(self, hasher):
        self.hasher: Any = hasher


class CryptContext:
    """Represents a cryptographic provider context and its keys."""

    def __init__(self, handles, cname, pname, ptype, flags):
        self.handles: HandleTable = handles
        self.container_name: str | None = cname
        self.provider_name: str | None = pname
        self.ptype: str | int | None = ptype
        self.flags: int | None = flags
        self.keys: dict[int, CryptKey | CryptoApiKey] = {}
        self.chaining_mode: str = "ChainingModeCBC"

    def import_key(self, blob_type=None, blob=None, blob_len=None, hnd_import_key=None, param_list=None, flags=None):
        return self.add_key(CryptKey(self, blob_type, blob, blob_len, hnd_import_key, param_list, flags))

    def add_key(self, key: CryptKey | CryptoApiKey) -> int:
        hnd = self.handles.new_handle(key)
        self.keys[hnd] = key
        return hnd

    def get_key(self, hnd) -> CryptKey | None:
        key = self.keys.get(hnd)
        return key if isinstance(key, CryptKey) else None

    def get_default_rc4_bits(self) -> int:
        """Get the RC4 key length of a key without a length: 128 bits for PROV_RSA_AES, else 40 bits."""
        return 128 if self.ptype == adv32defs.PROV_RSA_AES else 40

    def delete_key(self, hnd) -> bool:
        self.keys.pop(hnd & HANDLE_MASK)
        return self.handles.close(hnd)


class CryptoManager:
    """
    Keep the provider contexts, keys and hashes of the CryptoAPI handlers.

    Providers, keys and hashes are not kernel objects, so their handles are in a table of the
    manager and not in the process handle table, and CloseHandle does not close them.
    """

    def __init__(self, allocator, config=None):
        super().__init__()
        self.handles: HandleTable = HandleTable(allocator, release=lambda obj: None)
        self.config: object | None = config

    def crypt_open(self, cname=None, pname=None, ptype=None, flags=None):
        return self.handles.new_handle(CryptContext(self.handles, cname, pname, ptype, flags))

    def crypt_close(self, hnd) -> bool:
        """
        Close a provider handle and the handles of its keys.

        Return False if the handle does not refer to a provider.
        """
        ctx = self.handles.get(hnd, CryptContext)
        if ctx is None:
            return False
        for key_hnd in list(ctx.keys):
            ctx.delete_key(key_hnd)
        return self.handles.close(hnd)

    def get_context(self, hnd) -> CryptContext | None:
        """Get the context of a provider handle, else None."""
        return self.handles.get(hnd, CryptContext)

    def get_key(self, hnd) -> CryptKey | None:
        """Get the key of a key handle, else None."""
        return self.handles.get(hnd, CryptKey)

    def delete_key(self, hnd) -> bool:
        """Close a key handle. Return False if the handle does not refer to a key."""
        key = self.get_key(hnd)
        if key is None:
            return False
        return key.context.delete_key(hnd)

    def get_crypto_api_key(self, hnd) -> CryptoApiKey | None:
        """Get the key of a CryptoAPI key handle, else None."""
        return self.handles.get(hnd, CryptoApiKey)

    def destroy_crypto_api_key(self, hnd) -> bool:
        """Close a CryptoAPI key handle. Return False if the handle does not refer to such a key."""
        key = self.get_crypto_api_key(hnd)
        if key is None:
            return False
        return key.context.delete_key(hnd)

    def create_hash(self, hasher) -> int:
        return self.handles.new_handle(CryptHash(hasher))

    def get_hash(self, hnd):
        """Get the hashlib object of a hash handle, else None."""
        h = self.handles.get(hnd, CryptHash)
        return None if h is None else h.hasher
