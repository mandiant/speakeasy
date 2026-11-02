# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

from typing import Any

from speakeasy.windows.handles import HANDLE_MASK, HandleTable


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


class CryptHash:
    """Represents a hash object of CryptCreateHash, with the hashlib object that keeps its state."""

    def __init__(self, hasher):
        self.hasher: Any = hasher


class CryptContext:
    """Represents crypto context used by crypto functions."""

    def __init__(self, handles, cname, pname, ptype, flags):
        self.handles: HandleTable = handles
        self.container_name: str | None = cname
        self.provider_name: str | None = pname
        self.ptype: str | int | None = ptype
        self.flags: int | None = flags
        self.keys: dict[int, CryptKey] = {}
        self.chaining_mode: str = "ChainingModeCBC"

    def import_key(self, blob_type=None, blob=None, blob_len=None, hnd_import_key=None, param_list=None, flags=None):
        key = CryptKey(self, blob_type, blob, blob_len, hnd_import_key, param_list, flags)
        hnd = self.handles.new_handle(key)
        self.keys.update({hnd: key})

        return hnd

    def get_key(self, hnd):
        return self.keys.get(hnd, None)

    def delete_key(self, hnd):
        self.keys.pop(hnd & HANDLE_MASK)
        self.handles.close(hnd)


class CryptoManager:
    """
    Manages the emulation of crypto functions.

    Providers, keys and hashes are not kernel objects, so their handles are in a table of the
    manager and not in the process handle table, and CloseHandle does not close them.
    """

    def __init__(self, allocator, config=None):
        super().__init__()
        self.handles: HandleTable = HandleTable(allocator, release=lambda obj: None)
        self.config: object | None = config

    def crypt_open(self, cname=None, pname=None, ptype=None, flags=None):
        return self.handles.new_handle(CryptContext(self.handles, cname, pname, ptype, flags))

    def crypt_close(self, hnd):
        """
        Close a provider handle and the handles of its keys.

        Raises:
            InvalidHandle: if the handle does not refer to a provider.
        """
        ctx = self.handles.get(hnd, CryptContext)
        for key_hnd in list(ctx.keys):
            ctx.delete_key(key_hnd)
        self.handles.close(hnd)

    def get_context(self, hnd) -> CryptContext:
        """
        Get the context of a provider handle.

        Raises:
            InvalidHandle: if the handle does not refer to a provider.
        """
        return self.handles.get(hnd, CryptContext)

    def get_key(self, hnd) -> CryptKey:
        """
        Get the key of a key handle.

        Raises:
            InvalidHandle: if the handle does not refer to a key.
        """
        return self.handles.get(hnd, CryptKey)

    def delete_key(self, hnd):
        """
        Close a key handle.

        Raises:
            InvalidHandle: if the handle does not refer to a key.
        """
        self.get_key(hnd).context.delete_key(hnd)

    def create_hash(self, hasher) -> int:
        return self.handles.new_handle(CryptHash(hasher))

    def get_hash(self, hnd):
        """
        Get the hashlib object of a hash handle.

        Raises:
            InvalidHandle: if the handle does not refer to a hash.
        """
        return self.handles.get(hnd, CryptHash).hasher
