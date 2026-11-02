# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

from typing import Any, TypeVar

from speakeasy.windows.handles import HANDLE_MASK, HandleTable, InvalidHandle

T = TypeVar("T")


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
        """Close a provider handle and the handles of its keys."""
        ctx = self.crypt_get(hnd)
        if ctx is None:
            return
        for key_hnd in list(ctx.keys):
            ctx.delete_key(key_hnd)
        self.handles.close(hnd)

    def get_handle_object(self, hnd, otype: type[T]) -> T | None:
        """Get the object of an open handle if it is an ``otype``, else None."""
        try:
            return self.handles.get(hnd, otype)
        except InvalidHandle:
            return None

    def crypt_get(self, hnd) -> CryptContext | None:
        return self.get_handle_object(hnd, CryptContext)

    def get_key(self, hnd) -> CryptKey | None:
        return self.get_handle_object(hnd, CryptKey)

    def delete_key(self, hnd) -> bool:
        """Close a key handle. Return False if the handle is not a key."""
        key = self.get_key(hnd)
        if key is None:
            return False
        key.context.delete_key(hnd)
        return True

    def create_hash(self, hasher) -> int:
        return self.handles.new_handle(CryptHash(hasher))

    def get_hash(self, hnd):
        """Get the hashlib object of a hash handle, or None."""
        obj = self.get_handle_object(hnd, CryptHash)
        return obj.hasher if obj else None
