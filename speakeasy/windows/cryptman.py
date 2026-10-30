# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from speakeasy.windows.objman import HandleAllocator


class CryptKey:
    def __init__(self, blob_type, blob, blob_len, hnd_import_key, param_list, flags):
        self.blob_type: str | None = blob_type
        self.blob: bytes | None = blob
        self.blob_len: int | None = blob_len
        self.import_key: int | None = hnd_import_key
        self.param_list: int | None = param_list
        self.flags: int | None = flags
        self.chaining_mode: str | None = None


class CryptContext:
    """
    Represents crypto context used by crypto functions
    """

    def __init__(self, allocator, cname, pname, ptype, flags):
        self.allocator: HandleAllocator = allocator
        self.container_name: str | None = cname
        self.provider_name: str | None = pname
        self.ptype: str | int | None = ptype
        self.flags: int | None = flags
        self.keys: dict[int, CryptKey] = {}
        self.chaining_mode: str = "ChainingModeCBC"

    def get_handle(self):
        return self.allocator.allocate_crypt_context_handle()

    def import_key(self, blob_type=None, blob=None, blob_len=None, hnd_import_key=None, param_list=None, flags=None):
        key = CryptKey(blob_type, blob, blob_len, hnd_import_key, param_list, flags)
        hnd = self.get_handle()
        self.keys.update({hnd: key})

        return hnd

    def get_key(self, hnd):
        return self.keys.get(hnd, None)

    def delete_key(self, hnd):
        self.keys.pop(hnd)


class CryptoManager:
    """
    Manages the emulation of crypto functions
    """

    def __init__(self, allocator, config=None):
        super().__init__()
        self.ctx_handles: dict[int, CryptContext] = {}
        self.config: object | None = config
        self.allocator: HandleAllocator = allocator

    def crypt_open(self, cname=None, pname=None, ptype=None, flags=None):
        ctx = CryptContext(self.allocator, cname, pname, ptype, flags)
        hnd = ctx.get_handle()

        self.ctx_handles.update({hnd: ctx})
        return hnd

    def crypt_close(self, hnd):
        self.ctx_handles.pop(hnd, None)

    def crypt_get(self, hnd):
        return self.ctx_handles.get(hnd, None)
