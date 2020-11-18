# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

class CryptKey(object):
    def __init__(self, blob_type, blob, blob_len, hnd_import_key, param_list, flags):
        self.blob_type = blob_type
        self.blob = blob
        self.blob_len = blob_len
        self.import_key = hnd_import_key
        self.param_list = param_list
        self.flags = flags


class CryptContext(object):
    """
    Represents crypto context used by crypto functions
    """
    curr_handle = 0x680

    def __init__(self, cname, pname, ptype, flags):
        self.container_name = cname
        self.provider_name = pname
        self.ptype = ptype
        self.flags = flags
        self.keys = {}

    def get_handle(self):
        hkey = CryptContext.curr_handle
        CryptContext.curr_handle += 4
        return hkey

    def import_key(self, blob_type=None, blob=None, blob_len=None, hnd_import_key=None,
                   param_list=None, flags=None):
        key = CryptKey(blob_type, blob, blob_len, hnd_import_key, param_list, flags)
        hnd = self.get_handle()
        self.keys.update({hnd: key})

        return hnd

    def get_key(self, hnd):
        return self.keys.get(hnd, None)

    def delete_key(self, hnd):
        self.keys.pop(hnd)


class CryptoManager(object):
    """
    Manages the emulation of crypto functions
    """
    def __init__(self, config=None):
        super(CryptoManager, self).__init__()
        self.ctx_handles = {}
        self.config = config

    def crypt_open(self, cname=None, pname=None, ptype=None, flags=None):
        ctx = CryptContext(cname, pname, ptype, flags)
        hnd = ctx.get_handle()

        self.ctx_handles.update({hnd: ctx})
        return hnd

    def crypt_close(self, hnd):
        self.ctx_handles.pop(hnd)

    def crypt_get(self, hnd):
        return self.ctx_handles.get(hnd, None)
