# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

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

    def get_handle(self):
        hkey = CryptContext.curr_handle
        CryptContext.curr_handle += 4
        return hkey


class CryptoManager(object):
    """
    Manages the emulation of crypto functions
    """
    def __init__(self, config=None):
        super(CryptoManager, self).__init__()
        self.ctx_handles = {}
        self.config = config

    def crypt_open(self, cname, pname, ptype, flags):
        ctx = CryptContext(cname, pname, ptype, flags)
        hnd = ctx.get_handle()

        self.ctx_handles.update({hnd: ctx})
        return hnd

    def crypt_close(self, hnd):
        self.ctx_handles.pop(hnd)

    def crypt_get(self, hnd):
        return self.ctx_handles.get(hnd, None)
