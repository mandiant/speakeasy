# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import random

import speakeasy.winenv.defs.windows.windows as windefs

from .. import api

class RPCRT4(api.ApiHandler):
    """
    Implements exported functions from rpcrt4.dll
    """
    name = 'rpcrt4'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super(RPCRT4, self).__init__(emu)

    @apihook('UuidCreate', argc=1)
    def UuidCreate(self, emu, argv, ctx={}):
        """
        RPC_STATUS UuidCreate(
          UUID *Uuid
        );
        """
        uuidp, = argv

        if not uuidp:
            return 1

        new_uuid = windefs.GUID()
        new_uuid.Data1 = random.randint(0, 0xffffffff)
        new_uuid.Data2 = random.randint(0, 0xffffffff) & 0xffff
        new_uuid.Data3 = random.randint(0, 0xffffffff) & 0xffff
        new_uuid.Data4 = random.randbytes(8)

        self.mem_write(uuidp, new_uuid.get_bytes())

        return 0
    
    @apihook('UuidToStringA', argc=2)
    def UuidToStringA(self, emu, argv, ctx={}):
        """
        RPC_STATUS UuidToStringA(
          const UUID *Uuid,
          RPC_CSTR   *StringUuid
        );
        """
        uuidp, stringp = argv

        if not uuidp or not stringp:
            return 1

        uuid = self.mem_cast(windefs.GUID(), uuidp)

        last = int.from_bytes(uuid.Data4, "little")

        string = "%x-%x-%x-%x-%x" % (int(hex(uuid.Data1), 16),
                int(hex(uuid.Data2), 16), int(hex(uuid.Data3), 16),
                int(hex(last >> 48), 16),
                int(hex(last & 0xffffffffffff), 16))

        self.mem_write(stringp, bytes(string, "utf8"))

        return 0
