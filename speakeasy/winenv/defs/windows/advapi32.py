# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from speakeasy.struct import EmuStruct, Ptr
import ctypes as ct

NTE_BAD_ALGID = 0x80090008

SERVICE_WIN32 = 0x30

SERVICE_ACTIVE = 0x1
SERVICE_INACTIVE = 0x2
SERVICE_STATE_ALL = 0x3


class SERVICE_TABLE_ENTRY(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.lpServiceName = Ptr
        self.lpServiceProc = Ptr

class HCRYPTKEY(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Algid = ct.c_uint32
        self.keylen = ct.c_uint32
        self.keyp = Ptr


def get_define_int(define, prefix=''):
    for k, v in globals().items():
        if not isinstance(v, int) or v != define:
            continue
        if prefix:
            if k.startswith(prefix):
                return k
        else:
            return k
