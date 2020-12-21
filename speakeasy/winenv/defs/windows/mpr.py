# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

RESOURCE_CONNECTED = 1
RESOURCE_GLOBALNET = 2
RESOURCE_REMEMBERED = 3
RESOURCE_CONTEXT = 5

RESOURCETYPE_ANY = 0
RESOURCETYPE_DISK = 1
RESOURCETYPE_PRINT = 2

RESOURCEUSAGE_CONNECTABLE = 1
RESOURCEUSAGE_CONTAINER = 2
RESOURCEUSAGE_ATTACHED = 0x10
RESOURCEUSAGE_ALL = 0x13

ERROR_NO_NETWORK = 0x4C6


def get_define_int(define, prefix=''):
    for k, v in globals().items():
        if not isinstance(v, int) or v != define:
            continue
        if prefix:
            if k.startswith(prefix):
                return k
        else:
            return k
