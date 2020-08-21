# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

__all__ = ["volmgr"] # noqa

from . import * # noqa


def _get_kmods():
    def imports():
        import types
        for name, val in globals().items():
            if isinstance(val, types.ModuleType):
                yield val
    kmods = []
    imps = list(imports())
    for i in imps:
        if 'DriverModule' in dir(i):
            kmods.append(i)
    return kmods
