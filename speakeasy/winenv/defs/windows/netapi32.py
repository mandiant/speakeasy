# Copyright (C) 2021 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from typing import Annotated

from speakeasy.struct import EmuStruct, Ptr

NERR_Success = 0

NetSetupUnknownStatus = 0
NetSetupUnjoined = 1
NetSetupWorkgroupName = 2
NetSetupDomainName = 3


class WKSTA_INFO_100(EmuStruct):
    wki_platform_id: Annotated[int, Ptr]
    wki_computername: Annotated[int, Ptr]
    wki_langroup: Annotated[int, Ptr]
    wki_ver_major: Annotated[int, ct.c_uint32]
    wki_ver_minor: Annotated[int, ct.c_uint32]


class WKSTA_INFO_101(EmuStruct):
    wki_platform_id: Annotated[int, Ptr]
    wki_computername: Annotated[int, Ptr]
    wki_langroup: Annotated[int, Ptr]
    wki_ver_major: Annotated[int, ct.c_uint32]
    wki_ver_minor: Annotated[int, ct.c_uint32]
    wki_lanroot: Annotated[int, Ptr]


class WKSTA_INFO_102(EmuStruct):
    wki_platform_id: Annotated[int, Ptr]
    wki_computername: Annotated[int, Ptr]
    wki_langroup: Annotated[int, Ptr]
    wki_ver_major: Annotated[int, ct.c_uint32]
    wki_ver_minor: Annotated[int, ct.c_uint32]
    wki_lanroot: Annotated[int, Ptr]
    wki_logged_on_users: Annotated[int, Ptr]
