# Copyright (C) 2021 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from typing import Annotated

from speakeasy.struct import EmuStruct, Ptr

NERR_Success = 0

NetSetupUnknownStatus = 0
NetSetupUnjoined = 1
NetSetupWorkgroupName = 2
NetSetupDomainName = 3

SERVICE_WORKSTATION = "LanmanWorkstation"
SERVICE_SERVER = "LanmanServer"


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


class STAT_WORKSTATION_0(EmuStruct):
    StatisticsStartTime: Annotated[int, ct.c_int64]
    BytesReceived: Annotated[int, ct.c_int64]
    SmbsReceived: Annotated[int, ct.c_int64]
    PagingReadBytesRequested: Annotated[int, ct.c_int64]
    NonPagingReadBytesRequested: Annotated[int, ct.c_int64]
    CacheReadBytesRequested: Annotated[int, ct.c_int64]
    NetworkReadBytesRequested: Annotated[int, ct.c_int64]
    BytesTransmitted: Annotated[int, ct.c_int64]
    SmbsTransmitted: Annotated[int, ct.c_int64]
    PagingWriteBytesRequested: Annotated[int, ct.c_int64]
    NonPagingWriteBytesRequested: Annotated[int, ct.c_int64]
    CacheWriteBytesRequested: Annotated[int, ct.c_int64]
    NetworkWriteBytesRequested: Annotated[int, ct.c_int64]
    InitiallyFailedOperations: Annotated[int, ct.c_uint32]
    FailedCompletionOperations: Annotated[int, ct.c_uint32]
    ReadOperations: Annotated[int, ct.c_uint32]
    RandomReadOperations: Annotated[int, ct.c_uint32]
    ReadSmbs: Annotated[int, ct.c_uint32]
    LargeReadSmbs: Annotated[int, ct.c_uint32]
    SmallReadSmbs: Annotated[int, ct.c_uint32]
    WriteOperations: Annotated[int, ct.c_uint32]
    RandomWriteOperations: Annotated[int, ct.c_uint32]
    WriteSmbs: Annotated[int, ct.c_uint32]
    LargeWriteSmbs: Annotated[int, ct.c_uint32]
    SmallWriteSmbs: Annotated[int, ct.c_uint32]
    RawReadsDenied: Annotated[int, ct.c_uint32]
    RawWritesDenied: Annotated[int, ct.c_uint32]
    NetworkErrors: Annotated[int, ct.c_uint32]
    Sessions: Annotated[int, ct.c_uint32]
    FailedSessions: Annotated[int, ct.c_uint32]
    Reconnects: Annotated[int, ct.c_uint32]
    CoreConnects: Annotated[int, ct.c_uint32]
    Lanman20Connects: Annotated[int, ct.c_uint32]
    Lanman21Connects: Annotated[int, ct.c_uint32]
    LanmanNtConnects: Annotated[int, ct.c_uint32]
    ServerDisconnects: Annotated[int, ct.c_uint32]
    HungSessions: Annotated[int, ct.c_uint32]
    UseCount: Annotated[int, ct.c_uint32]
    FailedUseCount: Annotated[int, ct.c_uint32]
    CurrentCommands: Annotated[int, ct.c_uint32]


class STAT_SERVER_0(EmuStruct):
    sts0_start: Annotated[int, ct.c_uint32]
    sts0_fopens: Annotated[int, ct.c_uint32]
    sts0_devopens: Annotated[int, ct.c_uint32]
    sts0_jobsqueued: Annotated[int, ct.c_uint32]
    sts0_sopens: Annotated[int, ct.c_uint32]
    sts0_stimedout: Annotated[int, ct.c_uint32]
    sts0_serrorout: Annotated[int, ct.c_uint32]
    sts0_pwerrors: Annotated[int, ct.c_uint32]
    sts0_permerrors: Annotated[int, ct.c_uint32]
    sts0_syserrors: Annotated[int, ct.c_uint32]
    sts0_bytessent_low: Annotated[int, ct.c_uint32]
    sts0_bytessent_high: Annotated[int, ct.c_uint32]
    sts0_bytesrcvd_low: Annotated[int, ct.c_uint32]
    sts0_bytesrcvd_high: Annotated[int, ct.c_uint32]
    sts0_avresponse: Annotated[int, ct.c_uint32]
    sts0_reqbufneed: Annotated[int, ct.c_uint32]
    sts0_bigbufneed: Annotated[int, ct.c_uint32]
