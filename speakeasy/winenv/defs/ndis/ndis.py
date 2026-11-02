# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from typing import Annotated

from speakeasy.struct import EmuStruct, Ptr


class NDIS_OBJECT_HEADER(EmuStruct):
    Type: Annotated[int, ct.c_uint8]
    Revision: Annotated[int, ct.c_uint8]
    Size: Annotated[int, ct.c_uint16]


class NDIS_GENERIC_OBJECT(EmuStruct):
    Header: NDIS_OBJECT_HEADER
    Caller: Annotated[int, Ptr]
    CallersCaller: Annotated[int, Ptr]
    DriverObject: Annotated[int, Ptr]


class NET_BUFFER_LIST_POOL_PARAMETERS(EmuStruct):
    Header: NDIS_OBJECT_HEADER
    ProtocolId: Annotated[int, ct.c_uint8]
    fAllocateNetBuffer: Annotated[int, ct.c_uint8]
    ContextSize: Annotated[int, ct.c_uint16]
    PoolTag: Annotated[int, ct.c_uint32]
    DataSize: Annotated[int, ct.c_uint32]


class NET_BUFFER_LIST(EmuStruct):
    Next: Annotated[int, Ptr]
    FirstNetBuffer: Annotated[int, Ptr]
    Context: Annotated[int, Ptr]
    ParentNetBufferList: Annotated[int, Ptr]
    NdisPoolHandle: Annotated[int, Ptr]
    NdisReserved: Annotated[list[int], Ptr * 2]
    ProtocolReserved: Annotated[list[int], Ptr * 4]
    MiniportReserved: Annotated[list[int], Ptr * 2]
    Scratch: Annotated[int, Ptr]
    SourceHandle: Annotated[int, Ptr]
    NblFlags: Annotated[int, ct.c_uint32]
    ChildRefCount: Annotated[int, ct.c_uint32]
    Flags: Annotated[int, ct.c_uint32]
    NetBufferListInfo: Annotated[list[int], Ptr * 11]


class NET_BUFFER_DATA(EmuStruct):
    Next: Annotated[int, Ptr]
    CurrentMdl: Annotated[int, Ptr]
    CurrentMdlOffset: Annotated[int, ct.c_uint32]
    NbDataLength: Annotated[int, ct.c_uint32]
    MdlChain: Annotated[int, Ptr]
    DataOffset: Annotated[int, ct.c_uint32]


class NET_BUFFER_HEADER(EmuStruct):
    NetBufferData: NET_BUFFER_DATA
    Link: Annotated[int, Ptr]


class NET_BUFFER(EmuStruct):
    Link: Annotated[int, Ptr]
    NetBufferHeader: NET_BUFFER_HEADER
    ChecksumBias: Annotated[int, Ptr]
    Reserved: Annotated[int, Ptr]
    NdisPoolHandle: Annotated[int, Ptr]
    NdisReserved: Annotated[list[int], Ptr * 2]
    ProtocolReserved: Annotated[list[int], Ptr * 6]
    MiniportReserved: Annotated[list[int], Ptr * 4]
    DataPhysicalAddress: Annotated[int, ct.c_uint64]
    SharedMemoryInfo: Annotated[int, Ptr]
