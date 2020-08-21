# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from speakeasy.struct import EmuStruct, Ptr
import ctypes as ct


class NDIS_OBJECT_HEADER(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Type = ct.c_uint8
        self.Revision = ct.c_uint8
        self.Size = ct.c_uint16


class NDIS_GENERIC_OBJECT(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Header = NDIS_OBJECT_HEADER
        self.Caller = Ptr
        self.CallersCaller = Ptr
        self.DriverObject = Ptr


class NET_BUFFER_LIST_POOL_PARAMETERS(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Header = NDIS_OBJECT_HEADER
        self.ProtocolId = ct.c_uint8
        self.fAllocateNetBuffer = ct.c_uint8
        self.ContextSize = ct.c_uint16
        self.PoolTag = ct.c_uint32
        self.DataSize = ct.c_uint32


class NET_BUFFER_LIST(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Next = Ptr
        self.FirstNetBuffer = Ptr
        self.Context = Ptr
        self.ParentNetBufferList = Ptr
        self.NdisPoolHandle = Ptr
        self.NdisReserved = Ptr * 2
        self.ProtocolReserved = Ptr * 4
        self.MiniportReserved = Ptr * 2
        self.Scratch = Ptr
        self.SourceHandle = Ptr
        self.NblFlags = ct.c_uint32
        self.ChildRefCount = ct.c_uint32
        self.Flags = ct.c_uint32
        self.NetBufferListInfo = Ptr * 11


class NET_BUFFER_DATA(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Next = Ptr
        self.CurrentMdl = Ptr
        self.CurrentMdlOffset = ct.c_uint32
        self.NbDataLength = ct.c_uint32
        self.MdlChain = Ptr
        self.DataOffset = ct.c_uint32


class NET_BUFFER_HEADER(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.NetBufferData = NET_BUFFER_DATA
        self.Link = Ptr


class NET_BUFFER(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Link = Ptr
        self.NetBufferHeader = NET_BUFFER_HEADER
        self.ChecksumBias = Ptr
        self.Reserved = Ptr
        self.NdisPoolHandle = Ptr
        self.NdisReserved = Ptr * 2
        self.ProtocolReserved = Ptr * 6
        self.MiniportReserved = Ptr * 4
        self.DataPhysicalAddress = ct.c_uint64
        self.SharedMemoryInfo = Ptr
