# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from speakeasy.struct import EmuStruct, Ptr
import ctypes as ct

WSADESCRIPTION_LEN = 256
WSASYS_STATUS_LEN = 128


class WSAData(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.wVersion = ct.c_uint16
        self.wHighVersion = ct.c_uint32
        self.iMaxSockets = ct.c_uint32
        self.iMaxUdpDg = ct.c_uint32
        self.lpVendorInfo = ct.c_uint16
        self.szDescription = ct.c_uint8 * (WSADESCRIPTION_LEN + 1)
        self.szSystemStatus = ct.c_uint8 * (WSASYS_STATUS_LEN + 1)


class sockaddr(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.sa_family = ct.c_uint16
        self.sa_data = ct.c_uint8 * 14


class sockaddr_in(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.sin_family = ct.c_uint16
        self.sin_port = ct.c_uint16
        self.sin_addr = ct.c_uint32
        self.sin_zero = ct.c_uint8 * 8


class hostent(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.h_name = Ptr
        self.h_aliases = Ptr
        self.h_addrtype = ct.c_uint16
        self.h_length = ct.c_uint16
        self.h_addr_list = Ptr


class addrinfo(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.ai_flags = ct.c_uint32
        self.ai_family = ct.c_uint32
        self.ai_socktype = ct.c_uint32
        self.ai_protocol = ct.c_uint32
        self.ai_addrlen = ct.c_uint
        self.ai_canonname = Ptr
        self.ai_addr = Ptr
        self.ai_next = Ptr
