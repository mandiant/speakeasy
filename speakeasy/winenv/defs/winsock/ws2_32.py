# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from typing import Annotated

from speakeasy.struct import EmuStruct, Ptr

WSADESCRIPTION_LEN = 256
WSASYS_STATUS_LEN = 128


class WSAData(EmuStruct):
    wVersion: Annotated[int, ct.c_uint16]
    wHighVersion: Annotated[int, ct.c_uint16]
    szDescription: bytes
    szSystemStatus: bytes
    iMaxSockets: int
    iMaxUdpDg: int
    lpVendorInfo: int

    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        description = ct.c_uint8 * (WSADESCRIPTION_LEN + 1)
        status = ct.c_uint8 * (WSASYS_STATUS_LEN + 1)
        if ptr_size == 8:
            self.add_fields(
                iMaxSockets=ct.c_uint16,
                iMaxUdpDg=ct.c_uint16,
                lpVendorInfo=Ptr,
                szDescription=description,
                szSystemStatus=status,
            )
        else:
            self.add_fields(
                szDescription=description,
                szSystemStatus=status,
                iMaxSockets=ct.c_uint16,
                iMaxUdpDg=ct.c_uint16,
                lpVendorInfo=Ptr,
            )


class sockaddr(EmuStruct):
    sa_family: Annotated[int, ct.c_uint16]
    sa_data: Annotated[bytes, ct.c_uint8 * 14]


class sockaddr_in(EmuStruct):
    sin_family: Annotated[int, ct.c_uint16]
    sin_port: Annotated[int, ct.c_uint16]
    sin_addr: Annotated[int, ct.c_uint32]
    sin_zero: Annotated[bytes, ct.c_uint8 * 8]


class hostent(EmuStruct):
    h_name: Annotated[int, Ptr]
    h_aliases: Annotated[int, Ptr]
    h_addrtype: Annotated[int, ct.c_uint16]
    h_length: Annotated[int, ct.c_uint16]
    h_addr_list: Annotated[int, Ptr]


class addrinfo(EmuStruct):
    ai_flags: Annotated[int, ct.c_uint32]
    ai_family: Annotated[int, ct.c_uint32]
    ai_socktype: Annotated[int, ct.c_uint32]
    ai_protocol: Annotated[int, ct.c_uint32]
    ai_addrlen: Annotated[int, Ptr]
    ai_canonname: Annotated[int, Ptr]
    ai_addr: Annotated[int, Ptr]
    ai_next: Annotated[int, Ptr]
