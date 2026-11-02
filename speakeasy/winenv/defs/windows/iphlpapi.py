# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.

from __future__ import annotations

import ctypes as ct
from typing import Annotated

from speakeasy.struct import EmuStruct, Ptr

MAX_ADAPTER_NAME_LENGTH = 256
MAX_ADAPTER_DESCRIPTION_LENGTH = 128
MAX_ADAPTER_ADDRESS_LENGTH = 8

MIB_IF_TYPE_OTHER = 1
MIB_IF_TYPE_ETHERNET = 6
MIB_IF_TYPE_PPP = 23
MIB_IF_TYPE_LOOPBACK = 24
MIB_IF_TYPE_SLIP = 28

IF_TYPE_ISO88025_TOKENRING = 9
IF_TYPE_IEEE80211 = 71


class IP_ADAPTER_INFO(EmuStruct):
    Next: Annotated[int, Ptr]
    ComboIndex: Annotated[int, ct.c_uint32]
    AdapterName: Annotated[bytes, ct.c_uint8 * (MAX_ADAPTER_NAME_LENGTH + 4)]
    Description: Annotated[bytes, ct.c_uint8 * (MAX_ADAPTER_DESCRIPTION_LENGTH + 4)]
    AddressLength: Annotated[int, ct.c_uint32]
    Address: Annotated[bytes, ct.c_uint8 * MAX_ADAPTER_ADDRESS_LENGTH]
    Index: Annotated[int, ct.c_uint32]
    Type: Annotated[int, ct.c_uint32]
    DhcpEnabled: Annotated[int, ct.c_uint32]
    CurrentIpAddress: Annotated[int, Ptr]
    IpAddressList: IP_ADDR_STRING
    GatewayList: IP_ADDR_STRING
    DhcpServer: IP_ADDR_STRING
    HaveWins: Annotated[int, ct.c_uint32]
    PrimaryWinsServer: IP_ADDR_STRING
    SecondaryWinsServer: IP_ADDR_STRING
    LeaseObtained: Annotated[int, ct.c_int64]
    LeaseExpires: Annotated[int, ct.c_int64]


class IP_ADDR_STRING(EmuStruct):
    Next: Annotated[int, Ptr]
    IpAddress: Annotated[bytes, ct.c_uint8 * 16]
    IpMask: Annotated[bytes, ct.c_uint8 * 16]
    Context: Annotated[int, ct.c_uint32]


def get_adapter_type(type_str):
    if type_str == "ethernet":
        return MIB_IF_TYPE_ETHERNET
    return MIB_IF_TYPE_OTHER
