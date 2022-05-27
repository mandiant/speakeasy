# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.

from speakeasy.struct import EmuStruct, Ptr
import ctypes as ct

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
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Next = Ptr
        self.ComboIndex = ct.c_uint32
        self.AdapterName = ct.c_uint8 * (MAX_ADAPTER_NAME_LENGTH + 4)
        self.Description = ct.c_uint8 * (MAX_ADAPTER_DESCRIPTION_LENGTH + 4)
        self.AddressLength = ct.c_uint32
        self.Address = ct.c_uint8 * MAX_ADAPTER_ADDRESS_LENGTH
        self.Index = ct.c_uint32
        self.Type = ct.c_uint32
        self.DhcpEnabled = ct.c_bool
        self.CurrentIpAddress = Ptr
        self.IpAddressList = IP_ADDR_STRING
        self.GatewayList = IP_ADDR_STRING
        self.DhcpServer = IP_ADDR_STRING
        self.HaveWins = ct.c_uint32
        self.PrimaryWinsServer = IP_ADDR_STRING
        self.SecondaryWinsServer = IP_ADDR_STRING
        self.LeaseObtained = Ptr
        self.LeaseExpires = Ptr


class IP_ADDR_STRING(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Next = Ptr
        self.IpAddress = ct.c_uint8 * 16
        self.IpMask = ct.c_uint8 * 16
        self.Context = ct.c_uint32


def get_adapter_type(type_str):
    if type_str == 'ethernet':
        return MIB_IF_TYPE_ETHERNET
