# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from speakeasy.struct import EmuStruct, Ptr
import ctypes as ct


class WSK_PROVIDER_BASIC_DISPATCH(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.WskControlSocket = Ptr
        self.WskCloseSocket = Ptr


class WSK_PROVIDER_DATAGRAM_DISPATCH(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Basic = WSK_PROVIDER_BASIC_DISPATCH
        self.WskBind = Ptr
        self.WskSendTo = Ptr
        self.WskReceiveFrom = Ptr
        self.WskRelease = Ptr
        self.WskGetLocalAddress = Ptr
        self.WskSendMessages = Ptr


class WSK_CLIENT_DISPATCH(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Version = ct.c_uint16
        self.Reserved = ct.c_uint16
        self.WskClientEvent = Ptr


class WSK_CLIENT_NPI(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.ClientContext = Ptr
        self.Dispatch = Ptr


class WSK_PROVIDER_DISPATCH(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Version = ct.c_uint16
        self.Reserved = ct.c_uint16
        self.WskSocket = Ptr
        self.WskSocketConnect = Ptr
        self.WskControlClient = Ptr
        self.WskGetAddressInfo = Ptr
        self.WskFreeAddressInfo = Ptr
        self.WskGetNameInfo = Ptr


class WSK_PROVIDER_NPI(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Client = Ptr
        self.Dispatch = Ptr
