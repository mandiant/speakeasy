# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from typing import Annotated

from speakeasy.struct import EmuStruct, Ptr


class WSK_PROVIDER_BASIC_DISPATCH(EmuStruct):
    WskControlSocket: Annotated[int, Ptr]
    WskCloseSocket: Annotated[int, Ptr]


class WSK_PROVIDER_DATAGRAM_DISPATCH(EmuStruct):
    Basic: WSK_PROVIDER_BASIC_DISPATCH
    WskBind: Annotated[int, Ptr]
    WskSendTo: Annotated[int, Ptr]
    WskReceiveFrom: Annotated[int, Ptr]
    WskRelease: Annotated[int, Ptr]
    WskGetLocalAddress: Annotated[int, Ptr]
    WskSendMessages: Annotated[int, Ptr]


class WSK_CLIENT_DISPATCH(EmuStruct):
    Version: Annotated[int, ct.c_uint16]
    Reserved: Annotated[int, ct.c_uint16]
    WskClientEvent: Annotated[int, Ptr]


class WSK_CLIENT_NPI(EmuStruct):
    ClientContext: Annotated[int, Ptr]
    Dispatch: Annotated[int, Ptr]


class WSK_PROVIDER_DISPATCH(EmuStruct):
    Version: Annotated[int, ct.c_uint16]
    Reserved: Annotated[int, ct.c_uint16]
    WskSocket: Annotated[int, Ptr]
    WskSocketConnect: Annotated[int, Ptr]
    WskControlClient: Annotated[int, Ptr]
    WskGetAddressInfo: Annotated[int, Ptr]
    WskFreeAddressInfo: Annotated[int, Ptr]
    WskGetNameInfo: Annotated[int, Ptr]


class WSK_PROVIDER_NPI(EmuStruct):
    Client: Annotated[int, Ptr]
    Dispatch: Annotated[int, Ptr]
