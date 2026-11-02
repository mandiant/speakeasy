# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from typing import Annotated

from speakeasy.struct import EmuStruct, EmuUnion, Ptr


class GUID(EmuStruct):
    Data1: Annotated[int, ct.c_uint32]
    Data2: Annotated[int, ct.c_uint16]
    Data3: Annotated[int, ct.c_uint16]
    Data4: Annotated[bytes, ct.c_uint8 * 8]


class FWPM_DISPLAY_DATA0(EmuStruct):
    name: Annotated[int, Ptr]
    description: Annotated[int, Ptr]


class FWP_VALUE0(EmuStruct):
    type: Annotated[int, ct.c_uint32]
    data: Annotated[int, Ptr]


class FWP_BYTE_BLOB(EmuStruct):
    size: Annotated[int, ct.c_uint32]
    data: Annotated[int, Ptr]


class FWPM_SUBLAYER0(EmuStruct):
    subLayerKey: GUID
    displayData: FWPM_DISPLAY_DATA0
    flags: Annotated[int, ct.c_uint32]
    providerKey: Annotated[int, Ptr]
    providerData: FWP_BYTE_BLOB
    weight: Annotated[int, ct.c_uint16]


class FWPS_CALLOUT1(EmuStruct):
    calloutKey: GUID
    flags: Annotated[int, ct.c_uint32]
    classifyFn: Annotated[int, Ptr]
    notifyFn: Annotated[int, Ptr]
    flowDeleteFn: Annotated[int, Ptr]


class FWPM_CALLOUT0(EmuStruct):
    calloutKey: GUID
    displayData: FWPM_DISPLAY_DATA0
    flags: Annotated[int, ct.c_uint32]
    providerKey: Annotated[int, Ptr]
    providerData: FWP_BYTE_BLOB
    applicableLayer: GUID
    calloutId: Annotated[int, ct.c_uint32]


class FWPM_FILTER_CONDITION0(EmuStruct):
    fieldKey: GUID
    matchType: Annotated[int, ct.c_uint32]
    conditionValue: FWP_VALUE0


class FWPM_ACTION0(EmuStruct):
    type: Annotated[int, ct.c_uint32]
    filterType: GUID


class FWPM_FILTER0_CONTEXT(EmuUnion):
    rawContext: Annotated[int, ct.c_uint64]

    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.providerContextKey = GUID(ptr_size).get_cstruct()


class FWPM_FILTER0(EmuStruct):
    filterKey: GUID
    displayData: FWPM_DISPLAY_DATA0
    flags: Annotated[int, ct.c_uint32]
    providerKey: Annotated[int, Ptr]
    providerData: FWP_BYTE_BLOB
    layerKey: GUID
    subLayerKey: GUID
    weight: FWP_VALUE0
    numFilterConditions: Annotated[int, ct.c_uint32]
    filterCondition: Annotated[int, Ptr]
    action: FWPM_ACTION0
    Anonymous: FWPM_FILTER0_CONTEXT
    reserved: Annotated[int, Ptr]
    filterId: Annotated[int, ct.c_uint64]
    effectiveWeight: FWP_VALUE0
