# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from speakeasy.struct import EmuStruct, Ptr
import ctypes as ct


class GUID(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Data1 = ct.c_uint32
        self.Data2 = ct.c_uint16
        self.Data3 = ct.c_uint16
        self.Data4 = ct.c_uint8 * 8


class FWPM_DISPLAY_DATA0(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.name = Ptr
        self.description = Ptr


class FWP_VALUE0(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.type = ct.c_uint32
        self.data = Ptr


class FWP_BYTE_BLOB(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.size = ct.c_uint32
        self.data = Ptr


class FWPM_SUBLAYER0(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.subLayerKey = GUID
        self.displayData = FWPM_DISPLAY_DATA0
        self.flags = ct.c_uint32
        self.providerKey = GUID
        self.providerData = FWP_BYTE_BLOB
        self.weight = ct.c_uint16


class FWPS_CALLOUT1(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.calloutKey = GUID
        self.flags = ct.c_uint32
        self.classifyFn = Ptr
        self.notifyFn = Ptr
        self.flowDeleteFn = Ptr


class FWPM_CALLOUT0(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.calloutKey = GUID
        self.displayData = FWPM_DISPLAY_DATA0
        self.flags = ct.c_uint32
        self.providerKey = GUID
        self.providerData = FWP_BYTE_BLOB
        self.applicableLayer = GUID
        self.calloutId = ct.c_uint32


class FWPM_FILTER_CONDITION0(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.fieldKey = GUID
        self.matchType = ct.c_uint32
        self.conditionValue = FWP_VALUE0


class FWPM_ACTION0(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.type = ct.c_uint32
        self.filterType = GUID


class FWPM_FILTER0(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.filterKey = GUID
        self.displayData = FWPM_DISPLAY_DATA0
        self.flags = ct.c_uint32
        self.providerKey = GUID
        self.providerData = FWP_BYTE_BLOB
        self.layerKey = GUID
        self.subLayerKey = GUID
        self.weight = FWP_VALUE0
        self.numFilterConditions = ct.c_uint32
        self.filterCondition = Ptr
        self.action = FWPM_ACTION0
        self.providerContextKey = GUID
        self.reserved = Ptr
        self.filterId = ct.c_uint64
        self.effectiveWeight = FWP_VALUE0
