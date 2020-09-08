# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from speakeasy.struct import EmuStruct, Ptr


class ComInterface(object):
    def __init__(self, iface, name, ptr_size):
        self.iface = iface(ptr_size)
        self.address = 0
        self.name = name


class IUnknown(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.QueryInterface = Ptr
        self.AddRef = Ptr
        self.Release = Ptr


class IMalloc(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.IUnknown = IUnknown
        self.Alloc = Ptr
        self.Realloc = Ptr
        self.Free = Ptr
        self.GetSize = Ptr
        self.DidAlloc = Ptr
        self.HeapMinimize = Ptr


IFACE_TYPES = {'IUnknown': IUnknown,
               'IMalloc':  IMalloc}
