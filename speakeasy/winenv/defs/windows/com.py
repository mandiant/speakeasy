# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from speakeasy.struct import EmuStruct, Ptr

RPC_C_AUTHN_LEVEL_DEFAULT = 0
RPC_C_AUTHN_LEVEL_NONE = 1
RPC_C_AUTHN_LEVEL_CONNECT = 2
RPC_C_AUTHN_LEVEL_CALL = 3
RPC_C_AUTHN_LEVEL_PKT = 4
RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 5
RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6

RPC_C_IMP_LEVEL_DEFAULT = 0
RPC_C_IMP_LEVEL_ANONYMOUS = 1
RPC_C_IMP_LEVEL_IDENTIFY = 2
RPC_C_IMP_LEVEL_IMPERSONATE = 3
RPC_C_IMP_LEVEL_DELEGATE = 4

CLSID_WbemLocator = "{4590F811-1D3A-11D0-891F-00AA004B2E24}"

IID_IWbemLocator = "{DC12A687-737F-11CF-884D-00AA004B2E24}"


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


def get_define_int(define, prefix=''):
    for k, v in globals().items():
        if not isinstance(v, int) or v != define:
            continue
        if prefix:
            if k.startswith(prefix):
                return k
        else:
            return k


def get_define_str(define, prefix=''):
    for k, v in globals().items():
        if not isinstance(v, str) or v != define:
            continue
        if prefix:
            if k.startswith(prefix):
                return k
        else:
            return k


def get_clsid(define):
    return get_define_str(define, prefix='CLSID_')


def get_iid(define):
    return get_define_str(define, prefix='IID_')


def get_rpc_authlevel(define):
    return get_define_int(define, prefix='RPC_C_AUTHN_LEVEL_')


def get_rcp_implevel(define):
    return get_define_int(define, prefix='RPC_C_IMP_LEVEL_')
