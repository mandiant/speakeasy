# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import uuid

from speakeasy.struct import EmuStruct, Ptr

S_OK = 0

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

CLSID_WbemLocator = '{4590F811-1D3A-11D0-891F-00AA004B2E24}'
CLSID_IWbemContext = '{674B6698-EE92-11D0-AD71-00C04FD8FDFF}'

IID_IWbemLocator = '{DC12A687-737F-11CF-884D-00AA004B2E24}'
IID_IWbemContext = '{44ACA674-E8FC-11D0-A07C-00C04FB68820}'


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


class IWbemLocator(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.IUnknown = IUnknown
        self.ConnectServer = Ptr


class IWbemServices(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.IUnknown = IUnknown
        self.OpenNamespace = Ptr
        self.CancelAsyncCall = Ptr
        self.QueryObjectSink = Ptr
        self.GetObject = Ptr
        self.GetObjectAsync = Ptr
        self.PutClass = Ptr
        self.PutClassAsync = Ptr
        self.DeleteClass = Ptr
        self.DeleteClassAsync = Ptr
        self.CreateClassEnum = Ptr
        self.CreateClassEnumAsync = Ptr
        self.PutInstance = Ptr
        self.PutInstanceAsync = Ptr
        self.DeleteInstance = Ptr
        self.DeleteInstanceAsync = Ptr
        self.CreateInstanceEnum = Ptr
        self.CreateInstanceEnumAsync = Ptr
        self.ExecQuery = Ptr
        self.ExecQueryAsync = Ptr
        self.ExecNotificationQuery = Ptr
        self.ExecNotificationQueryAsync = Ptr
        self.ExecMethod = Ptr
        self.ExecMethodAsync = Ptr


class IWbemContext(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.IUnknown = IUnknown
        self.Clone = Ptr
        self.GetNames = Ptr
        self.BeginEnumeration = Ptr
        self.Next = Ptr
        self.EndEnumeration = Ptr
        self.SetValue = Ptr
        self.GetValue = Ptr
        self.DeleteValue = Ptr
        self.DeleteAll = Ptr


IFACE_TYPES = {'IUnknown': IUnknown,
               'IMalloc':  IMalloc,
               'IWbemLocator': IWbemLocator,
               'IWbemServices': IWbemServices,
               'IWbemContext': IWbemContext}


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


def convert_guid_bytes_to_str(guid_bytes):
    u = uuid.UUID(bytes_le=guid_bytes)
    return ('{%s}' % u).upper()
