# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import uuid

from speakeasy.struct import EmuStruct, Ptr

S_OK = 0
S_FALSE = 1
E_NOINTERFACE = 0x80004002
E_POINTER = 0x80004003
CLASS_E_CLASSNOTAVAILABLE = 0x80040111
REGDB_E_CLASSNOTREG = 0x80040154
CO_E_CLASSSTRING = 0x800401F3
WBEM_E_NOT_FOUND = 0x80041002

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
CLSID_IWbemContext = "{674B6698-EE92-11D0-AD71-00C04FD8FDFF}"

PROGID_CLSIDS = {
    "adodb.stream": "{00000566-0000-0010-8000-00AA006D2EA4}",
    "microsoft.xmlhttp": "{ED8C108E-4349-11D2-91A4-00C04F7969E8}",
    "msxml2.xmlhttp": "{F6D90F16-9C73-11D3-B32E-00C04F990BB4}",
    "msxml2.xmlhttp.3.0": "{F5078F35-C551-11D3-89B9-0000F81FE221}",
    "msxml2.xmlhttp.6.0": "{88D96A0A-F192-11D4-A65F-0040963251E5}",
    "schedule.service": "{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}",
    "scripting.filesystemobject": "{0D43FE01-F093-11CF-8940-00A0C9054228}",
    "shell.application": "{13709620-C279-11CE-A49E-444553540000}",
    "wbemscripting.swbemlocator": "{76A64158-CB41-11D1-8B02-00600806D9B6}",
    "winhttp.winhttprequest.5.1": "{2087C2F4-2CEF-4953-A8AB-66779B670495}",
    "wscript.shell": "{72C24DD5-D70A-438B-8A42-98424B88AFB8}",
}

IID_IUnknown = "{00000000-0000-0000-C000-000000000046}"
IID_IWbemLocator = "{DC12A687-737F-11CF-884D-00AA004B2E24}"
IID_IWbemContext = "{44ACA674-E8FC-11D0-A07C-00C04FB68820}"


class ComInterface:
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


IFACE_TYPES = {
    "IUnknown": IUnknown,
    "IMalloc": IMalloc,
    "IWbemLocator": IWbemLocator,
    "IWbemServices": IWbemServices,
    "IWbemContext": IWbemContext,
}


def get_define_int(define, prefix=""):
    for k, v in globals().items():
        if not isinstance(v, int) or v != define:
            continue
        if prefix:
            if k.startswith(prefix):
                return k
        else:
            return k


def get_define_str(define, prefix=""):
    for k, v in globals().items():
        if not isinstance(v, str) or v != define:
            continue
        if prefix:
            if k.startswith(prefix):
                return k
        else:
            return k


def get_clsid(define):
    return get_define_str(define, prefix="CLSID_")


def get_iid(define):
    return get_define_str(define, prefix="IID_")


def convert_guid_bytes_to_str(guid_bytes):
    u = uuid.UUID(bytes_le=guid_bytes)
    return (f"{{{u}}}").upper()
