# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from speakeasy.struct import EmuStruct, Enum
import ctypes as ct

REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7
REG_QWORD = 11

RTL_REGISTRY_ABSOLUTE = 0
RTL_REGISTRY_SERVICES = 1
RTL_REGISTRY_CONTROL = 2
RTL_REGISTRY_WINDOWS_NT = 3
RTL_REGISTRY_DEVICEMAP = 4
RTL_REGISTRY_USER = 5
RTL_REGISTRY_MAXIMUM = 6

HKEY_CLASSES_ROOT = 0x80000000
HKEY_CURRENT_USER = 0x80000001
HKEY_LOCAL_MACHINE = 0x80000002
HKEY_USERS = 0x80000003


KEY_VALUE_INFORMATION_CLASS = Enum()
KEY_VALUE_INFORMATION_CLASS.KeyValueBasicInformation = 0x00
KEY_VALUE_INFORMATION_CLASS.KeyValueFullInformation = 0x01
KEY_VALUE_INFORMATION_CLASS.KeyValuePartialInformation = 0x02
KEY_VALUE_INFORMATION_CLASS.KeyValueFullInformationAlign64 = 0x03
KEY_VALUE_INFORMATION_CLASS.KeyValuePartialInformationAlign64 = 0x04
KEY_VALUE_INFORMATION_CLASS.KeyValueLayerInformation = 0x05
KEY_VALUE_INFORMATION_CLASS.MaxKeyValueInfoClass = 0x06


class KEY_VALUE_PARTIAL_INFORMATION(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.TitleIndex = ct.c_uint32
        self.Type = ct.c_uint32
        self.DataLength = ct.c_uint32
        # Data[1]


class KEY_VALUE_BASIC_INFORMATION(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.TitleIndex = ct.c_uint32
        self.Type = ct.c_uint32
        self.NameLength = ct.c_uint32
        # Name[1]


class KEY_VALUE_FULL_INFORMATION(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.TitleIndex = ct.c_uint32
        self.Type = ct.c_uint32
        self.DataOffset = ct.c_uint32
        self.DataLength = ct.c_uint32
        self.NameLength = ct.c_uint32


def get_defines(define, prefix=''):
    for k, v in globals().items():
        if not isinstance(v, int) or v != define:
            continue
        if prefix:
            if k.startswith(prefix):
                return k
        else:
            return k


def get_flag_value(flag):
    return globals().get(flag)


def get_value_type(define):
    return get_defines(define, prefix='REG_')


def get_hkey_type(define):
    return get_defines(define, prefix='HKEY_')
