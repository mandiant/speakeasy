# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct

from speakeasy.struct import EmuStruct, Enum
from speakeasy.winenv.defs.enums import HKEY

REG_CREATED_NEW_KEY = 1
REG_OPENED_EXISTING_KEY = 2

RTL_REGISTRY_ABSOLUTE = 0
RTL_REGISTRY_SERVICES = 1
RTL_REGISTRY_CONTROL = 2
RTL_REGISTRY_WINDOWS_NT = 3
RTL_REGISTRY_DEVICEMAP = 4
RTL_REGISTRY_USER = 5
RTL_REGISTRY_MAXIMUM = 6


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


def normalize_hkey(hkey):
    """
    Map a predefined key that x64 code passes sign-extended to its 32-bit value.

    For example, ``0xFFFFFFFF80000002`` for ``HKEY_LOCAL_MACHINE`` becomes ``0x80000002``.
    """
    if hkey >> 32 == 0xFFFFFFFF and 0x80000000 <= hkey & 0xFFFFFFFF <= 0x80000007:
        return hkey & 0xFFFFFFFF
    return hkey


def get_hkey_type(hkey):
    """Get the name of a predefined key, or None for another key."""
    hkey = normalize_hkey(hkey)
    return next((key.name for key in HKEY if key == hkey), None)
