# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from enum import IntEnum, IntFlag

from speakeasy.struct import EmuStruct, Ptr

NTE_BAD_ALGID = 0x80090008
NTE_INVALID_HANDLE = 0x80090026

CRYPT_NO_SALT = 0x10

HP_HASHVAL = 2
HP_HASHSIZE = 4


class ENUM_SERVICE_TYPE(IntFlag):
    SERVICE_DRIVER = 0x0000000B
    SERVICE_KERNEL_DRIVER = 0x00000001
    SERVICE_WIN32 = 0x00000030
    SERVICE_WIN32_SHARE_PROCESS = 0x00000020
    SERVICE_ADAPTER = 0x00000004
    SERVICE_FILE_SYSTEM_DRIVER = 0x00000002
    SERVICE_RECOGNIZER_DRIVER = 0x00000008
    SERVICE_WIN32_OWN_PROCESS = 0x00000010
    SERVICE_USER_OWN_PROCESS = 0x00000050
    SERVICE_USER_SHARE_PROCESS = 0x00000060


class ENUM_SERVICE_STATE(IntEnum):
    SERVICE_ACTIVE = 1
    SERVICE_INACTIVE = 2
    SERVICE_STATE_ALL = 3


class SERVICE_STATUS_CURRENT_STATE(IntEnum):
    SERVICE_CONTINUE_PENDING = 5
    SERVICE_PAUSE_PENDING = 6
    SERVICE_PAUSED = 7
    SERVICE_RUNNING = 4
    SERVICE_START_PENDING = 2
    SERVICE_STOP_PENDING = 3
    SERVICE_STOPPED = 1


SERVICE_ACCEPT_STOP = 0x1

_SHARE_PROCESS = ENUM_SERVICE_TYPE.SERVICE_WIN32_SHARE_PROCESS
_OWN_PROCESS = ENUM_SERVICE_TYPE.SERVICE_WIN32_OWN_PROCESS
_RUNNING = SERVICE_STATUS_CURRENT_STATE.SERVICE_RUNNING
_STOPPED = SERVICE_STATUS_CURRENT_STATE.SERVICE_STOPPED

# Win32 services that EnumServicesStatus reports: (name, display name, type, state)
EMULATED_SERVICES = (
    ("Dhcp", "DHCP Client", _SHARE_PROCESS, _RUNNING),
    ("Dnscache", "DNS Client", _SHARE_PROCESS, _RUNNING),
    ("EventLog", "Windows Event Log", _SHARE_PROCESS, _RUNNING),
    ("LanmanServer", "Server", _SHARE_PROCESS, _RUNNING),
    ("LanmanWorkstation", "Workstation", _SHARE_PROCESS, _RUNNING),
    ("Schedule", "Task Scheduler", _SHARE_PROCESS, _RUNNING),
    ("Winmgmt", "Windows Management Instrumentation", _SHARE_PROCESS, _RUNNING),
    ("Fax", "Fax", _OWN_PROCESS, _STOPPED),
    ("RemoteRegistry", "Remote Registry", _SHARE_PROCESS, _STOPPED),
    ("SNMPTRAP", "SNMP Trap", _OWN_PROCESS, _STOPPED),
    ("TapiSrv", "Telephony", _SHARE_PROCESS, _STOPPED),
    ("WebClient", "WebClient", _SHARE_PROCESS, _STOPPED),
    ("seclogon", "Secondary Logon", _SHARE_PROCESS, _STOPPED),
)


class SERVICE_TABLE_ENTRY(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.lpServiceName = Ptr
        self.lpServiceProc = Ptr


class HCRYPTKEY(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Algid = ct.c_uint32
        self.keylen = ct.c_uint32
        self.keyp = Ptr
