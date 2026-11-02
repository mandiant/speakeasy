# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from typing import Annotated

from speakeasy.struct import EmuStruct, Ptr
from speakeasy.winenv.defs.enums import ENUM_SERVICE_TYPE, SERVICE_STATUS_CURRENT_STATE

NTE_BAD_ALGID = 0x80090008
NTE_INVALID_HANDLE = 0x80090026

CRYPT_NO_SALT = 0x10

HP_HASHVAL = 2
HP_HASHSIZE = 4


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
    lpServiceName: Annotated[int, Ptr]
    lpServiceProc: Annotated[int, Ptr]


class HCRYPTKEY(EmuStruct):
    Algid: Annotated[int, ct.c_uint32]
    keylen: Annotated[int, ct.c_uint32]
    keyp: Annotated[int, Ptr]
