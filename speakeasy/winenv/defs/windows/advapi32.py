# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct

from speakeasy.struct import EmuStruct, Ptr

NTE_BAD_ALGID = 0x80090008
NTE_INVALID_HANDLE = 0x80090026

CRYPT_NO_SALT = 0x10

HP_HASHVAL = 2
HP_HASHSIZE = 4

SERVICE_WIN32 = 0x30

SERVICE_ACTIVE = 0x1
SERVICE_INACTIVE = 0x2
SERVICE_STATE_ALL = 0x3

SERVICE_WIN32_OWN_PROCESS = 0x10
SERVICE_WIN32_SHARE_PROCESS = 0x20

SERVICE_STOPPED = 0x1
SERVICE_RUNNING = 0x4

SERVICE_ACCEPT_STOP = 0x1

# Win32 services that EnumServicesStatus reports: (name, display name, type, state)
EMULATED_SERVICES = (
    ("Dhcp", "DHCP Client", SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING),
    ("Dnscache", "DNS Client", SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING),
    ("EventLog", "Windows Event Log", SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING),
    ("LanmanServer", "Server", SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING),
    ("LanmanWorkstation", "Workstation", SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING),
    ("Schedule", "Task Scheduler", SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING),
    ("Winmgmt", "Windows Management Instrumentation", SERVICE_WIN32_SHARE_PROCESS, SERVICE_RUNNING),
    ("Fax", "Fax", SERVICE_WIN32_OWN_PROCESS, SERVICE_STOPPED),
    ("RemoteRegistry", "Remote Registry", SERVICE_WIN32_SHARE_PROCESS, SERVICE_STOPPED),
    ("SNMPTRAP", "SNMP Trap", SERVICE_WIN32_OWN_PROCESS, SERVICE_STOPPED),
    ("TapiSrv", "Telephony", SERVICE_WIN32_SHARE_PROCESS, SERVICE_STOPPED),
    ("WebClient", "WebClient", SERVICE_WIN32_SHARE_PROCESS, SERVICE_STOPPED),
    ("seclogon", "Secondary Logon", SERVICE_WIN32_SHARE_PROCESS, SERVICE_STOPPED),
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


def get_define_int(define, prefix=""):
    for k, v in globals().items():
        if not isinstance(v, int) or v != define:
            continue
        if prefix:
            if k.startswith(prefix):
                return k
        else:
            return k
