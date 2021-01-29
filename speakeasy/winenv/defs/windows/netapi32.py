# Copyright (C) 2021 FireEye, Inc. All Rights Reserved.

from speakeasy.struct import EmuStruct, Ptr
import ctypes as ct

NERR_Success = 0

NetSetupUnknownStatus = 0
NetSetupUnjoined = 1
NetSetupWorkgroupName = 2
NetSetupDomainName = 3


class WKSTA_INFO_100(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.wki_platform_id = Ptr
        self.wki_computername = Ptr
        self.wki_langroup = Ptr
        self.wki_ver_major = ct.c_uint32
        self.wki_ver_minor = ct.c_uint32


class WKSTA_INFO_101(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.wki_platform_id = Ptr
        self.wki_computername = Ptr
        self.wki_langroup = Ptr
        self.wki_ver_major = ct.c_uint32
        self.wki_ver_minor = ct.c_uint32
        self.wki_lanroot = Ptr


class WKSTA_INFO_102(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.wki_platform_id = Ptr
        self.wki_computername = Ptr
        self.wki_langroup = Ptr
        self.wki_ver_major = ct.c_uint32
        self.wki_ver_minor = ct.c_uint32
        self.wki_lanroot = Ptr
        self.wki_logged_on_users = Ptr
