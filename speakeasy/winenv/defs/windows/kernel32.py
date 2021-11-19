# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from speakeasy.struct import EmuStruct, Ptr
import ctypes as ct

WSADESCRIPTION_LEN = 256
WSASYS_STATUS_LEN = 128

MAX_PATH = 260
MAX_MODULE_NAME32 = 255

FILE_ATTRIBUTE_NORMAL = 0x80

TH32CS_INHERIT = 0x80000000
TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004

PROCESSOR_ARCHITECTURE_AMD64 = 9
PROCESSOR_ARCHITECTURE_INTEL = 0

LOCALE_INVARIANT = 0x7F
LOCALE_USER_DEFAULT = 0x400
LOCALE_SYSTEM_DEFAULT = 0x800
LOCALE_CUSTOM_DEFAULT = 0xC00
LOCALE_CUSTOM_UNSPECIFIED = 0x1000
LOCALE_CUSTOM_UI_DEFAULT = 0x1400

LOCALE_SENGLISHLANGUAGENAME = 0x1001
LOCALE_SENGLISHCOUNTRYNAME = 0x1002

DRIVE_UNKNOWN = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
DRIVE_RAMDISK = 6

ComputerNameNetBIOS = 0
ComputerNameDnsHostname = 1
ComputerNameDnsDomain = 2
ComputerNameDnsFullyQualified = 3
ComputerNamePhysicalNetBIOS = 4
ComputerNamePhysicalDnsHostname = 5
ComputerNamePhysicalDnsDomain = 6
ComputerNamePhysicalDnsFullyQualified = 7
ComputerNameMax = 8

GetFileExInfoStandard = 0

EXCEPTION_CONTINUE_SEARCH = 0
EXCEPTION_EXECUTE_HANDLER = 1

THREAD_PRIORITY_NORMAL = 0

class PROCESSENTRY32(EmuStruct):
    def __init__(self, ptr_size, width):
        super().__init__(ptr_size)
        self.dwSize = ct.c_uint32
        self.cntUsage = ct.c_uint32
        self.th32ProcessID = ct.c_uint32
        self.th32DefaultHeapID = Ptr
        self.th32ModuleID = ct.c_uint32
        self.cntThreads = ct.c_uint32
        self.th32ParentProcessID = ct.c_uint32
        self.pcPriClassBase = ct.c_uint32
        self.dwFlags = ct.c_uint32
        self.szExeFile = ct.c_uint8 * (MAX_PATH * width)


class THREADENTRY32(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.dwSize = ct.c_uint32
        self.cntUsage = ct.c_uint32
        self.th32ThreadID = ct.c_uint32
        self.th32OwnerProcessID = ct.c_uint32
        self.tpBasePri = ct.c_uint32
        self.tpDeltaPri = ct.c_uint32
        self.dwFlags = ct.c_uint32


class MODULEENTRY32(EmuStruct):
    def __init__(self, ptr_size, width):
        super().__init__(ptr_size)
        self.dwSize = ct.c_uint32
        self.th32ModuleID = ct.c_uint32
        self.th32ProcessID = ct.c_uint32
        self.GlblcntUsage = ct.c_uint32
        self.ProccntUsage = ct.c_uint32
        self.modBaseAddr = Ptr
        self.modBaseSize = ct.c_uint32
        self.hModule = ct.c_uint32
        self.szModule = ct.c_uint8 * ((MAX_MODULE_NAME32 + 1) * width)
        self.szExePath = ct.c_uint8 * (MAX_PATH * width)


class PROCESS_INFORMATION(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.hProcess = Ptr
        self.hThread = Ptr
        self.dwProcessId = ct.c_uint32
        self.dwThreadId = ct.c_uint32


class MEMORY_BASIC_INFORMATION(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.BaseAddress = Ptr
        self.AllocationBase = Ptr
        self.AllocationProtect = ct.c_uint32
        self.RegionSize = Ptr
        self.State = ct.c_uint32
        self.Protect = ct.c_uint32
        self.Type = ct.c_uint32


class FILETIME(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.dwLowDateTime = ct.c_uint32
        self.dwHighDateTime = ct.c_uint32


class WIN32_FIND_DATA(EmuStruct):
    def __init__(self, ptr_size, width):
        super().__init__(ptr_size)
        self.dwFileAttributes = ct.c_uint32
        self.ftCreationTime = FILETIME
        self.ftLastAccessTime = FILETIME
        self.ftLastWriteTime = FILETIME
        self.nFileSizeHigh = ct.c_uint32
        self.nFileSizeLow = ct.c_uint32
        self.dwReserved0 = ct.c_uint32
        self.dwReserved1 = ct.c_uint32
        self.cFileName = ct.c_uint8 * (260 * width)
        self.cAlternateFileName = ct.c_uint8 * (14 * width)


class WIN32_FILE_ATTRIBUTE_DATA(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.dwFileAttributes = ct.c_uint32
        self.ftCreationTime = FILETIME
        self.ftLastAccessTime = FILETIME
        self.ftLastWriteTime = FILETIME
        self.nFileSizeHigh = ct.c_uint32
        self.nFileSizeLow = ct.c_uint32


class SYSTEM_INFO(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.wProcessorArchitecture = ct.c_uint16
        self.dwPageSize = ct.c_uint32
        self.lpMinimumApplicationAddress = Ptr
        self.lpMaximumApplicationAddress = Ptr
        self.dwActiveProcessorMask = Ptr
        self.dwNumberOfProcessors = ct.c_uint32
        self.dwProcessorType = ct.c_uint32
        self.dwAllocationGranularity = ct.c_uint32
        self.wProcessorLevel = ct.c_uint16
        self.wProcessorRevision = ct.c_uint16


class SYSTEMTIME(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.wYear = ct.c_uint16
        self.wMonth = ct.c_uint16
        self.wDayOfWeek = ct.c_uint16
        self.wDay = ct.c_uint16
        self.wHour = ct.c_uint16
        self.wMinute = ct.c_uint16
        self.wSecond = ct.c_uint16
        self.wMilliseconds = ct.c_uint16


class STARTUPINFO(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.cb = ct.c_uint32
        self.lpReserved = Ptr
        self.lpDesktop = Ptr
        self.lpTitle = Ptr
        self.dwX = ct.c_uint32
        self.dwY = ct.c_uint32
        self.dwXSize = ct.c_uint32
        self.dwYSize = ct.c_uint32
        self.dwXCountChars = ct.c_uint32
        self.dwYCountChars = ct.c_uint32
        self.dwFillAttribute = ct.c_uint32
        self.dwFlags = ct.c_uint32
        self.wShowWindow = ct.c_uint16
        self.cbReserved2 = ct.c_uint16
        self.lpReserved2 = Ptr
        self.hStdInput = Ptr
        self.hStdOutput = Ptr
        self.hStdError = Ptr


class OSVERSIONINFO(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.dwOSVersionInfoSize = ct.c_uint32
        self.dwMajorVersion = ct.c_uint32
        self.dwMinorVersion = ct.c_uint32
        self.dwBuildNumber = ct.c_uint32
        self.dwPlatformId = ct.c_uint32
        self.szCSDVersion = ct.c_uint8 * 128


class OSVERSIONINFOEX(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.dwOSVersion = OSVERSIONINFO
        self.dwPlatformId = ct.c_uint16
        self.dwPlatformId = ct.c_uint16
        self.wProductType = ct.c_uint8
        self.wReserved = ct.c_uint8


def get_define(define, prefix=''):
    for k, v in globals().items():
        if not isinstance(v, int) or v != define:
            continue
        if prefix:
            if k.startswith(prefix):
                return k
        else:
            return k


def get_define_value(define, prefix=''):
    for k, v in globals().items():
        if not isinstance(v, int) or k != define:
            continue
        if prefix:
            if k.startswith(prefix):
                return v
        else:
            return v


def get_flag_defines(flags, prefix=''):
    defs = []
    for k, v in globals().items():
        if not isinstance(v, int):
            continue
        if v & flags:
            if prefix and k.startswith(prefix):
                defs.append(k)
    return defs
