# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from enum import IntEnum
from typing import Annotated

from speakeasy.struct import EmuStruct, Ptr

MAX_PATH = 260
MAX_MODULE_NAME32 = 255


GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS = 0x00000004

FORMAT_MESSAGE_MAX_WIDTH_MASK = 0x000000FF
FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100
FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200
FORMAT_MESSAGE_FROM_STRING = 0x00000400
FORMAT_MESSAGE_FROM_HMODULE = 0x00000800
FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000

SYSTEM_MESSAGES = {
    0: "The operation completed successfully.\r\n",
    1: "Incorrect function.\r\n",
    2: "The system cannot find the file specified.\r\n",
    3: "The system cannot find the path specified.\r\n",
    4: "The system cannot open the file.\r\n",
    5: "Access is denied.\r\n",
    6: "The handle is invalid.\r\n",
    8: "Not enough memory resources are available to process this command.\r\n",
    32: "The process cannot access the file because it is being used by another process.\r\n",
    87: "The parameter is incorrect.\r\n",
    122: "The data area passed to a system call is too small.\r\n",
    126: "The specified module could not be found.\r\n",
    127: "The specified procedure could not be found.\r\n",
    183: "Cannot create a file when that file already exists.\r\n",
    1450: "Insufficient system resources exist to complete the requested service.\r\n",
    0x80004005: "Unspecified error\r\n",
    0x80040154: "Class not registered\r\n",
}

INIT_ONCE_CHECK_ONLY = 0x00000001
INIT_ONCE_ASYNC = 0x00000002
INIT_ONCE_INIT_FAILED = 0x00000004

PROCESSOR_ARCHITECTURE_AMD64 = 9
PROCESSOR_ARCHITECTURE_INTEL = 0

PROCESSOR_INTEL_PENTIUM = 586
PROCESSOR_AMD_X8664 = 8664


class LCID(IntEnum):
    """
    The predefined locale identifiers.

    The SDK defines them with the MAKELCID macro, so win32json has no constants for them.
    """

    LOCALE_INVARIANT = 0x7F
    LOCALE_USER_DEFAULT = 0x400
    LOCALE_SYSTEM_DEFAULT = 0x800
    LOCALE_CUSTOM_DEFAULT = 0xC00
    LOCALE_CUSTOM_UNSPECIFIED = 0x1000
    LOCALE_CUSTOM_UI_DEFAULT = 0x1400


THREAD_PRIORITY_NORMAL = 0


class PROCESSENTRY32(EmuStruct):
    dwSize: Annotated[int, ct.c_uint32]
    cntUsage: Annotated[int, ct.c_uint32]
    th32ProcessID: Annotated[int, ct.c_uint32]
    th32DefaultHeapID: Annotated[int, Ptr]
    th32ModuleID: Annotated[int, ct.c_uint32]
    cntThreads: Annotated[int, ct.c_uint32]
    th32ParentProcessID: Annotated[int, ct.c_uint32]
    pcPriClassBase: Annotated[int, ct.c_uint32]
    dwFlags: Annotated[int, ct.c_uint32]
    szExeFile: bytes

    def __init__(self, ptr_size, width):
        super().__init__(ptr_size)
        self.add_fields(szExeFile=ct.c_uint8 * (MAX_PATH * width))


class THREADENTRY32(EmuStruct):
    dwSize: Annotated[int, ct.c_uint32]
    cntUsage: Annotated[int, ct.c_uint32]
    th32ThreadID: Annotated[int, ct.c_uint32]
    th32OwnerProcessID: Annotated[int, ct.c_uint32]
    tpBasePri: Annotated[int, ct.c_uint32]
    tpDeltaPri: Annotated[int, ct.c_uint32]
    dwFlags: Annotated[int, ct.c_uint32]


class MODULEENTRY32(EmuStruct):
    dwSize: Annotated[int, ct.c_uint32]
    th32ModuleID: Annotated[int, ct.c_uint32]
    th32ProcessID: Annotated[int, ct.c_uint32]
    GlblcntUsage: Annotated[int, ct.c_uint32]
    ProccntUsage: Annotated[int, ct.c_uint32]
    modBaseAddr: Annotated[int, Ptr]
    modBaseSize: Annotated[int, ct.c_uint32]
    hModule: Annotated[int, Ptr]
    szModule: bytes
    szExePath: bytes

    def __init__(self, ptr_size, width):
        super().__init__(ptr_size)
        self.add_fields(
            szModule=ct.c_uint8 * ((MAX_MODULE_NAME32 + 1) * width),
            szExePath=ct.c_uint8 * (MAX_PATH * width),
        )


class PROCESS_INFORMATION(EmuStruct):
    hProcess: Annotated[int, Ptr]
    hThread: Annotated[int, Ptr]
    dwProcessId: Annotated[int, ct.c_uint32]
    dwThreadId: Annotated[int, ct.c_uint32]


class MEMORY_BASIC_INFORMATION(EmuStruct):
    BaseAddress: Annotated[int, Ptr]
    AllocationBase: Annotated[int, Ptr]
    AllocationProtect: Annotated[int, ct.c_uint32]
    RegionSize: Annotated[int, Ptr]
    State: Annotated[int, ct.c_uint32]
    Protect: Annotated[int, ct.c_uint32]
    Type: Annotated[int, ct.c_uint32]


class FILETIME(EmuStruct):
    dwLowDateTime: Annotated[int, ct.c_uint32]
    dwHighDateTime: Annotated[int, ct.c_uint32]


class WIN32_FIND_DATA(EmuStruct):
    dwFileAttributes: Annotated[int, ct.c_uint32]
    ftCreationTime: FILETIME
    ftLastAccessTime: FILETIME
    ftLastWriteTime: FILETIME
    nFileSizeHigh: Annotated[int, ct.c_uint32]
    nFileSizeLow: Annotated[int, ct.c_uint32]
    dwReserved0: Annotated[int, ct.c_uint32]
    dwReserved1: Annotated[int, ct.c_uint32]
    cFileName: bytes
    cAlternateFileName: bytes

    def __init__(self, ptr_size, width):
        super().__init__(ptr_size)
        self.add_fields(cFileName=ct.c_uint8 * (260 * width), cAlternateFileName=ct.c_uint8 * (14 * width))


class BY_HANDLE_FILE_INFORMATION(EmuStruct):
    dwFileAttributes: Annotated[int, ct.c_uint32]
    ftCreationTime: FILETIME
    ftLastAccessTime: FILETIME
    ftLastWriteTime: FILETIME
    dwVolumeSerialNumber: Annotated[int, ct.c_uint32]
    nFileSizeHigh: Annotated[int, ct.c_uint32]
    nFileSizeLow: Annotated[int, ct.c_uint32]
    nNumberOfLinks: Annotated[int, ct.c_uint32]
    nFileIndexHigh: Annotated[int, ct.c_uint32]
    nFileIndexLow: Annotated[int, ct.c_uint32]


class WIN32_FILE_ATTRIBUTE_DATA(EmuStruct):
    dwFileAttributes: Annotated[int, ct.c_uint32]
    ftCreationTime: FILETIME
    ftLastAccessTime: FILETIME
    ftLastWriteTime: FILETIME
    nFileSizeHigh: Annotated[int, ct.c_uint32]
    nFileSizeLow: Annotated[int, ct.c_uint32]


class SYSTEM_INFO(EmuStruct):
    wProcessorArchitecture: Annotated[int, ct.c_uint16]
    dwPageSize: Annotated[int, ct.c_uint32]
    lpMinimumApplicationAddress: Annotated[int, Ptr]
    lpMaximumApplicationAddress: Annotated[int, Ptr]
    dwActiveProcessorMask: Annotated[int, Ptr]
    dwNumberOfProcessors: Annotated[int, ct.c_uint32]
    dwProcessorType: Annotated[int, ct.c_uint32]
    dwAllocationGranularity: Annotated[int, ct.c_uint32]
    wProcessorLevel: Annotated[int, ct.c_uint16]
    wProcessorRevision: Annotated[int, ct.c_uint16]


class SYSTEMTIME(EmuStruct):
    wYear: Annotated[int, ct.c_uint16]
    wMonth: Annotated[int, ct.c_uint16]
    wDayOfWeek: Annotated[int, ct.c_uint16]
    wDay: Annotated[int, ct.c_uint16]
    wHour: Annotated[int, ct.c_uint16]
    wMinute: Annotated[int, ct.c_uint16]
    wSecond: Annotated[int, ct.c_uint16]
    wMilliseconds: Annotated[int, ct.c_uint16]


class STARTUPINFO(EmuStruct):
    cb: Annotated[int, ct.c_uint32]
    lpReserved: Annotated[int, Ptr]
    lpDesktop: Annotated[int, Ptr]
    lpTitle: Annotated[int, Ptr]
    dwX: Annotated[int, ct.c_uint32]
    dwY: Annotated[int, ct.c_uint32]
    dwXSize: Annotated[int, ct.c_uint32]
    dwYSize: Annotated[int, ct.c_uint32]
    dwXCountChars: Annotated[int, ct.c_uint32]
    dwYCountChars: Annotated[int, ct.c_uint32]
    dwFillAttribute: Annotated[int, ct.c_uint32]
    dwFlags: Annotated[int, ct.c_uint32]
    wShowWindow: Annotated[int, ct.c_uint16]
    cbReserved2: Annotated[int, ct.c_uint16]
    lpReserved2: Annotated[int, Ptr]
    hStdInput: Annotated[int, Ptr]
    hStdOutput: Annotated[int, Ptr]
    hStdError: Annotated[int, Ptr]


class OSVERSIONINFO(EmuStruct):
    dwOSVersionInfoSize: Annotated[int, ct.c_uint32]
    dwMajorVersion: Annotated[int, ct.c_uint32]
    dwMinorVersion: Annotated[int, ct.c_uint32]
    dwBuildNumber: Annotated[int, ct.c_uint32]
    dwPlatformId: Annotated[int, ct.c_uint32]
    szCSDVersion: bytes

    def __init__(self, ptr_size, width):
        super().__init__(ptr_size)
        self.add_fields(szCSDVersion=ct.c_uint8 * (128 * width))


class OSVERSIONINFOEX(EmuStruct):
    dwOSVersionInfoSize: Annotated[int, ct.c_uint32]
    dwMajorVersion: Annotated[int, ct.c_uint32]
    dwMinorVersion: Annotated[int, ct.c_uint32]
    dwBuildNumber: Annotated[int, ct.c_uint32]
    dwPlatformId: Annotated[int, ct.c_uint32]
    szCSDVersion: bytes
    wServicePackMajor: int
    wServicePackMinor: int
    wSuiteMask: int
    wProductType: int
    wReserved: int

    def __init__(self, ptr_size, width):
        super().__init__(ptr_size)
        self.add_fields(
            szCSDVersion=ct.c_uint8 * (128 * width),
            wServicePackMajor=ct.c_uint16,
            wServicePackMinor=ct.c_uint16,
            wSuiteMask=ct.c_uint16,
            wProductType=ct.c_uint8,
            wReserved=ct.c_uint8,
        )
