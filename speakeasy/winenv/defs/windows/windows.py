# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from enum import IntEnum, IntFlag

from speakeasy.struct import EmuStruct, Ptr

NULL = 0

ERROR_SUCCESS = 0
ERROR_INVALID_FUNCTION = 1
ERROR_FILE_NOT_FOUND = 2
ERROR_PATH_NOT_FOUND = 3
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_HANDLE = 6
ERROR_NOT_ENOUGH_MEMORY = 8
ERROR_INVALID_DATA = 13
ERROR_NO_MORE_FILES = 18
ERROR_GEN_FAILURE = 31
ERROR_FILE_EXISTS = 80
ERROR_INVALID_PARAMETER = 87
ERROR_BUFFER_OVERFLOW = 111
ERROR_NEGATIVE_SEEK = 131
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_INVALID_SID = 1337
ERROR_INVALID_LEVEL = 124
ERROR_MOD_NOT_FOUND = 126
ERROR_PROC_NOT_FOUND = 127
ERROR_ALREADY_EXISTS = 183
ERROR_BAD_EXE_FORMAT = 193
ERROR_ENVVAR_NOT_FOUND = 203
ERROR_MORE_DATA = 234
ERROR_NO_MORE_ITEMS = 259
ERROR_MR_MID_NOT_FOUND = 317
ERROR_INVALID_ADDRESS = 487
ERROR_INVALID_WINDOW_HANDLE = 1400
ERROR_TIMEOUT = 1460
ERROR_RESOURCE_DATA_NOT_FOUND = 1812
ERROR_RESOURCE_TYPE_NOT_FOUND = 1813
ERROR_RESOURCE_NAME_NOT_FOUND = 1814
ERROR_RESOURCE_ENUM_USER_STOP = 15106

S_OK = 0
E_OUTOFMEMORY = 0x8007000E
E_FILE_NOT_FOUND = 0x80070002
E_INVALIDARG = 0x80070057

WAIT_OBJECT_0 = 0

IMAGE_FILE_MACHINE_UNKNOWN = 0
IMAGE_FILE_MACHINE_I386 = 0x14C
IMAGE_FILE_MACHINE_AMD64 = 0x8664

MEM_COMMIT = 0x1000
MEM_FREE = 0x10000
MEM_RESERVE = 0x2000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

HEAP_REALLOC_IN_PLACE_ONLY = 0x10


class PAGE_PROTECTION_FLAGS(IntFlag):
    PAGE_NOACCESS = 0x00000001
    PAGE_READONLY = 0x00000002
    PAGE_READWRITE = 0x00000004
    PAGE_WRITECOPY = 0x00000008
    PAGE_EXECUTE = 0x00000010
    PAGE_EXECUTE_READ = 0x00000020
    PAGE_EXECUTE_READWRITE = 0x00000040
    PAGE_EXECUTE_WRITECOPY = 0x00000080
    PAGE_GUARD = 0x00000100
    PAGE_NOCACHE = 0x00000200
    PAGE_WRITECOMBINE = 0x00000400
    PAGE_GRAPHICS_NOACCESS = 0x00000800
    PAGE_GRAPHICS_READONLY = 0x00001000
    PAGE_GRAPHICS_READWRITE = 0x00002000
    PAGE_GRAPHICS_EXECUTE = 0x00004000
    PAGE_GRAPHICS_EXECUTE_READ = 0x00008000
    PAGE_GRAPHICS_EXECUTE_READWRITE = 0x00010000
    PAGE_GRAPHICS_COHERENT = 0x00020000
    PAGE_GRAPHICS_NOCACHE = 0x00040000
    PAGE_ENCLAVE_THREAD_CONTROL = 0x80000000
    PAGE_REVERT_TO_FILE_MAP = 0x80000000
    PAGE_TARGETS_NO_UPDATE = 0x40000000
    PAGE_TARGETS_INVALID = 0x40000000
    PAGE_ENCLAVE_UNVALIDATED = 0x20000000
    PAGE_ENCLAVE_MASK = 0x10000000
    PAGE_ENCLAVE_DECOMMIT = 0x10000000
    PAGE_ENCLAVE_SS_FIRST = 0x10000001
    PAGE_ENCLAVE_SS_REST = 0x10000002
    SEC_PARTITION_OWNER_HANDLE = 0x00040000
    SEC_64K_PAGES = 0x00080000
    SEC_FILE = 0x00800000
    SEC_IMAGE = 0x01000000
    SEC_PROTECTED_IMAGE = 0x02000000
    SEC_RESERVE = 0x04000000
    SEC_COMMIT = 0x08000000
    SEC_NOCACHE = 0x10000000
    SEC_WRITECOMBINE = 0x40000000
    SEC_LARGE_PAGES = 0x80000000
    SEC_IMAGE_NO_EXECUTE = 0x11000000


class FILE_CREATION_DISPOSITION(IntEnum):
    CREATE_NEW = 1
    CREATE_ALWAYS = 2
    OPEN_EXISTING = 3
    OPEN_ALWAYS = 4
    TRUNCATE_EXISTING = 5


FILE_BEGIN = 0
FILE_CURRENT = 1
FILE_END = 2

INVALID_HANDLE_VALUE = 0xFFFFFFFF
HFILE_ERROR = 0xFFFFFFFF
INVALID_SET_FILE_POINTER = 0xFFFFFFFF

EXCEPTION_CONTINUE_SEARCH = 0
EXCEPTION_EXECUTE_HANDLER = 1
EXCEPTION_CONTINUE_EXECUTION = 0xFFFFFFFF
ExceptionContinueExecution = 0
ExceptionContinueSearch = 1
ExceptionNestedException = 2
ExceptionCollidedUnwind = 3

FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

WAIT_TIMEOUT = 0x102
WAIT_OBJECT_0 = 0x0

STILL_ACTIVE = 0x103

CREATE_EVENT_MANUAL_RESET = 0x00000001
CREATE_EVENT_INITIAL_SET = 0x00000002

# Signal numbers
SIGSEGV = 11
SIGILL = 4
SIGFPE = 8


class PROCESS_CREATION_FLAGS(IntFlag):
    DEBUG_PROCESS = 0x00000001
    DEBUG_ONLY_THIS_PROCESS = 0x00000002
    CREATE_SUSPENDED = 0x00000004
    DETACHED_PROCESS = 0x00000008
    CREATE_NEW_CONSOLE = 0x00000010
    NORMAL_PRIORITY_CLASS = 0x00000020
    IDLE_PRIORITY_CLASS = 0x00000040
    HIGH_PRIORITY_CLASS = 0x00000080
    REALTIME_PRIORITY_CLASS = 0x00000100
    CREATE_NEW_PROCESS_GROUP = 0x00000200
    CREATE_UNICODE_ENVIRONMENT = 0x00000400
    CREATE_SEPARATE_WOW_VDM = 0x00000800
    CREATE_SHARED_WOW_VDM = 0x00001000
    CREATE_FORCEDOS = 0x00002000
    BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
    ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000
    INHERIT_PARENT_AFFINITY = 0x00010000
    INHERIT_CALLER_PRIORITY = 0x00020000
    CREATE_PROTECTED_PROCESS = 0x00040000
    EXTENDED_STARTUPINFO_PRESENT = 0x00080000
    PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000
    PROCESS_MODE_BACKGROUND_END = 0x00200000
    CREATE_SECURE_PROCESS = 0x00400000
    CREATE_BREAKAWAY_FROM_JOB = 0x01000000
    CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000
    CREATE_DEFAULT_ERROR_MODE = 0x04000000
    CREATE_NO_WINDOW = 0x08000000
    PROFILE_USER = 0x10000000
    PROFILE_KERNEL = 0x20000000
    PROFILE_SERVER = 0x40000000
    CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000


class THREAD_CREATION_FLAGS(IntFlag):
    THREAD_CREATE_RUN_IMMEDIATELY = 0x00000000
    THREAD_CREATE_SUSPENDED = 0x00000004
    STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000


class GUID(EmuStruct):
    def __init__(self):
        super().__init__()
        self.Data1 = ct.c_uint32
        self.Data2 = ct.c_uint16
        self.Data3 = ct.c_uint16
        self.Data4 = ct.c_uint8 * 8


class SID(EmuStruct):
    def __init__(self, ptr_size, sub_authority_count):
        super().__init__(ptr_size)
        self.Revision = ct.c_uint8
        self.SubAuthorityCount = ct.c_uint8
        self.IdentifierAuthority = ct.c_uint8 * 6
        self.SubAuthority = ct.c_uint32 * sub_authority_count


class KSYSTEM_TIME(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.LowPart = ct.c_uint32
        self.High1Time = ct.c_uint32
        self.High2Time = ct.c_uint32


class M128A(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Low = ct.c_uint64
        self.High = ct.c_uint64


class EXCEPTION_REGISTRATION(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Next = Ptr
        self.Handler = Ptr
        self.ScopeTable = Ptr
        self.TryLevel = Ptr


class UNICODE_STRING(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Length = ct.c_uint16
        self.MaximumLength = ct.c_uint16
        self.Buffer = Ptr


class EXCEPTION_POINTERS(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.ExceptionRecord = Ptr
        self.ContextRecord = Ptr


# See http://www.openrce.org/articles/full_view/21
class EH4_SCOPETABLE(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.GSCookieOffset = ct.c_uint32
        self.GSCookieXOROffset = ct.c_uint32
        self.EHCookieOffset = ct.c_uint32
        self.EHCookieXOROffset = ct.c_uint32


class EH4_SCOPETABLE_RECORD(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.EnclosingLevel = ct.c_uint32
        self.FilterFunc = Ptr
        self.HandlerAddress = Ptr


class EXCEPTION_RECORD(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.ExceptionCode = ct.c_uint32
        self.ExceptionFlags = ct.c_uint32
        self.ExceptionRecord = Ptr
        self.ExceptionAddress = Ptr
        self.NumberParameters = ct.c_uint32
        self.ExceptionInformation = ct.c_uint32 * 15


class FLOATING_SAVE_AREA(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.ControlWord = ct.c_uint32
        self.StatusWord = ct.c_uint32
        self.TagWord = ct.c_uint32
        self.ErrorOffset = ct.c_uint32
        self.ErrorSelector = ct.c_uint32
        self.DataOffset = ct.c_uint32
        self.DataSelector = ct.c_uint32
        self.RegisterArea = ct.c_uint8 * 80
        self.Spare0 = ct.c_uint32


class CONTEXT(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.ContextFlags = ct.c_uint32
        self.Dr0 = ct.c_uint32
        self.Dr1 = ct.c_uint32
        self.Dr2 = ct.c_uint32
        self.Dr3 = ct.c_uint32
        self.Dr6 = ct.c_uint32
        self.Dr7 = ct.c_uint32
        self.FloatSave = FLOATING_SAVE_AREA
        self.SegGs = ct.c_uint32
        self.SegFs = ct.c_uint32
        self.SegEs = ct.c_uint32
        self.SegDs = ct.c_uint32
        self.Edi = ct.c_uint32
        self.Esi = ct.c_uint32
        self.Ebx = ct.c_uint32
        self.Edx = ct.c_uint32
        self.Ecx = ct.c_uint32
        self.Eax = ct.c_uint32
        self.Ebp = ct.c_uint32
        self.Eip = ct.c_uint32
        self.SegCs = ct.c_uint32
        self.EFlags = ct.c_uint32
        self.Esp = ct.c_uint32
        self.SegSs = ct.c_uint32
        self.ExtendedRegisters = ct.c_uint8 * 512


class CONTEXT64(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.P1Home = ct.c_uint64
        self.P2Home = ct.c_uint64
        self.P3Home = ct.c_uint64
        self.P4Home = ct.c_uint64
        self.P5Home = ct.c_uint64
        self.P6Home = ct.c_uint64

        self.ContextFlags = ct.c_uint32
        self.MxCsr = ct.c_uint32

        self.SegCs = ct.c_uint16
        self.SegDs = ct.c_uint16
        self.SegEs = ct.c_uint16
        self.SegFs = ct.c_uint16
        self.SegGs = ct.c_uint16
        self.SegSs = ct.c_uint16
        self.EFlags = ct.c_uint32

        self.Dr0 = ct.c_uint64
        self.Dr1 = ct.c_uint64
        self.Dr2 = ct.c_uint64
        self.Dr3 = ct.c_uint64
        self.Dr6 = ct.c_uint64
        self.Dr7 = ct.c_uint64

        self.Rax = ct.c_uint64
        self.Rcx = ct.c_uint64
        self.Rdx = ct.c_uint64
        self.Rbx = ct.c_uint64
        self.Rsp = ct.c_uint64
        self.Rbp = ct.c_uint64
        self.Rsi = ct.c_uint64
        self.Rdi = ct.c_uint64
        self.R8 = ct.c_uint64
        self.R9 = ct.c_uint64
        self.R10 = ct.c_uint64
        self.R11 = ct.c_uint64
        self.R12 = ct.c_uint64
        self.R13 = ct.c_uint64
        self.R14 = ct.c_uint64
        self.R15 = ct.c_uint64
        self.Rip = ct.c_uint64

        self.Header = M128A * 2
        self.Legacy = M128A * 8
        self.Xmm0 = M128A
        self.Xmm1 = M128A
        self.Xmm2 = M128A
        self.Xmm3 = M128A
        self.Xmm4 = M128A
        self.Xmm5 = M128A
        self.Xmm6 = M128A
        self.Xmm7 = M128A
        self.Xmm8 = M128A
        self.Xmm9 = M128A
        self.Xmm10 = M128A
        self.Xmm11 = M128A
        self.Xmm12 = M128A
        self.Xmm13 = M128A
        self.Xmm14 = M128A
        self.Xmm15 = M128A
        # The rest of the 512-byte FltSave area that Header, Legacy and Xmm0-15 overlay
        self.FltSaveReserved = ct.c_uint8 * 96

        self.VectorRegister = M128A * 26
        self.VectorControl = ct.c_uint64
        self.DebugControl = ct.c_uint64
        self.LastBranchToRip = ct.c_uint64
        self.LastBranchFromRip = ct.c_uint64
        self.LastExceptionToRip = ct.c_uint64
        self.LastExceptionFromRip = ct.c_uint64


def convert_sid_str_to_struct(ptr_size, sid_str):
    sid_elements = sid_str.split("-")
    sid_elements.remove("S")
    sub_authority_count = len(sid_elements) - 2

    sid_struct = SID(ptr_size, sub_authority_count)
    sid_struct.Revision = int(sid_elements[0])
    sid_struct.SubAuthorityCount = sub_authority_count
    sid_struct.IdentifierAuthority = int(sid_elements[1]).to_bytes(6, "big")
    sub_authorities = sid_elements[2:]
    for i in range(len(sub_authorities)):
        sid_struct.SubAuthority[i] = int(sub_authorities[i])

    return sid_struct
