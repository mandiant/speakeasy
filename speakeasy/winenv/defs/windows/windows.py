# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from speakeasy.struct import EmuStruct, Ptr
import ctypes as ct

NULL = 0

ERROR_SUCCESS = 0
ERROR_FILE_NOT_FOUND = 2
ERROR_PATH_NOT_FOUND = 3
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_HANDLE = 6
ERROR_NO_MORE_FILES = 18
ERROR_FILE_EXISTS = 80
ERROR_INVALID_PARAMETER = 87
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_INVALID_LEVEL = 124
ERROR_MOD_NOT_FOUND = 126
ERROR_ALREADY_EXISTS = 183
ERROR_NO_MORE_ITEMS = 259

S_OK = 0

WAIT_OBJECT_0 = 0

MEM_COMMIT = 0x1000
MEM_FREE = 0x10000
MEM_RESERVE = 0x2000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04

# File creation dispositions
CREATE_ALWAYS = 2
CREATE_NEW = 1
OPEN_ALWAYS = 4
OPEN_EXISTING = 3
TRUNCATE_EXISTING = 4

INVALID_HANDLE_VALUE = 0xFFFFFFFF

EXCEPTION_CONTINUE_SEARCH = 0
EXCEPTION_EXECUTE_HANDLER = 1
EXCEPTION_CONTINUE_EXECUTION = 0xFFFFFFFF
ExceptionContinueExecution = 0
ExceptionContinueSearch = 1
ExceptionNestedException = 2
ExceptionCollidedUnwind = 3

FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

WAIT_TIMEOUT = 0x102
WAIT_OBJECT_0 = 0x0

# Signal numbers
SIGSEGV = 11
SIGILL = 4
SIGFPE = 8

CREATE_NEW_CONSOLE = 0x00000010
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000
CREATE_PROTECTED_PROCESS = 0x00040000
CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000
CREATE_SECURE_PROCESS = 0x00400000
CREATE_SEPARATE_WOW_VDM = 0x00000800
CREATE_SHARED_WOW_VDM = 0x00001000
CREATE_SUSPENDED = 0x00000004
CREATE_UNICODE_ENVIRONMENT = 0x00000400


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
        self.EFlags = ct.c_uint64

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

        self.VectorRegister = M128A * 26
        self.VectorControl = ct.c_uint64
        self.DebugControl = ct.c_uint64
        self.LastBranchToRip = ct.c_uint64
        self.LastBranchFromRip = ct.c_uint64
        self.LastExceptionToRip = ct.c_uint64
        self.LastExceptionFromRip = ct.c_uint64


def get_create_disposition(flags):
    disp = None
    dispostions = ('CREATE_ALWAYS', 'CREATE_NEW', 'OPEN_ALWAYS',
                   'OPEN_EXISTING', 'TRUNCATE_EXISTING')

    for k, v in [(k, v) for k, v in globals().items() if k in dispostions]:
        if isinstance(v, int):
            if v == flags:
                disp = k
                break

    return disp


def get_define(define, prefix=''):
    for k, v in globals().items():
        if not isinstance(v, int) or v != define:
            continue
        if prefix:
            if k.startswith(prefix):
                return k
        else:
            return k


def get_flag_defines(flags, prefix=''):
    defs = []
    for k, v in globals().items():
        if not isinstance(v, int):
            continue
        if v & flags:
            if prefix and k.startswith(prefix):
                defs.append(k)
    return defs


def get_page_rights(define):
    return get_flag_defines(define, prefix='PAGE_')


def get_creation_flags(flags):
    return get_flag_defines(flags, prefix='CREATE_')


def convert_sid_str_to_struct(ptr_size, sid_str):
    sid_elements = sid_str.split('-')
    sid_elements.remove('S')
    sub_authority_count = len(sid_elements) - 2

    sid_struct = SID(ptr_size, sub_authority_count)
    sid_struct.Revision = int(sid_elements[0])
    sid_struct.SubAuthorityCount = sub_authority_count
    sid_struct.IdentifierAuthority = int(sid_elements[1]).to_bytes(6, 'big')
    sub_authorities = sid_elements[2:]
    for i in range(len(sub_authorities)):
        sid_struct.SubAuthority[i] = int(sub_authorities[i])
 
    return sid_struct
