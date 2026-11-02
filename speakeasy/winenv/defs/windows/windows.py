# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from typing import Annotated

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

EXCEPTION_MAXIMUM_PARAMETERS = 15


FILE_BEGIN = 0
FILE_CURRENT = 1
FILE_END = 2

# (HANDLE)(LONG_PTR)-1. The guest sees a pointer-sized value with all bits set.
INVALID_HANDLE_VALUE = -1
HFILE_ERROR = 0xFFFFFFFF
INVALID_SET_FILE_POINTER = 0xFFFFFFFF
INVALID_FILE_SIZE = 0xFFFFFFFF

# Verdicts of exception filters and vectored handlers. A guest function returns them as a LONG.
EXCEPTION_CONTINUE_SEARCH = 0
EXCEPTION_EXECUTE_HANDLER = 1
EXCEPTION_CONTINUE_EXECUTION = -1
ExceptionContinueExecution = 0
ExceptionContinueSearch = 1
ExceptionNestedException = 2
ExceptionCollidedUnwind = 3

FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_ARCHIVE = 0x20
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

WAIT_TIMEOUT = 0x102
WAIT_OBJECT_0 = 0x0
WAIT_FAILED = 0xFFFFFFFF

STILL_ACTIVE = 0x103

# The performance counter frequency of Windows 10 and later
PERF_FREQUENCY = 10_000_000

CREATE_EVENT_MANUAL_RESET = 0x00000001
CREATE_EVENT_INITIAL_SET = 0x00000002


class GUID(EmuStruct):
    Data1: Annotated[int, ct.c_uint32]
    Data2: Annotated[int, ct.c_uint16]
    Data3: Annotated[int, ct.c_uint16]
    Data4: Annotated[bytes, ct.c_uint8 * 8]

    def __init__(self):
        super().__init__()


class SID(EmuStruct):
    Revision: Annotated[int, ct.c_uint8]
    SubAuthorityCount: Annotated[int, ct.c_uint8]
    IdentifierAuthority: Annotated[bytes, ct.c_uint8 * 6]
    SubAuthority: list[int]

    def __init__(self, ptr_size, sub_authority_count):
        super().__init__(ptr_size)
        self.add_fields(SubAuthority=ct.c_uint32 * sub_authority_count)


class KSYSTEM_TIME(EmuStruct):
    LowPart: Annotated[int, ct.c_uint32]
    High1Time: Annotated[int, ct.c_uint32]
    High2Time: Annotated[int, ct.c_uint32]


class M128A(EmuStruct):
    Low: Annotated[int, ct.c_uint64]
    High: Annotated[int, ct.c_uint64]


class EXCEPTION_REGISTRATION(EmuStruct):
    Next: Annotated[int, Ptr]
    Handler: Annotated[int, Ptr]
    ScopeTable: Annotated[int, Ptr]
    TryLevel: Annotated[int, Ptr]


class UNICODE_STRING(EmuStruct):
    Length: Annotated[int, ct.c_uint16]
    MaximumLength: Annotated[int, ct.c_uint16]
    Buffer: Annotated[int, Ptr]


class EXCEPTION_POINTERS(EmuStruct):
    ExceptionRecord: Annotated[int, Ptr]
    ContextRecord: Annotated[int, Ptr]


# See http://www.openrce.org/articles/full_view/21
class EH4_SCOPETABLE(EmuStruct):
    GSCookieOffset: Annotated[int, ct.c_uint32]
    GSCookieXOROffset: Annotated[int, ct.c_uint32]
    EHCookieOffset: Annotated[int, ct.c_uint32]
    EHCookieXOROffset: Annotated[int, ct.c_uint32]


class EH4_SCOPETABLE_RECORD(EmuStruct):
    EnclosingLevel: Annotated[int, ct.c_uint32]
    FilterFunc: Annotated[int, Ptr]
    HandlerAddress: Annotated[int, Ptr]


class EXCEPTION_RECORD(EmuStruct):
    ExceptionCode: Annotated[int, ct.c_uint32]
    ExceptionFlags: Annotated[int, ct.c_uint32]
    ExceptionRecord: Annotated[int, Ptr]
    ExceptionAddress: Annotated[int, Ptr]
    NumberParameters: Annotated[int, ct.c_uint32]
    ExceptionInformation: Annotated[list[int], Ptr * EXCEPTION_MAXIMUM_PARAMETERS]


class FLOATING_SAVE_AREA(EmuStruct):
    ControlWord: Annotated[int, ct.c_uint32]
    StatusWord: Annotated[int, ct.c_uint32]
    TagWord: Annotated[int, ct.c_uint32]
    ErrorOffset: Annotated[int, ct.c_uint32]
    ErrorSelector: Annotated[int, ct.c_uint32]
    DataOffset: Annotated[int, ct.c_uint32]
    DataSelector: Annotated[int, ct.c_uint32]
    RegisterArea: Annotated[bytes, ct.c_uint8 * 80]
    Spare0: Annotated[int, ct.c_uint32]


class CONTEXT(EmuStruct):
    ContextFlags: Annotated[int, ct.c_uint32]
    Dr0: Annotated[int, ct.c_uint32]
    Dr1: Annotated[int, ct.c_uint32]
    Dr2: Annotated[int, ct.c_uint32]
    Dr3: Annotated[int, ct.c_uint32]
    Dr6: Annotated[int, ct.c_uint32]
    Dr7: Annotated[int, ct.c_uint32]
    FloatSave: FLOATING_SAVE_AREA
    SegGs: Annotated[int, ct.c_uint32]
    SegFs: Annotated[int, ct.c_uint32]
    SegEs: Annotated[int, ct.c_uint32]
    SegDs: Annotated[int, ct.c_uint32]
    Edi: Annotated[int, ct.c_uint32]
    Esi: Annotated[int, ct.c_uint32]
    Ebx: Annotated[int, ct.c_uint32]
    Edx: Annotated[int, ct.c_uint32]
    Ecx: Annotated[int, ct.c_uint32]
    Eax: Annotated[int, ct.c_uint32]
    Ebp: Annotated[int, ct.c_uint32]
    Eip: Annotated[int, ct.c_uint32]
    SegCs: Annotated[int, ct.c_uint32]
    EFlags: Annotated[int, ct.c_uint32]
    Esp: Annotated[int, ct.c_uint32]
    SegSs: Annotated[int, ct.c_uint32]
    ExtendedRegisters: Annotated[bytes, ct.c_uint8 * 512]


class CONTEXT64(EmuStruct):
    P1Home: Annotated[int, ct.c_uint64]
    P2Home: Annotated[int, ct.c_uint64]
    P3Home: Annotated[int, ct.c_uint64]
    P4Home: Annotated[int, ct.c_uint64]
    P5Home: Annotated[int, ct.c_uint64]
    P6Home: Annotated[int, ct.c_uint64]

    ContextFlags: Annotated[int, ct.c_uint32]
    MxCsr: Annotated[int, ct.c_uint32]

    SegCs: Annotated[int, ct.c_uint16]
    SegDs: Annotated[int, ct.c_uint16]
    SegEs: Annotated[int, ct.c_uint16]
    SegFs: Annotated[int, ct.c_uint16]
    SegGs: Annotated[int, ct.c_uint16]
    SegSs: Annotated[int, ct.c_uint16]
    EFlags: Annotated[int, ct.c_uint32]

    Dr0: Annotated[int, ct.c_uint64]
    Dr1: Annotated[int, ct.c_uint64]
    Dr2: Annotated[int, ct.c_uint64]
    Dr3: Annotated[int, ct.c_uint64]
    Dr6: Annotated[int, ct.c_uint64]
    Dr7: Annotated[int, ct.c_uint64]

    Rax: Annotated[int, ct.c_uint64]
    Rcx: Annotated[int, ct.c_uint64]
    Rdx: Annotated[int, ct.c_uint64]
    Rbx: Annotated[int, ct.c_uint64]
    Rsp: Annotated[int, ct.c_uint64]
    Rbp: Annotated[int, ct.c_uint64]
    Rsi: Annotated[int, ct.c_uint64]
    Rdi: Annotated[int, ct.c_uint64]
    R8: Annotated[int, ct.c_uint64]
    R9: Annotated[int, ct.c_uint64]
    R10: Annotated[int, ct.c_uint64]
    R11: Annotated[int, ct.c_uint64]
    R12: Annotated[int, ct.c_uint64]
    R13: Annotated[int, ct.c_uint64]
    R14: Annotated[int, ct.c_uint64]
    R15: Annotated[int, ct.c_uint64]
    Rip: Annotated[int, ct.c_uint64]

    Header: Annotated[list[M128A], M128A * 2]
    Legacy: Annotated[list[M128A], M128A * 8]
    Xmm0: M128A
    Xmm1: M128A
    Xmm2: M128A
    Xmm3: M128A
    Xmm4: M128A
    Xmm5: M128A
    Xmm6: M128A
    Xmm7: M128A
    Xmm8: M128A
    Xmm9: M128A
    Xmm10: M128A
    Xmm11: M128A
    Xmm12: M128A
    Xmm13: M128A
    Xmm14: M128A
    Xmm15: M128A
    # The rest of the 512-byte FltSave area that Header, Legacy and Xmm0-15 overlay
    FltSaveReserved: Annotated[bytes, ct.c_uint8 * 96]

    VectorRegister: Annotated[list[M128A], M128A * 26]
    VectorControl: Annotated[int, ct.c_uint64]
    DebugControl: Annotated[int, ct.c_uint64]
    LastBranchToRip: Annotated[int, ct.c_uint64]
    LastBranchFromRip: Annotated[int, ct.c_uint64]
    LastExceptionToRip: Annotated[int, ct.c_uint64]
    LastExceptionFromRip: Annotated[int, ct.c_uint64]


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
