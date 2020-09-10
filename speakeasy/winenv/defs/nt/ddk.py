# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from speakeasy.struct import Enum

WINDOWS_CONSOLE = 3

# IRQL Levels
PASSIVE_LEVEL = 0             # Passive release level
LOW_LEVEL = 0                 # Lowest interrupt level
APC_LEVEL = 1                 # APC interrupt level
DISPATCH_LEVEL = 2            # Dispatcher level
CMCI_LEVEL = 5                # CMCI handler level
PROFILE_LEVEL = 27            # timer used for profiling.
CLOCK1_LEVEL = 28             # Interval clock 1 level - Not used on x86
CLOCK2_LEVEL = 28             # Interval clock 2 level
IPI_LEVEL = 29                # Interprocessor interrupt level
POWER_LEVEL = 30              # Power failure level
HIGH_LEVEL = 31               # Highest interrupt level

STATUS_SUCCESS = 0
STATUS_BREAKPOINT = 0x80000003
STATUS_SINGLE_STEP = 0x80000004
STATUS_UNSUCCESSFUL = 0xC0000001
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
STATUS_ACCESS_VIOLATION = 0xC0000005
STATUS_INVALID_HANDLE = 0xC0000008
STATUS_ILLEGAL_INSTRUCTION = 0xC000001D
STATUS_PRIVILEGED_INSTRUCTION = 0xC0000096
STATUS_BUFFER_TOO_SMALL = 0xC0000023
STATUS_INVALID_CID = 0xC000000B
STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_PROCEDURE_NOT_FOUND = 0xC000007A
STATUS_NOT_SUPPORTED = 0xC00000BB
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_DEBUGGER_INACTIVE = 0xC0000354
STATUS_BAD_COMPRESSION_BUFFER = 0xC0000242
STATUS_UNSUPPORTED_COMPRESSION = 0xC000025F
STATUS_INVALID_DEVICE_REQUEST = 0xC0000010
STATUS_OBJECT_TYPE_MISMATCH = 0xC0000024
STATUS_NOINTERFACE = 0xC00002B9
STATUS_PORT_NOT_SET = 0xC0000353

# Device Flags
DO_DIRECT_IO = 0x00000010
DO_BUFFERED_IO = 0x00000004
DO_EXCLUSIVE = 0x00000008
DO_DEVICE_INITIALIZING = 0x00000080

IRP_MJ_CREATE = 0x00
IRP_MJ_CREATE_NAMED_PIPE = 0x01
IRP_MJ_CLOSE = 0x02
IRP_MJ_READ = 0x03
IRP_MJ_WRITE = 0x04
IRP_MJ_QUERY_INFORMATION = 0x05
IRP_MJ_SET_INFORMATION = 0x06
IRP_MJ_QUERY_EA = 0x07
IRP_MJ_SET_EA = 0x08
IRP_MJ_FLUSH_BUFFERS = 0x09
IRP_MJ_QUERY_VOLUME_INFORMATION = 0x0a
IRP_MJ_SET_VOLUME_INFORMATION = 0x0b
IRP_MJ_DIRECTORY_CONTROL = 0x0c
IRP_MJ_FILE_SYSTEM_CONTROL = 0x0d
IRP_MJ_DEVICE_CONTROL = 0x0e
IRP_MJ_INTERNAL_DEVICE_CONTROL = 0x0f
IRP_MJ_SHUTDOWN = 0x10
IRP_MJ_LOCK_CONTROL = 0x11
IRP_MJ_CLEANUP = 0x12
IRP_MJ_CREATE_MAILSLOT = 0x13
IRP_MJ_QUERY_SECURITY = 0x14
IRP_MJ_SET_SECURITY = 0x15
IRP_MJ_POWER = 0x16
IRP_MJ_SYSTEM_CONTROL = 0x17
IRP_MJ_DEVICE_CHANGE = 0x18
IRP_MJ_QUERY_QUOTA = 0x19
IRP_MJ_SET_QUOTA = 0x1a
IRP_MJ_PNP = 0x1b
IRP_MJ_PNP_POWER = IRP_MJ_PNP
IRP_MJ_MAXIMUM_FUNCTION = 0x1b

COMPRESSION_FORMAT_LZNT1 = 0x2
COMPRESSION_FORMAT_XPRESS = 0x3

DELETE = 0x00010000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
SYNCHRONIZE = 0x00100000
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
GENERIC_EXECUTE = 0x20000000
GENERIC_ALL = 0x10000000

# Create Dispositions
FILE_SUPERSEDE = 0x00000000
FILE_OPEN = 0x00000001
FILE_CREATE = 0x00000002
FILE_OPEN_IF = 0x00000003
FILE_OVERWRITE = 0x00000004
FILE_OVERWRITE_IF = 0x00000005

# File specific access mask
FILE_READ_DATA = 0x0001  # file & pipe
FILE_WRITE_DATA = 0x0002  # file & pipe
FILE_APPEND_DATA = 0x0004  # file
FILE_READ_EA = 0x0008  # file & directory
FILE_WRITE_EA = 0x0010  # file & directory
FILE_EXECUTE = 0x0020  # file
FILE_DELETE_CHILD = 0x0040  # directory
FILE_READ_ATTRIBUTES = 0x0080  # all
FILE_WRITE_ATTRIBUTES = 0x0100  # all


PROCESSINFOCLASS = Enum()
PROCESSINFOCLASS.ProcessBasicInformation = 0
PROCESSINFOCLASS.ProcessDebugPort = 7
PROCESSINFOCLASS.ProcessWow64Information = 0x1a
PROCESSINFOCLASS.ProcessImageFileName = 0x1b
PROCESSINFOCLASS.ProcessBreakOnTermination = 0x1d
PROCESSINFOCLASS.ProcessDebugObjectHandle = 0x1e
PROCESSINFOCLASS.ProcessProtectionInformation = 0x3d


SYSTEM_INFORMATION_CLASS = Enum()
SYSTEM_INFORMATION_CLASS.SystemBasicInformation = 0x00
SYSTEM_INFORMATION_CLASS.SystemProcessorInformation = 0x01
SYSTEM_INFORMATION_CLASS.SystemPerformanceInformation = 0x02
SYSTEM_INFORMATION_CLASS.SystemTimeOfDayInformation = 0x03
SYSTEM_INFORMATION_CLASS.SystemPathInformation = 0x04
SYSTEM_INFORMATION_CLASS.SystemProcessInformation = 0x05
SYSTEM_INFORMATION_CLASS.SystemCallCountInformation = 0x06
SYSTEM_INFORMATION_CLASS.SystemDeviceInformation = 0x07
SYSTEM_INFORMATION_CLASS.SystemProcessorPerformanceInformation = 0x08
SYSTEM_INFORMATION_CLASS.SystemFlagsInformation = 0x09
SYSTEM_INFORMATION_CLASS.SystemCallTimeInformation = 0x0A
SYSTEM_INFORMATION_CLASS.SystemModuleInformation = 0x0B
SYSTEM_INFORMATION_CLASS.SystemKernelDebuggerInformation = 0x23


FILE_INFORMATION_CLASS = Enum()
FILE_INFORMATION_CLASS.FileDirectoryInformation = 1
FILE_INFORMATION_CLASS.FileFullDirectoryInformation = 2
FILE_INFORMATION_CLASS.FileBothDirectoryInformation = 3
FILE_INFORMATION_CLASS.FileBasicInformation = 4
FILE_INFORMATION_CLASS.FileStandardInformation = 5
FILE_INFORMATION_CLASS.FileInternalInformation = 6
FILE_INFORMATION_CLASS.FileEaInformation = 7
FILE_INFORMATION_CLASS.FileAccessInformation = 8
FILE_INFORMATION_CLASS.FileNameInformation = 9
FILE_INFORMATION_CLASS.FileRenameInformation = 10
FILE_INFORMATION_CLASS.FileLinkInformation = 11


POOL_TYPE = Enum()
POOL_TYPE.NonPagedPool = 0
POOL_TYPE.PagedPool = 1
POOL_TYPE.NonPagedPoolMustSucceed = 2
POOL_TYPE.DontUseThisType = 3
POOL_TYPE.NonPagedPoolCacheAligned = 4
POOL_TYPE.PagedPoolCacheAligned = 5
POOL_TYPE.NonPagedPoolCacheAlignedMustS = 6
POOL_TYPE.MaxPoolType = 7
POOL_TYPE.NonPagedPoolSession = 32
POOL_TYPE.PagedPoolSession = 33
POOL_TYPE.NonPagedPoolMustSucceedSession = 34
POOL_TYPE.DontUseThisTypeSession = 35
POOL_TYPE.NonPagedPoolCacheAlignedSession = 36
POOL_TYPE.PagedPoolCacheAlignedSession = 37
POOL_TYPE.NonPagedPoolCacheAlignedMustSSession = 38
POOL_TYPE.NonPagedPoolNx = 512

MODE = Enum()
MODE.KernelMode = 0
MODE.UserMode = 1
MODE.MaximumMode = 2

IMAGE_DOS_SIGNATURE = b'MZ'
PE32_BIT = 0x0100
PE32_PLUS_BIT = 0x0200


def get_flag_defines(flags, prefix=''):
    defs = []
    for k, v in globals().items():
        if isinstance(v, int):
            if v & flags:
                if prefix:
                    if k.startswith(prefix):
                        defs.append(k)
                else:
                    defs.append(k)
    return defs


def get_const_defines(const, prefix=''):
    defs = []
    for k, v in globals().items():
        if isinstance(v, int):
            if v == const:
                if prefix:
                    if k.startswith(prefix):
                        defs.append(k)
                else:
                    defs.append(k)
    return defs


def get_access_defines(flags):
    defs = []
    accesses = ('DELETE', 'READ_CONTROL', 'WRITE_DAC',
                'WRITE_OWNER', 'SYNCHRONIZE', 'GENERIC_READ',
                'GENERIC_WRITE', 'GENERIC_EXECUTE', 'GENERIC_ALL')

    for k, v in [(k, v) for k, v in globals().items() if k in accesses]:
        if isinstance(v, int):
            if v & flags:
                defs.append(k)

    return defs


def get_file_access_defines(flags):
    defs = get_flag_defines(flags, 'FILE_')
    defs = [d for d in defs if d.startswith(('FILE_READ', 'FILE_WRITE',
                                            'FILE_DELETE', 'FILE_APPEND', 'FILE_EXECUTE'))]

    return defs


def get_create_disposition(disp):
    defs = get_const_defines(disp, 'FILE_')
    defs = [d for d in defs if not d.startswith('FILE_SHARE')]

    ret = 0
    if len(defs):
        ret = defs[0]
    return ret
