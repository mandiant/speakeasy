# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

import ctypes as ct
from typing import Annotated

from speakeasy.struct import EmuStruct, EmuUnion, Ptr
from speakeasy.winenv.defs import *  # noqa


class KSYSTEM_TIME(EmuStruct):
    LowPart: Annotated[int, ct.c_uint32]
    High1Time: Annotated[int, ct.c_uint32]
    High2Time: Annotated[int, ct.c_uint32]


class TIME_FIELDS(EmuStruct):
    Year: Annotated[int, ct.c_uint16]
    Month: Annotated[int, ct.c_uint16]
    Day: Annotated[int, ct.c_uint16]
    Hour: Annotated[int, ct.c_uint16]
    Minute: Annotated[int, ct.c_uint16]
    Second: Annotated[int, ct.c_uint16]
    Milliseconds: Annotated[int, ct.c_uint16]
    Weekday: Annotated[int, ct.c_uint16]


class SSDT(EmuStruct):  # KeServiceDescriptorTable
    pServiceTable: Annotated[int, Ptr]
    pCounterTable: Annotated[int, Ptr]
    NumberOfServices: Annotated[int, ct.c_uint32]
    pArgumentTable: Annotated[int, Ptr]


class UNICODE_STRING(EmuStruct):
    Length: Annotated[int, ct.c_uint16]
    MaximumLength: Annotated[int, ct.c_uint16]
    Buffer: Annotated[int, Ptr]


class DeviceIoControl(EmuStruct):
    OutputBufferLength: Annotated[int, ct.c_uint32]
    # ULONG POINTER_ALIGNMENT, so each takes a pointer-sized slot
    InputBufferLength: Annotated[int, Ptr]
    IoControlCode: Annotated[int, Ptr]
    Type3InputBuffer: Annotated[int, Ptr]


class IO_PARAMETERS_OTHERS(EmuStruct):
    Argument1: Annotated[int, Ptr]
    Argument2: Annotated[int, Ptr]
    Argument3: Annotated[int, Ptr]
    Argument4: Annotated[int, Ptr]


class STRING(EmuStruct):
    Length: Annotated[int, ct.c_uint16]
    MaximumLength: Annotated[int, ct.c_uint16]
    Buffer: Annotated[int, Ptr]


class SYSTEM_MODULE(EmuStruct):
    Reserved: Annotated[list[int], Ptr * 2]
    Base: Annotated[int, Ptr]
    Size: Annotated[int, ct.c_uint32]
    Flags: Annotated[int, ct.c_uint32]
    Index: Annotated[int, ct.c_uint16]
    Unknown: Annotated[int, ct.c_uint16]
    LoadCount: Annotated[int, ct.c_uint16]
    ModuleNameOffset: Annotated[int, ct.c_uint16]
    ImageName: Annotated[bytes, ct.c_uint8 * 256]


class SYSTEM_BASIC_INFORMATION(EmuStruct):
    Reserved: Annotated[int, ct.c_uint32]
    TimerResolution: Annotated[int, ct.c_uint32]
    PageSize: Annotated[int, ct.c_uint32]
    NumberOfPhysicalPages: Annotated[int, ct.c_uint32]
    LowestPhysicalPageNumber: Annotated[int, ct.c_uint32]
    HighestPhysicalPageNumber: Annotated[int, ct.c_uint32]
    AllocationGranularity: Annotated[int, ct.c_uint32]
    MinimumUserModeAddress: Annotated[int, Ptr]
    MaximumUserModeAddress: Annotated[int, Ptr]
    ActiveProcessorsAffinityMask: Annotated[int, Ptr]
    NumberOfProcessors: Annotated[int, ct.c_uint8]


class SYSTEM_TIMEOFDAY_INFORMATION(EmuStruct):
    BootTime: Annotated[int, ct.c_uint64]
    CurrentTime: Annotated[int, ct.c_uint64]
    TimeZoneBias: Annotated[int, ct.c_uint64]
    TimeZoneId: Annotated[int, ct.c_uint32]
    Reserved: Annotated[int, ct.c_uint32]
    BootTimeBias: Annotated[int, ct.c_uint64]
    SleepTimeBias: Annotated[int, ct.c_uint64]


class SYSTEM_PROCESS_INFORMATION(EmuStruct):
    NextEntryOffset: Annotated[int, ct.c_uint32]
    NumberOfThreads: Annotated[int, ct.c_uint32]
    Reserved1: Annotated[bytes, ct.c_uint8 * 48]
    ImageName: UNICODE_STRING
    BasePriority: Annotated[int, ct.c_uint32]
    UniqueProcessId: Annotated[int, Ptr]
    InheritedFromUniqueProcessId: Annotated[int, Ptr]
    HandleCount: Annotated[int, ct.c_uint32]
    SessionId: Annotated[int, ct.c_uint32]
    UniqueProcessKey: Annotated[int, Ptr]
    PeakVirtualSize: Annotated[int, Ptr]
    VirtualSize: Annotated[int, Ptr]
    PageFaultCount: Annotated[int, ct.c_uint32]

    PeakWorkingSetSize: Annotated[int, Ptr]
    WorkingSetSize: Annotated[int, Ptr]
    QuotaPeakPagedPoolUsage: Annotated[int, Ptr]
    QuotaPagedPoolUsage: Annotated[int, Ptr]
    QuotaPeakNonPagedPoolUsage: Annotated[int, Ptr]
    QuotaNonPagedPoolUsage: Annotated[int, Ptr]
    PagefileUsage: Annotated[int, Ptr]

    PeakPagefileUsage: Annotated[int, Ptr]
    PrivatePageCount: Annotated[int, Ptr]
    Reserved7: Annotated[list[LARGE_INTEGER], LARGE_INTEGER * 6]


class SYSTEM_THREAD_INFORMATION(EmuStruct):
    Reserved1: Annotated[list[LARGE_INTEGER], LARGE_INTEGER * 3]
    Reserved2: Annotated[int, ct.c_uint32]
    StartAddress: Annotated[int, Ptr]
    ClientId: CLIENT_ID
    Priority: Annotated[int, ct.c_uint32]
    BasePriority: Annotated[int, ct.c_uint32]
    ContextSwitches: Annotated[int, ct.c_uint32]
    ThreadState: Annotated[int, ct.c_uint32]
    WaitReason: Annotated[int, ct.c_uint32]


class CLIENT_ID(EmuStruct):
    UniqueProcess: Annotated[int, Ptr]
    UniqueThread: Annotated[int, Ptr]


class MDL(EmuStruct):
    Next: Annotated[int, Ptr]
    Size: Annotated[int, ct.c_uint16]
    MdlFlags: Annotated[int, ct.c_uint16]
    Process: Annotated[int, Ptr]
    MappedSystemVa: Annotated[int, Ptr]
    StartVa: Annotated[int, Ptr]
    ByteCount: Annotated[int, ct.c_uint32]
    ByteOffset: Annotated[int, ct.c_uint32]


class KIDTENTRY(EmuStruct):
    OffsetLow: Annotated[int, ct.c_uint16]
    Selector: Annotated[int, ct.c_uint16]
    Base: Annotated[int, ct.c_uint32]


class KIDTENTRY64(EmuStruct):
    OffsetLow: Annotated[int, ct.c_uint16]
    Selector: Annotated[int, ct.c_uint16]
    Reserved0: Annotated[int, ct.c_uint16]
    OffsetMiddle: Annotated[int, ct.c_uint16]
    OffsetHigh: Annotated[int, ct.c_uint32]
    Reserved1: Annotated[int, ct.c_uint32]


class ETHREAD(EmuStruct):
    """
    An opaque 4096-byte ETHREAD.

    The layout of ETHREAD changes with each Windows build, so speakeasy declares no fields.
    objman.Thread fills the bytes with 0xFF.
    """

    Data: Annotated[bytes, ct.c_uint8 * 4096]


class EPROCESS(EmuStruct):
    """
    An opaque 4096-byte EPROCESS.

    The layout of EPROCESS changes with each Windows build, so speakeasy declares no fields. objman.Process
    writes only ActiveProcessLinks, as an empty LIST_ENTRY that points to itself. Its offset is 0x88 on x86, as
    in Windows XP, and 0x188 on x64, as in Windows 7.
    """

    Data: Annotated[bytes, ct.c_uint8 * 4096]


class DISPATCHER_HEADER(EmuStruct):
    Type: Annotated[int, ct.c_uint8]
    Signalling: Annotated[int, ct.c_uint8]
    Size: Annotated[int, ct.c_uint8]
    Reserved1: Annotated[int, ct.c_uint8]
    SignalState: Annotated[int, ct.c_int32]
    WaitListHead: LIST_ENTRY


class KEVENT(EmuStruct):
    Header: DISPATCHER_HEADER


class KMUTANT(EmuStruct):
    Header: DISPATCHER_HEADER
    MutantListEntry: LIST_ENTRY
    OwnerThread: Annotated[int, Ptr]
    MutantFlags: Annotated[int, ct.c_uint8]
    ApcDisable: Annotated[int, ct.c_uint8]


class KSEMAPHORE(EmuStruct):
    Header: DISPATCHER_HEADER
    Limit: Annotated[int, ct.c_int32]


class RTL_OSVERSIONINFOW(EmuStruct):
    dwOSVersionInfoSize: Annotated[int, ct.c_uint32]
    dwMajorVersion: Annotated[int, ct.c_uint32]
    dwMinorVersion: Annotated[int, ct.c_uint32]
    dwBuildNumber: Annotated[int, ct.c_uint32]
    dwPlatformId: Annotated[int, ct.c_uint32]
    szCSDVersion: Annotated[bytes, ct.c_uint8 * 256]


class RTL_OSVERSIONINFOEXW(EmuStruct):
    dwOSVersionInfoSize: Annotated[int, ct.c_uint32]
    dwMajorVersion: Annotated[int, ct.c_uint32]
    dwMinorVersion: Annotated[int, ct.c_uint32]
    dwBuildNumber: Annotated[int, ct.c_uint32]
    dwPlatformId: Annotated[int, ct.c_uint32]
    szCSDVersion: Annotated[bytes, ct.c_uint8 * 256]
    wServicePackMajor: Annotated[int, ct.c_uint16]
    wServicePackMinor: Annotated[int, ct.c_uint16]
    wSuiteMask: Annotated[int, ct.c_uint16]
    wProductType: Annotated[int, ct.c_uint8]
    wReserved: Annotated[int, ct.c_uint8]


class IDT(EmuStruct):
    Limit: Annotated[int, ct.c_uint16]
    Descriptors: Annotated[int, Ptr]


class KAPC(EmuStruct):
    Type: Annotated[int, ct.c_uint8]
    SpareByte0: Annotated[int, ct.c_uint8]
    Size: Annotated[int, ct.c_uint8]
    SpareByte1: Annotated[int, ct.c_uint8]
    SpareLong0: Annotated[int, ct.c_uint32]
    Thread: Annotated[int, Ptr]
    ApcListEntry: LIST_ENTRY
    KernelRoutine: Annotated[int, Ptr]
    RundownRoutine: Annotated[int, Ptr]
    NormalRoutine: Annotated[int, Ptr]
    NormalContext: Annotated[int, Ptr]
    SystemArgument1: Annotated[int, Ptr]
    SystemArgument2: Annotated[int, Ptr]
    ApcStateIndex: Annotated[int, ct.c_uint8]
    ApcMode: Annotated[int, ct.c_uint8]
    Inserted: Annotated[int, ct.c_uint8]


class OBJECT_ATTRIBUTES(EmuStruct):
    Length: Annotated[int, ct.c_uint32]
    RootDirectory: Annotated[int, Ptr]
    ObjectName: Annotated[int, Ptr]
    Attributes: Annotated[int, ct.c_uint32]
    SecurityDescriptor: Annotated[int, Ptr]
    SecurityQualityOfService: Annotated[int, Ptr]


class FILE_STANDARD_INFORMATION(EmuStruct):
    AllocationSize: LARGE_INTEGER
    EndOfFile: LARGE_INTEGER
    NumberOfLinks: Annotated[int, ct.c_uint32]
    DeletePending: Annotated[int, ct.c_uint8]
    Directory: Annotated[int, ct.c_uint8]


class DESCRIPTOR_TABLE(EmuStruct):
    Table: list[KIDTENTRY] | list[KIDTENTRY64]

    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.add_fields(Table=(KIDTENTRY if ptr_size == 4 else KIDTENTRY64) * 256)


class DRIVER_OBJECT(EmuStruct):
    Type: Annotated[int, ct.c_uint16]
    Size: Annotated[int, ct.c_uint16]
    DeviceObject: Annotated[int, Ptr]
    Flags: Annotated[int, ct.c_uint32]
    DriverStart: Annotated[int, Ptr]
    DriverSize: Annotated[int, ct.c_uint32]
    DriverSection: Annotated[int, Ptr]
    DriverExtension: Annotated[int, Ptr]
    DriverName: UNICODE_STRING
    HardwareDatabase: Annotated[int, Ptr]
    FastIoDispatch: Annotated[int, Ptr]
    DriverInit: Annotated[int, Ptr]
    DriverStartIo: Annotated[int, Ptr]
    DriverUnload: Annotated[int, Ptr]
    MajorFunction: Annotated[list[int], Ptr * 28]


class KDEVICE_QUEUE(EmuStruct):
    Type: Annotated[int, ct.c_uint16]
    Size: Annotated[int, ct.c_uint16]
    DeviceListHead: LIST_ENTRY
    Lock: Annotated[int, Ptr]
    Busy: Annotated[int, ct.c_uint8]


class KDPC(EmuStruct):
    Type: Annotated[int, ct.c_uint8]
    Importance: Annotated[int, ct.c_uint8]
    Number: Annotated[int, ct.c_uint16]
    DpcListEntry: LIST_ENTRY
    DeferredRoutine: Annotated[int, Ptr]
    DeferredContext: Annotated[int, Ptr]
    SystemArgument1: Annotated[int, Ptr]
    SystemArgument2: Annotated[int, Ptr]
    DpcData: Annotated[int, Ptr]


class WAIT_CONTEXT_BLOCK(EmuStruct):
    WaitQueueEntry: KDEVICE_QUEUE_ENTRY
    DeviceRoutine: Annotated[int, Ptr]
    DeviceContext: Annotated[int, Ptr]
    NumberOfMapRegisters: Annotated[int, ct.c_uint32]
    DeviceObject: Annotated[int, Ptr]
    CurrentIrp: Annotated[int, Ptr]
    BufferChainingDpc: Annotated[int, Ptr]


class DEVICE_OBJECT_QUEUE(EmuUnion):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.ListEntry = LIST_ENTRY(ptr_size).get_cstruct()
        self.Wcb = WAIT_CONTEXT_BLOCK(ptr_size).get_cstruct()


class DEVICE_OBJECT(EmuStruct):
    Type: Annotated[int, ct.c_uint16]
    Size: Annotated[int, ct.c_uint16]
    ReferenceCount: Annotated[int, ct.c_uint32]
    DriverObject: Annotated[int, Ptr]
    NextDevice: Annotated[int, Ptr]
    AttachedDevice: Annotated[int, Ptr]
    CurrentIrp: Annotated[int, Ptr]
    Timer: Annotated[int, Ptr]
    Flags: Annotated[int, ct.c_uint32]
    Characteristics: Annotated[int, ct.c_uint32]
    Vpb: Annotated[int, Ptr]
    DeviceExtension: Annotated[int, Ptr]
    DeviceType: Annotated[int, ct.c_uint32]
    StackSize: Annotated[int, ct.c_uint8]
    Queue: DEVICE_OBJECT_QUEUE
    AlignmentRequirement: Annotated[int, ct.c_uint32]
    DeviceQueue: KDEVICE_QUEUE
    Dpc: KDPC
    ActiveThreadCount: Annotated[int, ct.c_uint32]
    SecurityDescriptor: Annotated[int, Ptr]
    DeviceLock: KEVENT
    SectorSize: Annotated[int, ct.c_uint16]
    Spare1: Annotated[int, ct.c_uint16]
    DeviceObjectExtension: Annotated[int, Ptr]
    Reserved: Annotated[int, Ptr]
    Padding: bytes

    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        if ptr_size == 8:
            # DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) rounds the size up to 16 bytes
            self.add_fields(Padding=ct.c_uint8 * 8)


class FILE_OBJECT(EmuStruct):
    Type: Annotated[int, ct.c_uint16]
    Size: Annotated[int, ct.c_uint16]
    DeviceObject: Annotated[int, Ptr]
    Vpb: Annotated[int, Ptr]
    FsContext: Annotated[int, Ptr]
    FsContext2: Annotated[int, Ptr]
    SectionObjectPointer: Annotated[int, Ptr]
    PrivateCacheMap: Annotated[int, Ptr]
    FinalStatus: Annotated[int, ct.c_uint32]
    RelatedFileObject: Annotated[int, Ptr]
    LockOperation: Annotated[int, ct.c_uint8]
    DeletePending: Annotated[int, ct.c_uint8]
    ReadAccess: Annotated[int, ct.c_uint8]
    WriteAccess: Annotated[int, ct.c_uint8]
    DeleteAccess: Annotated[int, ct.c_uint8]
    SharedRead: Annotated[int, ct.c_uint8]
    SharedWrite: Annotated[int, ct.c_uint8]
    SharedDelete: Annotated[int, ct.c_uint8]
    Flags: Annotated[int, ct.c_uint32]
    FileName: UNICODE_STRING
    CurrentByteOffset: LARGE_INTEGER
    Waiters: Annotated[int, ct.c_uint32]
    Busy: Annotated[int, ct.c_uint32]
    LastLock: Annotated[int, Ptr]
    Lock: KEVENT
    Event: KEVENT
    CompletionContext: Annotated[int, Ptr]
    IrpListLock: Annotated[int, Ptr]
    IrpList: LIST_ENTRY
    FileObjectExtension: Annotated[int, Ptr]


class IO_PARAMETERS(EmuUnion):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.DeviceIoControl = DeviceIoControl(ptr_size).get_cstruct()
        self.Others = IO_PARAMETERS_OTHERS(ptr_size).get_cstruct()


class IO_STACK_LOCATION(EmuStruct):
    MajorFunction: Annotated[int, ct.c_uint8]
    MinorFunction: Annotated[int, ct.c_uint8]
    Flags: Annotated[int, ct.c_uint8]
    Control: Annotated[int, ct.c_uint8]
    Parameters: IO_PARAMETERS
    DeviceObject: Annotated[int, Ptr]
    FileObject: Annotated[int, Ptr]
    CompletionRoutine: Annotated[int, Ptr]
    Context: Annotated[int, Ptr]


class IRP_OVERLAY(EmuStruct):
    UserApcRoutine: Annotated[int, Ptr]
    UserApcContext: Annotated[int, Ptr]


class IRP(EmuStruct):
    Type: Annotated[int, ct.c_uint16]
    Size: Annotated[int, ct.c_uint16]
    MdlAddress: Annotated[int, Ptr]
    Flags: Annotated[int, ct.c_uint32]
    AssociatedIrp: Annotated[int, Ptr]
    ThreadListEntry: LIST_ENTRY
    IoStatus: IO_STATUS_BLOCK
    RequestorMode: Annotated[int, ct.c_uint8]
    PendingReturned: Annotated[int, ct.c_uint8]
    StackCount: Annotated[int, ct.c_uint8]
    CurrentLocation: Annotated[int, ct.c_uint8]
    Cancel: Annotated[int, ct.c_uint8]
    CancelIrql: Annotated[int, ct.c_uint8]
    ApcEnvironment: Annotated[int, ct.c_uint8]
    AllocationFlags: Annotated[int, ct.c_uint8]
    UserIosb: Annotated[int, Ptr]
    UserEvent: Annotated[int, Ptr]
    Overlay: IRP_OVERLAY
    CancelRoutine: Annotated[int, Ptr]
    UserBuffer: Annotated[int, Ptr]
    Tail: IRP_TAIL


class IO_STATUS_BLOCK(EmuStruct):
    Status: Annotated[int, Ptr]
    Information: Annotated[int, Ptr]


class KDEVICE_QUEUE_ENTRY(EmuStruct):
    DeviceListEntry: LIST_ENTRY
    SortKey: Annotated[int, ct.c_uint32]
    Inserted: Annotated[int, ct.c_uint8]


class TAIL_OVERLAY_QUEUE(EmuUnion):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.DeviceQueueEntry = KDEVICE_QUEUE_ENTRY(ptr_size).get_cstruct()
        self.DriverContext = Ptr * 4


class TAIL_OVERLAY(EmuStruct):
    Anonymous: TAIL_OVERLAY_QUEUE
    Thread: Annotated[int, Ptr]
    AuxiliaryBuffer: Annotated[int, Ptr]
    ListEntry: LIST_ENTRY
    CurrentStackLocation: Annotated[int, Ptr]
    OriginalFileObject: Annotated[int, Ptr]


class IRP_TAIL(EmuUnion):
    Overlay: TAIL_OVERLAY

    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Apc = KAPC(ptr_size).get_cstruct()
        self.CompletionKey = Ptr


class LIST_ENTRY(EmuStruct):
    Flink: Annotated[int, Ptr]
    Blink: Annotated[int, Ptr]


class NT_TIB(EmuStruct):
    ExceptionList: Annotated[int, Ptr]
    StackBase: Annotated[int, Ptr]
    StackLimit: Annotated[int, Ptr]
    Reserved1: Annotated[int, Ptr]
    Reserved2: Annotated[int, Ptr]
    Reserved3: Annotated[int, Ptr]
    Self: Annotated[int, Ptr]


class TEB(EmuStruct):
    NtTib: NT_TIB
    EnvironmentPointer: Annotated[int, Ptr]
    ClientId: CLIENT_ID
    ActiveRpcHandle: Annotated[int, Ptr]
    ThreadLocalStoragePointer: Annotated[int, Ptr]
    ProcessEnvironmentBlock: Annotated[int, Ptr]
    LastErrorValue: Annotated[int, ct.c_uint32]
    CountOfOwnedCriticalSections: Annotated[int, ct.c_uint32]
    CsrClientThread: Annotated[int, Ptr]
    Win32ThreadInfo: Annotated[int, Ptr]
    User32Reserved: Annotated[list[int], ct.c_uint32 * 26]
    UserReserved: Annotated[list[int], ct.c_uint32 * 5]
    WOW32Reserved: Annotated[int, Ptr]
    CurrentLocale: Annotated[int, ct.c_uint32]


class PEB(EmuStruct):
    InheritedAddressSpace: Annotated[int, ct.c_uint8]
    ReadImageFileExecOptions: Annotated[int, ct.c_uint8]
    BeingDebugged: Annotated[int, ct.c_uint8]
    BitField: Annotated[int, ct.c_uint8]
    Mutant: Annotated[int, Ptr]
    ImageBaseAddress: Annotated[int, Ptr]
    Ldr: Annotated[int, Ptr]
    ProcessParameters: Annotated[int, Ptr]
    SubSystemData: Annotated[int, Ptr]
    ProcessHeap: Annotated[int, Ptr]
    FastPebLock: Annotated[int, Ptr]
    AtlThunkSListPtr: Annotated[int, Ptr]
    IFEOKey: Annotated[int, Ptr]
    CrossProcessFlags: Annotated[int, Ptr]
    UserSharedInfoPtr: Annotated[int, Ptr]
    SystemReserved: Annotated[int, ct.c_uint32]
    AtlThunkSListPtr32: Annotated[int, ct.c_uint32]
    ApiSetMap: Annotated[int, Ptr]
    TlsExpansionCounter: Annotated[int, Ptr]
    TlsBitmap: Annotated[int, Ptr]
    TlsBitmapBits: Annotated[list[int], ct.c_uint32 * 2]
    ReadOnlySharedMemoryBase: Annotated[int, Ptr]
    SharedData: Annotated[int, Ptr]  # HotpatchInformation
    ReadOnlyStaticServerData: Annotated[int, Ptr]
    AnsiCodePageData: Annotated[int, Ptr]
    OemCodePageData: Annotated[int, Ptr]
    UnicodeCaseTableData: Annotated[int, Ptr]
    NumberOfProcessors: Annotated[int, ct.c_uint32]
    NtGlobalFlag: Annotated[int, ct.c_uint32]
    CriticalSectionTimeout: Annotated[int, ct.c_longlong]  # LARGE_INTEGER
    HeapSegmentReserve: Annotated[int, Ptr]
    HeapSegmentCommit: Annotated[int, Ptr]
    HeapDeCommitTotalFreeThreshold: Annotated[int, Ptr]
    HeapDeCommitFreeBlockThreshold: Annotated[int, Ptr]
    NumberOfHeaps: Annotated[int, ct.c_uint32]
    MaximumNumberOfHeaps: Annotated[int, ct.c_uint32]
    ProcessHeaps: Annotated[int, Ptr]
    GdiSharedHandleTable: Annotated[int, Ptr]
    ProcessStarterHelper: Annotated[int, Ptr]
    GdiDCAttributeList: Annotated[int, Ptr]
    LoaderLock: Annotated[int, Ptr]
    OSMajorVersion: Annotated[int, ct.c_uint32]
    OSMinorVersion: Annotated[int, ct.c_uint32]
    OSBuildNumber: Annotated[int, ct.c_uint16]
    OSCSDVersion: Annotated[int, ct.c_uint16]
    OSPlatformId: Annotated[int, ct.c_uint32]
    ImageSubsystem: Annotated[int, ct.c_uint32]
    ImageSubsystemMajorVersion: Annotated[int, ct.c_uint32]
    ImageSubsystemMinorVersion: Annotated[int, Ptr]
    ActiveProcessAffinityMask: Annotated[int, Ptr]
    GdiHandleBuffer: list[int]
    PostProcessInitRoutine: int
    TlsExpansionBitmap: int
    TlsExpansionBitmapBits: list[int]
    SessionId: int
    AppCompatFlags: int
    AppCompatFlagsUser: int
    pShimData: int
    AppCompatInfo: int
    CSDVersion: UNICODE_STRING
    ActivationContextData: int
    ProcessAssemblyStorageMap: int
    SystemDefaultActivationContextData: int
    SystemAssemblyStorageMap: int
    MinimumStackCommit: int
    FlsCallback: int
    FlsListHead: LIST_ENTRY
    FlsBitmap: int
    FlsBitmapBits: list[int]
    FlsHighIndex: int
    WerRegistrationData: int
    WerShipAssertPtr: int
    pUnused: int
    pImageHeaderHash: int
    TracingFlags: int
    CsrServerReadOnlySharedMemoryBase: int
    TppWorkerpListLock: int
    TppWorkerpList: LIST_ENTRY
    WaitOnAddressHashTable: list[int]

    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.add_fields(
            GdiHandleBuffer=ct.c_uint32 * (60 if ptr_size == 8 else 34),
            PostProcessInitRoutine=Ptr,
            TlsExpansionBitmap=Ptr,
            TlsExpansionBitmapBits=ct.c_uint32 * 32,
            SessionId=Ptr,
            AppCompatFlags=ct.c_ulonglong,  # ULARGE_INTEGER
            AppCompatFlagsUser=ct.c_ulonglong,  # ULARGE_INTEGER
            pShimData=Ptr,
            AppCompatInfo=Ptr,
            CSDVersion=UNICODE_STRING,
            ActivationContextData=Ptr,
            ProcessAssemblyStorageMap=Ptr,
            SystemDefaultActivationContextData=Ptr,
            SystemAssemblyStorageMap=Ptr,
            MinimumStackCommit=Ptr,
            FlsCallback=Ptr,
            FlsListHead=LIST_ENTRY,
            FlsBitmap=Ptr,
            FlsBitmapBits=ct.c_uint32 * 4,
            FlsHighIndex=Ptr,
            WerRegistrationData=Ptr,
            WerShipAssertPtr=Ptr,
            pUnused=Ptr,  # pContextData
            pImageHeaderHash=Ptr,
            TracingFlags=ct.c_uint64,
            CsrServerReadOnlySharedMemoryBase=ct.c_uint64,
            TppWorkerpListLock=Ptr,
            TppWorkerpList=LIST_ENTRY,
            WaitOnAddressHashTable=Ptr * 128,
        )


class PEB_LDR_DATA(EmuStruct):
    Length: Annotated[int, ct.c_uint32]
    Initialized: Annotated[bytes, ct.c_uint8 * 4]
    SsHandle: Annotated[int, Ptr]
    InLoadOrderModuleList: LIST_ENTRY
    InMemoryOrderModuleList: LIST_ENTRY
    InInitializationOrderModuleList: LIST_ENTRY
    EntryInProgress: Annotated[int, Ptr]
    ShutdownInProgress: Annotated[int, ct.c_uint8]
    ShutdownThreadId: Annotated[int, Ptr]


class LDR_DATA_TABLE_ENTRY(EmuStruct):
    InLoadOrderLinks: LIST_ENTRY
    InMemoryOrderLinks: LIST_ENTRY
    InInitializationOrderLinks: LIST_ENTRY
    DllBase: Annotated[int, Ptr]
    EntryPoint: Annotated[int, Ptr]
    SizeOfImage: Annotated[int, ct.c_uint32]
    FullDllName: UNICODE_STRING
    BaseDllName: UNICODE_STRING
    Flags: Annotated[int, ct.c_uint32]
    LoadCount: Annotated[int, ct.c_uint16]


class LARGE_INTEGER(EmuStruct):
    QuadPart: Annotated[int, ct.c_int64]


class CURDIR(EmuStruct):
    DosPath: UNICODE_STRING
    Handle: Annotated[int, Ptr]


class RTL_USER_PROCESS_PARAMETERS(EmuStruct):
    MaximumLength: Annotated[int, ct.c_uint32]
    Length: Annotated[int, ct.c_uint32]
    Flags: Annotated[int, ct.c_uint32]
    DebugFlags: Annotated[int, ct.c_uint32]
    ConsoleHandle: Annotated[int, Ptr]
    ConsoleFlags: Annotated[int, ct.c_uint32]
    StandardInput: Annotated[int, Ptr]
    StandardOutput: Annotated[int, Ptr]
    StandardError: Annotated[int, Ptr]
    CurrentDirectory: CURDIR
    DllPath: UNICODE_STRING
    ImagePathName: UNICODE_STRING
    CommandLine: UNICODE_STRING
    Environment: Annotated[int, Ptr]
    StartingX: Annotated[int, ct.c_uint32]
    StartingY: Annotated[int, ct.c_uint32]
    CountX: Annotated[int, ct.c_uint32]
    CountY: Annotated[int, ct.c_uint32]
    CountCharsX: Annotated[int, ct.c_uint32]
    CountCharsY: Annotated[int, ct.c_uint32]
    FillAttribute: Annotated[int, ct.c_uint32]
    WindowFlags: Annotated[int, ct.c_uint32]
    ShowWindowFlags: Annotated[int, ct.c_uint32]
    WindowTitle: UNICODE_STRING
    DesktopInfo: UNICODE_STRING
    ShellInfo: UNICODE_STRING
    RuntimeData: UNICODE_STRING
