# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from speakeasy.struct import EmuStruct, EmuUnion, Ptr
import ctypes as ct

from speakeasy.winenv.defs import * # noqa


class KSYSTEM_TIME(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.LowPart = ct.c_uint32
        self.High1Time = ct.c_uint32
        self.High2Time = ct.c_uint32


class SSDT(EmuStruct):  # KeServiceDescriptorTable
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.pServiceTable = Ptr
        self.pCounterTable = Ptr
        self.NumberOfServices = ct.c_uint32
        self.pArgumentTable = Ptr


class UNICODE_STRING(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Length = ct.c_uint16
        self.MaximumLength = ct.c_uint16
        self.Buffer = Ptr


class DeviceIoControl(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.OutputBufferLength = ct.c_uint32
        self.InputBufferLength = ct.c_uint32
        self.IoControlCode = ct.c_uint32
        self.Type3InputBuffer = Ptr


class STRING(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Length = ct.c_uint16
        self.MaximumLength = ct.c_uint16
        self.Buffer = Ptr


class SYSTEM_MODULE(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Reserved = Ptr * 2
        self.Base = Ptr
        self.Size = ct.c_uint32
        self.Flags = ct.c_uint32
        self.Index = ct.c_uint16
        self.Unknown = ct.c_uint16
        self.LoadCount = ct.c_uint16
        self.ModuleNameOffset = ct.c_uint16
        self.ImageName = ct.c_uint8 * 256


class SYSTEM_TIMEOFDAY_INFORMATION(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.BootTime = ct.c_uint64
        self.CurrentTime = ct.c_uint64
        self.TimeZoneBias = ct.c_uint64
        self.TimeZoneId = ct.c_uint32
        self.Reserved = ct.c_uint32
        self.BootTimeBias = ct.c_uint64
        self.SleepTimeBias = ct.c_uint64


class SYSTEM_PROCESS_INFORMATION(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.NextEntryOffset = ct.c_uint32
        self.NumberOfThreads = ct.c_uint32
        self.Reserved1 = ct.c_uint8 * 48
        self.ImageName = UNICODE_STRING
        self.BasePriority = ct.c_uint32
        self.UniqueProcessId = Ptr
        self.InheritedFromUniqueProcessId = Ptr
        self.HandleCount = ct.c_uint32
        self.SessionId = ct.c_uint32
        self.UniqueProcessKey = Ptr
        self.PeakVirtualSize = Ptr
        self.VirtualSize = Ptr
        self.PageFaultCount = ct.c_uint32

        self.PeakWorkingSetSize = Ptr
        self.WorkingSetSize = Ptr
        self.QuotaPeakPagedPoolUsage = Ptr
        self.QuotaPagedPoolUsage = Ptr
        self.QuotaPeakNonPagedPoolUsage = Ptr
        self.QuotaNonPagedPoolUsage = Ptr
        self.PagefileUsage = Ptr

        self.PeakPagefileUsage = Ptr
        self.PrivatePageCount = Ptr
        self.Reserved7 = LARGE_INTEGER * 6


class SYSTEM_THREAD_INFORMATION(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Reserved1 = LARGE_INTEGER * 3
        self.Reserved2 = ct.c_uint32
        self.StartAddress = Ptr
        self.ClientId = CLIENT_ID
        self.Priority = ct.c_uint32
        self.BasePriority = ct.c_uint32
        self.ContextSwitches = ct.c_uint32
        self.ThreadState = ct.c_uint32
        self.WaitReason = ct.c_uint32


class CLIENT_ID(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.UniqueProcess = ct.c_uint32
        self.UniqueThread = ct.c_uint32


class MDL(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Next = Ptr
        self.Size = ct.c_uint16
        self.MdlFlags = ct.c_uint16
        self.Process = Ptr
        self.MappedSystemVa = Ptr
        self.StartVa = Ptr
        self.ByteCount = ct.c_uint32
        self.ByteOffset = ct.c_uint32


class KIDTENTRY(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.OffsetLow = ct.c_uint16
        self.Selector = ct.c_uint16
        self.Base = ct.c_uint32


class KIDTENTRY64(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.OffsetLow = ct.c_uint16
        self.Selector = ct.c_uint16
        self.Reserved0 = ct.c_uint16
        self.OffsetMiddle = ct.c_uint16
        self.OffsetHigh = ct.c_uint32
        self.Reserved1 = ct.c_uint32


class ETHREAD(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Data = ct.c_uint8 * 4096


class EPROCESS(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Data = ct.c_uint8 * 4096


class KEVENT(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Data = ct.c_uint8 * 4096


class MUTANT(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Data = ct.c_uint8 * 4096


class RTL_OSVERSIONINFOW(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.dwOSVersionInfoSize = ct.c_uint32
        self.dwMajorVersion = ct.c_uint32
        self.dwMinorVersion = ct.c_uint32
        self.dwBuildNumber = ct.c_uint32
        self.dwPlatformId = ct.c_uint32
        self.szCSDVersion = ct.c_uint8 * 256


class RTL_OSVERSIONINFOEXW(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.dwOSVersionInfoSize = ct.c_uint32
        self.dwMajorVersion = ct.c_uint32
        self.dwMinorVersion = ct.c_uint32
        self.dwBuildNumber = ct.c_uint32
        self.dwPlatformId = ct.c_uint32
        self.szCSDVersion = ct.c_uint8 * 256
        self.wServicePackMajor = ct.c_uint16
        self.wServicePackMinor = ct.c_uint16
        self.wSuiteMask = ct.c_uint16
        self.wProductType = ct.c_uint8
        self.wReserved = ct.c_uint8


class IDT(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Limit = ct.c_uint16
        self.Descriptors = Ptr


class KAPC(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Type = ct.c_uint8
        self.SpareByte0 = ct.c_uint8
        self.Size = ct.c_uint8
        self.SpareByte1 = ct.c_uint8
        self.SpareLong0 = ct.c_uint32
        self.Thread = Ptr
        self.ApcListEntry = LIST_ENTRY
        self.KernelRoutine = Ptr
        self.RundownRoutine = Ptr
        self.NormalRoutine = Ptr
        self.NormalContext = Ptr
        self.SystemArgument1 = Ptr
        self.SystemArgument2 = Ptr
        self.ApcStateIndex = ct.c_uint8
        self.ApcMode = ct.c_uint8
        self.Inserted = ct.c_uint8


class OBJECT_ATTRIBUTES(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Length = ct.c_uint32
        self.RootDirectory = Ptr
        self.ObjectName = Ptr
        self.Attributes = ct.c_uint32
        self.SecurityDescriptor = Ptr
        self.SecurityQualityOfService = Ptr


class FILE_STANDARD_INFORMATION(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.AllocationSize = LARGE_INTEGER
        self.EndOfFile = LARGE_INTEGER
        self.NumberOfLinks = ct.c_uint32
        self.DeletePending = ct.c_uint8
        self.Directory = ct.c_uint8


class DESCRIPTOR_TABLE(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        if ptr_size == 4:
            self.Table = KIDTENTRY * 256
        else:
            self.Table = KIDTENTRY64 * 256


class DRIVER_OBJECT(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Type = ct.c_uint16
        self.Size = ct.c_uint16
        self.DeviceObject = Ptr
        self.Flags = ct.c_uint32
        self.DriverStart = Ptr
        self.DriverSize = ct.c_uint32
        self.DriverSection = Ptr
        self.DriverExtension = Ptr
        self.DriverName = UNICODE_STRING
        self.HardwareDatabase = Ptr
        self.FastIoDispatch = Ptr
        self.DriverInit = Ptr
        self.DriverStartIo = Ptr
        self.DriverUnload = Ptr
        self.MajorFunction = Ptr * 28


class KDEVICE_QUEUE(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Type = ct.c_uint16
        self.Size = ct.c_uint16
        self.DeviceListHead = LIST_ENTRY
        self.Lock = ct.c_uint64
        self.Busy = ct.c_uint8


class KDPC(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Type = ct.c_uint8
        self.Importance = ct.c_uint8
        self.Number = ct.c_uint16
        self.DpcListEntry = LIST_ENTRY
        self.DeferredRoutine = Ptr
        self.DeferredContext = Ptr
        self.SystemArgument1 = Ptr
        self.SystemArgument2 = Ptr
        self.DpcData = Ptr


class DEVICE_OBJECT(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Type = ct.c_uint16
        self.Size = ct.c_uint16
        self.ReferenceCount = ct.c_uint32
        self.DriverObject = Ptr
        self.NextDevice = Ptr
        self.AttachedDevice = Ptr
        self.CurrentIrp = Ptr
        self.Timer = Ptr
        self.Flags = ct.c_uint32
        self.Characteristics = ct.c_uint32
        self.Vpb = Ptr
        self.DeviceExtension = Ptr
        self.DeviceType = ct.c_uint32
        self.StackSize = ct.c_uint8
        self.Queue = LIST_ENTRY
        self.AlignmentRequirement = ct.c_uint32
        self.DeviceQueue = KDEVICE_QUEUE
        self.Dpc = KDPC
        self.ActiveThreadCount = ct.c_uint32
        self.SecurityDescriptor = Ptr
        self.DeviceLock = KEVENT
        self.SectorSize = ct.c_uint16
        self.Spare1 = ct.c_uint16
        self.DeviceObjectExtension = Ptr
        self.Reserved = Ptr


class FILE_OBJECT(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Type = ct.c_uint16
        self.Size = ct.c_uint16
        self.DeviceObject = Ptr
        self.Vpb = Ptr
        self.FsContext = Ptr
        self.FsContext2 = Ptr
        self.SectionObjectPointer = Ptr
        self.PrivateCacheMap = Ptr
        self.FinalStatus = ct.c_uint32
        self.RelatedFileObject = Ptr
        self.LockOperation = ct.c_uint8
        self.DeletePending = ct.c_uint8
        self.ReadAccess = ct.c_uint8
        self.WriteAccess = ct.c_uint8
        self.DeleteAccess = ct.c_uint8
        self.SharedRead = ct.c_uint8
        self.SharedWrite = ct.c_uint8
        self.SharedDelete = ct.c_uint8
        self.Flags = ct.c_uint32
        self.FileName = UNICODE_STRING
        self.CurrentByteOffset = LARGE_INTEGER
        self.Waiters = ct.c_uint32
        self.Busy = ct.c_uint32
        self.LastLock = Ptr
        self.Lock = KEVENT
        self.Event = KEVENT
        self.CompletionContext = Ptr
        self.IrpListLock = ct.c_uint32
        self.IrpList = LIST_ENTRY
        self.FileObjectExtension = Ptr


class IO_PARAMETERS(EmuUnion):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.DeviceIoControl = DeviceIoControl(ptr_size).get_cstruct()


class IO_STACK_LOCATION(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.MajorFunction = ct.c_uint8
        self.MinorFunction = ct.c_uint8
        self.Flags = ct.c_uint8
        self.Control = ct.c_uint8
        if ptr_size == 8:
            self._padding = ct.c_uint8 * 8
        self.Parameters = IO_PARAMETERS
        self.DeviceObject = Ptr
        self.FileObject = Ptr
        self.CompletionRoutine = Ptr
        self.Context = Ptr


class IRP_OVERLAY(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.UserApcRoutine = Ptr
        self.UserApcContext = Ptr


class IRP(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Type = ct.c_uint16
        self.Size = ct.c_uint16
        self.MdlAddress = Ptr
        self.Flags = ct.c_uint32
        self.AssociatedIrp = Ptr
        self.ThreadListEntry = LIST_ENTRY
        self.IoStatus = IO_STATUS_BLOCK
        self.RequestorMode = ct.c_uint8
        self.PendingReturned = ct.c_uint8
        self.StackCount = ct.c_uint8
        self.CurrentLocation = ct.c_uint8
        self.Cancel = ct.c_uint8
        self.CancelIrql = ct.c_uint8
        self.ApcEnvironment = ct.c_uint8
        self.AllocationFlags = ct.c_uint8
        self.UserIosb = Ptr
        self.UserEvent = Ptr
        self.Overlay = IRP_OVERLAY
        self.CancelRoutine = Ptr
        self.UserBuffer = Ptr
        self.Tail = IRP_TAIL


class IO_STATUS_BLOCK(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Status = Ptr
        self.Information = Ptr


class KDEVICE_QUEUE_ENTRY(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.DeviceListEntry = LIST_ENTRY
        self.SortKey = ct.c_uint32
        self.Inserted = ct.c_uint8


class TAIL_OVERLAY(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.DeviceQueueEntry = KDEVICE_QUEUE_ENTRY
        if ptr_size == 8:
            self.padding = ct.c_uint8 * 8

        self.Reserved1 = Ptr * 2
        self.ListEntry = LIST_ENTRY
        self.CurrentStackLocation = Ptr
        self.Reserved2 = Ptr


class IRP_TAIL(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Overlay = TAIL_OVERLAY


class LIST_ENTRY(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Flink = Ptr
        self.Blink = Ptr


class NT_TIB(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.ExceptionList = Ptr
        self.StackBase = Ptr
        self.StackLimit = Ptr
        self.Reserved1 = Ptr
        self.Reserved2 = Ptr
        self.Reserved3 = Ptr
        self.Self = Ptr


class TEB(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.NtTib = NT_TIB
        self.EnvironmentPointer = Ptr
        self.ClientId = CLIENT_ID
        if ptr_size == 8:
            self.pad0 = Ptr
        self.ActiveRpcHandle = Ptr
        self.ThreadLocalStoragePointer = Ptr
        self.ProcessEnvironmentBlock = Ptr
        self.LastErrorValue = ct.c_uint32
        self.CountOfOwnedCriticalSections = ct.c_uint32
        self.CsrClientThread = Ptr
        self.Win32ThreadInfo = Ptr
        self.User32Reserved = ct.c_uint32 * 26
        self.UserReserved = ct.c_uint32 * 5
        self.WOW32Reserved = Ptr
        self.CurrentLocale = ct.c_uint32


class PEB(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.InheritedAddressSpace = ct.c_uint8
        self.ReadImageFileExecOptions = ct.c_uint8
        self.BeingDebugged = ct.c_uint8
        self.BitField = ct.c_uint8
        self.Mutant = Ptr
        self.ImageBaseAddress = Ptr
        self.Ldr = Ptr
        self.ProcessParameters = Ptr
        self.SubSystemData = Ptr
        self.ProcessHeap = Ptr
        self.FastPebLock = Ptr
        self.AtlThunkSListPtr = Ptr
        self.IFEOKey = Ptr
        self.CrossProcessFlags = Ptr
        self.UserSharedInfoPtr = Ptr
        self.SystemReserved = ct.c_uint32
        self.AtlThunkSListPtr32 = ct.c_uint32
        self.ApiSetMap = Ptr
        self.TlsExpansionCounter = Ptr
        self.TlsBitmap = Ptr
        self.TlsBitmapBits = ct.c_uint32 * 2
        self.ReadOnlySharedMemoryBase = Ptr
        self.SharedData = Ptr # HotpatchInformation
        self.ReadOnlyStaticServerData = Ptr
        self.AnsiCodePageData = Ptr
        self.OemCodePageData = Ptr
        self.UnicodeCaseTableData = Ptr
        self.NumberOfProcessors = ct.c_uint32
        self.NtGlobalFlag = ct.c_uint32
        self.CriticalSectionTimeout = ct.c_longlong # LARGE_INTEGER
        self.HeapSegmentReserve = Ptr
        self.HeapSegmentCommit = Ptr
        self.HeapDeCommitTotalFreeThreshold = Ptr
        self.HeapDeCommitFreeBlockThreshold = Ptr
        self.NumberOfHeaps = ct.c_uint32
        self.MaximumNumberOfHeaps = ct.c_uint32
        self.ProcessHeaps = Ptr
        self.GdiSharedHandleTable = Ptr
        self.ProcessStarterHelper = Ptr
        self.GdiDCAttributeList = Ptr
        self.LoaderLock = Ptr
        self.OSMajorVersion = ct.c_uint32
        self.OSMinorVersion = ct.c_uint32
        self.OSBuildNumber = ct.c_uint16
        self.OSCSDVersion = ct.c_uint16
        self.OSPlatformId = ct.c_uint32
        self.ImageSubsystem = ct.c_uint32
        self.ImageSubsystemMajorVersion = ct.c_uint32
        self.ImageSubsystemMinorVersion = Ptr
        self.ActiveProcessAffinityMask = Ptr
        if ptr_size == 8:
            self.GdiHandleBuffer = ct.c_uint32 * 60
        else:
            self.GdiHandleBuffer = ct.c_uint32 * 34
        self.PostProcessInitRoutine = Ptr
        self.TlsExpansionBitmap = Ptr
        self.TlsExpansionBitmapBits = ct.c_uint32 * 32
        self.SessionId = Ptr
        self.AppCompatFlags = ct.c_ulonglong # ULARGE_INTEGER
        self.AppCompatFlagsUser = ct.c_ulonglong # ULARGE_INTEGER
        self.pShimData = Ptr
        self.AppCompatInfo = Ptr
        self.CSDVersion = UNICODE_STRING
        self.ActivationContextData = Ptr
        self.ProcessAssemblyStorageMap = Ptr
        self.SystemDefaultActivationContextData = Ptr
        self.SystemAssemblyStorageMap = Ptr
        self.MinimumStackCommit = Ptr
        self.FlsCallback = Ptr
        self.FlsListHead = LIST_ENTRY
        self.FlsBitmap = Ptr
        self.FlsBitmapBits = ct.c_uint32 * 4
        self.FlsHighIndex = Ptr
        self.WerRegistrationData = Ptr
        self.WerShipAssertPtr = Ptr
        self.pUnused = Ptr # pContextData
        self.pImageHeaderHash = Ptr
        self.TracingFlags = ct.c_uint64
        self.CsrServerReadOnlySharedMemoryBase = ct.c_uint64
        self.TppWorkerpListLock = Ptr
        self.TppWorkerpList = LIST_ENTRY
        self.WaitOnAddressHashTable = Ptr * 128


class PEB_LDR_DATA(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Length = ct.c_uint32
        self.Initialized = ct.c_uint8 * 4
        self.SsHandle = Ptr
        self.InLoadOrderModuleList = LIST_ENTRY
        self.InMemoryOrderModuleList = LIST_ENTRY
        self.InInitializationOrderModuleList = LIST_ENTRY
        self.EntryInProgress = Ptr
        self.ShutdownInProgress = ct.c_uint8
        self.ShutdownThreadId = Ptr


class LDR_DATA_TABLE_ENTRY(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.InLoadOrderLinks = LIST_ENTRY
        self.InMemoryOrderLinks = LIST_ENTRY
        self.InInitializationOrderLinks = LIST_ENTRY
        self.DllBase = Ptr
        self.EntryPoint = Ptr
        self.SizeOfImage = ct.c_uint32
        self.FullDllName = UNICODE_STRING
        self.BaseDllName = UNICODE_STRING
        self.Flags = ct.c_uint32
        self.LoadCount = ct.c_uint16


class LARGE_INTEGER(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.LowPart = ct.c_uint32
        self.HighPart = ct.c_uint32


class RTL_USER_PROCESS_PARAMETERS(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Reserved1 = ct.c_uint8 * 16
        self.Reserved2 = ct.c_uint32 * 10
        self.ImagePathName = UNICODE_STRING
        self.CommandLine = UNICODE_STRING
