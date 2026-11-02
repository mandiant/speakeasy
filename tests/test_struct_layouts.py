"""The EmuStruct classes in speakeasy.winenv.defs have the size and the field offsets of the Windows structs."""

import ctypes as ct
import importlib
import importlib.util
import inspect
import json
import pkgutil
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import pytest

import speakeasy.winenv.defs
from speakeasy.struct import EmuStruct, EmuUnion

REPO_ROOT = Path(__file__).resolve().parent.parent
WIN32JSON = REPO_ROOT / "deps" / "win32json"
GEN_WIN32_SIGNATURES = REPO_ROOT / "scripts" / "gen_win32_signatures.py"

NTOSKRNL = "speakeasy.winenv.defs.nt.ntoskrnl"

PTR_SIZES = {"x86": 4, "x64": 8}
WIN32JSON_ARCHS = {"x86": "X86", "x64": "X64"}

# The win32json name of a class that has a different name in speakeasy. Two names are the A and W structs
# of a class that takes a character width.
WIN32JSON_NAMES = {
    "CONTEXT64": ("CONTEXT",),
    "CREATESTRUCT": ("CREATESTRUCTA",),
    "LVCOLUMN": ("LVCOLUMNA",),
    "MODULEENTRY32": ("MODULEENTRY32", "MODULEENTRY32W"),
    "PROCESSENTRY32": ("PROCESSENTRY32", "PROCESSENTRY32W"),
    "RTL_OSVERSIONINFOEXW": ("OSVERSIONINFOEXW",),
    "RTL_OSVERSIONINFOW": ("OSVERSIONINFOW",),
    "STARTUPINFO": ("STARTUPINFOA",),
    "WNDCLASS": ("WNDCLASSA",),
    "WNDCLASSEX": ("WNDCLASSEXA",),
    "addrinfo": ("ADDRINFOA",),
    "sockaddr": ("SOCKADDR",),
    "sockaddr_in": ("SOCKADDR_IN",),
}

# The architectures of a class that is for one architecture only
CLASS_ARCHS = {"CONTEXT": ("x86",), "CONTEXT64": ("x64",)}

# win32json declares these structs as in the public headers (winternl.h), with reserved arrays in place of
# the fields that speakeasy uses, and GUID as a native type. SID has a variable length.
SKIPPED = {"GUID", "LDR_DATA_TABLE_ENTRY", "PEB", "PEB_LDR_DATA", "RTL_USER_PROCESS_PARAMETERS", "SID", "TEB"}


@dataclass(frozen=True)
class Layout:
    # None when speakeasy declares only the first fields of the struct
    size: int | None
    # Offsets by field path. A path such as "ClientId.UniqueThread" names a field of a nested struct.
    offsets: dict[str, int]


@dataclass(frozen=True)
class Case:
    cls: str
    name: str
    width: int | None
    arch: str
    layout: Layout
    from_win32json: bool


# win32json does not have the kernel structs, and has only the public part of TEB. These layouts come from wdm.h of
# the Windows 10 WDK, and the TEB layout from ntpebteb.h of phnt.
# Each comment gives the offsets for x86, then for x64.

# typedef struct _TEB {                      // x86   x64
#     NT_TIB NtTib;                          // 0x00  0x00
#     PVOID EnvironmentPointer;              // 0x1c  0x38
#     CLIENT_ID ClientId;                    // 0x20  0x40
#     PVOID ActiveRpcHandle;                 // 0x28  0x50
#     PVOID ThreadLocalStoragePointer;       // 0x2c  0x58
#     PPEB ProcessEnvironmentBlock;          // 0x30  0x60
#     ULONG LastErrorValue;                  // 0x34  0x68
#     ...
# } TEB;
TEB_X86 = Layout(
    None,
    {
        "EnvironmentPointer": 0x1C,
        "ClientId.UniqueProcess": 0x20,
        "ClientId.UniqueThread": 0x24,
        "ActiveRpcHandle": 0x28,
        "ThreadLocalStoragePointer": 0x2C,
        "ProcessEnvironmentBlock": 0x30,
        "LastErrorValue": 0x34,
    },
)
TEB_X64 = Layout(
    None,
    {
        "EnvironmentPointer": 0x38,
        "ClientId.UniqueProcess": 0x40,
        "ClientId.UniqueThread": 0x48,
        "ActiveRpcHandle": 0x50,
        "ThreadLocalStoragePointer": 0x58,
        "ProcessEnvironmentBlock": 0x60,
        "LastErrorValue": 0x68,
    },
)

# typedef struct _KEVENT {                   // x86   x64
#     DISPATCHER_HEADER Header;              // 0x00  0x00
# } KEVENT;                                  // 0x10  0x18
KEVENT_X86 = Layout(0x10, {"Header": 0x00})
KEVENT_X64 = Layout(0x18, {"Header": 0x00})

# typedef struct _KMUTANT {                  // x86   x64
#     DISPATCHER_HEADER Header;              // 0x00  0x00
#     LIST_ENTRY MutantListEntry;            // 0x10  0x18
#     struct _KTHREAD *OwnerThread;          // 0x18  0x28
#     UCHAR MutantFlags;                     // 0x1c  0x30
#     BOOLEAN ApcDisable;                    // 0x1d  0x31
# } KMUTANT;                                 // 0x20  0x38
KMUTANT_X86 = Layout(0x20, {"MutantListEntry": 0x10, "OwnerThread": 0x18, "MutantFlags": 0x1C, "ApcDisable": 0x1D})
KMUTANT_X64 = Layout(0x38, {"MutantListEntry": 0x18, "OwnerThread": 0x28, "MutantFlags": 0x30, "ApcDisable": 0x31})

# typedef struct _KSEMAPHORE {               // x86   x64
#     DISPATCHER_HEADER Header;              // 0x00  0x00
#     LONG Limit;                            // 0x10  0x18
# } KSEMAPHORE;                              // 0x14  0x20
KSEMAPHORE_X86 = Layout(0x14, {"Limit": 0x10})
KSEMAPHORE_X64 = Layout(0x20, {"Limit": 0x18})

# typedef struct _KDEVICE_QUEUE_ENTRY {      // x86   x64
#     LIST_ENTRY DeviceListEntry;            // 0x00  0x00
#     ULONG SortKey;                         // 0x08  0x10
#     BOOLEAN Inserted;                      // 0x0c  0x14
# } KDEVICE_QUEUE_ENTRY;                     // 0x10  0x18
KDEVICE_QUEUE_ENTRY_X86 = Layout(0x10, {"SortKey": 0x08, "Inserted": 0x0C})
KDEVICE_QUEUE_ENTRY_X64 = Layout(0x18, {"SortKey": 0x10, "Inserted": 0x14})

# typedef struct _KDEVICE_QUEUE {            // x86   x64
#     CSHORT Type;                           // 0x00  0x00
#     CSHORT Size;                           // 0x02  0x02
#     LIST_ENTRY DeviceListHead;             // 0x04  0x08
#     KSPIN_LOCK Lock;                       // 0x0c  0x18
#     BOOLEAN Busy;                          // 0x10  0x20
# } KDEVICE_QUEUE;                           // 0x14  0x28
KDEVICE_QUEUE_X86 = Layout(0x14, {"DeviceListHead": 0x04, "Lock": 0x0C, "Busy": 0x10})
KDEVICE_QUEUE_X64 = Layout(0x28, {"DeviceListHead": 0x08, "Lock": 0x18, "Busy": 0x20})

# typedef struct _KDPC {                     // x86   x64
#     UCHAR Type;                            // 0x00  0x00
#     UCHAR Importance;                      // 0x01  0x01
#     USHORT Number;                         // 0x02  0x02
#     SINGLE_LIST_ENTRY DpcListEntry;        // 0x04  0x08
#     KAFFINITY ProcessorHistory;            // 0x08  0x10
#     PKDEFERRED_ROUTINE DeferredRoutine;    // 0x0c  0x18
#     PVOID DeferredContext;                 // 0x10  0x20
#     PVOID SystemArgument1;                 // 0x14  0x28
#     PVOID SystemArgument2;                 // 0x18  0x30
#     PVOID DpcData;                         // 0x1c  0x38
# } KDPC;                                    // 0x20  0x40
KDPC_X86 = Layout(0x20, {"DeferredRoutine": 0x0C, "DeferredContext": 0x10, "DpcData": 0x1C})
KDPC_X64 = Layout(0x40, {"DeferredRoutine": 0x18, "DeferredContext": 0x20, "DpcData": 0x38})

# typedef struct _KAPC {                     // x86   x64
#     UCHAR Type;                            // 0x00  0x00
#     UCHAR AllFlags;                        // 0x01  0x01
#     UCHAR Size;                            // 0x02  0x02
#     UCHAR SpareByte1;                      // 0x03  0x03
#     ULONG SpareLong0;                      // 0x04  0x04
#     struct _KTHREAD *Thread;               // 0x08  0x08
#     LIST_ENTRY ApcListEntry;               // 0x0c  0x10
#     PVOID Reserved[3];                     // 0x14  0x20
#     PVOID NormalContext;                   // 0x20  0x38
#     PVOID SystemArgument1;                 // 0x24  0x40
#     PVOID SystemArgument2;                 // 0x28  0x48
#     CCHAR ApcStateIndex;                   // 0x2c  0x50
#     KPROCESSOR_MODE ApcMode;               // 0x2d  0x51
#     BOOLEAN Inserted;                      // 0x2e  0x52
# } KAPC;                                    // 0x30  0x58
KAPC_X86 = Layout(0x30, {"Thread": 0x08, "ApcListEntry": 0x0C, "NormalContext": 0x20, "Inserted": 0x2E})
KAPC_X64 = Layout(0x58, {"Thread": 0x08, "ApcListEntry": 0x10, "NormalContext": 0x38, "Inserted": 0x52})

# typedef struct _IO_STACK_LOCATION {        // x86   x64
#     UCHAR MajorFunction;                   // 0x00  0x00
#     UCHAR MinorFunction;                   // 0x01  0x01
#     UCHAR Flags;                           // 0x02  0x02
#     UCHAR Control;                         // 0x03  0x03
#     union {
#         struct {
#             ULONG OutputBufferLength;                  // 0x04  0x08
#             ULONG POINTER_ALIGNMENT InputBufferLength; // 0x08  0x10
#             ULONG POINTER_ALIGNMENT IoControlCode;     // 0x0c  0x18
#             PVOID Type3InputBuffer;                    // 0x10  0x20
#         } DeviceIoControl;
#         ...
#     } Parameters;                          // 0x04  0x08
#     PDEVICE_OBJECT DeviceObject;           // 0x14  0x28
#     PFILE_OBJECT FileObject;               // 0x18  0x30
#     PIO_COMPLETION_ROUTINE CompletionRoutine; // 0x1c  0x38
#     PVOID Context;                         // 0x20  0x40
# } IO_STACK_LOCATION;                       // 0x24  0x48
IO_STACK_LOCATION_X86 = Layout(
    0x24,
    {
        "Parameters": 0x04,
        "Parameters.DeviceIoControl.OutputBufferLength": 0x04,
        "Parameters.DeviceIoControl.InputBufferLength": 0x08,
        "Parameters.DeviceIoControl.IoControlCode": 0x0C,
        "Parameters.DeviceIoControl.Type3InputBuffer": 0x10,
        "DeviceObject": 0x14,
        "Context": 0x20,
    },
)
IO_STACK_LOCATION_X64 = Layout(
    0x48,
    {
        "Parameters": 0x08,
        "Parameters.DeviceIoControl.OutputBufferLength": 0x08,
        "Parameters.DeviceIoControl.InputBufferLength": 0x10,
        "Parameters.DeviceIoControl.IoControlCode": 0x18,
        "Parameters.DeviceIoControl.Type3InputBuffer": 0x20,
        "DeviceObject": 0x28,
        "Context": 0x40,
    },
)

# typedef struct _IRP {                      // x86   x64
#     CSHORT Type;                           // 0x00  0x00
#     USHORT Size;                           // 0x02  0x02
#     PMDL MdlAddress;                       // 0x04  0x08
#     ULONG Flags;                           // 0x08  0x10
#     union { ... } AssociatedIrp;           // 0x0c  0x18
#     LIST_ENTRY ThreadListEntry;            // 0x10  0x20
#     IO_STATUS_BLOCK IoStatus;              // 0x18  0x30
#     KPROCESSOR_MODE RequestorMode;         // 0x20  0x40
#     ...
#     PIO_STATUS_BLOCK UserIosb;             // 0x28  0x48
#     PKEVENT UserEvent;                     // 0x2c  0x50
#     union { ... } Overlay;                 // 0x30  0x58
#     PDRIVER_CANCEL CancelRoutine;          // 0x38  0x68
#     PVOID UserBuffer;                      // 0x3c  0x70
#     union {
#         struct {
#             union {
#                 KDEVICE_QUEUE_ENTRY DeviceQueueEntry;
#                 PVOID DriverContext[4];
#             };                             // 0x40  0x78
#             PETHREAD Thread;               // 0x50  0x98
#             PCHAR AuxiliaryBuffer;         // 0x54  0xa0
#             LIST_ENTRY ListEntry;          // 0x58  0xa8
#             struct _IO_STACK_LOCATION *CurrentStackLocation; // 0x60  0xb8
#             PFILE_OBJECT OriginalFileObject; // 0x64  0xc0
#         } Overlay;
#         KAPC Apc;
#         PVOID CompletionKey;
#     } Tail;                                // 0x40  0x78
# } IRP;                                     // 0x70  0xd0
IRP_X86 = Layout(
    0x70,
    {
        "IoStatus": 0x18,
        "UserIosb": 0x28,
        "UserBuffer": 0x3C,
        "Tail": 0x40,
        "Tail.Overlay.ListEntry": 0x58,
        "Tail.Overlay.CurrentStackLocation": 0x60,
    },
)
IRP_X64 = Layout(
    0xD0,
    {
        "IoStatus": 0x30,
        "UserIosb": 0x48,
        "UserBuffer": 0x70,
        "Tail": 0x78,
        "Tail.Overlay.ListEntry": 0xA8,
        "Tail.Overlay.CurrentStackLocation": 0xB8,
    },
)

# typedef struct _DRIVER_OBJECT {            // x86   x64
#     CSHORT Type;                           // 0x00  0x00
#     CSHORT Size;                           // 0x02  0x02
#     PDEVICE_OBJECT DeviceObject;           // 0x04  0x08
#     ULONG Flags;                           // 0x08  0x10
#     PVOID DriverStart;                     // 0x0c  0x18
#     ULONG DriverSize;                      // 0x10  0x20
#     PVOID DriverSection;                   // 0x14  0x28
#     PDRIVER_EXTENSION DriverExtension;     // 0x18  0x30
#     UNICODE_STRING DriverName;             // 0x1c  0x38
#     PUNICODE_STRING HardwareDatabase;      // 0x24  0x48
#     PFAST_IO_DISPATCH FastIoDispatch;      // 0x28  0x50
#     PDRIVER_INITIALIZE DriverInit;         // 0x2c  0x58
#     PDRIVER_STARTIO DriverStartIo;         // 0x30  0x60
#     PDRIVER_UNLOAD DriverUnload;           // 0x34  0x68
#     PDRIVER_DISPATCH MajorFunction[28];    // 0x38  0x70
# } DRIVER_OBJECT;                           // 0xa8  0x150
DRIVER_OBJECT_X86 = Layout(0xA8, {"DriverName": 0x1C, "DriverUnload": 0x34, "MajorFunction": 0x38})
DRIVER_OBJECT_X64 = Layout(0x150, {"DriverName": 0x38, "DriverUnload": 0x68, "MajorFunction": 0x70})

# typedef struct _DEVICE_OBJECT {            // x86   x64
#     CSHORT Type;                           // 0x00  0x00
#     USHORT Size;                           // 0x02  0x02
#     LONG ReferenceCount;                   // 0x04  0x04
#     struct _DRIVER_OBJECT *DriverObject;   // 0x08  0x08
#     ...
#     PVOID DeviceExtension;                 // 0x28  0x40
#     DEVICE_TYPE DeviceType;                // 0x2c  0x48
#     CCHAR StackSize;                       // 0x30  0x4c
#     union {
#         LIST_ENTRY ListEntry;
#         WAIT_CONTEXT_BLOCK Wcb;
#     } Queue;                               // 0x34  0x50
#     ULONG AlignmentRequirement;            // 0x5c  0x98
#     KDEVICE_QUEUE DeviceQueue;             // 0x60  0xa0
#     KDPC Dpc;                              // 0x74  0xc8
#     ULONG ActiveThreadCount;               // 0x94  0x108
#     PSECURITY_DESCRIPTOR SecurityDescriptor; // 0x98  0x110
#     KEVENT DeviceLock;                     // 0x9c  0x118
#     USHORT SectorSize;                     // 0xac  0x130
#     USHORT Spare1;                         // 0xae  0x132
#     struct _DEVOBJ_EXTENSION *DeviceObjectExtension; // 0xb0  0x138
#     PVOID Reserved;                        // 0xb4  0x140
# } DEVICE_OBJECT;                           // 0xb8  0x150
DEVICE_OBJECT_X86 = Layout(
    0xB8,
    {
        "DeviceExtension": 0x28,
        "StackSize": 0x30,
        "Queue": 0x34,
        "AlignmentRequirement": 0x5C,
        "DeviceQueue": 0x60,
        "Dpc": 0x74,
        "DeviceLock": 0x9C,
        "DeviceObjectExtension": 0xB0,
    },
)
DEVICE_OBJECT_X64 = Layout(
    0x150,
    {
        "DeviceExtension": 0x40,
        "StackSize": 0x4C,
        "Queue": 0x50,
        "AlignmentRequirement": 0x98,
        "DeviceQueue": 0xA0,
        "Dpc": 0xC8,
        "DeviceLock": 0x118,
        "DeviceObjectExtension": 0x138,
    },
)

# typedef struct _FILE_OBJECT {              // x86   x64
#     CSHORT Type;                           // 0x00  0x00
#     CSHORT Size;                           // 0x02  0x02
#     PDEVICE_OBJECT DeviceObject;           // 0x04  0x08
#     ...
#     ULONG Flags;                           // 0x2c  0x50
#     UNICODE_STRING FileName;               // 0x30  0x58
#     LARGE_INTEGER CurrentByteOffset;       // 0x38  0x68
#     ULONG Waiters;                         // 0x40  0x70
#     ULONG Busy;                            // 0x44  0x74
#     PVOID LastLock;                        // 0x48  0x78
#     KEVENT Lock;                           // 0x4c  0x80
#     KEVENT Event;                          // 0x5c  0x98
#     PIO_COMPLETION_CONTEXT CompletionContext; // 0x6c  0xb0
#     KSPIN_LOCK IrpListLock;                // 0x70  0xb8
#     LIST_ENTRY IrpList;                    // 0x74  0xc0
#     PVOID FileObjectExtension;             // 0x7c  0xd0
# } FILE_OBJECT;                             // 0x80  0xd8
FILE_OBJECT_X86 = Layout(
    0x80,
    {
        "FileName": 0x30,
        "CurrentByteOffset": 0x38,
        "Lock": 0x4C,
        "Event": 0x5C,
        "IrpListLock": 0x70,
        "IrpList": 0x74,
        "FileObjectExtension": 0x7C,
    },
)
FILE_OBJECT_X64 = Layout(
    0xD8,
    {
        "FileName": 0x58,
        "CurrentByteOffset": 0x68,
        "Lock": 0x80,
        "Event": 0x98,
        "IrpListLock": 0xB8,
        "IrpList": 0xC0,
        "FileObjectExtension": 0xD0,
    },
)

KERNEL_LAYOUTS = {
    "TEB": (TEB_X86, TEB_X64),
    "KEVENT": (KEVENT_X86, KEVENT_X64),
    "KMUTANT": (KMUTANT_X86, KMUTANT_X64),
    "KSEMAPHORE": (KSEMAPHORE_X86, KSEMAPHORE_X64),
    "KDEVICE_QUEUE_ENTRY": (KDEVICE_QUEUE_ENTRY_X86, KDEVICE_QUEUE_ENTRY_X64),
    "KDEVICE_QUEUE": (KDEVICE_QUEUE_X86, KDEVICE_QUEUE_X64),
    "KDPC": (KDPC_X86, KDPC_X64),
    "KAPC": (KAPC_X86, KAPC_X64),
    "IO_STACK_LOCATION": (IO_STACK_LOCATION_X86, IO_STACK_LOCATION_X64),
    "IRP": (IRP_X86, IRP_X64),
    "DRIVER_OBJECT": (DRIVER_OBJECT_X86, DRIVER_OBJECT_X64),
    "DEVICE_OBJECT": (DEVICE_OBJECT_X86, DEVICE_OBJECT_X64),
    "FILE_OBJECT": (FILE_OBJECT_X86, FILE_OBJECT_X64),
}

# Layouts that are not correct yet
XFAIL = {
    "fwpmtypes.FWPM_CALLOUT0-x64",
    "fwpmtypes.FWPM_CALLOUT0-x86",
    "fwpmtypes.FWPM_FILTER0-x64",
    "fwpmtypes.FWPM_FILTER0-x86",
    "fwpmtypes.FWPM_SUBLAYER0-x64",
    "fwpmtypes.FWPM_SUBLAYER0-x86",
    "user32.LVCOLUMNA-x64",
    "user32.LVCOLUMNA-x86",
    "windows.EXCEPTION_RECORD-x64",
}


def get_defs_structs() -> list[type[EmuStruct]]:
    classes = []
    for info in pkgutil.walk_packages(speakeasy.winenv.defs.__path__, speakeasy.winenv.defs.__name__ + "."):
        module = importlib.import_module(info.name)
        for cls in vars(module).values():
            if (
                inspect.isclass(cls)
                and issubclass(cls, EmuStruct)
                and cls not in (EmuStruct, EmuUnion)
                and cls.__module__ == module.__name__
            ):
                classes.append(cls)
    return classes


def get_win32json_names(cls: type[EmuStruct]) -> list[tuple[str, int | None]]:
    """Get the win32json names of cls, each with the character width to build cls with."""
    names = WIN32JSON_NAMES.get(cls.__name__)
    if names is None:
        if "width" in inspect.signature(cls.__init__).parameters:
            names = (cls.__name__ + "A", cls.__name__ + "W")
        else:
            names = (cls.__name__,)
    if len(names) == 2:
        return [(names[0], 1), (names[1], 2)]
    return [(names[0], None)]


def load_gen_win32_signatures() -> ModuleType:
    spec = importlib.util.spec_from_file_location("gen_win32_signatures", GEN_WIN32_SIGNATURES)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_struct_types() -> dict[str, list[tuple[str, dict]]]:
    """Get the struct and union declarations by name, with the arch variants that load_win32json merges."""
    types: dict[str, list[tuple[str, dict]]] = {}
    for path in sorted((WIN32JSON / "api").glob("*.json")):
        for td in json.loads(path.read_text(encoding="utf-8")).get("Types", []):
            if td["Kind"] in ("Struct", "Union"):
                types.setdefault(td["Name"], []).append((path.stem, td))
    return types


def get_win32json_layout(resolver, variants: list[tuple[str, dict]], arch: str) -> Layout:
    """
    Get the size and the field offsets of a win32json struct on arch.

    Raises:
        LookupError: if no variant of the struct is for arch.
    """
    win32json_arch = WIN32JSON_ARCHS[arch]
    for api, td in variants:
        if win32json_arch in (td.get("Architectures") or [win32json_arch]):
            size, _ = resolver._layout_struct(td, api, PTR_SIZES[arch], ())
            offsets = resolver.field_offsets(td, api, PTR_SIZES[arch])
            return Layout(size, {f["Name"]: o for f, o in zip(td["Fields"], offsets)})
    raise LookupError(f"no {arch} variant")


def get_win32json_cases() -> list[Case]:
    """Get a case for each EmuStruct class and architecture that win32json has the struct for."""
    gen = load_gen_win32_signatures()
    namespaces, _, _ = gen.load_win32json(str(WIN32JSON))
    resolver = gen.TypeResolver(namespaces)
    types = load_struct_types()
    cases = []
    for cls in get_defs_structs():
        if cls.__name__ in SKIPPED:
            continue
        for name, width in get_win32json_names(cls):
            if name not in types:
                continue
            for arch in CLASS_ARCHS.get(cls.__name__, tuple(PTR_SIZES)):
                layout = get_win32json_layout(resolver, types[name], arch)
                cases.append(Case(f"{cls.__module__}.{cls.__name__}", name, width, arch, layout, True))
    return cases


def get_kernel_cases() -> list[Case]:
    cases = []
    for name, (x86, x64) in KERNEL_LAYOUTS.items():
        cases.append(Case(f"{NTOSKRNL}.{name}", name, None, "x86", x86, False))
        cases.append(Case(f"{NTOSKRNL}.{name}", name, None, "x64", x64, False))
    return cases


def get_param(case: Case):
    case_id = f"{case.cls.split('.')[-2]}.{case.name}-{case.arch}"
    marks = [pytest.mark.xfail(strict=True)] if case_id in XFAIL else []
    return pytest.param(case, id=case_id, marks=marks)


def get_cstruct(case: Case) -> type[ct.Structure]:
    module, _, name = case.cls.rpartition(".")
    cls = getattr(importlib.import_module(module), name)
    ptr_size = PTR_SIZES[case.arch]
    if case.width:
        return cls(ptr_size, case.width).get_cstruct()
    if "ptr_size" in inspect.signature(cls.__init__).parameters:
        return cls(ptr_size).get_cstruct()
    return cls().get_cstruct()


def get_offset(cstruct: type[ct.Structure], path: str) -> int:
    offset = 0
    for name in path.split("."):
        offset += getattr(cstruct, name).offset
        cstruct = dict(cstruct._fields_)[name]
    return offset


def get_params() -> list:
    """
    Get the test parameters.

    The win32json layouts come from deps/win32json at collection time, because each struct is one test case.
    """
    params = []
    if (WIN32JSON / "api").is_dir():
        params += [get_param(c) for c in get_win32json_cases()]
    else:
        params.append(
            pytest.param(None, id="win32json", marks=pytest.mark.skip(reason="deps/win32json is not checked out"))
        )
    params += [get_param(c) for c in get_kernel_cases()]
    return params


@pytest.mark.parametrize("case", get_params())
def test_struct_has_the_windows_layout(case: Case) -> None:
    cstruct = get_cstruct(case)
    if case.layout.size is not None:
        assert ct.sizeof(cstruct) == case.layout.size
    expected = case.layout.offsets
    if case.from_win32json:
        # speakeasy has other names for some fields, such as the members of an anonymous union
        names = {name for name, _ in cstruct._fields_}
        expected = {path: offset for path, offset in expected.items() if path in names}
    assert {path: get_offset(cstruct, path) for path in expected} == expected
