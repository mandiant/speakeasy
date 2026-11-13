from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Discriminator, Field

from speakeasy.report_types import HexInt, HexIntOptional


class EventType(str, Enum):
    """
    Event type discriminators, as they appear in the ``event`` field of a report event.

    The class uses ``str, Enum`` because ``StrEnum`` needs Python 3.11.
    """

    API = "api"
    PROCESS_CREATE = "process_create"
    MEM_ALLOC = "mem_alloc"
    MEM_WRITE = "mem_write"
    MEM_READ = "mem_read"
    MEM_PROTECT = "mem_protect"
    MEM_FREE = "mem_free"
    MODULE_LOAD = "module_load"
    THREAD_CREATE = "thread_create"
    THREAD_INJECT = "thread_inject"
    FILE_CREATE = "file_create"
    FILE_OPEN = "file_open"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    DIRECTORY_CREATE = "directory_create"
    DIRECTORY_DELETE = "directory_delete"
    REG_OPEN_KEY = "reg_open_key"
    REG_CREATE_KEY = "reg_create_key"
    REG_READ_VALUE = "reg_read_value"
    REG_WRITE_VALUE = "reg_write_value"
    REG_LIST_SUBKEYS = "reg_list_subkeys"
    REG_DELETE_KEY = "reg_delete_key"
    REG_DELETE_VALUE = "reg_delete_value"
    NET_DNS = "net_dns"
    NET_TRAFFIC = "net_traffic"
    NET_HTTP = "net_http"
    EXCEPTION = "exception"


class StackEntry(BaseModel):
    """One pointer-size slot of the stack at the time of an error or an exception."""

    model_config = ConfigDict(extra="forbid")

    offset: int = Field(description="Offset of the slot from the stack pointer, in bytes.")
    value: HexIntOptional = Field(default=None, description="Value in the slot. Absent when the slot is not mapped.")
    region: HexIntOptional = Field(
        default=None,
        description=(
            "Base of the memory region that contains ``value``, as in ``memory.layout``: for a module image, the base"
            " of its headers or section. Absent when ``value`` is not in mapped memory."
        ),
    )


class TracePosition(BaseModel):
    """Position of an event: the instruction count, the thread, the process and the pc."""

    model_config = ConfigDict(extra="forbid")

    tick: int | None = Field(
        default=None,
        description=(
            "Instruction count of the run at the time of the event, as in ``instruction_count`` of the run. "
            "The events of a run are in tick order. Absent when no option counts the instructions."
        ),
    )
    tid: int = Field(description="ID of the thread that did the operation.")
    pid: int = Field(description="ID of the process that did the operation.")
    pc: HexIntOptional = Field(
        default=None,
        description=(
            "Address of the instruction that did the operation. For an API event, the address of the instruction "
            "that goes to the API, such as a ``call``, or the ``jmp`` of an import thunk. "
            "For an event that the code of an API makes, such as a file, registry, memory, process, thread or "
            "network event, also the address of the call: the same ``pc`` as the ``api`` event of the call. "
            "Such an event comes just before the ``api`` event of its call, with the same ``tick``."
        ),
    )


class Event(BaseModel):
    """Base class of the report events. The ``event`` field gives the event type."""

    model_config = ConfigDict(extra="forbid")

    pos: TracePosition = Field(description="Position of the thread that did the operation.")
    event: EventType = Field(description="Type of the event. The type sets which other fields the event has.")


class ApiArgType(str, Enum):
    """How to read the ``display`` of an API argument."""

    INT = "int"
    PTR = "ptr"
    HANDLE = "handle"
    STR = "str"
    BOOL = "bool"
    ENUM = "enum"
    FLAGS = "flags"
    STRUCT = "struct"
    BYTES = "bytes"
    GUID = "guid"
    FLOAT = "float"
    TEXT = "text"


class ApiArg(BaseModel):
    """One argument of an API call, as passed by the caller and as shown in the trace."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(
        default=None,
        description="Parameter name from the API signature. Absent when the signature is not known.",
    )
    type: ApiArgType = Field(
        description=(
            "How to read ``display``: "
            "``int`` (hex), ``ptr`` (address, hex), ``handle`` (hex), ``str`` (decoded string, unquoted), "
            "``bool`` (TRUE or FALSE), ``enum`` (a member name), "
            "``flags`` (member names joined by ``|``, maybe with a hex remainder), "
            "``struct`` (``{field: value, ...}`` display text, not JSON), ``bytes`` (hex dump), "
            "``guid``, ``float`` (decimal), or ``text`` (a value decoded by a handler)."
        )
    )
    value: HexIntOptional = Field(
        default=None,
        description=(
            "Raw value as the caller passed it. "
            "A parameter that uses more than one argument slot has the combined value. "
            "A floating point argument that Win64 passes in an XMM register has the value of the "
            "integer register for the same position instead. "
            "Absent for an entry that a handler adds, such as the formatted output of a printf call."
        ),
    )
    display: str = Field(description="Human readable rendering of the argument.")


class ApiEvent(Event):
    """
    One call to an API.

    The profiler leaves out a call that repeats the API, pc, return address, shown arguments and
    return value of one of the last 3 events of the run.
    """

    event: Literal[EventType.API] = Field(default=EventType.API, description="Event type of an API call.")
    api_name: str = Field(description="API name in ``module.function`` form, such as ``kernel32.CreateFileA``.")
    args: list[ApiArg] = Field(
        description=(
            "Arguments of the call. With a usable API signature, one entry for each parameter. "
            "Else, one entry for each argument slot. A variadic handler can add entries."
        )
    )
    return_value: HexIntOptional = Field(
        default=None,
        description="Return value of the API, when the handler gives one.",
    )
    return_address: HexIntOptional = Field(
        default=None,
        description="Address where the call returns to the caller. Absent when the emulator does not know it.",
    )


class ProcessCreateEvent(Event):
    """A process that the guest creates, such as with ``CreateProcess`` or ``ShellExecute``."""

    event: Literal[EventType.PROCESS_CREATE] = Field(
        default=EventType.PROCESS_CREATE,
        description="Event type of a process creation.",
    )
    path: str = Field(description="Emulated path of the image of the new process.")
    command_line: str = Field(description="Command line of the new process.")
    pid: int | None = Field(
        default=None,
        description="ID of the new process.",
    )


class MemAllocEvent(Event):
    """Memory that the guest allocates with ``VirtualAlloc`` or ``VirtualAllocEx``."""

    event: Literal[EventType.MEM_ALLOC] = Field(
        default=EventType.MEM_ALLOC, description="Event type of a memory allocation."
    )
    path: str = Field(description="Image path of the target process.")
    base: HexInt = Field(description="Base address of the allocation.")
    size: int = Field(description="Size that the caller asked for, in bytes.")
    protect: list[str] | None = Field(
        default=None,
        description="Names of the requested page protection flags, such as ``PAGE_READWRITE``.",
    )
    pid: int | None = Field(
        default=None,
        description="ID of the target process. Absent when the target is the process in ``pos``.",
    )


class MemWriteEvent(Event):
    """
    Data that the guest writes to process memory with an API, such as ``WriteProcessMemory``.

    The profiler merges a write into the last process event when that event is a write that ends
    at the start of the new write.
    """

    event: Literal[EventType.MEM_WRITE] = Field(
        default=EventType.MEM_WRITE, description="Event type of a memory write."
    )
    path: str = Field(description="Image path of the target process.")
    base: HexInt = Field(description="Start address of the write.")
    size: int = Field(description="Number of bytes written.")
    data_ref: str | None = Field(
        default=None,
        description=("Key in the top-level ``data`` of the first bytes of the write. Absent when there are no bytes."),
    )
    pid: int | None = Field(
        default=None,
        description="ID of the target process. Absent when the target is the process in ``pos``.",
    )


class MemReadEvent(Event):
    """
    Data that the guest reads from process memory with an API, such as ``ReadProcessMemory``.

    The profiler merges a read into the last process event when that event is a read that ends at
    the start of the new read.
    """

    event: Literal[EventType.MEM_READ] = Field(default=EventType.MEM_READ, description="Event type of a memory read.")
    path: str = Field(description="Image path of the target process.")
    base: HexInt = Field(description="Start address of the read.")
    size: int = Field(description="Number of bytes read.")
    data_ref: str | None = Field(
        default=None,
        description=("Key in the top-level ``data`` of the first bytes of the read. Absent when there are no bytes."),
    )
    pid: int | None = Field(
        default=None,
        description="ID of the target process. Absent when the target is the process in ``pos``.",
    )


class MemProtectEvent(Event):
    """A change of page protection with ``VirtualProtectEx`` or ``NtProtectVirtualMemory``."""

    event: Literal[EventType.MEM_PROTECT] = Field(
        default=EventType.MEM_PROTECT,
        description="Event type of a page protection change.",
    )
    path: str = Field(description="Image path of the target process.")
    base: HexInt = Field(description="Base address of the range.")
    size: int = Field(description="Size of the range in bytes.")
    protect: list[str] | None = Field(
        default=None,
        description="Names of the new page protection flags, such as ``PAGE_EXECUTE_READ``.",
    )
    pid: int | None = Field(
        default=None,
        description="ID of the target process. Absent when the target is the process in ``pos``.",
    )


class MemFreeEvent(Event):
    """Memory that the guest frees."""

    event: Literal[EventType.MEM_FREE] = Field(default=EventType.MEM_FREE, description="Event type of a memory free.")
    path: str = Field(description="Image path of the target process.")
    base: HexInt = Field(description="Base address of the freed region.")
    size: int = Field(description="Size of the freed region in bytes.")
    pid: int | None = Field(
        default=None,
        description="ID of the target process. Absent when the target is the process in ``pos``.",
    )


class ModuleLoadEvent(Event):
    """A module that the guest loads at run time."""

    event: Literal[EventType.MODULE_LOAD] = Field(
        default=EventType.MODULE_LOAD, description="Event type of a module load."
    )
    name: str = Field(
        description="File name of the module, such as ``urlmon.dll``, the same as ``memory.modules[].name``."
    )
    path: str = Field(description="Emulated path of the module.")
    base: HexInt = Field(description="Base address of the module.")
    size: int = Field(description="Size of the module image in bytes.")


class ThreadCreateEvent(Event):
    """A thread that the guest creates in its own process."""

    event: Literal[EventType.THREAD_CREATE] = Field(
        default=EventType.THREAD_CREATE,
        description="Event type of a thread creation.",
    )
    path: str = Field(description="Image path of the target process.")
    start_address: HexInt = Field(description="Start address of the thread.")
    param: HexInt = Field(description="Parameter that the thread routine gets.")
    pid: int | None = Field(
        default=None,
        description="ID of the target process. Absent when the target is the process in ``pos``.",
    )
    tid: int | None = Field(
        default=None,
        description="ID of the new thread.",
    )


class ThreadInjectEvent(Event):
    """A thread that the guest creates in another process, such as with ``CreateRemoteThread``."""

    event: Literal[EventType.THREAD_INJECT] = Field(
        default=EventType.THREAD_INJECT,
        description="Event type of a thread injection.",
    )
    path: str = Field(description="Image path of the target process.")
    start_address: HexInt = Field(description="Start address of the thread.")
    param: HexInt = Field(description="Parameter that the thread routine gets.")
    pid: int | None = Field(
        default=None,
        description="ID of the target process. Absent when the target is the process in ``pos``.",
    )
    tid: int | None = Field(
        default=None,
        description="ID of the new thread.",
    )


class FileCreateEvent(Event):
    """A file that the guest creates, or opens with a disposition that can create the file."""

    event: Literal[EventType.FILE_CREATE] = Field(
        default=EventType.FILE_CREATE, description="Event type of a file creation."
    )
    path: str = Field(description="Emulated path of the file.")
    handle: HexIntOptional = Field(default=None, description="File handle that the API returns.")
    open_flags: list[str] | None = Field(
        default=None,
        description="Names of the disposition flags of the call, such as ``CREATE_ALWAYS``.",
    )
    access_flags: list[str] | None = Field(
        default=None,
        description="Names of the access rights that the caller asks for, such as ``GENERIC_READ``.",
    )


class FileOpenEvent(Event):
    """A file that the guest opens without a create disposition."""

    event: Literal[EventType.FILE_OPEN] = Field(default=EventType.FILE_OPEN, description="Event type of a file open.")
    path: str = Field(description="Emulated path of the file.")
    handle: HexIntOptional = Field(default=None, description="File handle that the API returns.")
    open_flags: list[str] | None = Field(
        default=None,
        description="Names of the disposition flags of the call, such as ``OPEN_EXISTING``.",
    )
    access_flags: list[str] | None = Field(
        default=None,
        description="Names of the access rights that the caller asks for, such as ``GENERIC_READ``.",
    )


class FileReadEvent(Event):
    """
    Data that the guest reads from a file.

    The profiler merges all reads of one path in a run into one event.
    """

    event: Literal[EventType.FILE_READ] = Field(default=EventType.FILE_READ, description="Event type of a file read.")
    path: str = Field(description="Emulated path of the file.")
    handle: HexIntOptional = Field(default=None, description="File handle of the first read.")
    size: int | None = Field(default=None, description="Total number of bytes that the guest read.")
    data_ref: str | None = Field(
        default=None,
        description=(
            "Key in the top-level ``data`` of the first bytes that the guest read. Absent when there are no bytes."
        ),
    )
    buffer: HexIntOptional = Field(
        default=None,
        description="Address of the buffer of the first read.",
    )


class FileWriteEvent(Event):
    """
    Data that the guest writes to a file.

    The profiler merges all writes to one path in a run into one event.
    """

    event: Literal[EventType.FILE_WRITE] = Field(
        default=EventType.FILE_WRITE, description="Event type of a file write."
    )
    path: str = Field(description="Emulated path of the file.")
    handle: HexIntOptional = Field(default=None, description="File handle of the first write.")
    size: int | None = Field(default=None, description="Total number of bytes that the guest wrote.")
    data_ref: str | None = Field(
        default=None,
        description=(
            "Key in the top-level ``data`` of the first bytes that the guest wrote. Absent when there are no bytes."
        ),
    )
    buffer: HexIntOptional = Field(
        default=None,
        description="Address of the buffer of the first write.",
    )


class FileDeleteEvent(Event):
    """A file that the guest deletes."""

    event: Literal[EventType.FILE_DELETE] = Field(
        default=EventType.FILE_DELETE, description="Event type of a file deletion."
    )
    path: str = Field(description="Emulated path of the file.")


class DirectoryCreateEvent(Event):
    """A directory that the guest creates."""

    event: Literal[EventType.DIRECTORY_CREATE] = Field(
        default=EventType.DIRECTORY_CREATE, description="Event type of a directory creation."
    )
    path: str = Field(description="Emulated path of the directory.")


class DirectoryDeleteEvent(Event):
    """A directory that the guest deletes."""

    event: Literal[EventType.DIRECTORY_DELETE] = Field(
        default=EventType.DIRECTORY_DELETE, description="Event type of a directory deletion."
    )
    path: str = Field(description="Emulated path of the directory.")


class RegOpenKeyEvent(Event):
    """A registry key that the guest opens."""

    event: Literal[EventType.REG_OPEN_KEY] = Field(
        default=EventType.REG_OPEN_KEY,
        description="Event type of a registry key open.",
    )
    path: str = Field(description="Path of the key.")
    handle: HexIntOptional = Field(default=None, description="Key handle that the API returns.")
    access_flags: list[str] | None = Field(
        default=None,
        description="Names of the access rights that the caller asks for, such as ``KEY_READ``.",
    )


class RegCreateKeyEvent(Event):
    """A registry key that the guest creates or opens with a create API, such as ``RegCreateKeyEx``."""

    event: Literal[EventType.REG_CREATE_KEY] = Field(
        default=EventType.REG_CREATE_KEY,
        description="Event type of a registry key creation.",
    )
    path: str = Field(description="Path of the key.")
    handle: HexIntOptional = Field(default=None, description="Key handle that the API returns.")
    open_flags: list[str] | None = Field(
        default=None,
        description=(
            "Disposition of the call, ``REG_CREATED_NEW_KEY`` or ``REG_OPENED_EXISTING_KEY``. "
            "Absent when the create fails."
        ),
    )
    access_flags: list[str] | None = Field(
        default=None,
        description="Names of the access rights that the caller asks for, such as ``KEY_READ``.",
    )


class RegReadValueEvent(Event):
    """A registry value that the guest reads."""

    event: Literal[EventType.REG_READ_VALUE] = Field(
        default=EventType.REG_READ_VALUE,
        description="Event type of a registry value read.",
    )
    path: str = Field(description="Path of the key that has the value.")
    handle: HexIntOptional = Field(default=None, description="Key handle of the call.")
    value_name: str | None = Field(default=None, description="Name of the value.")
    size: int | None = Field(default=None, description="Size of the value data in bytes.")
    data_ref: str | None = Field(
        default=None,
        description=(
            "Key in the top-level ``data`` of the first bytes of the value data. Absent when there are no bytes."
        ),
    )
    buffer: HexIntOptional = Field(default=None, description="Address of the output buffer.")


class RegWriteValueEvent(Event):
    """A registry value that the guest writes."""

    event: Literal[EventType.REG_WRITE_VALUE] = Field(
        default=EventType.REG_WRITE_VALUE,
        description="Event type of a registry value write.",
    )
    path: str = Field(description="Path of the key that has the value.")
    handle: HexIntOptional = Field(default=None, description="Key handle of the call.")
    value_name: str | None = Field(default=None, description="Name of the value.")
    size: int | None = Field(default=None, description="Size of the value data in bytes.")
    data_ref: str | None = Field(
        default=None,
        description=(
            "Key in the top-level ``data`` of the first bytes of the value data. Absent when there are no bytes."
        ),
    )
    buffer: HexIntOptional = Field(default=None, description="Address of the input buffer.")


class RegListSubkeysEvent(Event):
    """A registry key whose subkeys the guest lists."""

    event: Literal[EventType.REG_LIST_SUBKEYS] = Field(
        default=EventType.REG_LIST_SUBKEYS,
        description="Event type of a subkey list.",
    )
    path: str = Field(description="Path of the key.")
    handle: HexIntOptional = Field(default=None, description="Key handle of the call.")


class RegDeleteKeyEvent(Event):
    """A registry key that the guest deletes."""

    event: Literal[EventType.REG_DELETE_KEY] = Field(
        default=EventType.REG_DELETE_KEY,
        description="Event type of a registry key deletion.",
    )
    path: str = Field(description="Path of the key.")
    handle: HexIntOptional = Field(default=None, description="Key handle of the call.")


class RegDeleteValueEvent(Event):
    """A registry value that the guest deletes."""

    event: Literal[EventType.REG_DELETE_VALUE] = Field(
        default=EventType.REG_DELETE_VALUE,
        description="Event type of a registry value deletion.",
    )
    path: str = Field(description="Path of the key that had the value.")
    handle: HexIntOptional = Field(default=None, description="Key handle of the call.")
    value_name: str | None = Field(default=None, description="Name of the value.")


class NetDnsEvent(Event):
    """
    A host name that the guest looks up.

    The profiler adds one event for each query and response in a run.
    """

    event: Literal[EventType.NET_DNS] = Field(default=EventType.NET_DNS, description="Event type of a DNS lookup.")
    query: str = Field(description="Host name of the lookup.")
    response: str | None = Field(
        default=None,
        description="IP address from ``network.dns.names`` in the config. Absent when the config has no address.",
    )


class NetTrafficType(str, Enum):
    """Socket operation of a ``net_traffic`` event."""

    CONNECT = "connect"
    BIND = "bind"
    ACCEPT = "accept"
    DATA_IN = "data_in"
    DATA_OUT = "data_out"


class NetTrafficProtocol(str, Enum):
    """Protocol of the socket type of a ``net_traffic`` event."""

    TCP = "tcp"
    UDP = "udp"
    RAW = "raw"
    UNKNOWN = "unknown"


class NetHttpProtocol(str, Enum):
    """Protocol of a ``net_http`` event."""

    HTTP = "http"
    HTTPS = "https"


class NetTrafficEvent(Event):
    """A socket operation of the guest: connect, bind, accept, send or receive."""

    event: Literal[EventType.NET_TRAFFIC] = Field(
        default=EventType.NET_TRAFFIC, description="Event type of a socket operation."
    )
    server: str = Field(description="Host name or IP address of the socket peer.")
    port: int = Field(description="Port of the socket peer.")
    proto: NetTrafficProtocol = Field(
        description="Protocol of the socket type: ``tcp``, ``udp``, ``raw``, or ``unknown`` for another socket type."
    )
    type: NetTrafficType | None = Field(default=None, description="Socket operation of the event.")
    data_ref: str | None = Field(
        default=None,
        description=(
            "Key in the top-level ``data`` of the first bytes that the guest sent or received."
            " Absent when there are no bytes."
        ),
    )
    method: str | None = Field(default=None, description="Name of the operation, such as ``winsock.connect``.")


class NetHttpEvent(Event):
    """
    An HTTP request that the guest sends with WinINet or WinHTTP.

    The profiler adds one event for each server, port, protocol and headers in a run.
    """

    event: Literal[EventType.NET_HTTP] = Field(default=EventType.NET_HTTP, description="Event type of an HTTP request.")
    server: str = Field(description="Host name or address of the server.")
    port: int = Field(description="Port of the server.")
    proto: NetHttpProtocol = Field(description="``http``, or ``https`` for a secure request.")
    headers: str | None = Field(default=None, description="Headers of the request, as text.")
    data_ref: str | None = Field(
        default=None,
        description=(
            "Key in the top-level ``data`` of the first bytes of the request body. Absent when there are no bytes."
        ),
    )


class ExceptionEvent(Event):
    """An exception that the emulator sends to a guest handler."""

    event: Literal[EventType.EXCEPTION] = Field(default=EventType.EXCEPTION, description="Event type of an exception.")
    instruction: str = Field(description="Disassembly of the instruction at the exception address.")
    exception_code: HexInt = Field(description="Exception code, such as ``0xc0000005``.")
    handler_address: HexInt = Field(description="Address of the handler that gets the exception.")
    registers: dict[str, HexInt] = Field(description="Register values at the time of the exception.")
    address: HexIntOptional = Field(
        default=None, description="Memory address that caused an access violation or a guard page violation."
    )
    pc_module: str | None = Field(
        default=None,
        description="File name of the module that contains the faulting PC. The same as ``memory.modules[].name``.",
    )
    pc_offset: int | None = Field(default=None, description="Offset of the faulting PC from the base of ``pc_module``.")
    stack: list[StackEntry] | None = Field(default=None, description="Stack slots at the time of the exception.")


AnyEvent = Annotated[
    ApiEvent
    | ProcessCreateEvent
    | MemAllocEvent
    | MemWriteEvent
    | MemReadEvent
    | MemProtectEvent
    | MemFreeEvent
    | ModuleLoadEvent
    | ThreadCreateEvent
    | ThreadInjectEvent
    | FileCreateEvent
    | FileOpenEvent
    | FileReadEvent
    | FileWriteEvent
    | FileDeleteEvent
    | DirectoryCreateEvent
    | DirectoryDeleteEvent
    | RegOpenKeyEvent
    | RegCreateKeyEvent
    | RegReadValueEvent
    | RegWriteValueEvent
    | RegListSubkeysEvent
    | RegDeleteKeyEvent
    | RegDeleteValueEvent
    | NetDnsEvent
    | NetTrafficEvent
    | NetHttpEvent
    | ExceptionEvent,
    Discriminator("event"),
]
