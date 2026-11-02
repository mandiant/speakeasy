from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Discriminator, Field

from speakeasy.report_types import HexInt, HexIntOptional


class EventType(str, Enum):
    """
    Event type discriminators, as they appear in the ``event`` field of a report event.

    Use ``StrEnum`` when the minimum Python version is 3.11.
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


class TracePosition(BaseModel):
    """
    Locates where an event occurred in execution time and context.

    Every emitted event carries this structure so consumers can reconstruct
    chronology and thread/process ownership.

    Use ``tick`` ordering for timeline reconstruction and ``pc`` for direct
    disassembly alignment.
    """

    model_config = ConfigDict(extra="forbid")

    tick: int = Field(
        description=(
            "Instruction-count tick at the time of the event.\n\n"
            "Use this as the primary event ordering key within a run."
        )
    )
    tid: int = Field(
        description=(
            "Thread identifier active when the event was emitted.\n\n"
            "Correlate this with thread creation/injection activity."
        )
    )
    pid: int = Field(
        description=(
            "Process identifier active when the event was emitted.\n\n"
            "Use this to separate behavior across process boundaries."
        )
    )
    pc: HexIntOptional = Field(
        default=None,
        description=(
            "Program counter at event emission time, when available.\n\n"
            "Some synthetic events may omit this if no precise PC context exists."
        ),
    )


class Event(BaseModel):
    """
    Base class shared by all report event records.

    Concrete event types extend this with event-specific payload fields.

    Consumers should discriminate event payloads using the ``event`` field.
    """

    model_config = ConfigDict(extra="forbid")

    pos: TracePosition = Field(
        description=(
            "Execution position metadata for this event.\n\n"
            "Used to align event payloads with timeline and execution context."
        )
    )
    event: EventType = Field(
        description=("Event type discriminator.\n\nDetermines which concrete payload schema applies.")
    )


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
    Records one intercepted API invocation.

    API events are emitted by import-call handlers and represent core behavioral
    telemetry for most runs.

    Use these entries to understand control flow and argument-level intent.
    """

    event: Literal[EventType.API] = Field(default=EventType.API, description="Discriminator for API call events.")
    api_name: str = Field(
        description=(
            "Resolved API name in ``module.function`` form.\n\n"
            "Used for behavior signatures, clustering, and family comparison."
        )
    )
    args: list[ApiArg] = Field(
        description=(
            "Arguments of the call. With a usable API signature there is one entry per parameter; "
            "otherwise one entry per argument slot, plus any entries a variadic handler adds."
        )
    )
    ret_val: HexIntOptional = Field(
        default=None,
        description=(
            "Return value of the API call, when available.\n\n"
            "Use this to identify failure codes and branch-driving outcomes."
        ),
    )


class ProcessCreateEvent(Event):
    """
    Records creation of a child process context.

    Emitted when process-creation APIs are invoked and accepted by emulation.

    These events indicate lateral execution or staged payload spawning.
    """

    event: Literal[EventType.PROCESS_CREATE] = Field(
        default=EventType.PROCESS_CREATE,
        description="Discriminator for process creation events.",
    )
    path: str = Field(
        description=(
            "Target process image path.\n\nRepresents the emulated executable location requested by the sample."
        )
    )
    command_line: str = Field(
        description=(
            "Command line used for process creation.\n\nUse this to recover execution parameters and staged arguments."
        )
    )
    pid: int | None = Field(
        default=None,
        description=(
            "Target process identifier.\n\nThe actor (event pos) creates this process; the target may differ."
        ),
    )


class MemAllocEvent(Event):
    """
    Records remote or explicit process memory allocation activity.

    Emitted by memory allocation APIs that target process virtual memory.

    Commonly seen in injection and unpacking workflows.
    """

    event: Literal[EventType.MEM_ALLOC] = Field(
        default=EventType.MEM_ALLOC, description="Discriminator for memory allocation events."
    )
    path: str = Field(description="Target process path associated with the allocation event.")
    base: HexInt = Field(description="Allocated base address.")
    size: HexInt = Field(description="Allocation size in bytes.")
    protect: list[str] | None = Field(
        default=None,
        description="Names of the requested page protection flags, such as ``PAGE_READWRITE``.",
    )
    pid: int | None = Field(
        default=None,
        description=(
            "Target process identifier.\n\nThe actor (event pos) allocates in this process; NULL when the "
            "target is the actor itself."
        ),
    )


class MemWriteEvent(Event):
    """
    Records writes into process memory.

    Emitted for API-mediated memory writes and may merge adjacent writes in the
    profiler for compactness.

    Use with thread/process events to identify code injection flows.
    """

    event: Literal[EventType.MEM_WRITE] = Field(
        default=EventType.MEM_WRITE, description="Discriminator for memory write events."
    )
    path: str = Field(description="Target process path associated with the write event.")
    base: HexInt = Field(description="Write start address.")
    size: int = Field(description="Number of bytes written.")
    data_ref: str | None = Field(
        default=None,
        description=("Reference into the top-level report ``data`` store for the captured write preview bytes."),
    )
    pid: int | None = Field(
        default=None,
        description=(
            "Target process identifier.\n\nThe actor (event pos) writes into this process; NULL when the "
            "target is the actor itself."
        ),
    )


class MemReadEvent(Event):
    """
    Records reads from process memory.

    Emitted for API-mediated memory reads and may merge adjacent reads in the
    profiler for compactness.

    Useful for identifying memory scraping or credential theft behavior.
    """

    event: Literal[EventType.MEM_READ] = Field(
        default=EventType.MEM_READ, description="Discriminator for memory read events."
    )
    path: str = Field(description="Target process path associated with the read event.")
    base: HexInt = Field(description="Read start address.")
    size: int = Field(description="Number of bytes read.")
    data_ref: str | None = Field(
        default=None,
        description="Reference into the top-level report ``data`` store for the captured read preview bytes.",
    )
    pid: int | None = Field(
        default=None,
        description=(
            "Target process identifier.\n\nThe actor (event pos) reads from this process; NULL when the "
            "target is the actor itself."
        ),
    )


class MemProtectEvent(Event):
    """
    Records memory protection changes.

    Emitted for API paths that alter page permissions in process memory.

    This is a key indicator for RWX transitions and shellcode staging.
    """

    event: Literal[EventType.MEM_PROTECT] = Field(
        default=EventType.MEM_PROTECT,
        description="Discriminator for memory protection change events.",
    )
    path: str = Field(description="Target process path associated with the protection change.")
    base: HexInt = Field(description="Protection-change base address.")
    size: HexInt = Field(description="Protection-change size in bytes.")
    protect: list[str] | None = Field(
        default=None,
        description="Names of the new page protection flags, such as ``PAGE_EXECUTE_READ``.",
    )
    pid: int | None = Field(
        default=None,
        description=(
            "Target process identifier.\n\nThe actor (event pos) changes protection in this process; NULL when "
            "the target is the actor itself."
        ),
    )


class MemFreeEvent(Event):
    """
    Records memory free/decommit operations.

    Emitted when memory free APIs are invoked against process regions.

    Use this to track lifecycle of allocation artifacts.
    """

    event: Literal[EventType.MEM_FREE] = Field(
        default=EventType.MEM_FREE, description="Discriminator for memory free events."
    )
    path: str = Field(description="Target process path associated with the free event.")
    base: HexInt = Field(description="Freed region base address.")
    size: HexInt = Field(description="Freed region size in bytes.")
    pid: int | None = Field(
        default=None,
        description=(
            "Target process identifier.\n\nThe actor (event pos) frees memory in this process; NULL when the "
            "target is the actor itself."
        ),
    )


class ModuleLoadEvent(Event):
    """
    Records dynamic module loading activity.

    Emitted when module load operations map additional images during runtime.

    Useful for dependency discovery and staged import behavior.
    """

    event: Literal[EventType.MODULE_LOAD] = Field(
        default=EventType.MODULE_LOAD, description="Discriminator for module load events."
    )
    name: str = Field(description="Loaded module name.")
    path: str = Field(description="Loaded module path in emulated filesystem space.")
    base: HexInt = Field(description="Module base address.")
    size: HexInt = Field(description="Mapped module size in bytes.")


class ThreadCreateEvent(Event):
    """
    Records thread creation in a process context.

    Emitted for thread creation APIs and often accompanies process injection
    workflows.

    Combine with memory-write and start-address analysis for attribution.
    """

    event: Literal[EventType.THREAD_CREATE] = Field(
        default=EventType.THREAD_CREATE,
        description="Discriminator for thread creation events.",
    )
    path: str = Field(description="Target process path where the thread is created.")
    start_address: HexInt = Field(description="Thread start address.")
    param: HexInt = Field(description="Thread parameter pointer or value.")
    pid: int | None = Field(
        default=None,
        description=(
            "Target process identifier.\n\nThe actor (event pos) creates the thread in this process; NULL when "
            "the target is the actor itself."
        ),
    )
    tid: int | None = Field(
        default=None,
        description="Target thread identifier of the newly created thread, when known.",
    )


class ThreadInjectEvent(Event):
    """
    Records thread injection activity into another process.

    Emitted for injection-oriented thread APIs.

    Treat these as high-signal indicators of code injection behavior.
    """

    event: Literal[EventType.THREAD_INJECT] = Field(
        default=EventType.THREAD_INJECT,
        description="Discriminator for thread injection events.",
    )
    path: str = Field(description="Target process path receiving the injected thread.")
    start_address: HexInt = Field(description="Injected thread start address.")
    param: HexInt = Field(description="Injected thread parameter pointer or value.")
    pid: int | None = Field(
        default=None,
        description=(
            "Target process identifier receiving the injected thread.\n\nNULL when the target is the actor itself."
        ),
    )
    tid: int | None = Field(
        default=None,
        description="Target thread identifier of the injected thread, when known.",
    )


class FileCreateEvent(Event):
    """
    Records file creation/open-with-create semantics.

    Emitted when file APIs request creation semantics for a path.

    Use with follow-up write events to track dropped artifacts.
    """

    event: Literal[EventType.FILE_CREATE] = Field(
        default=EventType.FILE_CREATE, description="Discriminator for file create events."
    )
    path: str = Field(description="File path targeted by creation request.")
    handle: HexIntOptional = Field(default=None, description="Assigned file handle, when available.")
    open_flags: list[str] | None = Field(
        default=None,
        description="Creation/open disposition flags supplied by the API call.",
    )
    access_flags: list[str] | None = Field(
        default=None,
        description="Requested access rights for the file operation.",
    )


class FileOpenEvent(Event):
    """
    Records file open operations without explicit create intent.

    Emitted for open-style file API calls.

    Use to reconstruct file-read dependency chains.
    """

    event: Literal[EventType.FILE_OPEN] = Field(
        default=EventType.FILE_OPEN, description="Discriminator for file open events."
    )
    path: str = Field(description="File path targeted by open request.")
    handle: HexIntOptional = Field(default=None, description="Assigned file handle, when available.")
    open_flags: list[str] | None = Field(
        default=None,
        description="Open disposition flags supplied by the API call.",
    )
    access_flags: list[str] | None = Field(
        default=None,
        description="Requested access rights for the file operation.",
    )


class FileReadEvent(Event):
    """
    Records reads from a file handle.

    Emitted when file-read APIs pull bytes from emulated files.

    Useful for identifying configuration ingestion and payload loading.
    """

    event: Literal[EventType.FILE_READ] = Field(
        default=EventType.FILE_READ, description="Discriminator for file read events."
    )
    path: str = Field(description="File path associated with the read operation.")
    handle: HexIntOptional = Field(default=None, description="File handle used by the read operation.")
    size: int | None = Field(default=None, description="Number of bytes requested/read.")
    data_ref: str | None = Field(
        default=None,
        description="Reference into the top-level report ``data`` store for the captured file bytes.",
    )
    buffer: HexIntOptional = Field(
        default=None,
        description="Destination buffer pointer.",
    )


class FileWriteEvent(Event):
    """
    Records writes to a file handle.

    Emitted when file-write APIs append or overwrite emulated file data.

    Combine with dropped-file summaries to recover persisted payloads.
    """

    event: Literal[EventType.FILE_WRITE] = Field(
        default=EventType.FILE_WRITE, description="Discriminator for file write events."
    )
    path: str = Field(description="File path associated with the write operation.")
    handle: HexIntOptional = Field(default=None, description="File handle used by the write operation.")
    size: int | None = Field(default=None, description="Number of bytes written.")
    data_ref: str | None = Field(
        default=None,
        description="Reference into the top-level report ``data`` store for the captured file bytes.",
    )
    buffer: HexIntOptional = Field(
        default=None,
        description="Source buffer pointer.",
    )


class FileDeleteEvent(Event):
    """
    Records file deletion.

    Emitted when file APIs delete a file.

    Use with file create events to track files that a sample removes after use.
    """

    event: Literal[EventType.FILE_DELETE] = Field(
        default=EventType.FILE_DELETE, description="Discriminator for file delete events."
    )
    path: str = Field(description="File path targeted by the delete request.")


class DirectoryCreateEvent(Event):
    """
    Records directory creation.

    Emitted when file APIs create a directory.

    Use with file create events to track where a sample drops files.
    """

    event: Literal[EventType.DIRECTORY_CREATE] = Field(
        default=EventType.DIRECTORY_CREATE, description="Discriminator for directory create events."
    )
    path: str = Field(description="Directory path targeted by the create request.")


class DirectoryDeleteEvent(Event):
    """
    Records directory removal.

    Emitted when file APIs remove a directory.

    Use with directory create events to track staging directories.
    """

    event: Literal[EventType.DIRECTORY_DELETE] = Field(
        default=EventType.DIRECTORY_DELETE, description="Discriminator for directory delete events."
    )
    path: str = Field(description="Directory path targeted by the remove request.")


class RegOpenKeyEvent(Event):
    """
    Records registry key open operations.

    Emitted when registry APIs open existing keys.

    Use these to identify configuration and persistence probing paths.
    """

    event: Literal[EventType.REG_OPEN_KEY] = Field(
        default=EventType.REG_OPEN_KEY,
        description="Discriminator for registry key open events.",
    )
    path: str = Field(description="Registry key path targeted by the open operation.")
    handle: HexIntOptional = Field(default=None, description="Registry handle returned for the key, when available.")
    open_flags: list[str] | None = Field(
        default=None,
        description="Open/disposition flags associated with the operation.",
    )
    access_flags: list[str] | None = Field(
        default=None,
        description="Requested registry access rights.",
    )


class RegCreateKeyEvent(Event):
    """
    Records registry key creation operations.

    Emitted when registry APIs create new keys.

    Strong signal for persistence and installation behavior.
    """

    event: Literal[EventType.REG_CREATE_KEY] = Field(
        default=EventType.REG_CREATE_KEY,
        description="Discriminator for registry key create events.",
    )
    path: str = Field(description="Registry key path targeted by the create operation.")
    handle: HexIntOptional = Field(default=None, description="Registry handle returned for the key, when available.")
    open_flags: list[str] | None = Field(
        default=None,
        description="Create/open disposition flags associated with the operation.",
    )
    access_flags: list[str] | None = Field(
        default=None,
        description="Requested registry access rights.",
    )


class RegReadValueEvent(Event):
    """
    Records registry value read operations.

    Emitted when value-query APIs request data from a key.

    Use this to identify configuration keys and anti-analysis checks.
    """

    event: Literal[EventType.REG_READ_VALUE] = Field(
        default=EventType.REG_READ_VALUE,
        description="Discriminator for registry value read events.",
    )
    path: str = Field(description="Registry key path containing the queried value.")
    handle: HexIntOptional = Field(default=None, description="Registry key handle used for the read, when available.")
    value_name: str | None = Field(default=None, description="Registry value name requested by the API call.")
    size: int | None = Field(default=None, description="Requested/returned value size in bytes.")
    data_ref: str | None = Field(
        default=None,
        description="Reference into the top-level report ``data`` store for the captured registry value bytes.",
    )
    buffer: HexIntOptional = Field(default=None, description="Destination buffer pointer.")


class RegWriteValueEvent(Event):
    """
    Records registry value write operations.

    Emitted when APIs set or overwrite a registry value.

    Use this to capture persistence and configuration mutations.
    """

    event: Literal[EventType.REG_WRITE_VALUE] = Field(
        default=EventType.REG_WRITE_VALUE,
        description="Discriminator for registry value write events.",
    )
    path: str = Field(description="Registry key path containing the written value.")
    handle: HexIntOptional = Field(default=None, description="Registry key handle used for the write, when available.")
    value_name: str | None = Field(default=None, description="Registry value name written by the API call.")
    size: int | None = Field(default=None, description="Written value size in bytes.")
    data_ref: str | None = Field(
        default=None,
        description="Reference into the top-level report ``data`` store for the written registry value bytes.",
    )
    buffer: HexIntOptional = Field(default=None, description="Source buffer pointer.")


class RegListSubkeysEvent(Event):
    """
    Records enumeration of registry subkeys.

    Emitted when APIs list child keys beneath a registry path.

    Helps reveal discovery behavior for installed software and services.
    """

    event: Literal[EventType.REG_LIST_SUBKEYS] = Field(
        default=EventType.REG_LIST_SUBKEYS,
        description="Discriminator for registry subkey enumeration events.",
    )
    path: str = Field(description="Registry key path being enumerated.")
    handle: HexIntOptional = Field(default=None, description="Registry handle used for enumeration, when available.")


class RegDeleteKeyEvent(Event):
    """
    Records registry key deletion.

    Emitted when registry APIs delete a key.

    Use this to track persistence cleanup and anti-forensics behavior.
    """

    event: Literal[EventType.REG_DELETE_KEY] = Field(
        default=EventType.REG_DELETE_KEY,
        description="Discriminator for registry key delete events.",
    )
    path: str = Field(description="Registry key path targeted by the delete operation.")
    handle: HexIntOptional = Field(default=None, description="Registry handle used for the delete, when available.")


class RegDeleteValueEvent(Event):
    """
    Records registry value deletion.

    Emitted when registry APIs delete a value from a key.

    Use this to track persistence cleanup and anti-forensics behavior.
    """

    event: Literal[EventType.REG_DELETE_VALUE] = Field(
        default=EventType.REG_DELETE_VALUE,
        description="Discriminator for registry value delete events.",
    )
    path: str = Field(description="Registry key path containing the deleted value.")
    handle: HexIntOptional = Field(default=None, description="Registry key handle used for the delete, when available.")
    value_name: str | None = Field(default=None, description="Registry value name deleted by the API call.")


class NetDnsEvent(Event):
    """
    Records DNS name resolution activity.

    Emitted when DNS APIs request host resolution or related lookups.

    Use for C2 endpoint discovery and fallback behavior analysis.
    """

    event: Literal[EventType.NET_DNS] = Field(default=EventType.NET_DNS, description="Discriminator for DNS events.")
    query: str = Field(description="Queried domain or hostname.")
    response: str | None = Field(
        default=None,
        description="Resolved IP response, when a mapping was available.",
    )


class NetTrafficEvent(Event):
    """
    Records non-HTTP network traffic and socket-level activity.

    Emitted for connect/bind/send/recv style network events.

    Use this for protocol flow reconstruction outside HTTP abstractions.
    """

    event: Literal[EventType.NET_TRAFFIC] = Field(
        default=EventType.NET_TRAFFIC, description="Discriminator for socket traffic events."
    )
    server: str = Field(description="Remote endpoint hostname or IP address.")
    port: int = Field(description="Remote endpoint port number.")
    proto: str = Field(description="Protocol label such as tcp/udp variants.")
    type: str | None = Field(default=None, description="Traffic subtype (connect, bind, data_in, data_out, etc.).")
    data_ref: str | None = Field(
        default=None,
        description="Reference into the top-level report ``data`` store for the captured traffic payload bytes.",
    )
    method: str | None = Field(default=None, description="Source API path or method that produced the event.")


class NetHttpEvent(Event):
    """
    Records HTTP request telemetry.

    Emitted by WinInet/WinHTTP handlers when requests are issued.

    Use these records to inspect request metadata and transmitted body content.
    """

    event: Literal[EventType.NET_HTTP] = Field(default=EventType.NET_HTTP, description="Discriminator for HTTP events.")
    server: str = Field(description="HTTP server hostname or address.")
    port: int = Field(description="HTTP server port.")
    proto: str = Field(description="Transport/protocol label, e.g. tcp.http or tcp.https.")
    headers: str | None = Field(default=None, description="Serialized HTTP request headers, when available.")
    body_ref: str | None = Field(
        default=None,
        description="Reference into the top-level report ``data`` store for the captured HTTP body bytes.",
    )


class ExceptionEvent(Event):
    """
    Records handled exception dispatch activity.

    Emitted when exception handling telemetry is captured during execution.

    Use this to understand exception-driven control flow and anti-analysis logic.
    """

    event: Literal[EventType.EXCEPTION] = Field(
        default=EventType.EXCEPTION, description="Discriminator for exception events."
    )
    instr: str = Field(description="Instruction text associated with the exception.")
    exception_code: str = Field(description="Exception code in hexadecimal string form.")
    handler_address: str = Field(description="Address of the selected exception handler.")
    registers: dict[str, str] = Field(description="Register snapshot captured at exception time.")
    faulting_address: str | None = Field(default=None, description="Address that caused the fault, if applicable.")
    pc_module: str | None = Field(default=None, description="Module name + offset containing the faulting PC.")
    stack_trace: list[str] | None = Field(default=None, description="Stack trace at exception time.")


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
