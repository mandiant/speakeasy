from typing import Annotated, Literal

from pydantic import BaseModel, Discriminator, Field


class TracePosition(BaseModel):
    """Locates where an event occurred in execution time and context.

    Every emitted event carries this structure so consumers can reconstruct
    chronology and thread/process ownership.

    Use ``tick`` ordering for timeline reconstruction and ``pc`` for direct
    disassembly alignment.
    """

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
    pc: int | None = Field(
        default=None,
        description=(
            "Program counter at event emission time, when available.\n\n"
            "Some synthetic events may omit this if no precise PC context exists."
        ),
    )


class Event(BaseModel):
    """Base class shared by all report event records.

    Concrete event types extend this with event-specific payload fields.

    Consumers should discriminate event payloads using the ``event`` field.
    """

    pos: TracePosition = Field(
        description=(
            "Execution position metadata for this event.\n\n"
            "Used to align event payloads with timeline and execution context."
        )
    )
    event: str = Field(description=("Event type discriminator.\n\nDetermines which concrete payload schema applies."))


class ApiEvent(Event):
    """Records one intercepted API invocation.

    API events are emitted by import-call handlers and represent core behavioral
    telemetry for most runs.

    Use these entries to understand control flow and argument-level intent.
    """

    event: Literal["api"] = Field(default="api", description="Discriminator for API call events.")
    api_name: str = Field(
        description=(
            "Resolved API name in ``module.function`` form.\n\n"
            "Used for behavior signatures, clustering, and family comparison."
        )
    )
    args: list[str] = Field(
        description=(
            "Formatted argument values captured for the call.\n\n"
            "Integers are typically represented in hexadecimal string form."
        )
    )
    ret_val: str | None = Field(
        default=None,
        description=(
            "Formatted return value for the API call, when available.\n\n"
            "Use this to identify failure codes and branch-driving outcomes."
        ),
    )


class ProcessCreateEvent(Event):
    """Records creation of a child process context.

    Emitted when process-creation APIs are invoked and accepted by emulation.

    These events indicate lateral execution or staged payload spawning.
    """

    event: Literal["process_create"] = Field(
        default="process_create",
        description="Discriminator for process creation events.",
    )
    path: str = Field(
        description=(
            "Target process image path.\n\nRepresents the emulated executable location requested by the sample."
        )
    )
    cmdline: str = Field(
        description=(
            "Command line used for process creation.\n\nUse this to recover execution parameters and staged arguments."
        )
    )


class MemAllocEvent(Event):
    """Records remote or explicit process memory allocation activity.

    Emitted by memory allocation APIs that target process virtual memory.

    Commonly seen in injection and unpacking workflows.
    """

    event: Literal["mem_alloc"] = Field(default="mem_alloc", description="Discriminator for memory allocation events.")
    path: str = Field(description="Target process path associated with the allocation event.")
    base: str = Field(description="Allocated base address in hexadecimal string form.")
    size: str = Field(description="Allocation size in hexadecimal string form.")
    protect: str | None = Field(
        default=None,
        description="Requested memory protection flags, when provided by the API path.",
    )


class MemWriteEvent(Event):
    """Records writes into process memory.

    Emitted for API-mediated memory writes and may merge adjacent writes in the
    profiler for compactness.

    Use with thread/process events to identify code injection flows.
    """

    event: Literal["mem_write"] = Field(default="mem_write", description="Discriminator for memory write events.")
    path: str = Field(description="Target process path associated with the write event.")
    base: str = Field(description="Write start address in hexadecimal string form.")
    size: int = Field(description="Number of bytes written.")
    data: str = Field(
        description=(
            "Base64-encoded written bytes.\n\nLarge sequences may be truncated or chunk-merged by profiler logic."
        )
    )


class MemReadEvent(Event):
    """Records reads from process memory.

    Emitted for API-mediated memory reads and may merge adjacent reads in the
    profiler for compactness.

    Useful for identifying memory scraping or credential theft behavior.
    """

    event: Literal["mem_read"] = Field(default="mem_read", description="Discriminator for memory read events.")
    path: str = Field(description="Target process path associated with the read event.")
    base: str = Field(description="Read start address in hexadecimal string form.")
    size: int = Field(description="Number of bytes read.")
    data: str = Field(description=("Base64-encoded read bytes.\n\nDecode to inspect sampled process memory content."))


class MemProtectEvent(Event):
    """Records memory protection changes.

    Emitted for API paths that alter page permissions in process memory.

    This is a key indicator for RWX transitions and shellcode staging.
    """

    event: Literal["mem_protect"] = Field(
        default="mem_protect",
        description="Discriminator for memory protection change events.",
    )
    path: str = Field(description="Target process path associated with the protection change.")
    base: str = Field(description="Protection-change base address in hexadecimal string form.")
    size: str = Field(description="Protection-change size in hexadecimal string form.")
    protect: str | None = Field(
        default=None,
        description="New protection value requested by the API call.",
    )


class MemFreeEvent(Event):
    """Records memory free/decommit operations.

    Emitted when memory free APIs are invoked against process regions.

    Use this to track lifecycle of allocation artifacts.
    """

    event: Literal["mem_free"] = Field(default="mem_free", description="Discriminator for memory free events.")
    path: str = Field(description="Target process path associated with the free event.")
    base: str = Field(description="Freed region base address in hexadecimal string form.")
    size: str = Field(description="Freed region size in hexadecimal string form.")


class ModuleLoadEvent(Event):
    """Records dynamic module loading activity.

    Emitted when module load operations map additional images during runtime.

    Useful for dependency discovery and staged import behavior.
    """

    event: Literal["module_load"] = Field(default="module_load", description="Discriminator for module load events.")
    name: str = Field(description="Loaded module name.")
    path: str = Field(description="Loaded module path in emulated filesystem space.")
    base: str = Field(description="Module base address in hexadecimal string form.")
    size: str = Field(description="Mapped module size in hexadecimal string form.")


class ThreadCreateEvent(Event):
    """Records thread creation in a process context.

    Emitted for thread creation APIs and often accompanies process injection
    workflows.

    Combine with memory-write and start-address analysis for attribution.
    """

    event: Literal["thread_create"] = Field(
        default="thread_create",
        description="Discriminator for thread creation events.",
    )
    path: str = Field(description="Target process path where the thread is created.")
    start_addr: str = Field(description="Thread start address in hexadecimal string form.")
    param: str = Field(description="Thread parameter pointer/value in hexadecimal string form.")


class ThreadInjectEvent(Event):
    """Records thread injection activity into another process.

    Emitted for injection-oriented thread APIs.

    Treat these as high-signal indicators of code injection behavior.
    """

    event: Literal["thread_inject"] = Field(
        default="thread_inject",
        description="Discriminator for thread injection events.",
    )
    path: str = Field(description="Target process path receiving the injected thread.")
    start_addr: str = Field(description="Injected thread start address in hexadecimal string form.")
    param: str = Field(description="Injected thread parameter in hexadecimal string form.")


class FileCreateEvent(Event):
    """Records file creation/open-with-create semantics.

    Emitted when file APIs request creation semantics for a path.

    Use with follow-up write events to track dropped artifacts.
    """

    event: Literal["file_create"] = Field(default="file_create", description="Discriminator for file create events.")
    path: str = Field(description="File path targeted by creation request.")
    handle: str | None = Field(default=None, description="Assigned file handle, when available.")
    open_flags: list[str] | None = Field(
        default=None,
        description="Creation/open disposition flags supplied by the API call.",
    )
    access_flags: list[str] | None = Field(
        default=None,
        description="Requested access rights for the file operation.",
    )


class FileOpenEvent(Event):
    """Records file open operations without explicit create intent.

    Emitted for open-style file API calls.

    Use to reconstruct file-read dependency chains.
    """

    event: Literal["file_open"] = Field(default="file_open", description="Discriminator for file open events.")
    path: str = Field(description="File path targeted by open request.")
    handle: str | None = Field(default=None, description="Assigned file handle, when available.")
    open_flags: list[str] | None = Field(
        default=None,
        description="Open disposition flags supplied by the API call.",
    )
    access_flags: list[str] | None = Field(
        default=None,
        description="Requested access rights for the file operation.",
    )


class FileReadEvent(Event):
    """Records reads from a file handle.

    Emitted when file-read APIs pull bytes from emulated files.

    Useful for identifying configuration ingestion and payload loading.
    """

    event: Literal["file_read"] = Field(default="file_read", description="Discriminator for file read events.")
    path: str = Field(description="File path associated with the read operation.")
    handle: str | None = Field(default=None, description="File handle used by the read operation.")
    size: int | None = Field(default=None, description="Number of bytes requested/read.")
    data: str | None = Field(
        default=None,
        description="Base64-encoded file bytes captured from the read operation.",
    )
    buffer: str | None = Field(
        default=None,
        description="Destination buffer pointer in hexadecimal string form.",
    )


class FileWriteEvent(Event):
    """Records writes to a file handle.

    Emitted when file-write APIs append or overwrite emulated file data.

    Combine with dropped-file summaries to recover persisted payloads.
    """

    event: Literal["file_write"] = Field(default="file_write", description="Discriminator for file write events.")
    path: str = Field(description="File path associated with the write operation.")
    handle: str | None = Field(default=None, description="File handle used by the write operation.")
    size: int | None = Field(default=None, description="Number of bytes written.")
    data: str | None = Field(
        default=None,
        description="Base64-encoded bytes captured from the write operation.",
    )
    buffer: str | None = Field(
        default=None,
        description="Source buffer pointer in hexadecimal string form.",
    )


class RegOpenKeyEvent(Event):
    """Records registry key open operations.

    Emitted when registry APIs open existing keys.

    Use these to identify configuration and persistence probing paths.
    """

    event: Literal["reg_open_key"] = Field(
        default="reg_open_key",
        description="Discriminator for registry key open events.",
    )
    path: str = Field(description="Registry key path targeted by the open operation.")
    handle: str | None = Field(default=None, description="Registry handle returned for the key, when available.")
    open_flags: list[str] | None = Field(
        default=None,
        description="Open/disposition flags associated with the operation.",
    )
    access_flags: list[str] | None = Field(
        default=None,
        description="Requested registry access rights.",
    )


class RegCreateKeyEvent(Event):
    """Records registry key creation operations.

    Emitted when registry APIs create new keys.

    Strong signal for persistence and installation behavior.
    """

    event: Literal["reg_create_key"] = Field(
        default="reg_create_key",
        description="Discriminator for registry key create events.",
    )
    path: str = Field(description="Registry key path targeted by the create operation.")
    handle: str | None = Field(default=None, description="Registry handle returned for the key, when available.")
    open_flags: list[str] | None = Field(
        default=None,
        description="Create/open disposition flags associated with the operation.",
    )
    access_flags: list[str] | None = Field(
        default=None,
        description="Requested registry access rights.",
    )


class RegReadValueEvent(Event):
    """Records registry value read operations.

    Emitted when value-query APIs request data from a key.

    Use this to identify configuration keys and anti-analysis checks.
    """

    event: Literal["reg_read_value"] = Field(
        default="reg_read_value",
        description="Discriminator for registry value read events.",
    )
    path: str = Field(description="Registry key path containing the queried value.")
    handle: str | None = Field(default=None, description="Registry key handle used for the read, when available.")
    value_name: str | None = Field(default=None, description="Registry value name requested by the API call.")
    size: int | None = Field(default=None, description="Requested/returned value size in bytes.")
    data: str | None = Field(default=None, description="Base64-encoded value data captured by the profiler.")
    buffer: str | None = Field(default=None, description="Destination buffer pointer in hexadecimal string form.")


class RegListSubkeysEvent(Event):
    """Records enumeration of registry subkeys.

    Emitted when APIs list child keys beneath a registry path.

    Helps reveal discovery behavior for installed software and services.
    """

    event: Literal["reg_list_subkeys"] = Field(
        default="reg_list_subkeys",
        description="Discriminator for registry subkey enumeration events.",
    )
    path: str = Field(description="Registry key path being enumerated.")
    handle: str | None = Field(default=None, description="Registry handle used for enumeration, when available.")


class NetDnsEvent(Event):
    """Records DNS name resolution activity.

    Emitted when DNS APIs request host resolution or related lookups.

    Use for C2 endpoint discovery and fallback behavior analysis.
    """

    event: Literal["net_dns"] = Field(default="net_dns", description="Discriminator for DNS events.")
    query: str = Field(description="Queried domain or hostname.")
    response: str | None = Field(
        default=None,
        description="Resolved IP response, when a mapping was available.",
    )


class NetTrafficEvent(Event):
    """Records non-HTTP network traffic and socket-level activity.

    Emitted for connect/bind/send/recv style network events.

    Use this for protocol flow reconstruction outside HTTP abstractions.
    """

    event: Literal["net_traffic"] = Field(default="net_traffic", description="Discriminator for socket traffic events.")
    server: str = Field(description="Remote endpoint hostname or IP address.")
    port: int = Field(description="Remote endpoint port number.")
    proto: str = Field(description="Protocol label such as tcp/udp variants.")
    type: str | None = Field(default=None, description="Traffic subtype (connect, bind, data_in, data_out, etc.).")
    data: str | None = Field(default=None, description="Base64-encoded payload bytes, when captured.")
    method: str | None = Field(default=None, description="Source API path or method that produced the event.")


class NetHttpEvent(Event):
    """Records HTTP request telemetry.

    Emitted by WinInet/WinHTTP handlers when requests are issued.

    Use these records to inspect request metadata and transmitted body content.
    """

    event: Literal["net_http"] = Field(default="net_http", description="Discriminator for HTTP events.")
    server: str = Field(description="HTTP server hostname or address.")
    port: int = Field(description="HTTP server port.")
    proto: str = Field(description="Transport/protocol label, e.g. tcp.http or tcp.https.")
    headers: str | None = Field(default=None, description="Serialized HTTP request headers, when available.")
    body: str | None = Field(default=None, description="Base64-encoded HTTP body payload, when present.")


class ExceptionEvent(Event):
    """Records handled exception dispatch activity.

    Emitted when exception handling telemetry is captured during execution.

    Use this to understand exception-driven control flow and anti-analysis logic.
    """

    event: Literal["exception"] = Field(default="exception", description="Discriminator for exception events.")
    instr: str = Field(description="Instruction text associated with the exception.")
    exception_code: str = Field(description="Exception code in hexadecimal string form.")
    handler_address: str = Field(description="Address of the selected exception handler.")
    registers: dict[str, str] = Field(description="Register snapshot captured at exception time.")


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
    | RegOpenKeyEvent
    | RegCreateKeyEvent
    | RegReadValueEvent
    | RegListSubkeysEvent
    | NetDnsEvent
    | NetTrafficEvent
    | NetHttpEvent
    | ExceptionEvent,
    Discriminator("event"),
]
