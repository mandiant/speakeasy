from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from speakeasy.profiler_events import AnyEvent, StackEntry, TracePosition
from speakeasy.report_types import HexInt, HexIntOptional

REPORT_VERSION = "7.0.0"


class StringCollection(BaseModel):
    """ANSI and UTF-16 strings from one source."""

    model_config = ConfigDict(extra="forbid")

    ansi: list[str] = Field(
        default_factory=list,
        description="ASCII strings.",
    )
    unicode: list[str] = Field(
        default_factory=list,
        description="UTF-16LE strings.",
    )


class StringsReport(BaseModel):
    """Strings of the input file, and strings that the guest made in memory."""

    model_config = ConfigDict(extra="forbid")

    static: StringCollection = Field(
        default_factory=StringCollection,
        description="Strings in the data of the input file.",
    )
    in_memory: StringCollection = Field(
        default_factory=StringCollection,
        description=(
            "Strings at the end of the emulation that are not in ``static``. Speakeasy reads the stack, the "
            "memory that API handlers allocate, and the images of the guest modules. In an image, it reads only "
            "the strings that the guest changed after the load. These strings often are decoded data."
        ),
    )


class RegionInfo(BaseModel):
    """
    One memory region: an allocation of the memory manager, or one part of a module image.

    The emulator splits the image of a module into one region for the headers and one region
    for each section. Each part has the tag ``emu.module``, and ``module`` and ``section`` give
    the image and the part.
    """

    model_config = ConfigDict(extra="forbid")

    base: HexInt = Field(description="Base address of the region.")
    size: int = Field(description="Size of the region in bytes.")
    perms: str = Field(
        description=(
            "Permissions, such as ``r-x`` or ``rw-``. For a part of a module image, the permissions from the "
            "section header, and ``r--`` for the headers."
        )
    )
    tag: str | None = Field(
        default=None,
        description=(
            "Tag of the memory manager, such as ``api.VirtualAlloc``, ``api.heap.HeapAlloc`` or ``emu.stack``. "
            "``emu.module`` for a part of a module image. Absent when the region has no tag."
        ),
    )
    module: str | None = Field(
        default=None,
        description=(
            "File name of the module, such as ``sample.exe`` or ``kernel32.dll``, the same as "
            "``memory.modules[].name``. Only for a part of a module image."
        ),
    )
    section: str | None = Field(
        default=None,
        description=(
            "Name of the section, such as ``.text``, or ``headers`` for the PE headers. Absent for a region that is "
            "not part of a module image, for a module image with no sections, and for an address in a module image "
            "that is outside the headers and the sections. In the last two cases, the region is the full image."
        ),
    )


class ErrorType(str, Enum):
    """Reason why a run or the emulation ended with an error."""

    PER_RUN_TIME_LIMIT = "per_run_time_limit"
    TOTAL_TIME_LIMIT = "total_time_limit"
    INSTRUCTION_LIMIT = "instruction_limit"
    API_CALL_LIMIT = "api_call_limit"
    API_LOOP_LIMIT = "api_loop_limit"
    UNSUPPORTED_API = "unsupported_api"
    INTERNAL_ERROR = "internal_error"
    ENGINE_STOPPED = "engine_stopped"
    INVALID_IMAGE = "invalid_image"
    DLL_INITIALIZATION_FAILED = "dll_initialization_failed"
    API_HANDLER_DID_NOT_RETURN = "api_handler_did_not_return"
    INVALID_READ = "invalid_read"
    INVALID_WRITE = "invalid_write"
    INVALID_FETCH = "invalid_fetch"
    INVALID_PROTECT_READ = "invalid_protect_read"
    INVALID_PROTECT_WRITE = "invalid_protect_write"
    INVALID_PROTECT_FETCH = "invalid_protect_fetch"
    GUARD_PAGE_VIOLATION = "guard_page_violation"
    PRIVILEGED_INSTRUCTION = "privileged_instruction"
    INVALID_INSTRUCTION = "invalid_instruction"
    UNSUPPORTED_CPU_FEATURE = "unsupported_cpu_feature"
    UNHANDLED_INTERRUPT = "unhandled_interrupt"
    UNHANDLED_EXCEPTION = "unhandled_exception"
    HARDWARE_BREAKPOINT = "hardware_breakpoint"
    BUG_CHECK = "bug_check"


class AccessType(str, Enum):
    """Kind of memory access that faulted."""

    READ = "read"
    WRITE = "write"
    FETCH = "fetch"


class ApiLoopSite(BaseModel):
    """One call site of an API loop."""

    model_config = ConfigDict(extra="forbid")

    api_name: str = Field(description="Name of the API in ``module.function`` form.")
    return_address: HexIntOptional = Field(default=None, description="Return address of the calls from this site.")
    calls: int = Field(description="Number of calls from this site in the loop.")


class ApiLoop(BaseModel):
    """
    The API calls of a run after its last call from a new call site.

    A call site is an API and a return address.
    """

    model_config = ConfigDict(extra="forbid")

    start: TracePosition = Field(description="Position of the first API call of the loop.")
    calls: int = Field(description="Number of API calls in the loop.")
    sites: list[ApiLoopSite] = Field(
        description="Call sites of the loop, the site with the most calls first. At most 16 sites."
    )


class ErrorInfo(BaseModel):
    """
    Why a run, or the emulation, ended with an error.

    The emulator fills only the fields that apply to the error ``type``.
    """

    model_config = ConfigDict(extra="forbid")

    type: ErrorType = Field(
        description=(
            "Kind of error, such as ``unsupported_api``, ``api_call_limit``, ``api_loop_limit`` or ``invalid_read``. "
            "A Python exception in Speakeasy itself, such as a bug in an API handler, is ``internal_error``."
        )
    )
    pc: HexIntOptional = Field(
        default=None,
        description="Address of the instruction that caused the error. For ``unsupported_api``, the return address.",
    )
    instruction: str | None = Field(
        default=None,
        description="Disassembly of the instruction at ``pc``.",
    )
    address: HexIntOptional = Field(
        default=None,
        description="Memory address that the faulting access used.",
    )
    access_type: AccessType | None = Field(
        default=None,
        description="Kind of the faulting access: read, write or fetch.",
    )
    registers: dict[str, HexInt] | None = Field(
        default=None,
        description="Register values at the time of the error.",
    )
    stack: list[StackEntry] | None = Field(
        default=None,
        description="Stack slots at the time of the error, from the stack pointer up.",
    )
    pc_module: str | None = Field(
        default=None,
        description=(
            "File name of the module that contains the faulting PC, for example ``sample.exe``. The same as "
            "``memory.modules[].name``."
        ),
    )
    pc_offset: int | None = Field(
        default=None,
        description="Offset of the faulting PC from the base of ``pc_module``.",
    )
    address_region: RegionInfo | None = Field(
        default=None,
        description="Memory region that contains ``address``. Absent when ``address`` is not mapped.",
    )
    nearby_regions: list[RegionInfo] | None = Field(
        default=None,
        description="The memory regions nearest to ``address`` when ``address`` is not mapped.",
    )
    tid: int | None = Field(default=None, description="Thread ID at the time of the error.")
    pid: int | None = Field(default=None, description="Process ID at the time of the error.")
    context_summary: str | None = Field(
        default=None,
        description="One line of text that tells what went wrong.",
    )
    traceback: str | None = Field(
        default=None,
        description="Python traceback of an ``internal_error``.",
    )
    message: str | None = Field(
        default=None,
        description="Text of the Python exception of an ``internal_error``.",
    )
    api_name: str | None = Field(
        default=None,
        description="Name of the API that has no handler, for ``unsupported_api``.",
    )
    count: int | None = Field(
        default=None,
        description=(
            "Limit that ended the run: ``limits.api_calls`` of the config for ``api_call_limit``, "
            "``limits.api_loop_calls`` for ``api_loop_limit``, or ``limits.instructions`` for ``instruction_limit``."
        ),
    )
    last_api: str | None = Field(
        default=None,
        description=(
            "Name of the API of the last call before the run ended, for ``api_call_limit`` and ``api_loop_limit``."
        ),
    )
    loop: ApiLoop | None = Field(
        default=None,
        description="The API loop that ended the run, for ``api_loop_limit``.",
    )
    interrupt_num: int | None = Field(
        default=None,
        description="Interrupt number, for ``unhandled_interrupt``.",
    )


class RegionAccesses(BaseModel):
    """Read, write and execute counts of one memory region in one run."""

    model_config = ConfigDict(extra="forbid")

    region: HexInt = Field(
        description=(
            "Base of the region, as in ``memory.layout``: for a module image, the base of its headers or section. "
            "An access in a module image outside the headers and the sections counts for the headers."
        )
    )
    reads: int = Field(description="Number of reads in the region.")
    writes: int = Field(description="Number of writes in the region.")
    execs: int = Field(description="Number of instructions that ran in the region.")


class SymbolAccesses(BaseModel):
    """Read, write and execute counts of one symbol address in one run."""

    model_config = ConfigDict(extra="forbid")

    symbol: str = Field(description="Symbol name in ``module.symbol`` form.")
    reads: int = Field(description="Number of reads that start at the symbol address.")
    writes: int = Field(description="Number of writes that start at the symbol address.")
    execs: int = Field(description="Number of instructions that ran at the symbol address.")


class MemoryAccesses(BaseModel):
    """Read, write and execute counts of the memory regions and the symbols that a run used."""

    model_config = ConfigDict(extra="forbid")

    regions: list[RegionAccesses] = Field(
        default_factory=list,
        description="Counts of each region that the run read, wrote or ran code in, in the order of ``region``.",
    )
    symbols: list[SymbolAccesses] = Field(
        default_factory=list,
        description=(
            "Counts of each symbol address that the run read, wrote or ran code at, in the order of the address. "
            "Only an access at the exact address of the symbol counts."
        ),
    )


class DynamicCodeContents(BaseModel):
    """The position and the data of a dynamic code region when code ran in it."""

    model_config = ConfigDict(extra="forbid")

    pos: TracePosition = Field(
        description=(
            "Position when the emulator found code that ran in the region: the first time, or for a later"
            " snapshot, the first block in the region after the change. ``pc`` is in the region."
        )
    )
    data_ref: str | None = Field(
        default=None,
        description=(
            "Key in the top-level ``data`` of the region data at ``pos``. Each snapshot of a region has different"
            " data from the snapshot before it. Absent when ``memory.dynamic_code_contents`` is off."
        ),
    )


class DynamicCodeRegion(BaseModel):
    """
    A dynamic code region where code ran.

    The emulator watches the memory that the guest allocates, for example with ``VirtualAlloc``, and
    adds a region when the guest runs code in the region. With ``memory.dynamic_code_contents``, the
    emulator adds one more snapshot to ``contents`` each time that code runs in the region after the
    region changed, and control came from outside the region.
    """

    model_config = ConfigDict(extra="forbid")

    region: HexInt = Field(description="Base address of the region, as in ``memory.layout``.")
    size: int = Field(description="Size of the region in bytes.")
    tag: str | None = Field(
        default=None,
        description=("Tag of the memory manager, such as ``api.VirtualAlloc``. Absent when the region has no tag."),
    )
    contents: list[DynamicCodeContents] = Field(
        description=(
            "With ``memory.dynamic_code_contents``, one snapshot for each time that code ran in the region with"
            " new data, in the order of ``pos.tick``. With the option off, one entry with the ``pos`` of the first"
            " time that code ran in the region."
        )
    )
    limit_reached: bool | None = Field(
        default=None,
        description=(
            "True if the region changed and code ran in it again after the last snapshot that"
            " ``memory.dynamic_code_contents.limit`` allows. Absent when ``memory.dynamic_code_contents`` is off."
        ),
    )


class ArtifactCompression(str, Enum):
    """Compression of a stored payload."""

    ZLIB = "zlib"


class ArtifactEncoding(str, Enum):
    """Text encoding of a stored payload."""

    BASE64 = "base64"


class DataArtifact(BaseModel):
    """
    One payload of the report.

    The top-level ``data`` of the report keys each payload by the SHA-256 of its bytes. A ``data_ref``
    field elsewhere in the report holds such a key.
    """

    model_config = ConfigDict(extra="forbid")

    compression: ArtifactCompression = Field(description="Compression of the payload.")
    encoding: ArtifactEncoding = Field(description="Text encoding of the compressed payload.")
    size: int = Field(description="Size of the payload before compression, in bytes.")
    data: str = Field(description="Payload, compressed and then encoded.")


class DroppedFile(BaseModel):
    """A file that the guest wrote completely, up to the end of the run."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(description="Emulated path of the file.")
    size: int = Field(description="Size of the file in bytes.")
    sha256: str = Field(description="SHA-256 of the file data.")
    data_ref: str | None = Field(
        default=None,
        description=(
            "Key in the top-level ``data`` of the file data. It is equal to ``sha256``. Absent for an empty file"
            " and for a file above ``MAX_EMBEDDED_FILE_SIZE`` (10 MiB)."
        ),
    )


class MemoryRegion(RegionInfo):
    """
    One memory region at the end of a run.

    The emulator splits the image of a module into one region for the headers and one region
    for each section. Each part has the tag ``emu.module``, and ``module`` and ``section`` give
    the image and the part.
    """

    freed: bool | None = Field(
        default=None,
        description=(
            "True if the guest freed the allocation of the region. Only with ``memory.freed_regions``, which keeps "
            "a freed allocation mapped. With the option off, the emulator unmaps a freed allocation when no other "
            "allocation of its block is live, and keeps it mapped while one is. The layout then leaves out each "
            "freed allocation."
        ),
    )
    data_ref: str | None = Field(
        default=None,
        description=(
            "Key in the top-level ``data`` of the region data: the images of the modules that load from a file, "
            "such as the input, the allocations and heaps of the guest (``api.*`` tags), the regions with no tag "
            "that API handlers allocate for the guest, and the static TLS data (``emu.tls.*`` tags). Absent when "
            "``memory.final_contents`` is off, for the stacks, for the memory of the emulator (the stub images of "
            "system modules and the other ``emu.*`` tags), and when the emulator cannot read the region."
        ),
    )


class LoadedModule(BaseModel):
    """A module that is loaded at the end of a run."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        description="File name of the module, such as ``sample.exe``. The ``module`` of the regions of its image."
    )
    path: str = Field(description="Emulated path of the module.")
    base: HexInt = Field(description="Base address of the module.")
    size: int = Field(description="Size of the module image in bytes.")


class MemoryLayout(BaseModel):
    """Memory regions and loaded modules at the end of a run."""

    model_config = ConfigDict(extra="forbid")

    layout: list[MemoryRegion] = Field(
        default_factory=list,
        description="Memory regions, with one region for the headers and one for each section of a module image.",
    )
    modules: list[LoadedModule] = Field(
        default_factory=list,
        description="Modules that are loaded at the end of the run.",
    )


class RunType(str, Enum):
    """Kind of code that a run executes."""

    MODULE_ENTRY = "module_entry"
    DLL_ENTRY = "dll_entry"
    TLS_CALLBACK = "tls_callback"
    EXPORT = "export"
    SHELLCODE = "shellcode"
    THREAD = "thread"
    SERVICE_MAIN = "service_main"
    DEPENDENCY_DLL_ENTRY = "dependency_dll_entry"
    DEPENDENCY_TLS_CALLBACK = "dependency_tls_callback"
    CALL = "call"
    DRIVER_ENTRY = "driver_entry"
    DRIVER_UNLOAD = "driver_unload"
    DRIVER_REINIT = "driver_reinit"
    IRP = "irp"


class RunReport(BaseModel):
    """
    One run, and the events and data that the run collected.

    A run starts at one address, such as the module entry point, an export, a TLS callback or a
    thread.
    """

    model_config = ConfigDict(extra="forbid")

    type: RunType = Field(
        description="Kind of code that the run executes, such as ``module_entry``, ``export`` or ``thread``."
    )
    name: str | None = Field(
        default=None,
        description=(
            "Detail for ``type``, such as the export name, the TLS callback index, the dependency module or "
            "the IRP major function. Absent when the type has no detail."
        ),
    )
    start_address: HexInt = Field(description="Address where the run started.")
    args: list[HexInt] = Field(
        default_factory=list,
        description="Arguments that the emulator gives to the code at ``start_address``.",
    )
    pid: int | None = Field(
        default=None,
        description="ID of the process of the run.",
    )
    tid: int | None = Field(
        default=None,
        description="ID of the thread of the run.",
    )
    instruction_count: int | None = Field(
        default=None,
        description=(
            "Number of instructions that the run executed. The emulator counts them only with ``memory.accesses``, "
            "``memory.dynamic_code_contents`` or a ``limits.instructions`` above 0. Absent when no option counts them."
        ),
    )
    api_call_count: int = Field(
        default=0,
        description=(
            "Number of API calls that the run made, also the calls that ``events`` leaves out as repeats. "
            "``limits.api_calls`` limits this count."
        ),
    )
    api_hash: str = Field(
        default="",
        description=(
            "SHA-256 of the lowercase names of the APIs that the run called, each name once, "
            "in the order of the first call."
        ),
    )
    return_value: HexIntOptional = Field(
        default=None,
        description="Value of the return register when the run completed.",
    )
    error: ErrorInfo | None = Field(
        default=None,
        description="Error that ended the run. Absent when the run completed.",
    )
    events: list[AnyEvent] = Field(
        default_factory=list,
        description="Events of the run, in order.",
    )
    accesses: MemoryAccesses | None = Field(
        default=None,
        description="Read, write and execute counts of the regions and the symbols. Only with ``memory.accesses``.",
    )
    dynamic_code: list[DynamicCodeRegion] = Field(
        default_factory=list,
        description=(
            "Dynamic code regions where code ran in the run, one entry for each region, in the order of the"
            " first time that code ran in the region."
        ),
    )
    coverage: list[HexInt] | None = Field(
        default=None,
        description="Sorted addresses of the instructions that ran. Only with ``code.coverage``.",
    )
    dropped_files: list[DroppedFile] | None = Field(
        default=None,
        description="Files that the guest wrote completely, up to the end of the run. User mode only.",
    )
    memory: MemoryLayout | None = Field(
        default=None,
        description="Memory regions and modules at the end of the run. User mode only.",
    )


class ProcessInfo(BaseModel):
    """
    One process that the report refers to.

    The report has an entry for the process of each run, for each process that the guest created,
    and for each process that is the target of an event, such as a process that existed before the
    emulation.
    """

    model_config = ConfigDict(extra="forbid")

    pid: int = Field(description="Process ID, the same as the ``pid`` of runs and events.")
    parent_pid: int | None = Field(
        default=None,
        description=(
            "ID of the process that created this process, the ``pos.pid`` of its ``process_create`` event. "
            "Absent for the first process and for a process that existed before the emulation."
        ),
    )
    path: str | None = Field(
        default=None,
        description=(
            "Emulated path of the process image, such as ``C:\\Windows\\explorer.exe``. "
            "Absent when the process has no image path."
        ),
    )
    command_line: str | None = Field(
        default=None,
        description=(
            "Command line of the process. Absent when the emulator has no command line for the process: for a "
            "process that existed before the emulation, and for a process that the guest created with no command "
            "line, such as ``CreateProcess`` with a NULL ``lpCommandLine``."
        ),
    )
    runs: list[int] = Field(
        default_factory=list,
        description="Indexes in ``runs`` of the runs of the process. Empty when no run executed in the process.",
    )


class Arch(str, Enum):
    """Architecture of the input."""

    X86 = "x86"
    X64 = "x64"


class FileType(str, Enum):
    """Kind of input file."""

    EXE = "exe"
    DLL = "dll"
    DRIVER = "driver"
    SHELLCODE = "shellcode"


class Report(BaseModel):
    """
    Report of one emulation: the input metadata, the runs and the payloads.

    Machine words are ``0x``-prefixed hex strings: addresses, pointers,
    handles, raw argument values, return values, register values and exception
    codes. A 64-bit word can be above 2**53 or 2**63, and JavaScript, Go
    ``interface{}``, jq and int64 stores such as SQLite lose such a value as a
    JSON number with no error. Quantities, such as sizes, counts, offsets,
    ticks and IDs, are JSON numbers.

    A key is absent when Speakeasy did not collect its data: its option is off,
    or the data does not apply, such as the memory layout in kernel mode. An
    empty list or object means that Speakeasy collected the data and found
    nothing. A counter or a boolean is always present when Speakeasy collects
    it, also when it is 0 or false.
    """

    model_config = ConfigDict(extra="forbid")

    report_version: str = Field(
        default=REPORT_VERSION,
        description="Version of the report format.",
    )
    emulation_total_runtime: float = Field(
        description=(
            "Wall-clock time in seconds, rounded to milliseconds, from the first start of the run queue "
            "to the end of the emulation."
        )
    )
    timestamp: int = Field(description="Unix time in seconds of the first start of the run queue.")
    arch: Arch | None = Field(
        default=None,
        description="Architecture of the input.",
    )
    path: str | None = Field(
        default=None,
        description="Host path of the input file. Absent when the input came from bytes.",
    )
    sha256: str | None = Field(
        default=None,
        description="SHA-256 of the input.",
    )
    size: int | None = Field(
        default=None,
        description="Size of the input in bytes.",
    )
    file_type: FileType | None = Field(
        default=None,
        description="Kind of input file.",
    )
    image_base: HexIntOptional = Field(
        default=None,
        description=(
            "Base address of the input image in the emulator. Rebase a disassembler database to this "
            "address to match the addresses of the report."
        ),
    )
    errors: list[ErrorInfo] = Field(
        default_factory=list,
        description="Errors that do not belong to one run, such as an ``invalid_image`` defect of the input PE.",
    )
    strings: StringsReport | None = Field(
        default=None,
        description="Strings of the input and of memory. Only with ``memory.strings``.",
    )
    data: dict[str, DataArtifact] = Field(
        default_factory=dict,
        description="Payloads of the report, keyed by SHA-256. Each ``data_ref`` field holds a key of this mapping.",
    )
    processes: list[ProcessInfo] = Field(
        default_factory=list,
        description=(
            "Processes of the runs and of the events, in the order of ``pid``. A kernel-mode run has no process, "
            "so in kernel mode the list has only the targets of process and memory events."
        ),
    )
    runs: list[RunReport] = Field(
        default_factory=list,
        description="Runs of the emulation, in the order that the runs started.",
    )


class FileManifestEntry(BaseModel):
    """One file in ``speakeasy_manifest.json`` of the dropped-files archive."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(description="Emulated path of the file.")
    file_name: str = Field(description="Name of the zip member that has the file data.")
    size: int = Field(description="Size of the file in bytes.")
    sha256: str = Field(description="SHA-256 of the file data.")
