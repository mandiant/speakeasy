from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from speakeasy.profiler_events import AnyEvent
from speakeasy.report_types import HexInt, HexIntOptional

REPORT_VERSION = "6.0.0"


class StringCollection(BaseModel):
    """
    Represents one categorized bucket of extracted strings.

    String extraction runs both on static image bytes and post-emulation memory
    snapshots. This model keeps ANSI and UTF-16 findings separated.

    Compare these lists to identify runtime-decoded strings that were not present
    in the original file bytes.
    """

    model_config = ConfigDict(extra="forbid")

    ansi: list[str] = Field(
        default_factory=list,
        description=(
            "ASCII/ANSI strings extracted for this bucket.\n\n"
            "These are populated by static string scans or memory string extraction "
            "depending on the parent field."
        ),
    )
    unicode: list[str] = Field(
        default_factory=list,
        description=(
            "UTF-16 style strings extracted for this bucket.\n\n"
            "Use these to spot wide-character configuration values and command "
            "artifacts."
        ),
    )


class StringsReport(BaseModel):
    """
    Groups static and in-memory string extraction results.

    Static strings come from the original loaded image, while in-memory strings
    are collected after execution and often include decoded/decrypted content.

    Use this section to quickly triage embedded versus runtime materialized
    indicators.
    """

    model_config = ConfigDict(extra="forbid")

    static: StringCollection = Field(
        default_factory=StringCollection,
        description=(
            "Strings extracted from the initial file image bytes.\n\n"
            "Primarily influenced by the module loader and static string scanner."
        ),
    )
    in_memory: StringCollection = Field(
        default_factory=StringCollection,
        description=(
            "Strings extracted from memory after emulation executes.\n\n"
            "Populated when string analysis is enabled and runtime decoding created "
            "new string material."
        ),
    )


class RegionInfo(BaseModel):
    """Describes a memory region for exception context."""

    model_config = ConfigDict(extra="forbid")

    tag: str = Field(description="Memory-map tag identifying the region.")
    base: HexInt = Field(description="Base address of the region.")
    size: int = Field(description="Region size in bytes.")
    perms: str | None = Field(default=None, description="Permission string (e.g. ``r-x``).")


class ErrorType(str, Enum):
    """Reason why a run or the emulation ended with an error."""

    TIMEOUT = "timeout"
    MAX_TOTAL_TIME = "max_total_time"
    MAX_INSTRUCTIONS = "max_instructions"
    MAX_API_COUNT = "max_api_count"
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
    UNHANDLED_INTERRUPT = "unhandled_interrupt"
    UNHANDLED_EXCEPTION = "unhandled_exception"
    HARDWARE_BREAKPOINT = "hardware_breakpoint"
    BUG_CHECK = "bug_check"


class AccessType(str, Enum):
    """Kind of memory access that faulted."""

    READ = "read"
    WRITE = "write"
    FETCH = "fetch"


class ErrorInfo(BaseModel):
    """
    Captures failure context for top-level or per-entry-point errors.

    Error records can represent unsupported API termination, instruction faults,
    explicit runtime limits, or unhandled exceptions.

    Inspect this structure first when a run exits unexpectedly.
    """

    model_config = ConfigDict(extra="forbid")

    type: ErrorType = Field(
        description=(
            "Error category identifier describing the failure mode.\n\n"
            "Examples include unsupported API paths, max API limits, and fault "
            "conditions raised by emulator hooks. A Python exception in Speakeasy "
            "itself, such as a bug in an API handler, is ``internal_error``."
        )
    )
    pc: HexIntOptional = Field(
        default=None,
        description=(
            "Program counter associated with the error, when available.\n\n"
            "Use this address to align failures with disassembly and event traces."
        ),
    )
    instruction: str | None = Field(
        default=None,
        description=(
            "Faulting instruction text, when known.\n\n"
            "Useful for quickly identifying invalid memory operations or bad control "
            "flow transitions."
        ),
    )
    address: HexIntOptional = Field(
        default=None,
        description="Faulting memory address that triggered the error.",
    )
    access_type: AccessType | None = Field(
        default=None,
        description="Memory access type that faulted: read, write, or fetch.",
    )
    registers: dict[str, HexInt] | None = Field(
        default=None,
        description="Register state snapshot at the time of the error.",
    )
    stack: list[str] | None = Field(
        default=None,
        description="Stack entries captured at the time of the error.",
    )
    pc_module: str | None = Field(
        default=None,
        description="Module name + offset containing the faulting PC (e.g. ``sample.exe+0x1234``).",
    )
    address_region: RegionInfo | None = Field(
        default=None,
        description="Memory region containing the faulting address, if mapped.",
    )
    nearby_regions: list[RegionInfo] | None = Field(
        default=None,
        description="Up to 2 nearest memory regions when the faulting address is unmapped.",
    )
    tid: int | None = Field(default=None, description="Thread ID at the time of the error.")
    pid: int | None = Field(default=None, description="Process ID at the time of the error.")
    context_summary: str | None = Field(
        default=None,
        description="Human-readable one-line triage summary of the error.",
    )
    traceback: str | None = Field(
        default=None,
        description="Python traceback when the error originated from an internal exception.",
    )
    message: str | None = Field(
        default=None,
        description="Text of the Python exception of an ``internal_error``.",
    )
    api_name: str | None = Field(
        default=None,
        description="API function name for unsupported-API errors.",
    )
    count: int | None = Field(
        default=None,
        description="API call count that triggered a max-API-count limit.",
    )
    last_api: str | None = Field(
        default=None,
        description="Last API name invoked before max-API-count termination.",
    )
    interrupt_num: int | None = Field(
        default=None,
        description="Interrupt number for unhandled-interrupt errors.",
    )


class SymAccessReport(BaseModel):
    """
    Summarizes memory accesses to symbol-resolved addresses.

    Symbol access accounting is mainly populated when memory tracing is active
    and the emulator can resolve touched addresses back to known symbols.

    Use these counters to identify import-table walking and export resolution
    behavior.
    """

    model_config = ConfigDict(extra="forbid")

    symbol: str = Field(
        description=(
            "Resolved symbol name in ``module.symbol`` form.\n\n"
            "This identifies the logical target accessed by code during tracing."
        )
    )
    reads: int = Field(
        description=(
            "Number of read accesses observed for this symbol.\n\n"
            "High values often indicate lookup loops or pointer chasing."
        )
    )
    writes: int = Field(
        description=(
            "Number of write accesses observed for this symbol.\n\n"
            "Non-zero writes can indicate tampering or patching behavior."
        )
    )
    execs: int = Field(
        description=(
            "Number of execution accesses observed for this symbol.\n\n"
            "Execution hits often represent direct calls/jumps through symbol-backed "
            "addresses."
        )
    )


class DynamicCodeSegment(BaseModel):
    """
    Describes one dynamically generated code region that executed.

    Dynamic code segments are added when execution reaches memory previously
    registered as dynamic code (for example after VirtualAlloc/WriteProcessMemory
    style paths).

    This section is useful for unpacking and staged payload detection.
    """

    model_config = ConfigDict(extra="forbid")

    tag: str = Field(
        description=(
            "Memory-map tag assigned to the dynamic region.\n\n"
            "Tags help correlate the segment with allocation provenance in traces."
        )
    )
    base: HexInt = Field(
        description=(
            "Base address of the dynamic code region.\n\n"
            "Use this with memory layout data to inspect surrounding mapped content."
        )
    )
    size: int = Field(
        description=(
            "Region size of the dynamic code segment.\n\n"
            "Large regions may indicate unpacked module images or staged blobs."
        )
    )


class ArtifactCompression(str, Enum):
    """Compression of a stored payload."""

    ZLIB = "zlib"


class ArtifactEncoding(str, Enum):
    """Text encoding of a stored payload."""

    BASE64 = "base64"


class DataArtifact(BaseModel):
    """
    Stores one deduplicated binary payload referenced elsewhere in a report.

    Payloads are keyed by SHA-256 in the top-level ``Report.data`` mapping.
    Other models store the SHA-256 key as a reference instead of embedding bytes
    inline repeatedly.
    """

    model_config = ConfigDict(extra="forbid")

    compression: ArtifactCompression = Field(description="Compression algorithm applied to the stored payload.")
    encoding: ArtifactEncoding = Field(description="Text encoding used for serialized payload bytes.")
    size: int = Field(description="Uncompressed payload size in bytes.")
    data: str = Field(description="Encoded payload bytes after compression and serialization.")


class DroppedFile(BaseModel):
    """
    Represents one file artifact written by emulated execution.

    Dropped-file entries are created from filesystem manager state when a run
    completes and fully written files are detected.

    Use these records to recover secondary payloads and configuration artifacts.
    """

    model_config = ConfigDict(extra="forbid")

    path: str = Field(
        description=(
            "Emulated destination path of the written file.\n\n"
            "Interpret this as the malware-intended filesystem location."
        )
    )
    size: int = Field(description="Dropped file size in bytes.")
    sha256: str = Field(
        description=(
            "SHA-256 hash of the dropped file bytes.\n\nUse this for sample correlation and deduplication workflows."
        )
    )
    data_ref: str | None = Field(
        default=None,
        description=(
            "Optional reference into the top-level report ``data`` store.\n\n"
            "When present, resolve this SHA-256 key in ``Report.data`` to recover the compressed file bytes."
        ),
    )


class MemoryAccesses(BaseModel):
    """
    Aggregates read/write/execute counters for one memory region.

    These counters are produced by runtime memory tracing hooks when enabled.

    Use them to prioritize regions with meaningful behavioral activity.
    """

    model_config = ConfigDict(extra="forbid")

    reads: int = Field(
        description=(
            "Total read operations observed for the region.\n\n"
            "High read density often indicates lookup tables or parsed structures."
        )
    )
    writes: int = Field(
        description=(
            "Total write operations observed for the region.\n\n"
            "High write density often indicates decoded payload construction."
        )
    )
    execs: int = Field(
        description=(
            "Total execute operations observed for the region.\n\n"
            "Non-zero execution marks code-bearing pages and trampoline regions."
        )
    )


class MemoryRegion(BaseModel):
    """
    Represents one memory layout entry captured for an entry point.

    Memory layout capture runs at run completion and may include section-split
    module regions plus generic heap/stack mappings.

    Use this data to correlate execution artifacts with mapped memory topology.
    """

    model_config = ConfigDict(extra="forbid")

    tag: str = Field(
        description=(
            "Region tag assigned by the memory manager.\n\n"
            "Tags encode provenance such as module sections, heaps, or emulator "
            "internal structures."
        )
    )
    base: HexInt = Field(
        description=(
            "Base address of the memory region.\n\n"
            "Treat this as the start of the region for disassembly and dump slicing."
        )
    )
    size: int = Field(
        description=("Region size in bytes.\n\nCombine with ``base`` to derive half-open address ranges.")
    )
    perms: str = Field(
        description=(
            "Permission string (for example ``r-x`` or ``rw-``).\n\n"
            "Interpret this as the final effective page protection at capture time."
        )
    )
    is_free: bool = Field(
        default=False,
        description=(
            "Whether the region had been freed at capture time.\n\n"
            "Freed regions can remain visible when memory retention settings keep old "
            "maps for analysis."
        ),
    )
    accesses: MemoryAccesses | None = Field(
        default=None,
        description=(
            "Optional read/write/execute counters for the region.\n\n"
            "Populated primarily when memory tracing was enabled for the run."
        ),
    )
    data_ref: str | None = Field(
        default=None,
        description=(
            "Optional reference into the top-level report ``data`` store.\n\n"
            "When present, resolve this SHA-256 key in ``Report.data`` to recover the compressed region bytes."
        ),
    )


class ModuleSegment(BaseModel):
    """
    Describes one section-like segment within a loaded module.

    Segment data is collected from module metadata during memory layout capture.

    Use this to align addresses with section boundaries and permissions.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        description=(
            "Segment or section name within the module image.\n\n"
            "Useful for mapping behavior to familiar PE sections such as ``.text``."
        )
    )
    base: HexInt = Field(
        description=(
            "Absolute virtual address of the segment start.\n\nUse with ``size`` to identify covered address ranges."
        )
    )
    size: int = Field(
        description=("Segment size in bytes.\n\nLarge executable segments usually contain primary code paths.")
    )
    perms: str = Field(
        description=(
            "Effective memory permissions for the segment, such as ``r-x``.\n\n"
            "Use this to identify writable-executable anomalies or data-only regions."
        )
    )


class LoadedModule(BaseModel):
    """
    Captures one module visible in the run's loaded-module inventory.

    Module entries are assembled from runtime module objects at run completion.

    This section provides a concise map of what binaries were present and where.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        description=(
            "Module file name or canonical module identifier.\n\n"
            "Use this to correlate module events and API import usage."
        )
    )
    path: str = Field(
        description=("Emulated module path.\n\nUseful for distinguishing system modules from payload modules.")
    )
    base: HexInt = Field(
        description=(
            "Module base address in virtual memory.\n\n"
            "Use this as the relocation anchor for offsets and symbol lookups."
        )
    )
    size: int = Field(
        description=("Total mapped module size in bytes.\n\nHelps identify unusually large or tiny mapped images.")
    )
    segments: list[ModuleSegment] = Field(
        default_factory=list,
        description=(
            "Section/segment breakdown for the module mapping.\n\n"
            "Use these entries for section-aware interpretation of memory behavior."
        ),
    )


class MemoryLayout(BaseModel):
    """
    Bundles memory-region and loaded-module snapshots for one run.

    This object is populated when the emulator captures run-end memory state.

    Use it to understand both raw mappings and higher-level module context.
    """

    model_config = ConfigDict(extra="forbid")

    layout: list[MemoryRegion] = Field(
        default_factory=list,
        description=(
            "Flat list of captured memory regions for the run.\n\n"
            "Entries may include module headers/sections and generic maps."
        ),
    )
    modules: list[LoadedModule] = Field(
        default_factory=list,
        description=(
            "Loaded modules present when the run completed.\n\n"
            "Use alongside ``layout`` to interpret address ownership and segment roles."
        ),
    )


class EntryPointType(str, Enum):
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
    CALLBACK = "callback"
    DRIVER_ENTRY = "driver_entry"
    DRIVER_UNLOAD = "driver_unload"
    DRIVER_REINIT = "driver_reinit"
    IRP = "irp"


class EntryPoint(BaseModel):
    """
    Represents one emulation execution primitive captured as a run.

    A run may be a module entry point, callback, exported function, injected
    thread, or other execution start context.

    Most behavioral telemetry is attached at this level, so treat each entry as
    a self-contained execution narrative.
    """

    model_config = ConfigDict(extra="forbid")

    type: EntryPointType = Field(
        description=(
            "Kind of code that this run executes.\n\n"
            "Examples include the module entry point, an export, a TLS callback, and a thread."
        )
    )
    name: str | None = Field(
        default=None,
        description=(
            "Detail for ``type``, or null when the type has no detail.\n\n"
            "For example the export name, the TLS callback index, the dependency module, or the IRP major function."
        ),
    )
    start_address: HexInt = Field(
        description=(
            "Address where this run began executing.\n\n"
            "Use this as the anchor when following control flow in disassembly."
        )
    )
    args: list[HexInt] = Field(
        default_factory=list,
        description="Argument values supplied at run entry.",
    )
    pid: int | None = Field(
        default=None,
        description=(
            "Process identifier associated with the run context.\n\n"
            "Populated when process context is known for this entry point."
        ),
    )
    tid: int | None = Field(
        default=None,
        description=(
            "Thread identifier associated with the run context.\n\n"
            "Useful for correlating with per-event ``pos.tid`` values."
        ),
    )
    instruction_count: int | None = Field(
        default=None,
        description=(
            "Instruction count executed for this run.\n\n"
            "Can be limited by configuration caps or early termination conditions."
        ),
    )
    api_hash: str = Field(
        default="",
        description=(
            "SHA-256 hash over unique API names invoked in first-seen order.\n\n"
            "Use this for coarse behavioral clustering across samples and architectures."
        ),
    )
    return_value: HexIntOptional = Field(
        default=None,
        description=(
            "Return value produced when the run ended normally.\n\n"
            "Interpret this in the calling convention context of ``type``."
        ),
    )
    error: ErrorInfo | None = Field(
        default=None,
        description=(
            "Run-local error details when execution did not complete cleanly.\n\n"
            "Consult this with ``events`` to identify the exact failure transition."
        ),
    )
    events: list[AnyEvent] | None = Field(
        default=None,
        description=(
            "Chronological event stream emitted during this run.\n\n"
            "Event contents are produced by API, process, file, registry, network, "
            "and exception recorders."
        ),
    )
    symbol_accesses: list[SymAccessReport] | None = Field(
        default=None,
        description=(
            "Symbol-level access counters observed during tracing.\n\n"
            "Typically populated when memory tracing hooks are active."
        ),
    )
    dynamic_code_segments: list[DynamicCodeSegment] | None = Field(
        default=None,
        description=(
            "Dynamically generated code regions that executed in this run.\n\n"
            "Indicates unpacking, JIT-like behavior, or in-memory staging activity."
        ),
    )
    coverage: list[HexInt] | None = Field(
        default=None,
        description=(
            "Sorted list of executed instruction addresses for coverage analysis.\n\n"
            "Populated only when coverage collection is enabled in config."
        ),
    )
    dropped_files: list[DroppedFile] | None = Field(
        default=None,
        description=(
            "File artifacts detected as fully written during the run.\n\n"
            "Use this list to extract secondary payloads and logs."
        ),
    )
    memory: MemoryLayout | None = Field(
        default=None,
        description=(
            "Optional memory and module snapshot captured at run completion.\n\n"
            "Populate this when memory-layout capture is active for the emulator mode."
        ),
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
    Top-level Speakeasy output report model.

    This object combines run telemetry, metadata for the emulated input, and
    optional analysis artifacts.

    Treat this as the canonical machine-readable output for downstream tooling.
    """

    model_config = ConfigDict(extra="forbid")

    report_version: str = Field(
        default=REPORT_VERSION,
        description=(
            "Schema/report format version generated by the profiler.\n\n"
            "Use this to route parsing logic when consuming multiple report versions."
        ),
    )
    emulation_total_runtime: float = Field(
        description=(
            "Total wall-clock runtime in seconds for the emulation session.\n\n"
            "Derived from profiler start/stop timing and rounded to milliseconds."
        )
    )
    timestamp: int = Field(
        description=(
            "Epoch timestamp (seconds) captured at emulation start time.\n\n"
            "Use this for timeline correlation with external logs."
        )
    )
    arch: Arch | None = Field(
        default=None,
        description=("Architecture of the input sample, when known.\n\nPopulated from loader metadata."),
    )
    path: str | None = Field(
        default=None,
        description=(
            "Host path of the input file, when the input was loaded from a file.\n\n"
            "Useful for provenance tracking in batch pipelines."
        ),
    )
    sha256: str | None = Field(
        default=None,
        description=(
            "SHA-256 hash of the emulated input bytes, when available.\n\n"
            "Use this as the primary stable sample identifier."
        ),
    )
    size: int | None = Field(
        default=None,
        description=(
            "Input file size in bytes, when available.\n\n"
            "Helps validate sample identity and triage packaging anomalies."
        ),
    )
    file_type: FileType | None = Field(
        default=None,
        description=("Kind of input file, when known.\n\nDerived from loader inspection before emulation starts."),
    )
    image_base: HexIntOptional = Field(
        default=None,
        description=(
            "Base address at which the primary module was loaded during emulation.\n\n"
            "Use this to rebase analysis tools (e.g. IDA Pro) to match emulated addresses."
        ),
    )
    errors: list[ErrorInfo] | None = Field(
        default=None,
        description=(
            "Top-level emulator errors not tied to a specific run.\n\n"
            "These usually reflect session-level failures rather than per-entry-point "
            "termination."
        ),
    )
    strings: StringsReport | None = Field(
        default=None,
        description=(
            "Optional static and in-memory string extraction output.\n\n"
            "Present when string analysis is enabled and at least one string bucket is "
            "non-empty."
        ),
    )
    data: dict[str, DataArtifact] | None = Field(
        default=None,
        description=(
            "Deduplicated binary payload store keyed by SHA-256.\n\n"
            "Resolve ``*_ref`` fields in the report against this mapping to recover compressed payload bytes."
        ),
    )
    entry_points: list[EntryPoint] = Field(
        default_factory=list,
        description=(
            "Ordered list of all runs executed during emulation.\n\n"
            "This is the primary behavioral timeline for the report."
        ),
    )


class FileManifestEntry(BaseModel):
    """
    Manifest entry used by dropped-file archive exports.

    These records are stored in ``speakeasy_manifest.json`` inside file archive
    bundles created by the high-level API.

    Use this manifest to map archive members back to emulated file paths.
    """

    model_config = ConfigDict(extra="forbid")

    path: str = Field(
        description=(
            "Emulated file path associated with the archived artifact.\n\n"
            "Represents where the sample wrote the file in emulated space."
        )
    )
    file_name: str = Field(
        description=(
            "Archive member file name for the artifact bytes.\n\n"
            "Use this to locate the corresponding entry inside the zip package."
        )
    )
    size: int = Field(
        description=(
            "Artifact size in bytes.\n\nUseful for quick filtering of tiny markers versus payload-like binaries."
        )
    )
    sha256: str = Field(
        description=("SHA-256 hash of the archived file bytes.\n\nSupports integrity checks and IOC correlation.")
    )
