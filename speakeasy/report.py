from base64 import b64encode
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, PlainSerializer

from speakeasy.profiler_events import AnyEvent


def hex_serializer(v: int | None) -> str | None:
    """Serialize integer values as ``0x``-prefixed hexadecimal strings.

    Args:
        v: Integer value to serialize.

    Returns:
        Hexadecimal string, or ``None`` when the input is ``None``.
    """

    if v is None:
        return None
    return hex(v)


def bytes_serializer(v: bytes | None) -> str | None:
    """Serialize byte sequences as base64 ASCII strings.

    Args:
        v: Byte payload to serialize.

    Returns:
        Base64-encoded ASCII string, or ``None`` when the input is ``None``.
    """

    if v is None:
        return None
    return b64encode(v).decode("ascii")


def _parse_hex_int(v: Any) -> Any:
    """Parse integer-like strings accepted by report models.

    Args:
        v: Raw input value.

    Returns:
        Parsed integer when ``v`` is a numeric string, otherwise ``v`` unchanged.
    """

    if isinstance(v, str):
        return int(v, 0)
    return v


HexInt = Annotated[int, BeforeValidator(_parse_hex_int), PlainSerializer(hex_serializer, return_type=str)]
HexIntOptional = Annotated[
    int | None,
    BeforeValidator(_parse_hex_int),
    PlainSerializer(hex_serializer, return_type=str | None),
]
Base64Bytes = Annotated[bytes | None, PlainSerializer(bytes_serializer, return_type=str | None)]


class StringCollection(BaseModel):
    """Represents one categorized bucket of extracted strings.

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
    """Groups static and in-memory string extraction results.

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


class ErrorInfo(BaseModel):
    """Captures failure context for top-level or per-entry-point errors.

    Error records can represent unsupported API termination, instruction faults,
    explicit runtime limits, or unhandled exceptions.

    Inspect this structure first when a run exits unexpectedly.
    """

    model_config = ConfigDict(extra="forbid")

    type: str = Field(
        description=(
            "Error category identifier describing the failure mode.\n\n"
            "Examples include unsupported API paths, max API limits, and fault "
            "conditions raised by emulator hooks."
        )
    )
    pc: HexIntOptional = Field(
        default=None,
        description=(
            "Program counter associated with the error, when available.\n\n"
            "Use this address to align failures with disassembly and event traces."
        ),
    )
    instr: str | None = Field(
        default=None,
        description=(
            "Faulting instruction text, when known.\n\n"
            "Useful for quickly identifying invalid memory operations or bad control "
            "flow transitions."
        ),
    )


class SymAccessReport(BaseModel):
    """Summarizes memory accesses to symbol-resolved addresses.

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
    """Describes one dynamically generated code region that executed.

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
    size: HexInt = Field(
        description=(
            "Region size of the dynamic code segment.\n\n"
            "Large regions may indicate unpacked module images or staged blobs."
        )
    )


class DroppedFile(BaseModel):
    """Represents one file artifact written by emulated execution.

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
    data: Base64Bytes = Field(
        default=None,
        description=(
            "Optional base64 content payload for the dropped file.\n\n"
            "When present, decode for direct artifact analysis without separate file "
            "archive export."
        ),
    )
    sha256: str = Field(
        description=(
            "SHA-256 hash of the dropped file bytes.\n\nUse this for sample correlation and deduplication workflows."
        )
    )


class MemoryAccesses(BaseModel):
    """Aggregates read/write/execute counters for one memory region.

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
    """Represents one memory layout entry captured for an entry point.

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
    address: HexInt = Field(
        description=(
            "Base address of the memory region.\n\n"
            "Treat this as the start of the region for disassembly and dump slicing."
        )
    )
    size: HexInt = Field(
        description=("Region size in bytes.\n\nCombine with ``address`` to derive half-open address ranges.")
    )
    prot: str = Field(
        description=(
            "Protection string (for example ``r-x`` or ``rw-``).\n\n"
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
    data: str | None = Field(
        default=None,
        description=(
            "Optional zlib-compressed, base64-encoded memory bytes.\n\n"
            "Populated when memory dump capture is enabled; decode via base64 then "
            "zlib to recover raw bytes."
        ),
    )


class ModuleSegment(BaseModel):
    """Describes one section-like segment within a loaded module.

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
    address: HexInt = Field(
        description=(
            "Absolute virtual address of the segment start.\n\nUse with ``size`` to identify covered address ranges."
        )
    )
    size: HexInt = Field(
        description=("Segment size in bytes.\n\nLarge executable segments usually contain primary code paths.")
    )
    prot: str = Field(
        description=(
            "Effective memory protection for the segment.\n\n"
            "Use this to identify writable-executable anomalies or data-only regions."
        )
    )


class LoadedModule(BaseModel):
    """Captures one module visible in the run's loaded-module inventory.

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
    size: HexInt = Field(
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
    """Bundles memory-region and loaded-module snapshots for one run.

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


class EntryPoint(BaseModel):
    """Represents one emulation execution primitive captured as a run.

    A run may be a module entry point, callback, exported function, injected
    thread, or other execution start context.

    Most behavioral telemetry is attached at this level, so treat each entry as
    a self-contained execution narrative.
    """

    model_config = ConfigDict(extra="forbid")

    ep_type: str = Field(
        description=(
            "Execution primitive label for this run.\n\n"
            "Examples include module entry, export callbacks, and thread contexts."
        )
    )
    start_addr: HexInt = Field(
        description=(
            "Address where this run began executing.\n\n"
            "Use this as the anchor when following control flow in disassembly."
        )
    )
    ep_args: list[Any] = Field(
        default_factory=list,
        description=(
            "Argument values supplied at run entry.\n\nInteger arguments are serialized as hex strings for readability."
        ),
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
    instr_count: int | None = Field(
        default=None,
        description=(
            "Instruction count executed for this run.\n\n"
            "Can be limited by configuration caps or early termination conditions."
        ),
    )
    apihash: str = Field(
        default="",
        description=(
            "SHA-256 hash over unique API names invoked in first-seen order.\n\n"
            "Use this for coarse behavioral clustering across samples and architectures."
        ),
    )
    ret_val: HexIntOptional = Field(
        default=None,
        description=(
            "Return value produced when the run ended normally.\n\n"
            "Interpret this in the calling convention context of ``ep_type``."
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
    sym_accesses: list[SymAccessReport] | None = Field(
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
    coverage: list[int] | None = Field(
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


class Report(BaseModel):
    """Top-level Speakeasy output report model.

    This object combines run telemetry, metadata for the emulated input, and
    optional analysis artifacts.

    Treat this as the canonical machine-readable output for downstream tooling.
    """

    model_config = ConfigDict(extra="allow")

    report_version: str = Field(
        default="2.0.0",
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
    arch: str | None = Field(
        default=None,
        description=(
            "Architecture label for the input sample, when known.\n\n"
            "Populated from loader metadata (for example ``x86`` or ``x64``)."
        ),
    )
    filepath: str | None = Field(
        default=None,
        description=(
            "Original local path of the emulated input file, when available.\n\n"
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
    filetype: str | None = Field(
        default=None,
        description=(
            "Coarse file-type classification (for example exe, dll, driver).\n\n"
            "Derived from loader inspection before emulation starts."
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
    entry_points: list[EntryPoint] = Field(
        default_factory=list,
        description=(
            "Ordered list of all runs executed during emulation.\n\n"
            "This is the primary behavioral timeline for the report."
        ),
    )


class FileManifestEntry(BaseModel):
    """Manifest entry used by dropped-file archive exports.

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


class MemoryBlock(BaseModel):
    """Manifest record for one dumped memory block.

    Memory block manifests are emitted alongside memory dump archives to keep
    hashable metadata separate from raw dump bytes.

    Use this for deterministic indexing of memory dump artifacts.
    """

    model_config = ConfigDict(extra="forbid")

    tag: str = Field(
        description=(
            "Memory-map tag identifying the dumped block's origin.\n\n"
            "Tags help group blocks by module, heap, shellcode, or internal regions."
        )
    )
    base: HexInt = Field(
        description=(
            "Base address of the dumped memory block.\n\n"
            "Use this as the primary address key when loading dumps in analysis tools."
        )
    )
    size: HexInt = Field(
        description=("Dumped block size in bytes.\n\nCombine with ``base`` to reconstruct memory ranges.")
    )
    is_free: bool = Field(
        description=(
            "Whether the block was marked free at dump capture time.\n\n"
            "Freed blocks can still contain useful residual payload material."
        )
    )
    sha256: str = Field(
        description=("SHA-256 hash of the dumped block bytes.\n\nUse for deduplication and reproducibility checks.")
    )
    file_name: str = Field(
        description=(
            "Archive file name storing this block's raw bytes.\n\n"
            "Use this with the manifest to resolve metadata to zip members."
        )
    )


class ProcessMemoryManifest(BaseModel):
    """Groups dumped memory-block manifest records per process.

    Memory dump archive generation emits one process manifest entry per process
    that contributed dumpable blocks.

    Use this to keep process context attached to raw dump artifacts.
    """

    model_config = ConfigDict(extra="forbid")

    pid: int = Field(
        description=(
            "Process identifier associated with the dumped blocks.\n\n"
            "Use this for correlation with run-level process and event metadata."
        )
    )
    process_name: str = Field(
        description=(
            "Process path/name label associated with the dump set.\n\n"
            "Helps distinguish blocks from parent and child process contexts."
        )
    )
    arch: str = Field(
        description=(
            "Process architecture label for the dump set.\n\n"
            "Useful when loading dumps into architecture-specific tooling."
        )
    )
    memory_blocks: list[MemoryBlock] = Field(
        default_factory=list,
        description=(
            "Dumped memory block descriptors belonging to this process.\n\n"
            "Each entry maps one archived ``.mem`` file to address and hash metadata."
        ),
    )
