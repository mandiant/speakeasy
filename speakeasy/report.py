from base64 import b64encode
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, PlainSerializer

from speakeasy.profiler_events import AnyEvent


def hex_serializer(v: int | None) -> str | None:
    if v is None:
        return None
    return hex(v)


def bytes_serializer(v: bytes | None) -> str | None:
    if v is None:
        return None
    return b64encode(v).decode("ascii")


HexInt = Annotated[int, PlainSerializer(hex_serializer, return_type=str)]
HexIntOptional = Annotated[int | None, PlainSerializer(hex_serializer, return_type=str | None)]
Base64Bytes = Annotated[bytes | None, PlainSerializer(bytes_serializer, return_type=str | None)]


class StringCollection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ansi: list[str] = []
    unicode: list[str] = []


class StringsReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    static: StringCollection = Field(default_factory=StringCollection)
    in_memory: StringCollection = Field(default_factory=StringCollection)


class ErrorInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    pc: HexIntOptional = None
    instr: str | None = None


class SymAccessReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    symbol: str
    reads: int
    writes: int
    execs: int


class DynamicCodeSegment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tag: str
    base: HexInt
    size: HexInt


class DroppedFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    data: Base64Bytes = None
    sha256: str


class MemoryAccesses(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reads: int
    writes: int
    execs: int


class MemoryRegion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tag: str
    address: HexInt
    size: HexInt
    prot: str
    is_free: bool = False
    accesses: MemoryAccesses | None = None


class ModuleSegment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    address: HexInt
    size: HexInt
    prot: str


class LoadedModule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    path: str
    base: HexInt
    size: HexInt
    segments: list[ModuleSegment] = []


class MemoryLayout(BaseModel):
    model_config = ConfigDict(extra="forbid")

    layout: list[MemoryRegion] = []
    modules: list[LoadedModule] = []


class EntryPoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ep_type: str
    start_addr: HexInt
    ep_args: list[Any] = []
    instr_count: int | None = None
    apihash: str = ""
    ret_val: HexIntOptional = None
    error: ErrorInfo | None = None
    events: list[AnyEvent] | None = None
    sym_accesses: list[SymAccessReport] | None = None
    dynamic_code_segments: list[DynamicCodeSegment] | None = None
    coverage: list[int] | None = None
    dropped_files: list[DroppedFile] | None = None
    memory: MemoryLayout | None = None


class Report(BaseModel):
    model_config = ConfigDict(extra="allow")

    report_version: str = "2.0.0"
    emulation_total_runtime: float
    timestamp: int
    arch: str | None = None
    filepath: str | None = None
    sha256: str | None = None
    size: int | None = None
    filetype: str | None = None
    errors: list[ErrorInfo] | None = None
    strings: StringsReport | None = None
    entry_points: list[EntryPoint] = []


class FileManifestEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    file_name: str
    size: int
    sha256: str


class MemoryBlock(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tag: str
    base: HexInt
    size: HexInt
    is_free: bool
    sha256: str
    file_name: str


class ProcessMemoryManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pid: int
    process_name: str
    arch: str
    memory_blocks: list[MemoryBlock] = []
