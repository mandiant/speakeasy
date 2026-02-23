from typing import Annotated, Literal

from pydantic import BaseModel, Discriminator


class TracePosition(BaseModel):
    tick: int
    tid: int
    pid: int
    pc: int | None = None


class Event(BaseModel):
    pos: TracePosition
    event: str


class ApiEvent(Event):
    event: Literal["api"] = "api"
    api_name: str
    args: list[str]
    ret_val: str | None = None


class ProcessCreateEvent(Event):
    event: Literal["process_create"] = "process_create"
    path: str
    cmdline: str


class MemAllocEvent(Event):
    event: Literal["mem_alloc"] = "mem_alloc"
    path: str
    base: str
    size: str
    protect: str | None = None


class MemWriteEvent(Event):
    event: Literal["mem_write"] = "mem_write"
    path: str
    base: str
    size: int
    data: str


class MemReadEvent(Event):
    event: Literal["mem_read"] = "mem_read"
    path: str
    base: str
    size: int
    data: str


class MemProtectEvent(Event):
    event: Literal["mem_protect"] = "mem_protect"
    path: str
    base: str
    size: str
    protect: str | None = None


class MemFreeEvent(Event):
    event: Literal["mem_free"] = "mem_free"
    path: str
    base: str
    size: str


class ModuleLoadEvent(Event):
    event: Literal["module_load"] = "module_load"
    name: str
    path: str
    base: str
    size: str


class ThreadCreateEvent(Event):
    event: Literal["thread_create"] = "thread_create"
    path: str
    start_addr: str
    param: str


class ThreadInjectEvent(Event):
    event: Literal["thread_inject"] = "thread_inject"
    path: str
    start_addr: str
    param: str


class FileCreateEvent(Event):
    event: Literal["file_create"] = "file_create"
    path: str
    handle: str | None = None
    open_flags: list[str] | None = None
    access_flags: list[str] | None = None


class FileOpenEvent(Event):
    event: Literal["file_open"] = "file_open"
    path: str
    handle: str | None = None
    open_flags: list[str] | None = None
    access_flags: list[str] | None = None


class FileReadEvent(Event):
    event: Literal["file_read"] = "file_read"
    path: str
    handle: str | None = None
    size: int | None = None
    data: str | None = None
    buffer: str | None = None


class FileWriteEvent(Event):
    event: Literal["file_write"] = "file_write"
    path: str
    handle: str | None = None
    size: int | None = None
    data: str | None = None
    buffer: str | None = None


class RegOpenKeyEvent(Event):
    event: Literal["reg_open_key"] = "reg_open_key"
    path: str
    handle: str | None = None
    open_flags: list[str] | None = None
    access_flags: list[str] | None = None


class RegCreateKeyEvent(Event):
    event: Literal["reg_create_key"] = "reg_create_key"
    path: str
    handle: str | None = None
    open_flags: list[str] | None = None
    access_flags: list[str] | None = None


class RegReadValueEvent(Event):
    event: Literal["reg_read_value"] = "reg_read_value"
    path: str
    handle: str | None = None
    value_name: str | None = None
    size: int | None = None
    data: str | None = None
    buffer: str | None = None


class RegListSubkeysEvent(Event):
    event: Literal["reg_list_subkeys"] = "reg_list_subkeys"
    path: str
    handle: str | None = None


class NetDnsEvent(Event):
    event: Literal["net_dns"] = "net_dns"
    query: str
    response: str | None = None


class NetTrafficEvent(Event):
    event: Literal["net_traffic"] = "net_traffic"
    server: str
    port: int
    proto: str
    type: str | None = None
    data: str | None = None
    method: str | None = None


class NetHttpEvent(Event):
    event: Literal["net_http"] = "net_http"
    server: str
    port: int
    proto: str
    headers: str | None = None
    body: str | None = None


class ExceptionEvent(Event):
    event: Literal["exception"] = "exception"
    instr: str
    exception_code: str
    handler_address: str
    registers: dict[str, str]


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
