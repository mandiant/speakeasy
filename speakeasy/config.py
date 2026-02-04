from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AnalysisConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    memory_tracing: bool = False
    strings: bool = True
    coverage: bool = False


class ExceptionsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    dispatch_handlers: bool = True


class OsVersionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: Literal["windows"] = "windows"
    major: int | None = None
    minor: int | None = None
    release: int | None = None
    build: int | None = None


class UserConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    is_admin: bool = False
    sid: str | None = None


class ApiHammeringConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool
    threshold: int
    allow_list: list[str] = []


class SymlinkConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    target: str


class DriveConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    root_path: str | None = None
    drive_type: str | None = None
    volume_guid_path: str | None = None


class ByteFillConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    byte: str
    size: int


class FileEntryFullPath(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["full_path"]
    emu_path: str
    path: str | None = None
    byte_fill: ByteFillConfig | None = None


class FileEntryByExt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["by_ext"]
    ext: str
    path: str | None = None
    byte_fill: ByteFillConfig | None = None


class FileEntryDefault(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["default"]
    path: str | None = None
    byte_fill: ByteFillConfig | None = None


FileEntry = Annotated[
    FileEntryFullPath | FileEntryByExt | FileEntryDefault,
    Field(discriminator="mode"),
]


class FilesystemConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    files: list[FileEntry] = []


class RegistryValueConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    type: str
    data: str


class RegistryKeyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str
    values: list[RegistryValueConfig] = []


class RegistryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    keys: list[RegistryKeyConfig] = []


class DnsTxtConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str | None = None
    path: str | None = None


class DnsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    names: dict[str, str] = {}
    txt: list[DnsTxtConfig] = []


class HttpResponseConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    verb: Literal["GET", "POST", "HEAD"] | None = None
    files: list[FileEntry] = []


class HttpConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    responses: list[HttpResponseConfig] = []


class WinsockConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    responses: list[FileEntry] = []


class NetworkAdapterConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str | None = None
    description: str | None = None
    mac_address: str | None = None
    type: str | None = None
    ip_address: str | None = None
    subnet_mask: str | None = None
    dhcp_enabled: bool | None = None


class NetworkConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    dns: DnsConfig | None = None
    http: HttpConfig | None = None
    winsock: WinsockConfig | None = None
    adapters: list[NetworkAdapterConfig] = []


class ProcessConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    base_addr: str
    path: str
    pid: int | None = None
    command_line: str | None = None
    is_main_exe: bool | None = None
    session: int | None = None


class ModuleImageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    arch: int
    name: str

    @field_validator("arch", mode="before")
    @classmethod
    def normalize_arch(cls, v: str | int) -> int:
        if isinstance(v, int):
            if v in (32, 64):
                return v
            raise ValueError(f"Invalid arch int: {v}")
        arch_str = v.lower()
        if arch_str in ("x86", "i386"):
            return 32
        elif arch_str in ("x64", "amd64"):
            return 64
        raise ValueError(f"Unsupported image arch: {v}")


class DeviceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str


class DriverConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    devices: list[DeviceConfig] = []


class UserModuleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    base_addr: str
    path: str
    images: list[ModuleImageConfig] = []


class SystemModuleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    base_addr: str
    path: str
    driver: DriverConfig | None = None


class ModulesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    modules_always_exist: bool = False
    functions_always_exist: bool = False
    module_directory_x86: str | None = None
    module_directory_x64: str | None = None
    user_modules: list[UserModuleConfig] = []
    system_modules: list[SystemModuleConfig] = []


class SpeakeasyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    config_version: Literal[0.2]
    description: str | None = None
    emu_engine: Literal["unicorn"]
    timeout: float
    max_api_count: int = 5000
    max_instructions: int = -1
    system: Literal["windows"]
    analysis: AnalysisConfig
    keep_memory_on_free: bool = False
    exceptions: ExceptionsConfig
    os_ver: OsVersionConfig
    current_dir: str
    command_line: str = ""
    env: dict[str, str] = {}
    domain: str | None = None
    hostname: str
    user: UserConfig
    api_hammering: ApiHammeringConfig | None = None
    symlinks: list[SymlinkConfig] = []
    drives: list[DriveConfig] = []
    filesystem: FilesystemConfig
    registry: RegistryConfig | None = None
    network: NetworkConfig
    processes: list[ProcessConfig] = []
    modules: ModulesConfig


def model_to_dict(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="python")
