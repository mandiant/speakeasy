from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AnalysisConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    memory_tracing: bool = Field(default=False, description="Enable memory access tracing in reports.")
    strings: bool = Field(default=True, description="Extract strings from input and emulated memory.")
    coverage: bool = Field(default=False, description="Collect executed instruction addresses per run.")


class ExceptionsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    dispatch_handlers: bool = Field(default=True, description="Dispatch configured exception handlers during faults.")


class OsVersionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: Literal["windows"] = Field(default="windows", description="Emulated operating system family.")
    major: int | None = Field(default=None, description="Emulated OS major version.")
    minor: int | None = Field(default=None, description="Emulated OS minor version.")
    release: int | None = Field(default=None, description="Optional emulated OS release number.")
    build: int | None = Field(default=None, description="Emulated OS build number.")


class UserConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(description="Username exposed to account and profile APIs.")
    is_admin: bool = Field(default=False, description="Expose elevated privileges to admin checks.")
    sid: str | None = Field(default=None, description="Optional explicit SID for the emulated user.")


class ApiHammeringConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = Field(description="Enable API hammering mitigation.")
    threshold: int = Field(description="Repetition threshold that triggers mitigation.")
    allow_list: list[str] = Field(default_factory=list, description="API names exempt from mitigation.")


class SymlinkConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(description="Object manager symlink name.")
    target: str = Field(description="Object manager symlink target.")


class DriveConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    root_path: str | None = Field(default=None, description="Drive root path returned by drive APIs.")
    drive_type: str | None = Field(default=None, description="Drive type token used by drive APIs.")
    volume_guid_path: str | None = Field(default=None, description="Volume GUID path mapped to this drive.")


class ByteFillConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    byte: str = Field(description="Byte value used to synthesize file content.")
    size: int = Field(description="Number of bytes to synthesize.")


class FileEntryFullPath(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["full_path"] = Field(description="File entry matcher mode.")
    emu_path: str = Field(description="Emulated path pattern matched by this entry.")
    path: str | None = Field(default=None, description="Host file path served for matched reads.")
    byte_fill: ByteFillConfig | None = Field(default=None, description="Synthetic content source for matched reads.")


class FileEntryByExt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["by_ext"] = Field(description="File entry matcher mode.")
    ext: str = Field(description="File extension matched by this entry.")
    path: str | None = Field(default=None, description="Host file path served for matched reads.")
    byte_fill: ByteFillConfig | None = Field(default=None, description="Synthetic content source for matched reads.")


class FileEntryDefault(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["default"] = Field(description="File entry matcher mode.")
    path: str | None = Field(default=None, description="Fallback host file path served for reads.")
    byte_fill: ByteFillConfig | None = Field(default=None, description="Fallback synthetic content source.")


FileEntry = Annotated[
    FileEntryFullPath | FileEntryByExt | FileEntryDefault,
    Field(discriminator="mode"),
]


class FilesystemConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    files: list[FileEntry] = Field(default_factory=list, description="Filesystem response mapping rules.")


class RegistryValueConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(description="Registry value name.")
    type: str = Field(description="Registry type token.")
    data: str = Field(description="Registry value payload.")


class RegistryKeyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(description="Registry key path.")
    values: list[RegistryValueConfig] = Field(default_factory=list, description="Values under this key.")


class RegistryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    keys: list[RegistryKeyConfig] = Field(default_factory=list, description="Seed registry key definitions.")


class DnsTxtConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str | None = Field(default=None, description="Domain name for this TXT response mapping.")
    path: str | None = Field(default=None, description="Host file path used as TXT response payload.")


class DnsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    names: dict[str, str] = Field(default_factory=dict, description="Domain-to-IP mappings used by DNS lookups.")
    txt: list[DnsTxtConfig] = Field(default_factory=list, description="TXT response mapping entries.")


class HttpResponseConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    verb: Literal["GET", "POST", "HEAD"] | None = Field(
        default=None, description="HTTP verb matched by this response set."
    )
    files: list[FileEntry] = Field(default_factory=list, description="File mapping rules for this HTTP response set.")


class HttpConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    responses: list[HttpResponseConfig] = Field(default_factory=list, description="HTTP response mapping entries.")


class WinsockConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    responses: list[FileEntry] = Field(default_factory=list, description="Winsock receive response mapping entries.")


class NetworkAdapterConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str | None = Field(default=None, description="Adapter name or GUID.")
    description: str | None = Field(default=None, description="Adapter description string.")
    mac_address: str | None = Field(default=None, description="Adapter MAC address.")
    type: str | None = Field(default=None, description="Adapter media type.")
    ip_address: str | None = Field(default=None, description="Adapter IPv4 address.")
    subnet_mask: str | None = Field(default=None, description="Adapter subnet mask.")
    dhcp_enabled: bool | None = Field(default=None, description="Whether DHCP is enabled for this adapter.")


class NetworkConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    dns: DnsConfig | None = Field(default=None, description="DNS emulation settings.")
    http: HttpConfig | None = Field(default=None, description="HTTP emulation settings.")
    winsock: WinsockConfig | None = Field(default=None, description="Winsock emulation settings.")
    adapters: list[NetworkAdapterConfig] = Field(default_factory=list, description="Network adapters returned by APIs.")


class ProcessConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(description="Process name.")
    base_addr: str = Field(description="Process image base address.")
    path: str = Field(description="Process executable path.")
    pid: int | None = Field(default=None, description="Optional process identifier.")
    command_line: str | None = Field(default=None, description="Optional process command line.")
    is_main_exe: bool | None = Field(default=None, description="Whether this process is the main executable container.")
    session: int | None = Field(default=None, description="Optional session identifier.")


class ModuleImageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    arch: int = Field(description="Module image architecture (32 or 64).")
    name: str = Field(description="Module image name.")

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
        if arch_str in ("x64", "amd64"):
            return 64
        raise ValueError(f"Unsupported image arch: {v}")


class DeviceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(description="Device object name.")


class DriverConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(description="Driver object name.")
    devices: list[DeviceConfig] = Field(default_factory=list, description="Device objects exposed by this driver.")


class UserModuleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(description="User-mode module short name.")
    base_addr: str = Field(description="Module base address.")
    path: str = Field(description="Module path.")
    images: list[ModuleImageConfig] = Field(
        default_factory=list, description="Architecture-specific module image definitions."
    )


class SystemModuleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(description="System module short name.")
    base_addr: str = Field(description="Module base address.")
    path: str = Field(description="Module path.")
    driver: DriverConfig | None = Field(default=None, description="Optional driver and device object metadata.")


class ModulesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    modules_always_exist: bool = Field(
        default=False, description="Synthesize unknown modules instead of failing loads."
    )
    functions_always_exist: bool = Field(default=False, description="Treat unresolved imports as existing stubs.")
    module_directory_x86: str | None = Field(default=None, description="Search path for x86 decoy modules.")
    module_directory_x64: str | None = Field(default=None, description="Search path for x64 decoy modules.")
    user_modules: list[UserModuleConfig] = Field(
        default_factory=list, description="Configured user-mode module inventory."
    )
    system_modules: list[SystemModuleConfig] = Field(
        default_factory=list, description="Configured kernel/system module inventory."
    )


class SpeakeasyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    config_version: Literal[0.2] = Field(  # type: ignore[valid-type]
        description="Configuration schema version."
    )
    description: str | None = Field(default=None, description="Human-readable profile description.")
    emu_engine: Literal["unicorn"] = Field(description="Emulation backend identifier.")
    timeout: float = Field(description="Emulation timeout in seconds.")
    max_api_count: int = Field(default=5000, description="Maximum API calls allowed per run.")
    max_instructions: int = Field(default=-1, description="Maximum instructions to execute per run.")
    system: Literal["windows"] = Field(description="Emulated operating system family.")
    analysis: AnalysisConfig = Field(description="Analysis and telemetry collection settings.")
    keep_memory_on_free: bool = Field(default=False, description="Retain freed memory maps for post-free inspection.")
    capture_memory_dumps: bool = Field(default=False, description="Include compressed raw memory in report regions.")
    exceptions: ExceptionsConfig = Field(description="Exception dispatch behavior.")
    os_ver: OsVersionConfig = Field(description="OS version values exposed to emulated code.")
    current_dir: str = Field(description="Current working directory for emulated process APIs.")
    command_line: str = Field(default="", description="Command line exposed to emulated process APIs.")
    env: dict[str, str] = Field(
        default_factory=dict, description="Environment variables visible to the emulated process."
    )
    domain: str | None = Field(default=None, description="Domain or workgroup identity.")
    hostname: str = Field(description="Hostname exposed to emulated system APIs.")
    user: UserConfig = Field(description="Primary emulated user account.")
    api_hammering: ApiHammeringConfig | None = Field(default=None, description="API hammering mitigation settings.")
    symlinks: list[SymlinkConfig] = Field(default_factory=list, description="Object manager symbolic links.")
    drives: list[DriveConfig] = Field(default_factory=list, description="Virtual drive metadata.")
    filesystem: FilesystemConfig = Field(description="Filesystem mapping rules.")
    registry: RegistryConfig | None = Field(default=None, description="Registry key and value seed data.")
    network: NetworkConfig = Field(description="Network emulation settings.")
    processes: list[ProcessConfig] = Field(
        default_factory=list, description="Process inventory visible to enumeration APIs."
    )
    modules: ModulesConfig = Field(description="Module loading and inventory settings.")


def model_to_dict(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="python")
