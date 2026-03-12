from __future__ import annotations

import copy
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

DEFAULT_CONFIG_DATA = {
    "config_version": 0.2,
    "description": "Default emulation profile to use when not overridden by user",
    "emu_engine": "unicorn",
    "timeout": 60,
    "max_api_count": 10000,
    "system": "windows",
    "analysis": {"memory_tracing": False, "strings": True, "coverage": False},
    "keep_memory_on_free": False,
    "exceptions": {"dispatch_handlers": True},
    "os_ver": {"name": "windows", "major": 6, "minor": 1, "build": 7601},
    "current_dir": "C:\\Windows\\system32",
    "command_line": "svchost.exe myarg1 myarg2",
    "env": {
        "comspec": "C:\\Windows\\system32\\cmd.exe",
        "systemroot": "C:\\Windows",
        "windir": "C:\\Windows",
        "temp": "C:\\Windows\\temp\\",
        "userprofile": "C:\\Users\\speakeasy_user",
        "systemdrive": "C:",
        "allusersprofile": "C:\\ProgramData",
        "programfiles": "C:\\Program Files",
    },
    "domain": "speakeasy_domain",
    "hostname": "speakeasy_host",
    "user": {"name": "speakeasy_user", "is_admin": True, "sid": "S-1-5-21-1111111111-2222222222-3333333333-1001"},
    "api_hammering": {"enabled": False, "threshold": 2000},
    "symlinks": [
        {"name": "\\??\\C:", "target": "\\Device\\HarddiskVolume1"},
        {"name": "\\??\\PhysicalDrive0", "target": "\\Device\\Harddisk0\\DR0"},
    ],
    "drives": [
        {
            "root_path": "C:\\",
            "drive_type": "DRIVE_FIXED",
            "volume_guid_path": "\\\\?\\Volume{bb1d6623-5e53-11ea-a949-100000000001}\\",
        },
        {
            "root_path": "D:\\",
            "drive_type": "DRIVE_CDROM",
            "volume_guid_path": "\\\\?\\Volume{bb1d6623-5e53-11ea-a949-100000000002}\\",
        },
        {
            "root_path": "E:\\",
            "drive_type": "DRIVE_REMOTE",
            "volume_guid_path": "\\\\?\\Volume{bb1d6623-5e53-11ea-a949-100000000003}\\",
        },
        {
            "root_path": "F:\\",
            "drive_type": "DRIVE_REMOVABLE",
            "volume_guid_path": "\\\\?\\Volume{bb1d6623-5e53-11ea-a949-100000000004}\\",
        },
    ],
    "filesystem": {
        "files": [
            {
                "mode": "full_path",
                "emu_path": "c:\\programdata\\mydir\\myfile.bin",
                "byte_fill": {"byte": "0x41", "size": 512},
            },
            {
                "mode": "full_path",
                "emu_path": "c:\\Windows\\system32\\cmd.exe",
                "path": "$ROOT$/resources/files/default.bin",
            },
            {
                "mode": "full_path",
                "emu_path": "c:\\Windows\\system32\\svchost.exe",
                "path": "$ROOT$/resources/files/default.bin",
            },
            {"mode": "by_ext", "ext": "exe", "path": "$ROOT$/resources/files/default.bin"},
            {"mode": "by_ext", "ext": "txt", "path": "$ROOT$/resources/files/default.bin"},
            {"mode": "full_path", "emu_path": "\\\\.\\pipe*", "path": "$ROOT$/resources/web/stager.bin"},
        ]
    },
    "registry": {
        "keys": [
            {
                "path": "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\usbsamp",
                "values": [
                    {"name": "DisplayName", "type": "REG_SZ", "data": "An example service"},
                    {"name": "Start", "type": "REG_DWORD", "data": "0x00000003"},
                ],
            },
            {
                "path": "HKEY_CLASSES_ROOT\\Interface\\{b196b287-bab4-101a-b69c-00aa00341d07}",
                "values": [{"name": "default", "type": "REG_SZ", "data": "IEnumConnections"}],
            },
            {
                "path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                "values": [{"name": "default", "type": "REG_SZ", "data": "IEnumConnections"}],
            },
            {
                "path": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                "values": [],
            },
        ]
    },
    "network": {
        "dns": {
            "names": {
                "speakeasy_host": "127.0.0.1",
                "default": "10.1.2.3",
                "google.com": "8.8.8.8",
                "localhost": "127.0.0.1",
            },
            "txt": [{"name": "default", "path": "$ROOT$/resources/web/default.bin"}],
        },
        "http": {
            "responses": [
                {
                    "verb": "GET",
                    "files": [
                        {"mode": "default", "path": "$ROOT$/resources/web/default.bin"},
                        {"mode": "by_ext", "ext": "gif", "path": "$ROOT$/resources/web/decoy.gif"},
                        {"mode": "by_ext", "ext": "jpg", "path": "$ROOT$/resources/web/decoy.jpg"},
                    ],
                }
            ]
        },
        "winsock": {"responses": [{"mode": "default", "path": "$ROOT$/resources/web/stager.bin"}]},
        "adapters": [
            {
                "name": "{00000000-0000-0000-0000-000000000000}",
                "description": "Intel(R) PRO/1000 MT Network Connection",
                "mac_address": "00-13-CE-12-34-56",
                "type": "ethernet",
                "ip_address": "127.0.0.1",
                "subnet_mask": "255.0.0.0",
                "dhcp_enabled": True,
            }
        ],
    },
    "processes": [
        {"name": "System", "base_addr": "0x80000000", "pid": 4, "path": "[System Process]"},
        {"name": "smss", "base_addr": "0x05000000", "path": "C:\\Windows\\system32\\smss.exe"},
        {"name": "csrss", "base_addr": "0x05510000", "path": "C:\\Windows\\system32\\csrss.exe"},
        {"name": "wininit", "base_addr": "0x05520000", "path": "C:\\Windows\\system32\\wininit.exe"},
        {"name": "services", "base_addr": "0x05530000", "path": "C:\\Windows\\system32\\services.exe"},
        {"name": "lsass", "base_addr": "0x05540000", "path": "C:\\Windows\\system32\\lsass.exe"},
        {"name": "winlogon", "base_addr": "0x05550000", "path": "C:\\Windows\\system32\\winlogon.exe"},
        {"name": "svchost", "base_addr": "0x05560000", "path": "C:\\Windows\\system32\\svchost.exe"},
        {"name": "outlook", "base_addr": "0x05590000", "path": "C:\\Windows\\system32\\outlook.exe"},
        {"name": "explorer", "base_addr": "0x05570000", "path": "C:\\Windows\\explorer.exe"},
        {
            "name": "main",
            "base_addr": "0x00400000",
            "path": "C:\\Windows\\system32\\svchost.exe",
            "command_line": "svchost.exe",
            "is_main_exe": True,
            "session": 1,
        },
    ],
    "modules": {
        "modules_always_exist": False,
        "functions_always_exist": False,
        "module_directory_x86": "$ROOT$/winenv/decoys/x86",
        "module_directory_x64": "$ROOT$/winenv/decoys/amd64",
        "system_modules": [
            {"name": "ntoskrnl", "base_addr": "0x803d0000", "path": "C:\\Windows\\system32\\ntoskrnl.exe"},
            {"name": "hal", "base_addr": "0xC1000000", "path": "C:\\Windows\\system32\\hal.dll"},
            {"name": "ntfs", "base_addr": "0xC2000000", "path": "C:\\Windows\\system32\\drivers\\ntfs.sys"},
            {"name": "netio", "base_addr": "0xD4000000", "path": "C:\\Windows\\system32\\drivers\\netio.sys"},
            {
                "name": "volmgr",
                "base_addr": "0xC6000000",
                "path": "C:\\Windows\\system32\\drivers\\volmgr.sys",
                "driver": {"name": "\\Driver\\volmgr", "devices": [{"name": "\\Device\\HarddiskVolume1"}]},
            },
            {
                "name": "disk",
                "base_addr": "0xC3000000",
                "path": "C:\\Windows\\system32\\drivers\\disk.sys",
                "driver": {"name": "\\Driver\\Disk", "devices": [{"name": "\\Device\\Harddisk0\\DR0"}]},
            },
            {
                "name": "tcpip",
                "base_addr": "0xC4000000",
                "path": "C:\\Windows\\system32\\drivers\\tcpip.sys",
                "driver": {"name": "\\Driver\\Tcpip", "devices": [{"name": "\\Device\\Tcp"}]},
            },
            {
                "name": "ndis",
                "base_addr": "0xC7000000",
                "path": "C:\\Windows\\system32\\drivers\\ndis.sys",
                "driver": {"name": "\\Driver\\Ndis", "devices": [{"name": "\\Device\\Ndis"}]},
            },
        ],
        "user_modules": [
            {"name": "ntdll", "base_addr": "0x7C000000", "path": "C:\\Windows\\system32\\ntdll.dll"},
            {"name": "kernel32", "base_addr": "0x77000000", "path": "C:\\Windows\\system32\\kernel32.dll"},
            {"name": "ws2_32", "base_addr": "0x78C00000", "path": "C:\\Windows\\system32\\ws2_32.dll"},
            {"name": "wininet", "base_addr": "0x7BC00000", "path": "C:\\Windows\\system32\\wininet.dll"},
            {"name": "winhttp", "base_addr": "0x7BA00000", "path": "C:\\Windows\\system32\\winhttp.dll"},
            {"name": "advapi32", "base_addr": "0x78000000", "path": "C:\\Windows\\system32\\advapi32.dll"},
            {"name": "psapi", "base_addr": "0x71000000", "path": "C:\\Windows\\system32\\psapi.dll"},
            {"name": "user32", "base_addr": "0x77D10000", "path": "C:\\Windows\\system32\\user32.dll"},
            {"name": "gdi32", "base_addr": "0x77E10000", "path": "C:\\Windows\\system32\\gdi32.dll"},
            {"name": "msvcrt", "base_addr": "0x77F10000", "path": "C:\\Windows\\system32\\msvcrt.dll"},
            {"name": "dnsapi", "base_addr": "0x78F10000", "path": "C:\\Windows\\system32\\dnsapi.dll"},
            {"name": "shlwapi", "base_addr": "0x67000000", "path": "C:\\Windows\\system32\\shlwapi.dll"},
            {"name": "advpack", "base_addr": "0x68F00000", "path": "C:\\Windows\\system32\\advpack.dll"},
            {"name": "dbghelp", "base_addr": "0x62000000", "path": "C:\\Windows\\system32\\dbghelp.dll"},
            {"name": "shell32", "base_addr": "0x69000000", "path": "C:\\Windows\\system32\\shell32.dll"},
            {"name": "WTSAPI32", "base_addr": "0x63000000", "path": "C:\\Windows\\system32\\WTSAPI32.dll"},
            {"name": "CRYPT32", "base_addr": "0x58000000", "path": "C:\\Windows\\system32\\CRYPT32.dll"},
            {"name": "mscoree", "base_addr": "0x53000000", "path": "C:\\Windows\\system32\\mscoree.dll"},
            {"name": "urlmon", "base_addr": "0x54500000", "path": "C:\\Windows\\system32\\urlmon.dll"},
            {"name": "riched32", "base_addr": "0x56500000", "path": "C:\\Windows\\system32\\riched32.dll"},
            {"name": "userenv", "base_addr": "0x76500000", "path": "C:\\Windows\\system32\\userenv.dll"},
            {"name": "ole32", "base_addr": "0x65500000", "path": "C:\\Windows\\system32\\ole32.dll"},
            {"name": "gdiplus", "base_addr": "0x75500000", "path": "C:\\Windows\\system32\\gdiplus.dll"},
            {"name": "setupapi", "base_addr": "0x55500000", "path": "C:\\Windows\\system32\\setupapi.dll"},
            {"name": "NETAPI32", "base_addr": "0x54400000", "path": "C:\\Windows\\system32\\NETAPI32.dll"},
            {"name": "rpcrt4", "base_addr": "0x53300000", "path": "C:\\Windows\\system32\\Rpcrt4.dll"},
            {"name": "linkinfo", "base_addr": "0x63300000", "path": "C:\\Windows\\system32\\linkinfo.dll"},
            {"name": "EhStorShell", "base_addr": "0x73300000", "path": "C:\\Windows\\system32\\EhStorShell.dll"},
            {"name": "comctl32", "base_addr": "0x5f500000", "path": "C:\\Windows\\system32\\comctl32.dll"},
            {"name": "secur32", "base_addr": "0x5f600000", "path": "C:\\Windows\\system32\\secur32.dll"},
            {"name": "KtmW32", "base_addr": "0x5f700000", "path": "C:\\Windows\\system32\\KtmW32.dll"},
            {"name": "oleaut32", "base_addr": "0x5f800000", "path": "C:\\Windows\\system32\\oleaut32.dll"},
            {"name": "bcrypt", "base_addr": "0x5f900000", "path": "C:\\Windows\\system32\\bcrypt.dll"},
            {"name": "ncrypt", "base_addr": "0x5fa00000", "path": "C:\\Windows\\system32\\ncrypt.dll"},
            {"name": "netutils", "base_addr": "0x5fb00000", "path": "C:\\Windows\\system32\\netutils.dll"},
            {"name": "wkscli", "base_addr": "0x5fc00000", "path": "C:\\Windows\\system32\\wkscli.dll"},
            {"name": "iphlpapi", "base_addr": "0x5fd00000", "path": "C:\\Windows\\system32\\iphlpapi.dll"},
            {"name": "sfc_os", "base_addr": "0x5fe00000", "path": "C:\\Windows\\system32\\sfc_os.dll"},
            {"name": "winmm", "base_addr": "0x5ff00000", "path": "C:\\Windows\\system32\\winmm.dll"},
            {
                "name": "bcryptprimitives",
                "base_addr": "0x60000000",
                "path": "C:\\Windows\\system32\\bcryptprimitives.dll",
            },
        ],
    },
}


def _copy_default_value(key: str) -> Any:
    return copy.deepcopy(DEFAULT_CONFIG_DATA[key])


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

    @model_validator(mode="before")
    @classmethod
    def migrate_legacy_memory_snapshot_field(cls, data: Any) -> Any:
        if isinstance(data, dict) and "snapshot_memory_regions" not in data and "capture_memory_dumps" in data:
            data = dict(data)
            data["snapshot_memory_regions"] = data.pop("capture_memory_dumps")
        return data

    config_version: Literal[0.2] = Field(  # type: ignore[valid-type]
        default=DEFAULT_CONFIG_DATA["config_version"],
        description="Configuration schema version.",
    )
    description: str | None = Field(
        default=DEFAULT_CONFIG_DATA["description"], description="Human-readable profile description."
    )
    emu_engine: Literal["unicorn"] = Field(
        default=DEFAULT_CONFIG_DATA["emu_engine"], description="Emulation backend identifier."
    )
    timeout: float = Field(default=DEFAULT_CONFIG_DATA["timeout"], description="Emulation timeout in seconds.")
    max_api_count: int = Field(
        default=DEFAULT_CONFIG_DATA["max_api_count"], description="Maximum API calls allowed per run."
    )
    max_instructions: int = Field(default=-1, description="Maximum instructions to execute per run.")
    system: Literal["windows"] = Field(
        default=DEFAULT_CONFIG_DATA["system"], description="Emulated operating system family."
    )
    analysis: AnalysisConfig = Field(
        default_factory=lambda: AnalysisConfig.model_validate(_copy_default_value("analysis")),
        description="Analysis and telemetry collection settings.",
    )
    keep_memory_on_free: bool = Field(
        default=DEFAULT_CONFIG_DATA["keep_memory_on_free"],
        description="Retain freed memory maps for post-free inspection.",
    )
    snapshot_memory_regions: bool = Field(
        default=False,
        description="Include run-end memory region snapshots in the report data store.",
    )
    exceptions: ExceptionsConfig = Field(
        default_factory=lambda: ExceptionsConfig.model_validate(_copy_default_value("exceptions")),
        description="Exception dispatch behavior.",
    )
    os_ver: OsVersionConfig = Field(
        default_factory=lambda: OsVersionConfig.model_validate(_copy_default_value("os_ver")),
        description="OS version values exposed to emulated code.",
    )
    current_dir: str = Field(
        default=DEFAULT_CONFIG_DATA["current_dir"],
        description="Current working directory for emulated process APIs.",
    )
    command_line: str = Field(
        default=DEFAULT_CONFIG_DATA["command_line"],
        description="Command line exposed to emulated process APIs.",
    )
    env: dict[str, str] = Field(
        default_factory=lambda: _copy_default_value("env"),
        description="Environment variables visible to the emulated process.",
    )
    domain: str | None = Field(default=DEFAULT_CONFIG_DATA["domain"], description="Domain or workgroup identity.")
    hostname: str = Field(
        default=DEFAULT_CONFIG_DATA["hostname"], description="Hostname exposed to emulated system APIs."
    )
    user: UserConfig = Field(
        default_factory=lambda: UserConfig.model_validate(_copy_default_value("user")),
        description="Primary emulated user account.",
    )
    api_hammering: ApiHammeringConfig | None = Field(
        default_factory=lambda: ApiHammeringConfig.model_validate(_copy_default_value("api_hammering")),
        description="API hammering mitigation settings.",
    )
    symlinks: list[SymlinkConfig] = Field(
        default_factory=lambda: [SymlinkConfig.model_validate(item) for item in _copy_default_value("symlinks")],
        description="Object manager symbolic links.",
    )
    drives: list[DriveConfig] = Field(
        default_factory=lambda: [DriveConfig.model_validate(item) for item in _copy_default_value("drives")],
        description="Virtual drive metadata.",
    )
    filesystem: FilesystemConfig = Field(
        default_factory=lambda: FilesystemConfig.model_validate(_copy_default_value("filesystem")),
        description="Filesystem mapping rules.",
    )
    registry: RegistryConfig | None = Field(
        default_factory=lambda: RegistryConfig.model_validate(_copy_default_value("registry")),
        description="Registry key and value seed data.",
    )
    network: NetworkConfig = Field(
        default_factory=lambda: NetworkConfig.model_validate(_copy_default_value("network")),
        description="Network emulation settings.",
    )
    processes: list[ProcessConfig] = Field(
        default_factory=lambda: [ProcessConfig.model_validate(item) for item in _copy_default_value("processes")],
        description="Process inventory visible to enumeration APIs.",
    )
    modules: ModulesConfig = Field(
        default_factory=lambda: ModulesConfig.model_validate(_copy_default_value("modules")),
        description="Module loading and inventory settings.",
    )


def model_to_dict(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="python")


def get_default_config() -> SpeakeasyConfig:
    return SpeakeasyConfig()


def get_default_config_dict() -> dict[str, Any]:
    return model_to_dict(get_default_config())
