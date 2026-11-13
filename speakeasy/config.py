from __future__ import annotations

import datetime
import re
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    TypeAdapter,
    field_validator,
    model_validator,
)

_DEFAULT_ENV: dict[str, str] = {
    "comspec": "C:\\Windows\\system32\\cmd.exe",
    "systemroot": "C:\\Windows",
    "windir": "C:\\Windows",
    "temp": "C:\\Windows\\temp",
    "tmp": "C:\\Windows\\temp",
    "userprofile": "C:\\Users\\speakeasy_user",
    "systemdrive": "C:",
    "allusersprofile": "C:\\ProgramData",
    "programdata": "C:\\ProgramData",
    "programfiles": "C:\\Program Files",
    "commonprogramfiles": "C:\\Program Files\\Common Files",
    "public": "C:\\Users\\Public",
    "appdata": "C:\\Users\\speakeasy_user\\AppData\\Roaming",
    "localappdata": "C:\\Users\\speakeasy_user\\AppData\\Local",
    "homedrive": "C:",
    "homepath": "\\Users\\speakeasy_user",
    "username": "speakeasy_user",
    "computername": "speakeasy_host",
    "path": "C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;"
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\",
    "pathext": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
    "os": "Windows_NT",
    "number_of_processors": "2",
}

_DEFAULT_SYMLINKS: list[dict[str, Any]] = [
    {"name": "\\??\\C:", "target": "\\Device\\HarddiskVolume1"},
    {"name": "\\??\\PhysicalDrive0", "target": "\\Device\\Harddisk0\\DR0"},
]

_DEFAULT_DRIVES: list[dict[str, Any]] = [
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
]

_DEFAULT_FILES: list[dict[str, Any]] = [
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

_DEFAULT_REGISTRY_KEYS: list[dict[str, Any]] = [
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
    {
        "path": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost",
        "values": [
            {
                "name": "netsvcs",
                "type": "REG_MULTI_SZ",
                "data": "AeLookupSvc\x00BITS\x00Browser\x00CertPropSvc\x00EventSystem\x00gpsvc\x00"
                "iphlpsvc\x00LanmanServer\x00ProfSvc\x00Schedule\x00SENS\x00ShellHWDetection\x00"
                "Themes\x00Winmgmt\x00wuauserv",
            },
            {"name": "LocalService", "type": "REG_MULTI_SZ", "data": "nsi\x00W32Time\x00WinHttpAutoProxySvc"},
        ],
    },
    {"path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "values": []},
    {"path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "values": []},
    {"path": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "values": []},
    {"path": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "values": []},
]

_DEFAULT_DNS_NAMES: dict[str, str] = {
    "speakeasy_host": "127.0.0.1",
    "default": "10.1.2.3",
    "google.com": "8.8.8.8",
    "localhost": "127.0.0.1",
}

_DEFAULT_DNS_TXT: list[dict[str, Any]] = [{"name": "default", "path": "$ROOT$/resources/web/default.bin"}]

_DEFAULT_HTTP_RESPONSES: list[dict[str, Any]] = [
    {
        "verb": "GET",
        "files": [
            {"mode": "default", "path": "$ROOT$/resources/web/default.bin"},
            {"mode": "by_ext", "ext": "gif", "path": "$ROOT$/resources/web/decoy.gif"},
            {"mode": "by_ext", "ext": "jpg", "path": "$ROOT$/resources/web/decoy.jpg"},
        ],
    }
]

_DEFAULT_WINSOCK_RESPONSES: list[dict[str, Any]] = [{"mode": "default", "path": "$ROOT$/resources/web/stager.bin"}]

_DEFAULT_ADAPTERS: list[dict[str, Any]] = [
    {
        "name": "{00000000-0000-0000-0000-000000000000}",
        "description": "Intel(R) PRO/1000 MT Network Connection",
        "mac_address": "00-13-CE-12-34-56",
        "type": "ethernet",
        "ip_address": "127.0.0.1",
        "subnet_mask": "255.0.0.0",
        "dhcp_enabled": True,
    }
]

_DEFAULT_PROCESSES: list[dict[str, Any]] = [
    {"name": "System", "base_addr": 0x80000000, "pid": 4, "path": "[System Process]"},
    {"name": "smss", "base_addr": 0x05000000, "path": "C:\\Windows\\system32\\smss.exe"},
    {"name": "csrss", "base_addr": 0x05510000, "path": "C:\\Windows\\system32\\csrss.exe"},
    {"name": "wininit", "base_addr": 0x05520000, "path": "C:\\Windows\\system32\\wininit.exe"},
    {"name": "services", "base_addr": 0x05530000, "path": "C:\\Windows\\system32\\services.exe"},
    {"name": "lsass", "base_addr": 0x05540000, "path": "C:\\Windows\\system32\\lsass.exe"},
    {"name": "winlogon", "base_addr": 0x05550000, "path": "C:\\Windows\\system32\\winlogon.exe"},
    {"name": "svchost", "base_addr": 0x05560000, "path": "C:\\Windows\\system32\\svchost.exe"},
    {"name": "outlook", "base_addr": 0x05590000, "path": "C:\\Windows\\system32\\outlook.exe"},
    {"name": "explorer", "base_addr": 0x05570000, "path": "C:\\Windows\\explorer.exe"},
    {
        "name": "main",
        "base_addr": 0x00400000,
        "path": "C:\\Windows\\system32\\svchost.exe",
        "command_line": "svchost.exe",
        "is_main_exe": True,
        "session": 1,
    },
]

_DEFAULT_SYSTEM_MODULES: list[dict[str, Any]] = [
    {"name": "ntoskrnl", "base_addr": 0x803D0000, "path": "C:\\Windows\\system32\\ntoskrnl.exe"},
    {"name": "hal", "base_addr": 0xC1000000, "path": "C:\\Windows\\system32\\hal.dll"},
    {"name": "ntfs", "base_addr": 0xC2000000, "path": "C:\\Windows\\system32\\drivers\\ntfs.sys"},
    {"name": "netio", "base_addr": 0xD4000000, "path": "C:\\Windows\\system32\\drivers\\netio.sys"},
    {
        "name": "volmgr",
        "base_addr": 0xC6000000,
        "path": "C:\\Windows\\system32\\drivers\\volmgr.sys",
        "driver": {"name": "\\Driver\\volmgr", "devices": [{"name": "\\Device\\HarddiskVolume1"}]},
    },
    {
        "name": "disk",
        "base_addr": 0xC3000000,
        "path": "C:\\Windows\\system32\\drivers\\disk.sys",
        "driver": {"name": "\\Driver\\Disk", "devices": [{"name": "\\Device\\Harddisk0\\DR0"}]},
    },
    {
        "name": "tcpip",
        "base_addr": 0xC4000000,
        "path": "C:\\Windows\\system32\\drivers\\tcpip.sys",
        "driver": {"name": "\\Driver\\Tcpip", "devices": [{"name": "\\Device\\Tcp"}]},
    },
    {
        "name": "ndis",
        "base_addr": 0xC7000000,
        "path": "C:\\Windows\\system32\\drivers\\ndis.sys",
        "driver": {"name": "\\Driver\\Ndis", "devices": [{"name": "\\Device\\Ndis"}]},
    },
]

_DEFAULT_USER_MODULES: list[dict[str, Any]] = [
    {"name": "ntdll", "base_addr": 0x7C000000, "path": "C:\\Windows\\system32\\ntdll.dll"},
    {"name": "kernel32", "base_addr": 0x77000000, "path": "C:\\Windows\\system32\\kernel32.dll"},
    {"name": "ws2_32", "base_addr": 0x78C00000, "path": "C:\\Windows\\system32\\ws2_32.dll"},
    {"name": "wininet", "base_addr": 0x7BC00000, "path": "C:\\Windows\\system32\\wininet.dll"},
    {"name": "winhttp", "base_addr": 0x7BA00000, "path": "C:\\Windows\\system32\\winhttp.dll"},
    {"name": "advapi32", "base_addr": 0x78000000, "path": "C:\\Windows\\system32\\advapi32.dll"},
    {"name": "psapi", "base_addr": 0x71000000, "path": "C:\\Windows\\system32\\psapi.dll"},
    {"name": "user32", "base_addr": 0x77D10000, "path": "C:\\Windows\\system32\\user32.dll"},
    {"name": "gdi32", "base_addr": 0x77E10000, "path": "C:\\Windows\\system32\\gdi32.dll"},
    {"name": "msvcrt", "base_addr": 0x77F10000, "path": "C:\\Windows\\system32\\msvcrt.dll"},
    {"name": "dnsapi", "base_addr": 0x78F10000, "path": "C:\\Windows\\system32\\dnsapi.dll"},
    {"name": "shlwapi", "base_addr": 0x67000000, "path": "C:\\Windows\\system32\\shlwapi.dll"},
    {"name": "advpack", "base_addr": 0x68F00000, "path": "C:\\Windows\\system32\\advpack.dll"},
    {"name": "dbghelp", "base_addr": 0x62000000, "path": "C:\\Windows\\system32\\dbghelp.dll"},
    {"name": "shell32", "base_addr": 0x69000000, "path": "C:\\Windows\\system32\\shell32.dll"},
    {"name": "WTSAPI32", "base_addr": 0x63000000, "path": "C:\\Windows\\system32\\WTSAPI32.dll"},
    {"name": "CRYPT32", "base_addr": 0x58000000, "path": "C:\\Windows\\system32\\CRYPT32.dll"},
    {"name": "mscoree", "base_addr": 0x53000000, "path": "C:\\Windows\\system32\\mscoree.dll"},
    {"name": "urlmon", "base_addr": 0x54500000, "path": "C:\\Windows\\system32\\urlmon.dll"},
    {"name": "riched32", "base_addr": 0x56500000, "path": "C:\\Windows\\system32\\riched32.dll"},
    {"name": "userenv", "base_addr": 0x76500000, "path": "C:\\Windows\\system32\\userenv.dll"},
    {"name": "ole32", "base_addr": 0x65500000, "path": "C:\\Windows\\system32\\ole32.dll"},
    {"name": "gdiplus", "base_addr": 0x75500000, "path": "C:\\Windows\\system32\\gdiplus.dll"},
    {"name": "setupapi", "base_addr": 0x55500000, "path": "C:\\Windows\\system32\\setupapi.dll"},
    {"name": "NETAPI32", "base_addr": 0x54400000, "path": "C:\\Windows\\system32\\NETAPI32.dll"},
    {"name": "rpcrt4", "base_addr": 0x53300000, "path": "C:\\Windows\\system32\\Rpcrt4.dll"},
    {"name": "linkinfo", "base_addr": 0x63300000, "path": "C:\\Windows\\system32\\linkinfo.dll"},
    {"name": "EhStorShell", "base_addr": 0x73300000, "path": "C:\\Windows\\system32\\EhStorShell.dll"},
    {"name": "comctl32", "base_addr": 0x5F500000, "path": "C:\\Windows\\system32\\comctl32.dll"},
    {"name": "secur32", "base_addr": 0x5F600000, "path": "C:\\Windows\\system32\\secur32.dll"},
    {"name": "KtmW32", "base_addr": 0x5F700000, "path": "C:\\Windows\\system32\\KtmW32.dll"},
    {"name": "oleaut32", "base_addr": 0x5F800000, "path": "C:\\Windows\\system32\\oleaut32.dll"},
    {"name": "bcrypt", "base_addr": 0x5F900000, "path": "C:\\Windows\\system32\\bcrypt.dll"},
    {"name": "ncrypt", "base_addr": 0x5FA00000, "path": "C:\\Windows\\system32\\ncrypt.dll"},
    {"name": "netutils", "base_addr": 0x5FB00000, "path": "C:\\Windows\\system32\\netutils.dll"},
    {"name": "wkscli", "base_addr": 0x5FC00000, "path": "C:\\Windows\\system32\\wkscli.dll"},
    {"name": "iphlpapi", "base_addr": 0x5FD00000, "path": "C:\\Windows\\system32\\iphlpapi.dll"},
    {"name": "sfc_os", "base_addr": 0x5FE00000, "path": "C:\\Windows\\system32\\sfc_os.dll"},
    {"name": "winmm", "base_addr": 0x5FF00000, "path": "C:\\Windows\\system32\\winmm.dll"},
    {
        "name": "bcryptprimitives",
        "base_addr": 0x60000000,
        "path": "C:\\Windows\\system32\\bcryptprimitives.dll",
    },
    {"name": "version", "base_addr": 0x60100000, "path": "C:\\Windows\\system32\\version.dll"},
]


def parse_start_time(text: str) -> datetime.datetime:
    """
    Parse an ISO 8601 time with a time zone, such as 2026-10-31T15:15:00Z.

    Raises:
        ValueError: if the text has no time zone or is not an ISO 8601 time.
    """
    # Python 3.10 fromisoformat does not accept the Z suffix.
    when = datetime.datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    if when.tzinfo is None:
        raise ValueError(f"start time {text!r} has no time zone")
    return when


def _parse_config_int(value: Any) -> Any:
    """
    Convert a hex string, such as "0x400000", to an int. Other values do not change.

    JSON has no hex numbers, so a config file gives a hex address or size as a string.

    Raises:
        ValueError: if a string does not start with 0x or is not a hex number.
    """
    if not isinstance(value, str):
        return value
    if not value.lower().startswith("0x"):
        raise ValueError(f"{value!r} is not a hex number: use a JSON number, or a string that starts with 0x")
    return int(value, 16)


_Address = Annotated[int, BeforeValidator(_parse_config_int), Field(ge=0), PlainSerializer(hex, when_used="json")]
_Size = Annotated[int, BeforeValidator(_parse_config_int), Field(ge=0)]

_HEX_BYTE = re.compile(r"(0x)?[0-9a-f]{1,2}", re.IGNORECASE)


def _validate_one_data_source(path: str | None, byte_fill: ByteFillConfig | None) -> None:
    """
    Check that a file entry gives its data from exactly one source.

    Raises:
        ValueError: if a file entry has neither or both of path and byte_fill.
    """
    if path is None and byte_fill is None:
        raise ValueError("a file entry needs path or byte_fill")
    if path is not None and byte_fill is not None:
        raise ValueError("a file entry takes path or byte_fill, not both")


class OsVersionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: Literal["windows"] = Field(default="windows", description="Emulated operating system family.")
    major: int | None = Field(default=6, description="Emulated OS major version.")
    minor: int | None = Field(default=1, description="Emulated OS minor version.")
    build: int | None = Field(default=7601, description="Emulated OS build number.")


class UserConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(default="speakeasy_user", description="User name, for example for GetUserName.")
    admin: bool = Field(default=True, description="If true, the token of the user is elevated.")
    sid: str = Field(default="S-1-5-21-1111111111-2222222222-3333333333-1001", description="SID of the emulated user.")


class SymlinkConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(description="Object manager symlink name.")
    target: str = Field(description="Object manager symlink target.")


class DriveConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    root_path: str | None = Field(default=None, description="Root path of the drive, such as C:\\.")
    drive_type: (
        Literal[
            "DRIVE_UNKNOWN",
            "DRIVE_NO_ROOT_DIR",
            "DRIVE_REMOVABLE",
            "DRIVE_FIXED",
            "DRIVE_REMOTE",
            "DRIVE_CDROM",
            "DRIVE_RAMDISK",
        ]
        | None
    ) = Field(default=None, description="Drive type that GetDriveType returns, such as DRIVE_FIXED.")
    volume_guid_path: str | None = Field(default=None, description="Volume GUID path of the drive.")


class ByteFillConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    byte: str = Field(description="Byte that fills the content, in hex, such as 0x41.")
    size: _Size = Field(description="Size of the content in bytes.")

    @field_validator("byte")
    @classmethod
    def validate_byte(cls, v: str) -> str:
        if not _HEX_BYTE.fullmatch(v):
            raise ValueError(f"{v!r} is not a hex byte: use 00 to ff, or 0x00 to 0xff")
        return v


_HOST_PATH_DESCRIPTION = "Host file that gives the data. $ROOT$ is the directory of the speakeasy package."
_BYTE_FILL_DESCRIPTION = "Data that the emulator makes, in place of a host file."


class FileEntryFullPath(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["full_path"] = Field(description="full_path matches the full path.")
    emu_path: str = Field(description="Path that this entry matches. It can have wildcards, such as *.")
    path: str | None = Field(default=None, description=_HOST_PATH_DESCRIPTION)
    byte_fill: ByteFillConfig | None = Field(default=None, description=_BYTE_FILL_DESCRIPTION)

    @model_validator(mode="after")
    def validate_data_source(self) -> FileEntryFullPath:
        _validate_one_data_source(self.path, self.byte_fill)
        return self


class FileEntryByExt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["by_ext"] = Field(description="by_ext matches all paths with the extension ext.")
    ext: str = Field(
        description="File extension that this entry matches, such as exe. Case and a leading dot do not matter."
    )
    path: str | None = Field(default=None, description=_HOST_PATH_DESCRIPTION)
    byte_fill: ByteFillConfig | None = Field(default=None, description=_BYTE_FILL_DESCRIPTION)

    @model_validator(mode="after")
    def validate_data_source(self) -> FileEntryByExt:
        _validate_one_data_source(self.path, self.byte_fill)
        return self

    @field_validator("ext")
    @classmethod
    def normalize_ext(cls, v: str) -> str:
        # The file manager compares the extension of a path in lower case and without the dot.
        return v.removeprefix(".").lower()


class FileEntryDefault(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["default"] = Field(description="default matches all paths that no other entry matches.")
    path: str | None = Field(default=None, description=_HOST_PATH_DESCRIPTION)
    byte_fill: ByteFillConfig | None = Field(default=None, description=_BYTE_FILL_DESCRIPTION)

    @model_validator(mode="after")
    def validate_data_source(self) -> FileEntryDefault:
        _validate_one_data_source(self.path, self.byte_fill)
        return self


FileEntry = Annotated[
    FileEntryFullPath | FileEntryByExt | FileEntryDefault,
    Field(discriminator="mode"),
]
_FILE_ENTRY: TypeAdapter[FileEntry] = TypeAdapter(FileEntry)


class FilesystemConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    files: list[FileEntry] = Field(
        default_factory=lambda: [_FILE_ENTRY.validate_python(item) for item in _DEFAULT_FILES],
        description="Entries that give the content of the files in the emulated file system.",
    )


class RegistryValueConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(description="Value name. default is the unnamed default value.")
    type: Literal["REG_SZ", "REG_EXPAND_SZ", "REG_MULTI_SZ", "REG_BINARY", "REG_DWORD", "REG_QWORD"] = Field(
        description="Value type."
    )
    data: str = Field(description="Value data as a string. REG_DWORD and REG_QWORD data is a number, such as 0x3.")

    @model_validator(mode="after")
    def validate_number_data(self) -> RegistryValueConfig:
        if self.type in ("REG_DWORD", "REG_QWORD"):
            try:
                int(self.data, 0)
            except ValueError:
                raise ValueError(f"{self.type} data {self.data!r} is not a number, such as 0x3") from None
        return self


class RegistryKeyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(description="Registry key path.")
    values: list[RegistryValueConfig] = Field(default_factory=list, description="Values under this key.")


class RegistryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    keys: list[RegistryKeyConfig] = Field(
        default_factory=lambda: [RegistryKeyConfig.model_validate(item) for item in _DEFAULT_REGISTRY_KEYS],
        description="Registry keys and values that exist when emulation starts.",
    )


class DnsTxtConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str | None = Field(
        default=None, description="Domain name of this TXT record. default gives the TXT record of all other names."
    )
    path: str | None = Field(default=None, description="Host file that gives the TXT record.")


class DnsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    names: dict[str, str] = Field(
        default_factory=lambda: dict(_DEFAULT_DNS_NAMES),
        description="IP address of each domain name. default gives the address of all other names.",
    )
    txt: list[DnsTxtConfig] = Field(
        default_factory=lambda: [DnsTxtConfig.model_validate(item) for item in _DEFAULT_DNS_TXT],
        description="Host files that give the TXT records.",
    )


class HttpResponseConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    verb: Literal["GET", "POST", "HEAD"] | None = Field(
        default=None, description="HTTP verb of the requests that these files answer."
    )
    files: list[FileEntry] = Field(
        default_factory=list,
        description="Files that give the response data. by_ext matches the extension of the URL path.",
    )


class HttpConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    responses: list[HttpResponseConfig] = Field(
        default_factory=lambda: [HttpResponseConfig.model_validate(item) for item in _DEFAULT_HTTP_RESPONSES],
        description="Files that give the HTTP response data, by verb.",
    )


class WinsockConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    responses: list[FileEntry] = Field(
        default_factory=lambda: [_FILE_ENTRY.validate_python(item) for item in _DEFAULT_WINSOCK_RESPONSES],
        description="Data that recv gives on a socket. The emulator uses only the default entry.",
    )


class NetworkAdapterConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str | None = Field(default=None, description="Adapter name or GUID.")
    description: str | None = Field(default=None, description="Adapter description string.")
    mac_address: str | None = Field(default=None, description="Adapter MAC address.")
    type: str | None = Field(default=None, description="Adapter media type.")
    ip_address: str | None = Field(default=None, description="Adapter IPv4 address.")
    subnet_mask: str | None = Field(default=None, description="Adapter subnet mask.")
    dhcp_enabled: bool | None = Field(default=None, description="If true, the adapter uses DHCP.")


class NetworkConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    dns: DnsConfig = Field(default_factory=DnsConfig, description="DNS emulation settings.")
    http: HttpConfig = Field(default_factory=HttpConfig, description="HTTP emulation settings.")
    winsock: WinsockConfig = Field(default_factory=WinsockConfig, description="Winsock emulation settings.")
    adapters: list[NetworkAdapterConfig] = Field(
        default_factory=lambda: [NetworkAdapterConfig.model_validate(item) for item in _DEFAULT_ADAPTERS],
        description="Network adapters that APIs such as GetAdaptersInfo give.",
    )


class ProcessConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(description="Process name.")
    base_addr: _Address = Field(description="Base address of the process image.")
    path: str = Field(description="Path of the process image.")
    pid: int | None = Field(default=None, description="Process ID.")
    command_line: str | None = Field(default=None, description="Command line of the process.")
    is_main_exe: bool | None = Field(
        default=None,
        description="If true, this entry gives the container process, in which a DLL or shellcode input runs.",
    )
    session: int | None = Field(default=None, description="Session ID of the process.")


class DeviceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(description="Device object name.")


class DriverConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(description="Driver object name.")
    devices: list[DeviceConfig] = Field(default_factory=list, description="Device objects of the driver.")


class UserModuleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(description="Module name without the extension.")
    base_addr: _Address = Field(description="Module base address.")
    path: str = Field(description="Module path.")


class SystemModuleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(description="Module name without the extension.")
    base_addr: _Address = Field(description="Module base address.")
    path: str = Field(description="Module path.")
    driver: DriverConfig | None = Field(default=None, description="Driver object and device objects of the module.")


class ModulesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    stubs: bool = Field(
        default=True,
        description="If true, the emulator loads an unknown module as an empty API module.",
    )
    directory_x86: str | None = Field(
        default=None, description="Directory of x86 DLLs that the emulator loads in place of the synthetic API modules."
    )
    directory_x64: str | None = Field(
        default=None, description="Directory of x64 DLLs that the emulator loads in place of the synthetic API modules."
    )
    user: list[UserModuleConfig] = Field(
        default_factory=lambda: [UserModuleConfig.model_validate(item) for item in _DEFAULT_USER_MODULES],
        description="User-mode modules that the emulator loads at their base addresses.",
    )
    system: list[SystemModuleConfig] = Field(
        default_factory=lambda: [SystemModuleConfig.model_validate(item) for item in _DEFAULT_SYSTEM_MODULES],
        description="Kernel-mode modules.",
    )


class LimitsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    per_run_time: float = Field(
        default=60,
        ge=0,
        allow_inf_nan=False,
        description="Limit of the execution time of each run, in seconds. 0 disables the limit.",
    )
    total_time: float = Field(
        default=0,
        ge=0,
        allow_inf_nan=False,
        description="Limit of the execution time of all runs in one call of run_module, run_shellcode, call or resume,"
        " in seconds. 0 disables the limit.",
    )
    api_calls: int = Field(default=10000, ge=0, description="Limit of the API calls of each run. 0 disables the limit.")
    api_loop_calls: int = Field(
        default=5000,
        ge=0,
        description="Limit of the API calls of a run with no call from a new call site (API and return address)."
        " The run then ends with an api_loop_limit error. 0 disables the limit.",
    )
    instructions: int = Field(
        default=0, ge=0, description="Limit of the instructions of each run. 0 disables the limit."
    )


class RunsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    exports: bool = Field(
        default=True,
        description="Also run the exports of the PE input. For a driver, also send IRPs to its dispatch functions"
        " and run its unload routine.",
    )
    children: bool = Field(
        default=True,
        description="After the PE input finishes, run the processes that it creates. Not in kernel mode.",
    )
    stack_size: _Size = Field(
        default=0,
        description="Size of the stack of the input in bytes. 0 uses max(SizeOfStackReserve, 0x12000) for a PE,"
        " and the stack_commit argument of run_shellcode (default 0x4000) for shellcode.",
    )


class DynamicCodeContentsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = Field(
        default=True,
        description="Add the contents of each dynamic code region to the report, at the first time that code runs"
        " in it, and again each time that code runs in it after the region changes. Dynamic code is memory that"
        " the guest allocated and then ran. If memory.accesses is off, the emulator then counts each instruction,"
        " so that the position of each snapshot has the instruction count.",
    )
    limit: int = Field(
        default=8,
        ge=1,
        description="Maximum number of snapshots of each dynamic code region in one run, with the first snapshot.",
    )


class MemoryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    accesses: bool = Field(
        default=True,
        description="Add to the report the count of reads, writes and executes of each symbol and memory region."
        " The emulator then hooks each instruction and each memory access.",
    )
    strings: bool = Field(
        default=True,
        description="Add to the report the strings of the input file, and the strings that the guest decoded in"
        " memory.",
    )
    final_contents: bool = Field(
        default=True,
        description="Add to the report the contents of each region of guest memory at the end of each run. The stacks"
        " and the memory of the emulator get no contents. User mode only.",
    )
    dynamic_code_contents: DynamicCodeContentsConfig = Field(
        default_factory=DynamicCodeContentsConfig,
        description="Snapshots of dynamic code regions.",
    )
    freed_regions: bool = Field(
        default=True,
        description="If true, a region that the guest frees stays mapped, so that its data can be read, and each"
        " region in the report has freed. If false, the report leaves out the freed regions.",
    )


class CodeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    coverage: bool = Field(
        default=True, description="Add to the report the address of each instruction that a run executes."
    )


class ApisConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    stubs: bool = Field(
        default=True,
        description="If true, an API without a handler or a declaration resolves to a stub that returns 1.",
    )


class ExceptionsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    dispatch: bool = Field(
        default=True,
        description="Send CPU exceptions to the VEH and SEH handlers of the guest. If false, a fault ends the run.",
    )


class SystemConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("start_time")
    @classmethod
    def validate_start_time(cls, v: str) -> str:
        parse_start_time(v)
        return v

    os_ver: OsVersionConfig = Field(
        default_factory=OsVersionConfig,
        description="Windows version that the PEB and the version APIs give.",
    )
    hostname: str = Field(default="speakeasy_host", description="Host name, for example for GetComputerName.")
    domain: str | None = Field(default="speakeasy_domain", description="Domain or workgroup of the user.")
    start_time: str = Field(
        default="2026-10-31T15:15:00Z",
        description="System time when emulation starts, in ISO 8601 with a time zone."
        " The emulated clock counts from it. The default is fixed so that runs repeat.",
    )
    random_seed: int = Field(
        default=0,
        description="Seed of the random number generator that gives random bytes and GUIDs to the guest.",
    )
    drives: list[DriveConfig] = Field(
        default_factory=lambda: [DriveConfig.model_validate(item) for item in _DEFAULT_DRIVES],
        description="Drives that the drive APIs, such as GetLogicalDrives, give.",
    )
    symlinks: list[SymlinkConfig] = Field(
        default_factory=lambda: [SymlinkConfig.model_validate(item) for item in _DEFAULT_SYMLINKS],
        description="Object manager symbolic links.",
    )


class ProcessEnvironmentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("env")
    @classmethod
    def lowercase_env_names(cls, v: dict[str, str]) -> dict[str, str]:
        # Windows environment variable names are not case-sensitive.
        # A later name wins over an earlier name that differs only in case.
        return {name.lower(): value for name, value in v.items()}

    command_line: str = Field(
        default="svchost.exe myarg1 myarg2",
        description="Command line of the process, for example for GetCommandLine.",
    )
    current_dir: str = Field(
        default="C:\\Windows\\system32",
        description="Current directory of the process.",
    )
    env: dict[str, str] = Field(
        default_factory=lambda: dict(_DEFAULT_ENV),
        description="Environment variables of the process. Names are not case-sensitive.",
    )


class SpeakeasyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    config_version: Literal["2.0"] = Field(default="2.0", description="Configuration schema version.")
    emu_engine: Literal["unicorn"] = Field(
        default="unicorn", description="Emulation engine. The only value is unicorn."
    )
    limits: LimitsConfig = Field(default_factory=LimitsConfig, description="Limits of the runs.")
    runs: RunsConfig = Field(default_factory=RunsConfig, description="The runs that the emulator starts.")
    memory: MemoryConfig = Field(
        default_factory=MemoryConfig,
        description="Memory data that the report collects, and the handling of freed memory.",
    )
    code: CodeConfig = Field(default_factory=CodeConfig, description="Code data that the report collects.")
    apis: ApisConfig = Field(default_factory=ApisConfig, description="Resolution and handling of API calls.")
    modules: ModulesConfig = Field(
        default_factory=ModulesConfig,
        description="Module loading settings and module lists.",
    )
    exceptions: ExceptionsConfig = Field(
        default_factory=ExceptionsConfig,
        description="Exception dispatch settings.",
    )
    system: SystemConfig = Field(
        default_factory=SystemConfig,
        description="Emulated system: OS version, host, clock, random numbers, drives and symbolic links.",
    )
    user: UserConfig = Field(
        default_factory=UserConfig,
        description="User account of the process.",
    )
    process: ProcessEnvironmentConfig = Field(
        default_factory=ProcessEnvironmentConfig,
        description="Command line, current directory and environment of the process.",
    )
    processes: list[ProcessConfig] = Field(
        default_factory=lambda: [ProcessConfig.model_validate(item) for item in _DEFAULT_PROCESSES],
        description="Processes that the process enumeration APIs give, and the container process.",
    )
    filesystem: FilesystemConfig = Field(
        default_factory=FilesystemConfig,
        description="Content of the files in the emulated file system.",
    )
    registry: RegistryConfig = Field(
        default_factory=RegistryConfig,
        description="Registry keys and values that exist when emulation starts.",
    )
    network: NetworkConfig = Field(
        default_factory=NetworkConfig,
        description="Network emulation settings.",
    )


def model_to_dict(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="python")


def get_default_config() -> SpeakeasyConfig:
    return SpeakeasyConfig()


def get_default_config_dict() -> dict[str, Any]:
    return model_to_dict(get_default_config())
