# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

import base64
import fnmatch
from collections.abc import Callable
from typing import TYPE_CHECKING

import speakeasy.winenv.defs.registry.reg as regdefs
from speakeasy.errors import RegistryEmuError
from speakeasy.windows.handles import HandleTable
from speakeasy.winenv.codepage import encode_ansi
from speakeasy.winenv.defs.enums import HKEY, REG_VALUE_TYPE

if TYPE_CHECKING:
    from speakeasy.config import RegistryConfig

CURRENT_VERSION_KEY = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
WINDOWS_CURRENT_VERSION_KEY = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
PRODUCT_NAMES = {
    (6, 1): "Windows 7 Professional",
    (6, 2): "Windows 8 Pro",
    (6, 3): "Windows 8.1 Pro",
    (10, 0): "Windows 10 Pro",
}


def get_current_version_values(os_ver):
    """Get the values of the Windows NT CurrentVersion key that Windows sets for the OS version."""
    product_name = PRODUCT_NAMES.get((os_ver.major, os_ver.minor))
    if not product_name:
        return []
    # Windows 10 and later keep CurrentVersion at 6.3 and give the real version as numbers
    values = [
        ("ProductName", REG_VALUE_TYPE.REG_SZ, product_name),
        ("CurrentVersion", REG_VALUE_TYPE.REG_SZ, "6.3" if os_ver.major >= 10 else f"{os_ver.major}.{os_ver.minor}"),
        ("EditionID", REG_VALUE_TYPE.REG_SZ, "Professional"),
        ("InstallationType", REG_VALUE_TYPE.REG_SZ, "Client"),
    ]
    if os_ver.major >= 10:
        values.append(("CurrentMajorVersionNumber", REG_VALUE_TYPE.REG_DWORD, os_ver.major))
        values.append(("CurrentMinorVersionNumber", REG_VALUE_TYPE.REG_DWORD, os_ver.minor))
    if os_ver.build is not None:
        values.append(("CurrentBuild", REG_VALUE_TYPE.REG_SZ, str(os_ver.build)))
        values.append(("CurrentBuildNumber", REG_VALUE_TYPE.REG_SZ, str(os_ver.build)))
    return values


def get_program_files_values(env, is_x64):
    """Get the values of the Windows CurrentVersion key that give the program files directories."""
    program_files = env.get("programfiles", "C:\\Program Files")
    common_files = env.get("commonprogramfiles", f"{program_files}\\Common Files")
    values = [
        ("ProgramFilesDir", REG_VALUE_TYPE.REG_SZ, program_files),
        ("CommonFilesDir", REG_VALUE_TYPE.REG_SZ, common_files),
    ]
    if is_x64:
        values += [
            ("ProgramFilesDir (x86)", REG_VALUE_TYPE.REG_SZ, env.get("programfiles(x86)", f"{program_files} (x86)")),
            (
                "CommonFilesDir (x86)",
                REG_VALUE_TYPE.REG_SZ,
                env.get("commonprogramfiles(x86)", f"{program_files} (x86)\\Common Files"),
            ),
            ("ProgramW6432Dir", REG_VALUE_TYPE.REG_SZ, env.get("programw6432", program_files)),
            ("CommonW6432Dir", REG_VALUE_TYPE.REG_SZ, common_files),
        ]
    return values


class RegValue:
    """Represents a registry value."""

    def __init__(self, name, val_type, data):
        self.name: str = name
        self.type: int = val_type
        self.data: str | int | bytes | None = self.normalize_value(val_type, data)

    def normalize_value(self, val_type, data):
        """Convert registry values to python types."""
        if val_type in (REG_VALUE_TYPE.REG_EXPAND_SZ, REG_VALUE_TYPE.REG_MULTI_SZ, REG_VALUE_TYPE.REG_SZ):
            if not isinstance(data, str):
                raise RegistryEmuError("Invalid registry value expected string")
            return data
        if val_type in (REG_VALUE_TYPE.REG_DWORD, REG_VALUE_TYPE.REG_QWORD):
            if isinstance(data, str):
                return int(data, 0)
            if isinstance(data, int):
                return data
        elif val_type == REG_VALUE_TYPE.REG_BINARY:
            if isinstance(data, bytes):
                return base64.b64encode(data)
            if isinstance(data, str):
                return base64.b64encode(data.encode("utf-8"))
            raise RegistryEmuError("Invalid registry value expected bytes or string")
        else:
            return data

    def get_name(self):
        return self.name

    def get_type(self):
        return self.type

    def get_data(self):
        return self.data

    def get_bytes(self, width):
        """
        Get the data as the registry APIs return it.

        Strings use characters of ``width`` bytes.
        """
        if self.type in (
            REG_VALUE_TYPE.REG_SZ,
            REG_VALUE_TYPE.REG_EXPAND_SZ,
            REG_VALUE_TYPE.REG_MULTI_SZ,
        ) and isinstance(self.data, str):
            text = self.data + ("\x00\x00" if self.type == REG_VALUE_TYPE.REG_MULTI_SZ else "\x00")
            return text.encode("utf-16le") if width == 2 else encode_ansi(text)
        if self.type == REG_VALUE_TYPE.REG_DWORD and isinstance(self.data, int):
            return (self.data & 0xFFFFFFFF).to_bytes(4, "little")
        if self.type == REG_VALUE_TYPE.REG_QWORD and isinstance(self.data, int):
            return (self.data & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        if self.type == REG_VALUE_TYPE.REG_BINARY and isinstance(self.data, bytes):
            return base64.b64decode(self.data)
        return self.data if isinstance(self.data, bytes) else b""


class RegKey:
    """Represents a registry key."""

    def __init__(self, path):
        self.path: str = path
        self.values: list[RegValue] = []

    def get_path(self):
        return self.path

    def create_value(self, name, val_type, value):
        val = RegValue(name, val_type, value)
        self.values.append(val)
        return val

    def get_values(self):
        return self.values

    def get_value(self, val_name):
        names = (val_name.lower(),) if val_name else ("", "default")
        for v in self.values:
            if v.get_name().lower() in names:
                return v


class RegistryManager:
    """
    Manages the emulation of the windows registry. This includes creating keys, subkeys and values.

    The handles of open keys go into the table that ``get_handle_table`` returns, the table of the
    current process. The predefined keys, such as ``HKEY_LOCAL_MACHINE``, are fixed values and not
    table entries.
    """

    def __init__(self, get_handle_table: Callable[[], HandleTable], config=None, os_ver=None):
        super().__init__()
        self.get_handle_table: Callable[[], HandleTable] = get_handle_table
        self.predefined_keys: dict[int, RegKey] = {}
        self.keys: list[RegKey] = []
        self.config: RegistryConfig | None = config

        for hk in HKEY:
            key = self.create_key(hk.name)
            self.predefined_keys.update({hk: key})

        if os_ver:
            self.add_default_values(CURRENT_VERSION_KEY, get_current_version_values(os_ver))

    def add_default_values(self, path, values):
        """Add values to a key, except values that the config sets."""
        if not values:
            return
        key = self.create_key(path)
        for name, val_type, data in values:
            if not key.get_value(name):
                key.create_value(name, val_type, data)

    def normalize_reg_path(self, path):
        if path:
            roots = ("\\registry\\machine\\", "hklm\\")
            for r in roots:
                if path.lower().startswith(r):
                    path = "HKEY_LOCAL_MACHINE\\" + path[len(r) :]
                    break
            prefix = "hkey_local_machine\\system\\controlset001\\"
            if path.lower().startswith(prefix):
                path = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\" + path[len(prefix) :]
            path = path.rstrip("\\")
        return path

    def get_key(self, handle) -> RegKey | None:
        """Get the key of a predefined key or an open key handle, else None."""
        handle = regdefs.normalize_hkey(handle)
        key = self.predefined_keys.get(handle)
        if key:
            return key
        return self.get_handle_table().get(handle, RegKey)

    def get_key_from_handle(self, handle):
        """Get the key of a predefined key or an open key handle, else None."""
        return self.get_key(handle)

    def close_key(self, handle) -> bool:
        """
        Close an open key handle. Closing a predefined key does nothing.

        Return False if the handle is not a predefined key and does not refer to an open key.
        """
        handle = regdefs.normalize_hkey(handle)
        if handle in self.predefined_keys:
            return True
        if self.get_handle_table().get(handle, RegKey) is None:
            return False
        return self.get_handle_table().close(handle)

    def get_key_from_path(self, path):
        path = self.normalize_reg_path(path)
        for key in self.keys:
            if fnmatch.fnmatch(key.get_path().lower(), path.lower()):
                return key
        return None

    def get_key_paths(self):
        """Get the paths of the open keys and of the keys in the config."""
        paths = [key.get_path() for key in self.keys]
        if self.config:
            paths += [key.path for key in self.config.keys]
        return paths

    def is_key_a_parent_key(self, path):
        prefix = path.lower().rstrip("\\") + "\\"
        return any(p.lower().startswith(prefix) for p in self.get_key_paths())

    def get_subkeys(self, key):
        # TODO: once we revamp the registry emulation,
        # make this better

        parent_path = key.get_path().rstrip("\\") + "\\"
        subkeys: list[str] = []
        for test_path in self.get_key_paths():
            if test_path.lower().startswith(parent_path.lower()):
                sub = test_path[len(parent_path) :]

                end_slash = sub.find("\\")
                if end_slash >= 0:
                    sub = sub[:end_slash]

                if not sub or sub.lower() in (s.lower() for s in subkeys):
                    continue

                subkeys.append(sub)

        return subkeys

    def get_key_from_config(self, path):
        """See if the emulator config file contains a handler for the requested registry path."""
        if not self.config:
            return None
        for key in self.config.keys:
            if key.path.lower() == path.lower():
                new_key = RegKey(path)
                for value in key.values:
                    val_name = value.name or ""
                    new_key.create_value(val_name, REG_VALUE_TYPE.__members__.get(value.type), value.data)
                return new_key
        return None

    def create_key(self, path):
        """Create a registry key."""
        path = self.normalize_reg_path(path)
        # Does this key already exist?
        key = self.get_key_from_path(path)
        if key:
            return key

        # Does this key exist in our config
        key = self.get_key_from_config(path)
        if key:
            self.keys.append(key)
            return key

        key = RegKey(path)
        self.keys.append(key)
        return key

    def open_key(self, path, create=False):
        """Open or optionally create a registry key."""
        hnd = None
        path = self.normalize_reg_path(path)
        # Does the key already exist?
        key = self.get_key_from_path(path)
        if key:
            return self.get_handle_table().new_handle(key)

        # Does this key exist in our config
        key = self.get_key_from_config(path)
        if key:
            self.keys.append(key)
            return self.get_handle_table().new_handle(key)

        # If we are instructed to create the key, do so
        if create or self.is_key_a_parent_key(path):
            key = RegKey(path)
            hnd = self.get_handle_table().new_handle(key)
            self.keys.append(key)
        return hnd
