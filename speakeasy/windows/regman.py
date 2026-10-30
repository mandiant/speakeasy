# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

import base64
import fnmatch
from typing import TYPE_CHECKING

import speakeasy.winenv.defs.registry.reg as regdefs
from speakeasy.errors import RegistryEmuError

if TYPE_CHECKING:
    from speakeasy.config import RegistryConfig
    from speakeasy.windows.objman import HandleAllocator

HKEY_CLASSES_ROOT = 0x80000000
HKEY_CURRENT_USER = 0x80000001
HKEY_LOCAL_MACHINE = 0x80000002
HKEY_USERS = 0x80000003

CURRENT_VERSION_KEY = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
WINDOWS_CURRENT_VERSION_KEY = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
PRODUCT_NAMES = {
    (6, 1): "Windows 7 Professional",
    (6, 2): "Windows 8 Pro",
    (6, 3): "Windows 8.1 Pro",
    (10, 0): "Windows 10 Pro",
}


def get_current_version_values(os_ver):
    """
    Get the values of the Windows NT CurrentVersion key that Windows sets for the OS version
    """
    product_name = PRODUCT_NAMES.get((os_ver.major, os_ver.minor))
    if not product_name:
        return []
    # Windows 10 and later keep CurrentVersion at 6.3 and give the real version as numbers
    values = [
        ("ProductName", regdefs.REG_SZ, product_name),
        ("CurrentVersion", regdefs.REG_SZ, "6.3" if os_ver.major >= 10 else f"{os_ver.major}.{os_ver.minor}"),
        ("EditionID", regdefs.REG_SZ, "Professional"),
        ("InstallationType", regdefs.REG_SZ, "Client"),
    ]
    if os_ver.major >= 10:
        values.append(("CurrentMajorVersionNumber", regdefs.REG_DWORD, os_ver.major))
        values.append(("CurrentMinorVersionNumber", regdefs.REG_DWORD, os_ver.minor))
    if os_ver.build is not None:
        values.append(("CurrentBuild", regdefs.REG_SZ, str(os_ver.build)))
        values.append(("CurrentBuildNumber", regdefs.REG_SZ, str(os_ver.build)))
    return values


def get_program_files_values(env, is_x64):
    """
    Get the values of the Windows CurrentVersion key that give the program files directories
    """
    program_files = env.get("programfiles", "C:\\Program Files")
    common_files = env.get("commonprogramfiles", f"{program_files}\\Common Files")
    values = [
        ("ProgramFilesDir", regdefs.REG_SZ, program_files),
        ("CommonFilesDir", regdefs.REG_SZ, common_files),
    ]
    if is_x64:
        values += [
            ("ProgramFilesDir (x86)", regdefs.REG_SZ, env.get("programfiles(x86)", f"{program_files} (x86)")),
            (
                "CommonFilesDir (x86)",
                regdefs.REG_SZ,
                env.get("commonprogramfiles(x86)", f"{program_files} (x86)\\Common Files"),
            ),
            ("ProgramW6432Dir", regdefs.REG_SZ, env.get("programw6432", program_files)),
            ("CommonW6432Dir", regdefs.REG_SZ, common_files),
        ]
    return values


class RegValue:
    """
    Represents a registry value
    """

    def __init__(self, name, val_type, data):
        self.name: str = name
        self.type: int = val_type
        self.data: str | int | bytes | None = self.normalize_value(val_type, data)

    def normalize_value(self, val_type, data):
        """
        Convert registry values to python types
        """
        if val_type in (regdefs.REG_EXPAND_SZ, regdefs.REG_MULTI_SZ, regdefs.REG_SZ):
            if not isinstance(data, str):
                raise RegistryEmuError("Invalid registry value expected string")
            return data
        elif val_type in (regdefs.REG_DWORD, regdefs.REG_QWORD):
            if isinstance(data, str):
                return int(data, 0)
            elif isinstance(data, int):
                return data
        elif val_type == regdefs.REG_BINARY:
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
        Get the data as the registry APIs return it, with strings encoded in
        characters of ``width`` bytes.
        """
        enc = "utf-16le" if width == 2 else "utf-8"
        if self.type in (regdefs.REG_SZ, regdefs.REG_EXPAND_SZ) and isinstance(self.data, str):
            return (self.data + "\x00").encode(enc)
        if self.type == regdefs.REG_MULTI_SZ and isinstance(self.data, str):
            return (self.data + "\x00\x00").encode(enc)
        if self.type == regdefs.REG_DWORD and isinstance(self.data, int):
            return (self.data & 0xFFFFFFFF).to_bytes(4, "little")
        if self.type == regdefs.REG_QWORD and isinstance(self.data, int):
            return (self.data & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        if self.type == regdefs.REG_BINARY and isinstance(self.data, bytes):
            return base64.b64decode(self.data)
        return self.data if isinstance(self.data, bytes) else b""


class RegKey:
    """
    Represents a registry key
    """

    def __init__(self, allocator, path):
        self.allocator: HandleAllocator = allocator
        self.path: str = path
        self.values: list[RegValue] = []

    def get_handle(self):
        return self.allocator.allocate_reg_key_handle()

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
    Manages the emulation of the windows registry. This includes creating keys, subkeys and values
    """

    def __init__(self, allocator, config=None, os_ver=None):
        super().__init__()
        self.reg_handles: dict[int, RegKey] = {}
        self.keys: list[RegKey] = []
        self.config: RegistryConfig | None = config
        self.allocator: HandleAllocator = allocator

        for hk in (HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS):
            path = regdefs.get_hkey_type(hk)
            key = self.create_key(path)
            self.reg_handles.update({hk: key})

        if os_ver:
            self.add_default_values(CURRENT_VERSION_KEY, get_current_version_values(os_ver))

    def add_default_values(self, path, values):
        """
        Add values to a key, except values that the config sets
        """
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

    def get_key_from_handle(self, handle):
        return self.reg_handles.get(regdefs.normalize_hkey(handle))

    def close_key(self, handle) -> bool:
        handle = regdefs.normalize_hkey(handle)
        if handle not in self.reg_handles:
            return False
        if handle not in (HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS):
            del self.reg_handles[handle]
        return True

    def get_key_from_path(self, path):
        path = self.normalize_reg_path(path)
        for key in self.keys:
            if fnmatch.fnmatch(key.get_path().lower(), path.lower()):
                return key
        return None

    def get_key_paths(self):
        """
        Get the paths of the open keys and of the keys in the config
        """
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
        """
        See if the emulator config file contains a handler for the requested registry path
        """
        if not self.config:
            return None
        for key in self.config.keys:
            if key.path.lower() == path.lower():
                new_key = RegKey(self.allocator, path)
                for value in key.values:
                    val_name = value.name or ""
                    new_key.create_value(val_name, regdefs.get_flag_value(value.type), value.data)
                return new_key
        return None

    def create_key(self, path):
        """
        Create a registry key
        """

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

        key = RegKey(self.allocator, path)
        self.keys.append(key)
        return key

    def open_key(self, path, create=False):
        """
        Open or optionally create a registry key
        """
        hnd = None
        path = self.normalize_reg_path(path)
        # Does the key already exist?
        key = self.get_key_from_path(path)
        if key:
            hnd = key.get_handle()
            self.reg_handles.update({hnd: key})
            return hnd

        # Does this key exist in our config
        key = self.get_key_from_config(path)
        if key:
            self.keys.append(key)
            hnd = key.get_handle()
            self.reg_handles.update({hnd: key})
            return hnd

        # If we are instructed to create the key, do so
        if create or self.is_key_a_parent_key(path):
            key = RegKey(self.allocator, path)
            hnd = key.get_handle()
            self.reg_handles.update({hnd: key})
            self.keys.append(key)
        return hnd
