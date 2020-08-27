# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import base64
import fnmatch
import speakeasy.winenv.defs.registry.reg as regdefs
from speakeasy.errors import RegistryEmuError

HKEY_CLASSES_ROOT = 0x80000000
HKEY_CURRENT_USER = 0x80000001
HKEY_LOCAL_MACHINE = 0x80000002
HKEY_USERS = 0x80000003


class RegValue(object):
    """
    Represents a registry value
    """
    def __init__(self, name, val_type, data):
        self.name = name
        self.type = val_type
        self.data = self.normalize_value(val_type, data)

    def normalize_value(self, val_type, data):
        """
        Convert registry values to python types
        """
        if val_type in (regdefs.REG_EXPAND_SZ, regdefs.REG_MULTI_SZ, regdefs.REG_SZ):
            if not isinstance(data, str):
                raise RegistryEmuError('Invalid registry value expected string')
            return data
        elif val_type in (regdefs.REG_DWORD, regdefs.REG_QWORD):
            if isinstance(data, str):
                return int(data, 0)
            elif isinstance(data, int):
                return data
        elif val_type == regdefs.REG_BINARY:
            # Binary data is expected to be base64'd
            return base64.b64encode(data.encode('utf-8'))
        else:
            return data

    def get_name(self):
        return self.name

    def get_type(self):
        return self.type

    def get_data(self):
        return self.data


class RegKey(object):
    """
    Represents a registry key
    """
    curr_handle = 0x180

    def __init__(self, path):
        self.path = path
        self.values = []

    def get_handle(self):
        hkey = RegKey.curr_handle
        RegKey.curr_handle += 4
        return hkey

    def get_path(self):
        return self.path

    def create_value(self, name, val_type, value):
        val = RegValue(name, val_type, value)
        self.values.append(val)
        return val

    def get_values(self):
        return self.values

    def get_value(self, val_name):
        if not val_name:
            val_name = 'default'
        for v in self.values:
            if val_name.lower() == v.get_name().lower():
                return v


class RegistryManager(object):
    """
    Manages the emulation of the windows registry. This includes creating keys, subkeys and values
    """
    def __init__(self, config=None):
        super(RegistryManager, self).__init__()
        self.reg_handles = {}
        self.keys = []
        self.config = config
        self.reg_tree = []

        for hk in (HKEY_CLASSES_ROOT, HKEY_CURRENT_USER,
                   HKEY_LOCAL_MACHINE, HKEY_USERS):
            path = regdefs.get_hkey_type(hk)
            key = self.create_key(path)
            self.reg_handles.update({hk: key})

    def normalize_reg_path(self, path):
        new = path
        if path:
            roots = ('\\registry\\machine\\', 'hklm\\')
            for r in roots:
                if path.lower().startswith(r):
                    new = 'HKEY_LOCAL_MACHINE\\' + path[len(r):]
                    return new
        return path

    def get_key_from_handle(self, handle):
        return self.reg_handles.get(handle)

    def get_key_from_path(self, path):
        path = self.normalize_reg_path(path)
        for key in self.keys:
            if fnmatch.fnmatch(key.get_path().lower(), path.lower()):
                return key
        return None

    def is_key_a_parent_key(self, path):
        for key in self.keys:
            if key.get_path().lower().startswith(path.lower()):
                return True
        return False

    def get_subkeys(self, key):
        # TODO: once we revamp the registry emulation,
        # make this better

        parent_path = key.get_path()
        subkeys = []
        for k in self.keys:
            test_path = k.get_path()
            if test_path.lower().startswith(parent_path.lower()):
                sub = test_path[len(parent_path):]
                if sub.startswith('\\'):
                    sub = sub[1:]

                end_slash = sub.find('\\')
                if end_slash >= 0:
                    sub = sub[:end_slash]

                if not sub:
                    continue

                subkeys.append(sub)

        return subkeys

    def get_key_from_config(self, path):
        """
        See if the emulator config file contains a handler for the requested registry path
        """
        for key in self.config.get('keys', []):
            if key['path'].lower() == path.lower():
                new_key = RegKey(path)
                for value in key.get('values', []):
                    val_type = value.get('type')
                    vts = regdefs.get_flag_value(val_type)  # noqa

                    val_name = value.get('name', '')
                    data = value.get('data')
                    new_key.create_value(val_name, val_type, data)
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
            return key

        key = RegKey(path)
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
            hnd = key.get_handle()
            self.reg_handles.update({hnd: key})
            return hnd

        # If we are instructed to create the key, do so
        if create or self.is_key_a_parent_key(path):
            key = RegKey(path)
            hnd = key.get_handle()
            self.reg_handles.update({hnd: key})
            self.keys.append(key)
        return hnd
