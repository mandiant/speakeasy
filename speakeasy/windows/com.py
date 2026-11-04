# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

import ctypes
from typing import TYPE_CHECKING

import speakeasy.winenv.defs.windows.com as comdefs
from speakeasy.errors import Win32EmuError
from speakeasy.winenv.api.usermode import com_api

if TYPE_CHECKING:
    from speakeasy.config import SpeakeasyConfig


class COM:
    """Build the COM interface vtables in guest memory."""

    def __init__(self, config: SpeakeasyConfig):
        super().__init__()
        self.interfaces: dict[str, comdefs.ComInterface] = {}
        self.config: SpeakeasyConfig = config

    def get_method_callback(self, emu, iface_name, method_name):
        """
        Get the address that a vtable slot of ``iface_name`` holds for ``method_name``.

        A method without a handler gets an address too, so that a call to it goes through handler
        resolution like an API without a handler.
        """
        method = getattr(com_api.ComApi, f"{iface_name}_{method_name}", None)
        func_name = method.__apihook__[0] if method else f"{iface_name}.{method_name}"
        return emu.add_callback(com_api.ComApi.name, func_name)

    def get_interface(self, emu, ptr_size, name):
        """
        Map a vtable for a COM interface, with one method address in each slot.

        Raises:
            Win32EmuError: if the interface is not known, or it has a field of an unsupported type.
        """
        iface = comdefs.IFACE_TYPES.get(name)
        if not iface:
            raise Win32EmuError(f"Invalid COM interface: {name}")

        ci = comdefs.ComInterface(iface, name, ptr_size)
        com_ptr = emu.mem_map(emu.sizeof(ci.iface), tag=f"emu.COM.{name}")
        ci.address = com_ptr

        fields = ci.iface.__dict__["__fields__"]
        field_offset = 0
        for field in fields:
            field_name, field_obj = field
            # A Structure field is an inherited interface, such as IUnknown.
            if issubclass(field_obj, ctypes.Structure):
                if field_name not in comdefs.IFACE_TYPES:
                    raise Win32EmuError(f"COM interface {name} inherits unsupported interface {field_name}")

                for subfield in field_obj._fields_:
                    subfield_name, subfield_type = subfield
                    if issubclass(subfield_type, (ctypes.c_uint32, ctypes.c_ulong, ctypes.c_ulonglong)):
                        addr = self.get_method_callback(emu, field_name, subfield_name)
                        emu.mem_write(com_ptr + field_offset, addr.to_bytes(emu.get_ptr_size(), "little"))

                    field_offset += ptr_size
            elif issubclass(field_obj, (ctypes.c_uint32, ctypes.c_ulong, ctypes.c_ulonglong)):
                addr = self.get_method_callback(emu, name, field_name)
                emu.mem_write(com_ptr + field_offset, addr.to_bytes(emu.get_ptr_size(), "little"))

                field_offset += ptr_size
            else:
                raise Win32EmuError(f"Invalid field type encountered for {name}.{field_name}")

        return ci
