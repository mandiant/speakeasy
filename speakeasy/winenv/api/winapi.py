# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import sys
import inspect

import speakeasy.winenv.arch as _arch
from speakeasy.errors import ApiEmuError
from speakeasy.winenv.api import api
from speakeasy.winenv.api.kernelmode import * # noqa
from speakeasy.winenv.api.usermode import * # noqa


def autoload_api_handlers():
    api_handlers = []

    for modname, modobj in sys.modules.items():
        if not modname.startswith(('speakeasy.winenv.api.kernelmode.',
                                   'speakeasy.winenv.api.usermode.')):
            continue
        for clsname, clsobj in inspect.getmembers(modobj, inspect.isclass):
            if clsobj is not api.ApiHandler and issubclass(clsobj, api.ApiHandler):
                api_handlers.append((clsobj.name, clsobj))

    return tuple(api_handlers)


API_HANDLERS = autoload_api_handlers()


class WindowsApi:

    def __init__(self, emu):
        self.mods = {}
        self.instances = []
        self.data = {}
        self.emu = emu
        arch = self.emu.get_arch()

        if arch == _arch.ARCH_X86:
            self.ptr_size = 4
        elif arch == _arch.ARCH_AMD64:
            self.ptr_size = 8
        else:
            raise ApiEmuError('Invalid architecture')

    def load_api_handler(self, mod_name):
        for name, hdl in API_HANDLERS:
            name = name.lower()
            if mod_name and name == mod_name.lower():
                handler = self.mods.get(name)
                if not handler:
                    handler = hdl(self.emu)
                    self.mods.update({name: handler})
                return handler
        return None

    def get_data_export_handler(self, mod_name, exp_name):
        mod = self.mods.get(mod_name)
        if not mod:
            mod = self.load_api_handler(mod_name)
        if not mod:
            return None, None
        return (mod, mod.get_data_handler(exp_name))

    def get_export_func_handler(self, mod_name, exp_name):
        mod = self.mods.get(mod_name)
        if not mod:
            mod = self.load_api_handler(mod_name)
        if not mod:
            return None, None
        return (mod, mod.get_func_handler(exp_name))

    def call_api_func(self, mod, func, argv, ctx):
        """
        Call the handler to implement the imported API
        """
        return func(mod, self.emu, argv, ctx)

    def call_data_func(self, mod, func, ptr):
        """
        Call the handler to initialize and return imported data variables
        """
        return func(mod, ptr)
