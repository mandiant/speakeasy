# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.arch as _arch
from speakeasy.errors import ApiEmuError
from speakeasy.winenv.api.kernelmode import ntoskrnl, hal, wdfldr, netio, ndis, fwpkclnt, usbd
from speakeasy.winenv.api.usermode import ws2_32, kernel32, wininet, winhttp, user32, \
                                          advapi32, msvcrt, wtsapi32, mscoree, dnsapi, \
                                          ntdll, crypt32, shell32, shlwapi, advpack, gdi32

API_HANDLERS = (
                    # Kernel mode
                    ('ntoskrnl', ntoskrnl.Ntoskrnl),
                    ('wdfldr', wdfldr.Wdfldr),
                    ('hal', hal.Hal),
                    ('usbd', usbd.Usbd),
                    ('netio', netio.Netio),
                    ('ndis', ndis.Ndis),
                    ('fwpkclnt', fwpkclnt.Fwpkclnt),
                    # User mode
                    ('ws2_32', ws2_32.Ws2_32),
                    ('kernel32', kernel32.Kernel32),
                    ('ntdll', ntdll.Ntdll),
                    ('wininet', wininet.Wininet),
                    ('winhttp', winhttp.WinHttp),
                    ('user32', user32.User32),
                    ('msvcrt', msvcrt.Msvcrt),
                    ('wtsapi32', wtsapi32.WtsApi32),
                    ('advapi32', advapi32.AdvApi32),
                    ('dnsapi', dnsapi.DnsApi),
                    ('mscoree', mscoree.Mscoree),
                    ('crypt32', crypt32.Crypt32),
                    ('shell32', shell32.Shell32),
                    ('shlwapi', shlwapi.Shlwapi),
                    ('advpack', advpack.Advpack),
                    ('gdi32', gdi32.GDI32),
               )


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
