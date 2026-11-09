# Copyright (C) 2026 Mandiant, Inc. All Rights Reserved.

import ntpath
from typing import TYPE_CHECKING

import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.windows import objman

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator


class Psapi(api.ApiHandler):
    name = "psapi"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        self.funcs = {}
        self.data = {}
        super().__get_hook_attrs__(self)

    def _get_process(self, hProcess) -> objman.Process | None:
        """Get the process of a process handle, else None."""
        return self.emu.get_handle_table().get(hProcess, objman.Process)

    def _get_process_module_bases(self, proc):
        proc_module = proc.pe
        if proc_module:
            return [proc_module.base]

        process_path = proc.path or ""
        process_name = ntpath.basename(process_path)
        module_name = ntpath.splitext(process_name)[0]
        if module_name:
            mod = self.emu.get_mod_by_name(module_name)
            if mod:
                return [mod.base]

        process_base = int(getattr(proc, "base", 0) or 0)
        if process_base:
            return [process_base]

        return []

    def _get_module_base_name(self, proc, hModule):
        if hModule:
            mod = self.emu.get_mod_from_addr(hModule)
            if mod:
                return ntpath.basename(mod.emu_path)

        return ntpath.basename(proc.path or "")

    def _get_module_file_name(self, proc, hModule):
        if hModule:
            mod = self.emu.get_mod_from_addr(hModule)
            if mod:
                return mod.emu_path

        return proc.path or ""

    @apihook("EnumProcesses", argc=3)
    def EnumProcesses(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnumProcesses(
            DWORD *lpidProcess,
            DWORD cb,
            LPDWORD lpcbNeeded
        );
        """
        lpidProcess, cb, lpcbNeeded = argv
        processes = emu.get_processes()

        if not lpidProcess or cb < 4:
            if lpcbNeeded:
                self.write_dword(lpcbNeeded, len(processes) * 4)
            return 1

        count = min(cb // 4, len(processes))
        cursor = lpidProcess
        for process in processes[:count]:
            pid = process.pid or 0
            self.write_dword(cursor, int(pid))
            cursor += 4

        if lpcbNeeded:
            self.write_dword(lpcbNeeded, count * 4)

        return 1

    @apihook("EnumProcessModules", argc=4)
    def EnumProcessModules(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnumProcessModules(
            HANDLE hProcess,
            HMODULE *lphModule,
            DWORD cb,
            LPDWORD lpcbNeeded
        );
        """
        hProcess, lphModule, cb, lpcbNeeded = argv
        proc = self._get_process(hProcess)
        if not proc:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        module_bases = self._get_process_module_bases(proc)
        ptr_size = self.get_ptr_size()

        if lpcbNeeded:
            self.write_dword(lpcbNeeded, len(module_bases) * ptr_size)

        if not lphModule or cb < ptr_size:
            return 1

        count = min(cb // ptr_size, len(module_bases))
        cursor = lphModule
        for module_base in module_bases[:count]:
            self.write_ptr(cursor, int(module_base))
            cursor += ptr_size

        return 1

    @apihook("EnumProcessModulesEx", argc=5)
    def EnumProcessModulesEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnumProcessModulesEx(
            HANDLE hProcess,
            HMODULE *lphModule,
            DWORD cb,
            LPDWORD lpcbNeeded,
            DWORD dwFilterFlag
        );

        The handler ignores dwFilterFlag.
        """
        return self.EnumProcessModules(emu, argv[:4], ctx)

    @apihook("GetModuleBaseName", argc=4)
    def GetModuleBaseName(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetModuleBaseName(
            HANDLE hProcess,
            HMODULE hModule,
            LPTSTR lpBaseName,
            DWORD nSize
        );

        The ANSI variant GetModuleBaseNameA takes LPSTR and writes narrow characters.
        """
        hProcess, hModule, lpBaseName, nSize = argv
        if not lpBaseName or nSize == 0:
            return 0

        proc = self._get_process(hProcess)
        if not proc:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        module_name = self._get_module_base_name(proc, hModule)
        if not module_name:
            return 0

        cw = self.get_char_width(ctx)

        truncated = module_name[: max(nSize - 1, 0)]
        output = self.encode_string(truncated + "\x00", cw)

        self.mem_write(lpBaseName, output)
        return len(truncated)

    @apihook("GetModuleFileNameEx", argc=4)
    def GetModuleFileNameEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetModuleFileNameEx(
            HANDLE hProcess,
            HMODULE hModule,
            LPTSTR lpFilename,
            DWORD nSize
        );

        The ANSI variant GetModuleFileNameExA takes LPSTR and writes narrow characters.
        """
        hProcess, hModule, lpFilename, nSize = argv
        if not lpFilename or nSize == 0:
            return 0

        proc = self._get_process(hProcess)
        if not proc:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        module_path = self._get_module_file_name(proc, hModule)
        if not module_path:
            return 0

        cw = self.get_char_width(ctx)

        truncated = module_path[: max(nSize - 1, 0)]
        output = self.encode_string(truncated + "\x00", cw)

        self.mem_write(lpFilename, output)
        return len(truncated)

    @apihook("GetModuleInformation", argc=4)
    def GetModuleInformation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetModuleInformation(
            HANDLE hProcess,
            HMODULE hModule,
            LPMODULEINFO lpmodinfo,
            DWORD cb
        );
        """
        hProcess, hModule, lpmodinfo, cb = argv
        ptr_size = self.get_ptr_size()
        if cb < ptr_size * 3:
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
            return 0

        proc = self._get_process(hProcess)
        if proc and not hModule:
            hModule = next(iter(self._get_process_module_bases(proc)), 0)
        mod = emu.get_mod_from_addr(hModule) if proc else None
        if not mod or mod.base != hModule:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        info = b"".join(v.to_bytes(ptr_size, "little") for v in (mod.base, mod.image_size, mod.get_ep()))
        self.mem_write(lpmodinfo, info)
        return 1

    @apihook("EnumDeviceDrivers", argc=3)
    def EnumDeviceDrivers(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnumDeviceDrivers(
            LPVOID *lpImageBase,
            DWORD cb,
            LPDWORD lpcbNeeded
        );

        The handler reports no drivers.
        """
        lpImageBase, cb, lpcbNeeded = argv
        if lpcbNeeded:
            self.write_dword(lpcbNeeded, 0)
        return 1
