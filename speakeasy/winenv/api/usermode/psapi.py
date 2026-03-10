# Copyright (C) 2026 Mandiant, Inc. All Rights Reserved.

import ntpath

from .. import api


class Psapi(api.ApiHandler):
    name = "psapi"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super().__init__(emu)
        self.funcs = {}
        self.data = {}
        super().__get_hook_attrs__(self)

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
    def EnumProcesses(self, emu, argv, ctx: dict[str, str] | None = None):
        ctx = ctx or {}
        lpidProcess, cb, lpcbNeeded = argv
        processes = emu.get_processes()

        if lpcbNeeded:
            self.mem_write(lpcbNeeded, (len(processes) * 4).to_bytes(4, "little"))

        if not lpidProcess or cb < 4:
            return 1

        count = min(cb // 4, len(processes))
        cursor = lpidProcess
        for process in processes[:count]:
            pid = process.pid or 0
            self.mem_write(cursor, int(pid).to_bytes(4, "little"))
            cursor += 4

        return 1

    @apihook("EnumProcessModules", argc=4)
    def EnumProcessModules(self, emu, argv, ctx: dict[str, str] | None = None):
        ctx = ctx or {}
        hProcess, lphModule, cb, lpcbNeeded = argv
        proc = self.get_object_from_handle(hProcess)
        if not proc:
            return 0

        module_bases = self._get_process_module_bases(proc)
        ptr_size = self.get_ptr_size()

        if lpcbNeeded:
            self.mem_write(lpcbNeeded, (len(module_bases) * ptr_size).to_bytes(4, "little"))

        if not lphModule or cb < ptr_size:
            return 1

        count = min(cb // ptr_size, len(module_bases))
        cursor = lphModule
        for module_base in module_bases[:count]:
            self.mem_write(cursor, int(module_base).to_bytes(ptr_size, "little"))
            cursor += ptr_size

        return 1

    @apihook("GetModuleBaseName", argc=4)
    @apihook("GetModuleBaseNameA", argc=4)
    @apihook("GetModuleBaseNameW", argc=4)
    def GetModuleBaseName(self, emu, argv, ctx: dict[str, str] | None = None):
        ctx = ctx or {}
        hProcess, hModule, lpBaseName, nSize = argv
        if not lpBaseName or nSize == 0:
            return 0

        proc = self.get_object_from_handle(hProcess)
        if not proc:
            return 0

        module_name = self._get_module_base_name(proc, hModule)
        if not module_name:
            return 0

        try:
            cw = self.get_char_width(ctx)
        except Exception:
            cw = 1

        truncated = module_name[: max(nSize - 1, 0)]
        if cw == 1:
            output = truncated.encode("utf-8") + b"\x00"
        else:
            output = truncated.encode("utf-16le") + b"\x00\x00"

        self.mem_write(lpBaseName, output)
        return len(truncated)

    @apihook("GetModuleFileNameEx", argc=4)
    @apihook("GetModuleFileNameExA", argc=4)
    @apihook("GetModuleFileNameExW", argc=4)
    def GetModuleFileNameEx(self, emu, argv, ctx: dict[str, str] | None = None):
        ctx = ctx or {}
        hProcess, hModule, lpFilename, nSize = argv
        if not lpFilename or nSize == 0:
            return 0

        proc = self.get_object_from_handle(hProcess)
        if not proc:
            return 0

        module_path = self._get_module_file_name(proc, hModule)
        if not module_path:
            return 0

        try:
            cw = self.get_char_width(ctx)
        except Exception:
            cw = 1

        truncated = module_path[: max(nSize - 1, 0)]
        if cw == 1:
            output = truncated.encode("utf-8") + b"\x00"
        else:
            output = truncated.encode("utf-16le") + b"\x00\x00"

        self.mem_write(lpFilename, output)
        return len(truncated)
