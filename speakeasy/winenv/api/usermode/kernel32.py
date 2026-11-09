# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
import datetime
import ntpath
import os
import string
import struct
import zlib
from typing import TYPE_CHECKING, Any

import speakeasy.windows.common as winemu
import speakeasy.winenv.arch as e_arch
import speakeasy.winenv.defs.windows.kernel32 as k32defs
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy import common
from speakeasy.errors import FileSystemEmuError, OutOfMemoryError, WindowsEmuError
from speakeasy.profiler_events import EventType
from speakeasy.windows import fileman, objman, seh, thread_context
from speakeasy.windows.api_registry import module_name
from speakeasy.windows.guest_callbacks import GuestCall, get_first_unmapped
from speakeasy.windows.handles import HandleTable
from speakeasy.winenv import codepage
from speakeasy.winenv.defs.enums import (
    COMPUTER_NAME_FORMAT,
    CREATE_TOOLHELP_SNAPSHOT_FLAGS,
    FILE_ACCESS_FLAGS,
    FILE_CREATION_DISPOSITION,
    GET_FILEEX_INFO_LEVELS,
    LCTYPE,
    PAGE_PROTECTION_FLAGS,
    PROCESS_CREATION_FLAGS,
    THREAD_CREATION_FLAGS,
)
from speakeasy.winenv.defs.lookup import decode, decode_flags
from speakeasy.winenv.defs.nt import ddk
from speakeasy.winenv.defs.windows import com as comdefs
from speakeasy.winenv.defs.windows.kernel32 import LCID

from .. import api
from ..compare import Fold, get_string_order
from ..exception_apis import ExceptionApis
from . import shlwapi

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator

LANG_EN_US = 0x409
NORM_IGNORECASE = 0x1
MOVEFILE_REPLACE_EXISTING = 0x1
MOVEFILE_DELAY_UNTIL_REBOOT = 0x4

DUPLICATE_CLOSE_SOURCE = 0x1

FILE_MAP_COPY = 0x0001
FILE_MAP_WRITE = 0x0002
FILE_MAP_READ = 0x0004
FILE_MAP_EXECUTE = 0x0020
FILE_MAP_ALL_ACCESS = 0xF001F

IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020

# TLS_MINIMUM_AVAILABLE + TLS_EXPANSION_SLOTS
TLS_SLOT_COUNT = 64 + 1024

# Unicorn counts host nanoseconds in the time stamp counter, as a 1 GHz processor would
TSC_FREQUENCY = 1_000_000_000

PROCESSOR_COUNT = 2
ALL_PROCESSOR_GROUPS = 0xFFFF

APPMODEL_ERROR_NO_PACKAGE = 15700

PATHCCH_MAX_CCH = 0x8000

ERROR_BAD_ARGUMENTS = 160
ERROR_OLD_WIN_VERSION = 1150

FILE_NAME_OPENED = 0x8
VOLUME_NAME_DOS = 0x0
VOLUME_NAME_GUID = 0x1
VOLUME_NAME_NT = 0x2
VOLUME_NAME_NONE = 0x4
VOLUME_NAME_MASK = 0x7

VER_MINORVERSION = 0x1
VER_MAJORVERSION = 0x2
VER_BUILDNUMBER = 0x4
VER_PLATFORMID = 0x8
VER_SERVICEPACKMINOR = 0x10
VER_SERVICEPACKMAJOR = 0x20
VER_PRODUCT_TYPE = 0x80
VER_CONDITION_MASK = 0x7
VER_COMPARE = {
    1: lambda a, b: a == b,
    2: lambda a, b: a > b,
    3: lambda a, b: a >= b,
    4: lambda a, b: a < b,
    5: lambda a, b: a <= b,
}
SERVICE_PACK_BUILDS = {6001: 1, 6002: 2, 7601: 1}

JobObjectBasicAccountingInformation = 1
JobObjectBasicLimitInformation = 2
JobObjectExtendedLimitInformation = 9

ACPI_PROVIDER = 0x41435049
FIRM_PROVIDER = 0x4649524D
RSMB_PROVIDER = 0x52534D42

VOLUME_SERIAL_NUMBER = 0x6C2E1F4A


def get_smbios_structure(kind: int, handle: int, formatted: bytes, strings: list[str]) -> bytes:
    header = struct.pack("<BBH", kind, 4 + len(formatted), handle)
    text = b"".join(s.encode("ascii") + b"\x00" for s in strings) or b"\x00"
    return header + formatted + text + b"\x00"


def get_raw_smbios_data() -> bytes:
    bios = get_smbios_structure(
        0, 0, struct.pack("<BBHBBQ", 1, 2, 0xF000, 3, 0xFF, 0x08), ["Dell Inc.", "1.20.0", "03/14/2023"]
    )
    uuid = bytes.fromhex("4c4c4544004a3510804bb4c04f4e4433")
    system = get_smbios_structure(
        1,
        1,
        struct.pack("<BBBB16sBBB", 1, 2, 3, 4, uuid, 6, 5, 6),
        ["Dell Inc.", "OptiPlex 7090", "1.0", "7J5D3N3", "0A6F", "OptiPlex"],
    )
    caches = b"".join(
        get_smbios_structure(
            7,
            0x0700 + level - 1,
            struct.pack(
                "<BHHHHHBBBBII", 1, config, size_kb, size_kb, 0x20, 0x20, 0, ecc, cache_type, ways, size_kb, size_kb
            ),
            [f"L{level} Cache"],
        )
        for level, config, size_kb, ecc, cache_type, ways in [
            (1, 0x0180, 384, 4, 4, 9),
            (2, 0x0181, 4096, 5, 5, 7),
            (3, 0x0182, 16384, 5, 5, 8),
        ]
    )
    end = get_smbios_structure(127, 0xFFFF, b"", [])
    tables = bios + system + caches + end
    return struct.pack("<BBBBI", 0, 3, 3, 0, len(tables)) + tables


def is_same_res_identifier(a: int | str, b: int | str) -> bool:
    """Compare two resource types or names as Windows does: integer IDs by value, strings without case."""
    return a == b if isinstance(a, int) else isinstance(b, str) and a.upper() == b.upper()


class Snapshot:
    """Represents a toolhelp snapshot: the process, thread and module lists and the read index of each."""

    def __init__(self, lists):
        self.lists: dict[int, list[Any]] = lists


class IoCompletionPort:
    """Represents an I/O completion port. No I/O completes on it."""


class Kernel32(ExceptionApis, api.ApiHandler):
    """
    Implements exported functions from kernel32.dll
    """

    name = "kernel32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs = {}
        self.data = {}

        self.heaps: list[int] = []
        self.curr_local_atom: int = 0xC000
        self.local_atom_table: dict[int, tuple[str, int]] = {}
        # Find handles are not kernel objects, so CloseHandle does not close them
        self.find_files: HandleTable = HandleTable(emu.handle_allocator, release=lambda obj: None)
        self.find_volumes: HandleTable = HandleTable(emu.handle_allocator, release=lambda obj: None)
        self.tls_count: int = 0
        self.fls_count: int = 0
        self.tick_counter: int = winemu.START_TICK_COUNT
        self.perf_base: int = 0x5FD27D571F - self.tick_counter * 10000
        self.start_time: int = emu.start_time
        self.boot_time: int = self.start_time - self.tick_counter * 10000

        self.startup_info: dict[tuple[objman.Process, int], list[int]] = {}

        self.k32types = k32defs

        super().__get_hook_attrs__(self)

    def get_tick_count(self):
        """
        Advance the tick count by 1 ms and return it.
        """
        self.tick_counter += 1
        return self.tick_counter

    def get_system_time(self):
        """
        Advance the tick count by 1 ms and return the system time as a FILETIME value.
        """
        return self.boot_time + self.get_tick_count() * 10000

    def get_local_time(self) -> datetime.datetime:
        """
        Advance the tick count by 1 ms and return the local time.
        The time zone that GetTimeZoneInformation reports has no bias.
        """
        return winemu.get_datetime_from_filetime(self.get_system_time())

    def get_performance_counter(self):
        """
        Advance the tick count by 1 ms and return the performance counter, which counts 100 ns units.
        """
        self.tick_counter += 1
        return self.perf_base + self.tick_counter * 10000

    def advance_clock(self, millisec):
        """
        Move the tick count, the system time, the performance counter and the time stamp counter forward.
        """
        self.tick_counter += millisec
        self.emu.emu_eng.advance_tsc(millisec * TSC_FREQUENCY // 1000)

    def get_system_time_struct(self, quad):
        st = self.k32types.SYSTEMTIME(self.emu.get_ptr_size())
        dt = winemu.get_datetime_from_filetime(quad)
        st.wYear = dt.year
        st.wMonth = dt.month
        st.wDayOfWeek = dt.isoweekday() % 7
        st.wDay = dt.day
        st.wHour = dt.hour
        st.wMinute = dt.minute
        st.wSecond = dt.second
        st.wMilliseconds = quad // 10000 % 1000
        return st

    def add_local_atom(self, s):
        atom, cnt = self.get_local_atom(s)
        if atom is None:
            self.local_atom_table[self.curr_local_atom] = s, 1
            # this is not accurate, but fast and simple and shouldn't hurt anything
            self.curr_local_atom += 1
            return self.curr_local_atom - 1

        # if the atom already exists, increase its ref count
        self.local_atom_table[atom] = self.local_atom_table[atom][0], cnt + 1
        return atom

    def find_local_atom(self, s):
        atom = None
        for k, v in self.local_atom_table.items():
            if v[0].lower() == s.lower():
                atom = k
                break

        return atom

    # gets atom and its reference count
    def get_local_atom(self, s):
        atom: tuple[int | None, int | None] = None, None
        for k, v in self.local_atom_table.items():
            if v[0].lower() == s.lower():
                atom = k, v[1]
                break

        return atom

    def delete_local_atom(self, atom):
        if atom in self.local_atom_table:
            s, cnt = self.local_atom_table[atom]
            cnt -= 1
            if cnt == 0:
                del self.local_atom_table[atom]
            else:
                self.local_atom_table[atom] = s, cnt

            return True

        return False

    def get_local_atom_name(self, atom):
        return self.local_atom_table.get(atom, (None, None))[0]

    def get_snapshot(self, emu, handle) -> dict[int, list[Any]] | None:
        """Get the lists of an open snapshot handle, or None if the handle does not refer to a snapshot."""
        snapshot = emu.get_handle_table().get(handle, Snapshot)
        return None if snapshot is None else snapshot.lists

    def is_std_handle(self, emu, handle):
        """
        Test if a handle is one of the standard handles of the current process and has no object.

        SetStdHandle can make an open handle a standard handle, and that handle still refers to its
        object.
        """
        proc = emu.get_current_process()
        return (
            proc is not None
            and handle in (proc.stdin, proc.stdout, proc.stderr)
            and handle not in emu.get_handle_table()
        )

    def create_heap(self, emu):
        heap = super().create_heap(emu)
        self.heaps.append(heap)
        return heap

    def _get_process_handle_table(self, emu, hProcess):
        """Get the handle table of the process of a process handle, or None if the handle refers to no process."""
        proc = emu.get_handle_table().get(hProcess, objman.Process)
        if proc is None:
            return None
        if proc is emu.get_current_process():
            return emu.get_handle_table()
        return proc.handles

    def emu_perms_to_win_perms(self, emu_perms):
        if emu_perms & common.PERM_MEM_WRITE:
            if emu_perms & common.PERM_MEM_EXEC:
                new = PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE
            else:
                new = PAGE_PROTECTION_FLAGS.PAGE_READWRITE
        elif emu_perms & common.PERM_MEM_EXEC:
            if emu_perms & common.PERM_MEM_READ:
                new = PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READ
            else:
                new = PAGE_PROTECTION_FLAGS.PAGE_EXECUTE
        elif emu_perms & common.PERM_MEM_READ:
            new = PAGE_PROTECTION_FLAGS.PAGE_READONLY
        else:
            new = PAGE_PROTECTION_FLAGS.PAGE_NOACCESS
        return new

    def get_max_application_address(self, emu):
        return 0x7FFEFFFF if emu.get_ptr_size() == 4 else 0x7FFFFFFEFFFF

    def map_view_access_to_emu_perms(self, desired_access, mapping_protect):
        perms = 0

        if desired_access & (FILE_MAP_READ | FILE_MAP_COPY | FILE_MAP_EXECUTE | FILE_MAP_ALL_ACCESS):
            perms |= common.PERM_MEM_READ
        if desired_access & (FILE_MAP_WRITE | FILE_MAP_COPY | FILE_MAP_ALL_ACCESS):
            perms |= common.PERM_MEM_WRITE
        if desired_access & (FILE_MAP_EXECUTE | FILE_MAP_ALL_ACCESS):
            perms |= common.PERM_MEM_EXEC

        if perms == 0:
            perms = self.win_perms_to_emu_perms(mapping_protect)
            if perms in (0, common.PERM_MEM_NONE):
                perms = common.PERM_MEM_READ

        return perms

    def find_resource(self, pe, name, type_):
        pe_metadata = pe.get_pe_metadata()
        if not pe_metadata:
            return None

        for res in pe_metadata.resources:
            if is_same_res_identifier(type_, res.type_id) and is_same_res_identifier(name, res.id):
                return res

        return None

    @apihook("GetThreadLocale", argc=0)
    def GetThreadLocale(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LCID GetThreadLocale();
        """
        return 0xC000

    @apihook("SetThreadLocale", argc=1)
    def SetThreadLocale(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetThreadLocale(
            LCID Locale
        );
        """
        (Locale,) = argv
        return Locale

    @apihook("IsValidLocale", argc=2)
    def IsValidLocale(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsValidLocale(
            LCID Locale,
            DWORD dwFlags
        );
        """
        Locale, dwFlags = argv
        return True

    @apihook("OutputDebugString", argc=1)
    def OutputDebugString(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID OutputDebugString(
            LPCTSTR lpOutputString
        );
        """
        (lpOutputString,) = argv
        cw = self.get_char_width(ctx)
        ctx.args["lpOutputString"].display = self.read_mem_string(lpOutputString, cw)

    @apihook("GetThreadTimes", argc=5)
    def GetThreadTimes(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetThreadTimes(
            HANDLE hThread,
            LPFILETIME lpCreationTime,
            LPFILETIME lpExitTime,
            LPFILETIME lpKernelTime,
            LPFILETIME lpUserTime
        );
        """
        hThread, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime = argv

        if lpCreationTime:
            self.mem_write(lpCreationTime, b"\x20\x20\x00\x00")
        return True

    @apihook("GetProcessTimes", argc=5)
    def GetProcessTimes(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetProcessTimes(
            HANDLE hProcess,
            LPFILETIME lpCreationTime,
            LPFILETIME lpExitTime,
            LPFILETIME lpKernelTime,
            LPFILETIME lpUserTime
        );
        """
        hProcess, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime = argv

        proc = emu.get_handle_table().get(hProcess, objman.Process)
        if not proc:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return False

        if proc is emu.get_current_process():
            creation = self.start_time
        else:
            # Other processes started shortly after boot
            creation = self.boot_time + 50000000
        times = ((lpCreationTime, creation), (lpExitTime, 0), (lpKernelTime, 156250), (lpUserTime, 312500))
        for ptr, value in times:
            if ptr:
                self.write_qword(ptr, value)
        return True

    @apihook("GetProcessHeap", argc=0)
    def GetProcessHeap(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE GetProcessHeap();
        """
        if not self.heaps:
            heap = self.create_heap(emu)
        else:
            heap = self.heaps[0]
        return heap

    @apihook("GetProcessVersion", argc=1)
    def GetProcessVersion(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetProcessVersion(
            DWORD ProcessId
        );
        """
        ver = self.emu.config.os_ver
        major = ver.major or 0
        minor = ver.minor or 0

        rv = 0xFFFFFFFF & (major << 16 | minor)

        return rv

    @apihook("DisableThreadLibraryCalls", argc=1)
    def DisableThreadLibraryCalls(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL DisableThreadLibraryCalls(
            HMODULE hLibModule
        );
        """
        (hLibModule,) = argv

        return True

    @apihook("CreateMutex", argc=3)
    def CreateMutex(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE CreateMutex(
            LPSECURITY_ATTRIBUTES lpMutexAttributes,
            BOOL bInitialOwner,
            LPCTSTR lpName
        );
        """
        lpMutexAttributes, bInitialOwner, lpName = argv

        cw = self.get_char_width(ctx)

        name = self.read_mem_string(lpName, cw) if lpName else 0

        obj = self.get_object_from_name(name)

        hnd = 0
        if obj:
            hnd = emu.get_object_handle(obj)
            emu.set_last_error(windefs.ERROR_ALREADY_EXISTS)
        else:
            emu.set_last_error(windefs.ERROR_SUCCESS)
            hnd, evt = emu.create_mutant(name)

        ctx.args["lpName"].display = name
        return hnd

    @apihook("CreateMutexEx", argc=4)
    def CreateMutexEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE CreateMutexEx(
            LPSECURITY_ATTRIBUTES lpMutexAttributes,
            LPCTSTR lpName,
            DWORD dwFlags,
            DWORD dwDesiredAccess
        );
        """
        lpMutexAttributes, lpName, dwFlags, dwDesiredAccess = argv

        cw = self.get_char_width(ctx)

        name = self.read_mem_string(lpName, cw) if lpName else 0

        obj = self.get_object_from_name(name)

        hnd = 0
        if obj:
            hnd = emu.get_object_handle(obj)
            emu.set_last_error(windefs.ERROR_ALREADY_EXISTS)
        else:
            emu.set_last_error(windefs.ERROR_SUCCESS)
            hnd, evt = emu.create_mutant(name)

        ctx.args["lpName"].display = name
        return hnd

    @apihook("LoadLibrary", argc=1)
    def LoadLibrary(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HMODULE LoadLibrary(
            LPCTSTR lpLibFileName
        );
        """
        (lpLibFileName,) = argv
        hmod = windefs.NULL

        cw = self.get_char_width(ctx)
        req_lib = self.read_mem_string(lpLibFileName, cw)
        lib = winemu.normalize_dll_name(req_lib)

        hmod = emu.load_library(lib)
        ctx.args["lpLibFileName"].display = req_lib

        return hmod

    @apihook("CreateToolhelp32Snapshot", argc=2)
    def CreateToolhelp32Snapshot(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE CreateToolhelp32Snapshot(
            DWORD dwFlags,
            DWORD th32ProcessID
        );
        """
        (
            dwFlags,
            th32ProcessID,
        ) = argv
        processes, threads, modules, pid = [], [], [], 0
        if dwFlags & (
            CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPTHREAD | CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPMODULE
        ):
            if th32ProcessID in [0, emu.get_current_process().pid]:
                proc = emu.get_current_process()
            else:
                proc = next((p for p in emu.get_processes() if p.pid == th32ProcessID), None)
            if proc is None:
                # Windows ignores the PID of a snapshot without a module list
                if dwFlags & CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPMODULE:
                    emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
                    return self.get_max_int()
                proc = emu.get_current_process()
            pid = proc.pid
            if dwFlags & CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPTHREAD:
                threads = proc.threads
            if dwFlags & CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPMODULE:
                modules = emu.get_peb_modules()
        if dwFlags & CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPPROCESS:
            processes = emu.get_processes()

        # TH32CS_SNAPHEAPLIST is not emulated, so a snapshot never has a heap list
        hnd = emu.get_handle_table().new_handle(
            Snapshot(
                {
                    CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPPROCESS: [0, processes],
                    CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPTHREAD: [0, threads, pid],
                    CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPMODULE: [0, modules, pid],
                }
            )
        )

        ctx.args["dwFlags"].display = decode(CREATE_TOOLHELP_SNAPSHOT_FLAGS, dwFlags)

        return hnd

    def _get_parent_pid(self, emu, proc):
        parents = {
            "smss": "system",
            "csrss": "smss",
            "wininit": "smss",
            "winlogon": "smss",
            "services": "wininit",
            "lsass": "wininit",
            "svchost": "services",
            "explorer": "winlogon",
        }
        if proc.pid == 4:
            return 0
        parent = parents.get(proc.name.lower(), "explorer")
        return next((p.pid for p in emu.get_processes() if p.name.lower() == parent), 0)

    def _write_process_entry(self, emu, ctx, pe32, proc):
        cw = self.get_char_width(ctx)
        pe = self.k32types.PROCESSENTRY32(emu.get_ptr_size(), cw)
        pe.dwSize = self.read_dword(pe32)
        pe.th32ProcessID = proc.pid
        pe.cntThreads = max(len(proc.threads), 1)
        pe.th32ParentProcessID = self._get_parent_pid(emu, proc)
        pe.pcPriClassBase = 8
        pe.szExeFile = self.encode_string(proc.image[: k32defs.MAX_PATH - 1], cw) + b"\x00" * cw
        self.mem_write(pe32, self.get_bytes(pe))

    @apihook("Process32First", argc=2)
    def Process32First(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL Process32First(
            HANDLE hSnapshot,
            LPPROCESSENTRY32 lppe
        );
        """
        (
            hSnapshot,
            lppe,
        ) = argv
        rv = False

        snap = self.get_snapshot(emu, hSnapshot)
        if snap is None:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return rv
        if not lppe or CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPPROCESS not in snap:
            return rv

        # Reset the handle index
        snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPPROCESS][0] = 1
        if not snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPPROCESS][1]:
            emu.set_last_error(windefs.ERROR_NO_MORE_FILES)
            return rv
        proc = snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPPROCESS][1][0]

        self._write_process_entry(emu, ctx, lppe, proc)
        return True

    @apihook("Process32Next", argc=2)
    def Process32Next(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL Process32Next(
            HANDLE hSnapshot,
            LPPROCESSENTRY32 lppe
        );
        """
        (
            hSnapshot,
            lppe,
        ) = argv
        rv = False

        snap = self.get_snapshot(emu, hSnapshot)
        if snap is None:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return rv
        if not lppe or CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPPROCESS not in snap:
            return rv

        index = snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPPROCESS][0]
        snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPPROCESS][0] += 1
        if index >= len(snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPPROCESS][1]):
            emu.set_last_error(windefs.ERROR_NO_MORE_FILES)
            return rv
        proc = snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPPROCESS][1][index]

        self._write_process_entry(emu, ctx, lppe, proc)
        return True

    @apihook("Thread32First", argc=2)
    def Thread32First(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL Thread32First(
            HANDLE hSnapshot,
            LPTHREADENTRY32 lpte
        );
        """
        (
            hSnapshot,
            lpte,
        ) = argv
        rv = False

        snap = self.get_snapshot(emu, hSnapshot)
        if snap is None:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return rv
        if not lpte or CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPTHREAD not in snap:
            return rv

        # Reset the handle index
        snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPTHREAD][0] = 1
        if not snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPTHREAD][1]:
            emu.set_last_error(windefs.ERROR_NO_MORE_FILES)
            return rv
        thread = snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPTHREAD][1][0]

        te = self.k32types.THREADENTRY32(emu.get_ptr_size())
        data = self.mem_cast(te, lpte)
        te.th32ThreadID = thread.tid
        te.th32OwnerProcessID = snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPTHREAD][2]

        self.mem_write(lpte, self.get_bytes(data))
        rv = True
        return rv

    @apihook("Thread32Next", argc=2)
    def Thread32Next(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL Thread32Next(
            HANDLE hSnapshot,
            LPTHREADENTRY32 lpte
        );
        """
        (
            hSnapshot,
            lpte,
        ) = argv
        rv = False

        snap = self.get_snapshot(emu, hSnapshot)
        if snap is None:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return rv
        if not lpte or CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPTHREAD not in snap:
            return rv

        index = snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPTHREAD][0]
        snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPTHREAD][0] += 1
        if index >= len(snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPTHREAD][1]):
            emu.set_last_error(windefs.ERROR_NO_MORE_FILES)
            return rv
        thread = snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPTHREAD][1][index]

        te = self.k32types.THREADENTRY32(emu.get_ptr_size())
        data = self.mem_cast(te, lpte)
        te.th32ThreadID = thread.tid
        te.th32OwnerProcessID = snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPTHREAD][2]

        self.mem_write(lpte, self.get_bytes(data))
        rv = True
        return rv

    def _write_module_entry(self, emu, ctx, mod32, module, pid):
        cw = self.get_char_width(ctx)
        mod = self.k32types.MODULEENTRY32(emu.get_ptr_size(), cw)
        data = self.mem_cast(mod, mod32)
        mod.th32ProcessID = pid
        mod.modBaseAddr = module.base
        mod.modBaseSize = module.image_size
        mod.hModule = module.base
        mod.szModule = self.encode_string(module.name[: k32defs.MAX_MODULE_NAME32], cw) + b"\x00" * cw
        mod.szExePath = self.encode_string(module.emu_path[: k32defs.MAX_PATH - 1], cw) + b"\x00" * cw
        self.mem_write(mod32, self.get_bytes(data))

    @apihook("Module32First", argc=2)
    def Module32First(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL Module32First(
            HANDLE hSnapshot,
            LPMODULEENTRY32 lpme
        );
        """
        (
            hSnapshot,
            lpme,
        ) = argv
        rv = False

        snap = self.get_snapshot(emu, hSnapshot)
        if snap is None:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return rv
        if not lpme or CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPMODULE not in snap:
            return rv

        # Reset the handle index
        snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPMODULE][0] = 1
        if not snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPMODULE][1]:
            emu.set_last_error(windefs.ERROR_NO_MORE_FILES)
            return rv
        module = snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPMODULE][1][0]

        self._write_module_entry(emu, ctx, lpme, module, snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPMODULE][2])
        return True

    @apihook("Module32Next", argc=2)
    def Module32Next(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL Module32Next(
            HANDLE hSnapshot,
            LPMODULEENTRY32 lpme
        );
        """
        (
            hSnapshot,
            lpme,
        ) = argv
        rv = False

        snap = self.get_snapshot(emu, hSnapshot)
        if snap is None:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return rv
        if not lpme or CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPMODULE not in snap:
            return rv

        index = snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPMODULE][0]
        snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPMODULE][0] += 1
        if index >= len(snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPMODULE][1]):
            emu.set_last_error(windefs.ERROR_NO_MORE_FILES)
            return rv
        module = snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPMODULE][1][index]
        self._write_module_entry(emu, ctx, lpme, module, snap[CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPMODULE][2])
        return True

    @apihook("OpenProcess", argc=3)
    def OpenProcess(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE OpenProcess(
            DWORD dwDesiredAccess,
            BOOL bInheritHandle,
            DWORD dwProcessId
        );
        """
        dwDesiredAccess, bInheritHandle, dwProcessId = argv

        hnd = emu.open_process(dwProcessId)
        if not hnd:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        emu.set_last_error(windefs.ERROR_SUCCESS)
        return hnd

    @apihook("OpenMutex", argc=3)
    def OpenMutex(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE OpenMutex(
            DWORD dwDesiredAccess,
            BOOL bInheritHandle,
            LPCTSTR lpName
        );
        """
        dwDesiredAccess, bInheritHandle, lpName = argv

        cw = self.get_char_width(ctx)

        if not lpName:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        obj_name = self.read_mem_string(lpName, cw)
        ctx.args["lpName"].display = obj_name

        obj = self.get_object_from_name(obj_name)

        hnd = 0
        if obj:
            hnd = emu.get_object_handle(obj)
        else:
            emu.set_last_error(windefs.ERROR_FILE_NOT_FOUND)
        return hnd

    @apihook("TerminateProcess", argc=2)
    def TerminateProcess(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL TerminateProcess(
            HANDLE hProcess,
            UINT uExitCode
        );
        """
        hProcess, uExitCode = argv

        proc = emu.get_handle_table().get(hProcess, objman.Process)
        if not proc:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return False

        if proc is emu.get_current_process():
            self.exit_process()
            return True

        emu.kill_process(proc)
        return True

    @apihook("FreeLibraryAndExitThread", argc=2)
    def FreeLibraryAndExitThread(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID FreeLibraryAndExitThread(
            HMODULE hLibModule,
            DWORD dwExitCode
        );
        """
        hLibModule, dwExitCode = argv
        emu.exit_thread(dwExitCode)

    @apihook("ExitThread", argc=1)
    def ExitThread(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID ExitThread(
            DWORD dwExitCode
        );
        """
        (dwExitCode,) = argv
        emu.exit_thread(dwExitCode)

    @apihook("WinExec", argc=2)
    def WinExec(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT WinExec(
            LPCSTR lpCmdLine,
            UINT uCmdShow
        );
        """
        lpCmdLine, uCmdShow = argv
        rv = 1

        if lpCmdLine:
            cmd = self.read_mem_string(lpCmdLine, 1)
            ctx.args["lpCmdLine"].display = cmd
            try:
                proc = emu.create_process(cmdline=cmd)
            except IsADirectoryError:
                return windefs.ERROR_ACCESS_DENIED
            except FileSystemEmuError:
                return windefs.ERROR_FILE_NOT_FOUND
            self.record_process_event(proc, EventType.PROCESS_CREATE)
            rv = 32

        return rv

    @apihook("LoadLibraryEx", argc=3)
    def LoadLibraryEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HMODULE LoadLibraryEx(
            LPCTSTR lpLibFileName,
            HANDLE hFile,
            DWORD dwFlags
        );
        """
        lpLibFileName, hFile, dwFlags = argv

        hmod = 0

        cw = self.get_char_width(ctx)
        req_lib = self.read_mem_string(lpLibFileName, cw)
        lib = winemu.normalize_dll_name(req_lib)

        hmod = emu.load_library(lib)

        flags = {
            0x1: "DONT_RESOLVE_DLL_REFERENCES",
            0x10: "LOAD_IGNORE_CODE_AUTHZ_LEVEL",
            0x2: "LOAD_LIBRARY_AS_DATAFILE",
            0x40: "LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE",
            0x20: "LOAD_LIBRARY_AS_IMAGE_RESOURCE",
            0x200: "LOAD_LIBRARY_SEARCH_APPLICATION_DIR",
            0x1000: "LOAD_LIBRARY_SEARCH_DEFAULT_DIRS",
            0x100: "LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR",
            0x800: "LOAD_LIBRARY_SEARCH_SYSTEM32",
            0x400: "LOAD_LIBRARY_SEARCH_USER_DIRS",
            0x8: "LOAD_WITH_ALTERED_SEARCH_PATH",
        }

        pretty_flags = " | ".join([name for bit, name in flags.items() if dwFlags & bit])

        ctx.args["lpLibFileName"].display = req_lib
        ctx.args["dwFlags"].display = pretty_flags

        if not hmod:
            emu.set_last_error(windefs.ERROR_MOD_NOT_FOUND)

        return hmod

    @apihook("CreateProcessInternal", argc=12)
    def CreateProcessInternal(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CreateProcessInternal(
            HANDLE hUserToken,
            LPCTSTR lpApplicationName,
            LPTSTR lpCommandLine,
            LPSECURITY_ATTRIBUTES lpProcessAttributes,
            LPSECURITY_ATTRIBUTES lpThreadAttributes,
            BOOL bInheritHandles,
            DWORD dwCreationFlags,
            LPVOID lpEnvironment,
            LPCTSTR lpCurrentDirectory,
            LPSTARTUPINFO lpStartupInfo,
            LPPROCESS_INFORMATION lpProcessInformation,
            HANDLE *hRestrictedUserToken
        );
        """
        # Args are the same as CreateProcess except for argv[0] and argv[-1]
        _argv = argv[1:-1]
        rv = self.CreateProcess(emu, _argv, ctx)
        app, cmd, flags = _argv[0], _argv[1], _argv[5]
        cw = self.get_char_width(ctx)
        if app:
            ctx.args[1].display = self.read_mem_string(app, cw)
        if cmd:
            ctx.args[2].display = self.read_mem_string(cmd, cw)
        ctx.args[6].display = decode(PROCESS_CREATION_FLAGS, flags)
        return rv

    @apihook("CreateProcess", argc=10)
    def CreateProcess(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CreateProcess(
            LPCTSTR lpApplicationName,
            LPTSTR lpCommandLine,
            LPSECURITY_ATTRIBUTES lpProcessAttributes,
            LPSECURITY_ATTRIBUTES lpThreadAttributes,
            BOOL bInheritHandles,
            DWORD dwCreationFlags,
            LPVOID lpEnvironment,
            LPCTSTR lpCurrentDirectory,
            LPSTARTUPINFO lpStartupInfo,
            LPPROCESS_INFORMATION lpProcessInformation
        );
        """
        (
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation,
        ) = argv

        cw = self.get_char_width(ctx)
        cmdstr = ""
        appstr = ""
        cdstr = ""
        if lpApplicationName:
            appstr = self.read_mem_string(lpApplicationName, cw)
            ctx.args["lpApplicationName"].display = appstr
        if lpCommandLine:
            cmdstr = self.read_mem_string(lpCommandLine, cw)
            ctx.args["lpCommandLine"].display = cmdstr
        if lpCurrentDirectory:
            cdstr = self.read_mem_string(lpCurrentDirectory, cw)
            ctx.args["lpCurrentDirectory"].display = cdstr

        ctx.args["dwCreationFlags"].display = decode(PROCESS_CREATION_FLAGS, dwCreationFlags)

        try:
            proc = emu.create_process(path=appstr, cmdline=cmdstr, child=True, cd=cdstr)
        except IsADirectoryError:
            emu.set_last_error(windefs.ERROR_ACCESS_DENIED)
            return 0
        except FileSystemEmuError:
            emu.set_last_error(windefs.ERROR_FILE_NOT_FOUND)
            return 0
        proc_hnd = self.get_object_handle(proc)

        thread = proc.threads[0]
        thread_hnd = self.get_object_handle(thread)

        if dwCreationFlags & PROCESS_CREATION_FLAGS.CREATE_SUSPENDED:
            thread.suspend_count = 1

        _pi = self.k32types.PROCESS_INFORMATION(emu.get_ptr_size())
        data = self.mem_cast(_pi, lpProcessInformation)
        _pi.hProcess = proc_hnd
        _pi.hThread = thread_hnd
        _pi.dwProcessId = proc.id
        _pi.dwThreadId = thread.tid

        self.mem_write(lpProcessInformation, self.get_bytes(data))

        rv = 1

        self.record_process_event(proc, EventType.PROCESS_CREATE)
        return rv

    def commit_pages(self, emu, mm, address, size, protect):
        """Apply the protection of a commit to the pages of an existing allocation, and return the first page."""
        base = address & ~0xFFF
        end = min((address + size + 0xFFF) & ~0xFFF, mm.base + mm.size)
        perms = self.win_perms_to_emu_perms(protect)
        emu.clear_guard_pages(base, end - base)
        emu.mem_protect(base, end - base, perms)
        if protect & PAGE_PROTECTION_FLAGS.PAGE_GUARD:
            emu.set_guard_pages(base, end - base, perms)
        return base

    @apihook("VirtualAlloc", argc=4)
    def VirtualAlloc(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPVOID VirtualAlloc(
            LPVOID lpAddress,
            SIZE_T dwSize,
            DWORD flAllocationType,
            DWORD flProtect
        );
        """
        lpAddress, dwSize, flAllocationType, flProtect = argv
        buf = 0
        tag_prefix = "api.VirtualAlloc"

        prot_def = decode_flags(PAGE_PROTECTION_FLAGS, flProtect)
        ctx.args["flProtect"].display = "|".join(prot_def)

        # Was this address already commited?
        mm = emu.get_address_map(lpAddress)
        if mm and mm.tag and mm.tag.startswith(tag_prefix):
            buf = lpAddress
            if flAllocationType & windefs.MEM_COMMIT:
                buf = self.commit_pages(emu, mm, lpAddress, dwSize, flProtect)
        elif dwSize:
            if lpAddress:
                test = lpAddress & 0xFFFFFFFFFFFFF000
            else:
                # This is an arbitrary base address and will be
                # auto-adjusted by the memory manager
                test = emu.virtual_mem_base
            size = dwSize
            try:
                base, size = emu.get_valid_ranges(size, addr=test)
            except OutOfMemoryError:
                emu.set_last_error(windefs.ERROR_NOT_ENOUGH_MEMORY)
                return 0
            if lpAddress and base != test:
                emu.set_last_error(windefs.ERROR_INVALID_ADDRESS)
                return 0
            while base and base & 0xFFF:
                base, size = emu.get_valid_ranges(size, addr=test)
                test += e_arch.PAGE_SIZE

            emu_perms = self.win_perms_to_emu_perms(flProtect)
            buf = self.mem_alloc(base=base, size=size, tag=tag_prefix, flags=flProtect, perms=emu_perms)
            if flProtect & PAGE_PROTECTION_FLAGS.PAGE_GUARD:
                emu.set_guard_pages(buf, size, emu_perms)

            proc = emu.get_current_process()
            if proc:
                self.record_process_event(
                    proc,
                    EventType.MEM_ALLOC,
                    base=buf,
                    size=dwSize,
                    type=flAllocationType,
                    protect=prot_def or None,
                )

            emu._set_dyn_code_hook(buf, size)

            # In the wild, I noticed some x64 malware samples that
            # will rely on the new buffer pointer being placed into the first
            # location in the x64 register backup on the stack (performed by
            # the Windows API). Let's do that here.
            arch = emu.get_arch()
            if arch == e_arch.ARCH_AMD64:
                sp = emu.get_stack_ptr()
                p = buf.to_bytes(8, "little")
                self.mem_write(sp + 8, p)

        return buf

    @apihook("VirtualAllocEx", argc=5)
    def VirtualAllocEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPVOID VirtualAllocEx(
            HANDLE hProcess,
            LPVOID lpAddress,
            SIZE_T dwSize,
            DWORD flAllocationType,
            DWORD flProtect
        );
        """
        hProcess, lpAddress, dwSize, flAllocationType, flProtect = argv
        flProtect &= 0xFFFFFFFF
        buf = 0

        obj = emu.get_handle_table().get(hProcess, objman.Process)
        if not obj:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return windefs.NULL

        proc_path = obj.path
        ctx.args["hProcess"].display = proc_path
        proc_path = ntpath.basename(proc_path)
        proc_path = proc_path.replace(".", "_")

        tag_prefix = f"api.VirtualAllocEx.{proc_path}.{obj.pid}"

        prot_def = decode_flags(PAGE_PROTECTION_FLAGS, flProtect)
        ctx.args["flProtect"].display = "|".join(prot_def)

        # Was this address already commited?
        mm = emu.get_address_map(lpAddress)
        if mm and mm.tag and mm.tag.startswith(tag_prefix):
            buf = lpAddress
            if flAllocationType & windefs.MEM_COMMIT:
                buf = self.commit_pages(emu, mm, lpAddress, dwSize, flProtect)
        elif dwSize:
            if lpAddress:
                test = lpAddress & 0xFFFFFFFFFFFFF000
            else:
                test = emu.virtual_mem_base
            size = dwSize
            base, size = emu.get_valid_ranges(size, addr=test)
            while base and base & 0xFFF:
                base, size = emu.get_valid_ranges(size, addr=test)
                test += e_arch.PAGE_SIZE

            emu_perms = self.win_perms_to_emu_perms(flProtect)
            buf = self.mem_alloc(base=base, size=size, tag=tag_prefix, flags=flProtect, perms=emu_perms, process=obj)
            if flProtect & PAGE_PROTECTION_FLAGS.PAGE_GUARD and obj is emu.get_current_process():
                emu.set_guard_pages(buf, size, emu_perms)
            mm = emu.get_address_map(buf)

            self.record_process_event(
                obj, EventType.MEM_ALLOC, base=buf, size=dwSize, type=flAllocationType, protect=prot_def or None
            )

            emu._set_dyn_code_hook(buf, size)

        return buf

    @apihook("WriteProcessMemory", argc=5)
    def WriteProcessMemory(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL WriteProcessMemory(
            HANDLE hProcess,
            LPVOID lpBaseAddress,
            LPCVOID lpBuffer,
            SIZE_T nSize,
            SIZE_T *lpNumberOfBytesWritten
        );
        """
        hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten = argv
        rv = False

        obj = emu.get_handle_table().get(hProcess, objman.Process)
        if not obj:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return rv

        proc_path = obj.path
        ctx.args["hProcess"].display = proc_path

        data = b""
        if lpBuffer and lpBaseAddress:
            data = self.mem_read(lpBuffer, nSize)
            self.mem_write(lpBaseAddress, data)
            if lpNumberOfBytesWritten:
                bw = (len(data)).to_bytes(self.get_ptr_size(), "little")
                self.mem_write(lpNumberOfBytesWritten, bw)
            rv = True
            obj.is_modified = True
            emu.set_last_error(windefs.ERROR_SUCCESS)
        else:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)

        self.record_process_event(obj, EventType.MEM_WRITE, base=lpBaseAddress, size=nSize, data=data)

        return rv

    @apihook("ReadProcessMemory", argc=5)
    def ReadProcessMemory(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL ReadProcessMemory(
            HANDLE hProcess,
            LPCVOID lpBaseAddress,
            LPVOID lpBuffer,
            SIZE_T nSize,
            SIZE_T *lpNumberOfBytesRead
        );
        """
        hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead = argv
        rv = False

        obj = emu.get_handle_table().get(hProcess, objman.Process)
        if not obj:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return rv

        proc_path = obj.path
        ctx.args["hProcess"].display = proc_path

        data = b""
        if lpBuffer and lpBaseAddress:
            try:
                data = self.mem_read(lpBaseAddress, nSize)
            except Exception:
                emu.set_last_error(windefs.ERROR_ACCESS_DENIED)
                return rv
            self.mem_write(lpBuffer, data)
            if lpNumberOfBytesRead:
                bw = (len(data)).to_bytes(self.get_ptr_size(), "little")
                self.mem_write(lpNumberOfBytesRead, bw)
            rv = True
            emu.set_last_error(windefs.ERROR_SUCCESS)
        else:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)

        self.record_process_event(obj, EventType.MEM_READ, base=lpBaseAddress, size=nSize, data=data)

        return rv

    @apihook("CreateRemoteThread", argc=7)
    def CreateRemoteThread(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE CreateRemoteThread(
            HANDLE hProcess,
            LPSECURITY_ATTRIBUTES lpThreadAttributes,
            SIZE_T dwStackSize,
            LPTHREAD_START_ROUTINE lpStartAddress,
            LPVOID lpParameter,
            DWORD dwCreationFlags,
            LPDWORD lpThreadId
        );
        """
        (hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId) = argv

        is_remote = hProcess != self.get_max_int()
        proc_obj = emu.get_handle_table().get(hProcess, objman.Process)
        if not proc_obj:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        ctx.args["hProcess"].display = proc_obj.path

        if is_remote:
            run_name = ntpath.basename(proc_obj.path)
            evt_type = EventType.THREAD_INJECT
        else:
            run_name = None
            evt_type = EventType.THREAD_CREATE

        handle, obj = self.create_thread(lpStartAddress, lpParameter, proc_obj, name=run_name)

        if not obj:
            return handle

        if lpThreadId:
            self.write_dword(lpThreadId, obj.id)

        self.record_process_event(proc_obj, evt_type, start_address=lpStartAddress, param=lpParameter, tid=obj.id)

        emu.set_last_error(windefs.ERROR_SUCCESS)

        return handle

    @apihook("CreateThread", argc=6)
    def CreateThread(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE CreateThread(
            LPSECURITY_ATTRIBUTES lpThreadAttributes,
            SIZE_T dwStackSize,
            LPTHREAD_START_ROUTINE lpStartAddress,
            LPVOID lpParameter,
            DWORD dwCreationFlags,
            LPDWORD lpThreadId
        );
        """
        (lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId) = argv

        proc_obj = emu.get_current_process()
        ctx.args["dwCreationFlags"].display = decode(THREAD_CREATION_FLAGS, dwCreationFlags)
        is_suspended = bool(dwCreationFlags & THREAD_CREATION_FLAGS.THREAD_CREATE_SUSPENDED)

        handle, obj = self.create_thread(lpStartAddress, lpParameter, proc_obj, is_suspended=is_suspended)

        if not obj:
            return handle

        if lpThreadId:
            self.write_dword(lpThreadId, obj.id)

        self.record_process_event(
            proc_obj, EventType.THREAD_CREATE, start_address=lpStartAddress, param=lpParameter, tid=obj.id
        )

        emu.set_last_error(windefs.ERROR_SUCCESS)

        return handle

    @apihook("ResumeThread", argc=1)
    def ResumeThread(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD ResumeThread(
            HANDLE hThread
        );
        """
        (hThread,) = argv
        obj = emu.get_handle_table().get(hThread, objman.Thread)
        if not obj:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0xFFFFFFFF

        rv = obj.suspend_count
        if rv > 0:
            obj.suspend_count -= 1
        if rv != 1:
            return rv

        if not emu.resume_thread(obj):
            proc = obj.process
            if proc is None or proc not in emu.child_processes or not proc.is_modified:
                return rv
            context = obj.get_context()
            if emu.get_arch() == e_arch.ARCH_AMD64:
                start_addr = context.Rip
                if not start_addr and context.Rcx:
                    start_addr = context.Rcx
            else:
                start_addr = context.Eip
                if not start_addr and context.Eax:
                    start_addr = context.Eax

            if start_addr:
                mm = emu.get_address_map(start_addr)
                if mm:
                    emu.ensure_pe_import_hooks(mm.base)

            handle, obj = self.create_thread(start_addr, 0, proc, name=proc.name)
            emu.child_processes.remove(proc)
        return rv

    @apihook("SuspendThread", argc=1)
    def SuspendThread(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD SuspendThread(
            HANDLE hThread
        );

        Speakeasy does not stop the current thread. The current run continues, and only a queued run of another thread
        waits for ResumeThread.
        """
        (hThread,) = argv
        obj = emu.get_handle_table().get(hThread, objman.Thread)
        if not obj:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0xFFFFFFFF

        rv = obj.suspend_count
        obj.suspend_count += 1
        if rv == 0 and obj is not emu.get_current_thread():
            queued = next((run for run in emu.run_queue if run.thread is obj), None)
            if queued is not None:
                emu.run_queue.remove(queued)
                emu.suspended_runs.append(queued)
        return rv

    @apihook("TerminateThread", argc=2)
    def TerminateThread(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL TerminateThread(
            HANDLE hThread,
            DWORD dwExitCode
        );

        Speakeasy does not model thread termination. The queued run of the thread still runs.
        """
        hThread, dwExitCode = argv
        rv = 0
        obj = emu.get_handle_table().get(hThread, objman.Thread)
        if not obj:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return rv

        rv = 1

        return rv

    @apihook("GetThreadId", argc=1)
    def GetThreadId(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetThreadId(
            HANDLE Thread
        );
        """
        (Thread,) = argv

        obj = emu.get_handle_table().get(Thread, objman.Thread)

        if not obj:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        return obj.id

    @apihook("GetProcessId", argc=1)
    def GetProcessId(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetProcessId(
            HANDLE Process
        );
        """
        (Process,) = argv

        proc = emu.get_handle_table().get(Process, objman.Process)
        if not proc:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0
        return proc.id

    @apihook("GetProcessIdOfThread", argc=1)
    def GetProcessIdOfThread(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetProcessIdOfThread(
            HANDLE Thread
        );
        """
        (Thread,) = argv

        thread = emu.get_handle_table().get(Thread, objman.Thread)
        if not thread:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0
        return (thread.process or emu.get_current_process()).id

    @apihook("VirtualQuery", argc=3)
    def VirtualQuery(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SIZE_T VirtualQuery(
            LPCVOID lpAddress,
            PMEMORY_BASIC_INFORMATION lpBuffer,
            SIZE_T dwLength
        );
        """
        rv = 0

        lpAddress, lpBuffer, dwLength = argv
        mbi = self.k32types.MEMORY_BASIC_INFORMATION(emu.get_ptr_size())

        if mbi.sizeof() > dwLength or not lpBuffer:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return rv

        mm = emu.get_address_map(lpAddress)
        if not mm:
            page = lpAddress & ~0xFFF
            reserve = emu.get_reserve_map(lpAddress)
            if reserve:
                mbi.BaseAddress = page
                mbi.AllocationBase = reserve.base
                mbi.RegionSize = reserve.base + reserve.size - page
                mbi.State = windefs.MEM_RESERVE
            else:
                end = self.get_max_application_address(emu) + 1
                if lpAddress >= end:
                    emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
                    return rv
                for m in [*emu.get_mem_maps(), *emu.mem_reserves]:
                    if page < m.base < end:
                        end = m.base
                mbi.BaseAddress = page
                mbi.RegionSize = end - page
                mbi.State = windefs.MEM_FREE
                mbi.Protect = PAGE_PROTECTION_FLAGS.PAGE_NOACCESS
            self.mem_write(lpBuffer, mbi.get_bytes())
            return mbi.sizeof()

        base, size, prot = mm.base, mm.size, mm.prot
        uc_to_perms = {v: k for k, v in emu.emu_eng.perms.items()}
        for begin, end, uc_perms in emu.get_mem_regions():
            if begin <= lpAddress <= end:
                base, size, prot = begin, end + 1 - begin, uc_to_perms.get(uc_perms, prot)
                break
        mbi.BaseAddress = base
        mbi.AllocationBase = mm.base
        mbi.AllocationProtect = self.emu_perms_to_win_perms(mm.prot)
        mbi.RegionSize = size
        mbi.State = windefs.MEM_COMMIT
        page = lpAddress & ~(e_arch.PAGE_SIZE - 1)
        if page in emu.guard_pages:
            mbi.Protect = self.emu_perms_to_win_perms(emu.guard_pages[page]) | PAGE_PROTECTION_FLAGS.PAGE_GUARD
        else:
            mbi.Protect = self.emu_perms_to_win_perms(prot)
        mbi.Type = 0

        self.mem_write(lpBuffer, mbi.get_bytes())
        rv = mbi.sizeof()

        return mbi.sizeof()

    @apihook("VirtualQueryEx", argc=4)
    def VirtualQueryEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SIZE_T VirtualQueryEx(
            HANDLE hProcess,
            LPCVOID lpAddress,
            PMEMORY_BASIC_INFORMATION lpBuffer,
            SIZE_T dwLength
        );
        """
        hProcess = argv[0]

        proc_obj = emu.get_handle_table().get(hProcess, objman.Process)

        if not proc_obj:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        ctx.args["hProcess"].display = proc_obj.path
        return self.VirtualQuery(emu, argv[1:], ctx)

    @apihook("VirtualProtect", argc=4)
    def VirtualProtect(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL VirtualProtect(
            LPVOID lpAddress,
            SIZE_T dwSize,
            DWORD flNewProtect,
            PDWORD lpflOldProtect
        );
        """
        rv = 0
        mm = None
        new = 0

        lpAddress, dwSize, flNewProtect, lpflOldProtect = argv

        maps = emu.get_mem_maps()
        for m in maps:
            if m.base <= lpAddress < m.base + m.size:
                mm = m
                break

        # convert the mem flags
        if mm and lpflOldProtect:
            # See if we saved off the flags if this chunk is from a previous
            # VirtualAlloc()
            old_prot = mm.flags
            if not old_prot:
                # Otherwise, get the perms from the emulator and convert it to
                # Win32 protection flags
                old_prot = self.emu_perms_to_win_perms(mm.prot)
            # Check for page alignment
            addr = lpAddress & 0xFFFFFFFFFFFFF000
            size = dwSize & 0xFFFFFFFFFFFFF000
            new = self.win_perms_to_emu_perms(flNewProtect)

            remainder = dwSize & 0xFFF
            if remainder:
                size += 0x1000
            if get_first_unmapped(emu, addr, size) != addr:
                emu.set_last_error(windefs.ERROR_INVALID_ADDRESS)
                return 0

            old_prot &= ~PAGE_PROTECTION_FLAGS.PAGE_GUARD
            if addr in emu.guard_pages:
                old_prot |= PAGE_PROTECTION_FLAGS.PAGE_GUARD
            emu.mem_protect(addr, size, new)
            emu.clear_guard_pages(addr, size)
            if flNewProtect & PAGE_PROTECTION_FLAGS.PAGE_GUARD:
                emu.set_guard_pages(addr, size, new)
            mm.prot = new
            self.write_dword(lpflOldProtect, old_prot)
            return 1

        return rv

    @apihook("VirtualProtectEx", argc=5)
    def VirtualProtectEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL VirtualProtectEx(
            HANDLE hProcess,
            LPVOID lpAddress,
            SIZE_T dwSize,
            DWORD flNewProtect,
            PDWORD lpflOldProtect
        );
        """
        hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect = argv

        proc_obj = emu.get_handle_table().get(hProcess, objman.Process)

        if not proc_obj:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return False

        rv = self.VirtualProtect(emu, argv[1:], ctx)

        prot_def = decode_flags(PAGE_PROTECTION_FLAGS, flNewProtect)
        ctx.args["flNewProtect"].display = "|".join(prot_def)

        self.record_process_event(
            proc_obj, EventType.MEM_PROTECT, base=lpAddress, size=dwSize, protect=prot_def or None
        )

        return rv

    @apihook("VirtualFree", argc=3)
    def VirtualFree(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL VirtualFree(
            LPVOID lpAddress,
            SIZE_T dwSize,
            DWORD dwFreeType
        );

        Speakeasy marks the region as free for the report, but does not unmap it, and always returns success.
        """
        rv = 0

        lpAddress, dwSize, dwFreeType = argv
        maps = emu.get_mem_maps()
        for m in maps:
            if m.base == lpAddress:
                m.free = True
                emu.clear_guard_pages(m.base, dwSize or m.size)
                proc = emu.get_current_process()
                if proc:
                    self.record_process_event(proc, EventType.MEM_FREE, base=lpAddress, size=dwSize or m.size)
                rv = True
                break

        rv = 1

        return rv

    @apihook("GetCurrentProcess", argc=0)
    def GetCurrentProcess(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE GetCurrentProcess();
        """
        rv = self.get_max_int()

        return rv

    @apihook("GetVersion", argc=0)
    def GetVersion(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetVersion();
        """
        ver = self.emu.config.os_ver
        build = ver.build or 0
        major = ver.major or 0
        minor = ver.minor or 0

        rv = 0xFFFFFFFF & ((build << 16) | minor << 8 | major)

        return rv

    @apihook("GetLastError", argc=0)
    def GetLastError(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetLastError();
        """
        rv = emu.get_last_error()

        # TODO: reset last error code here for now
        emu.set_last_error(windefs.ERROR_SUCCESS)

        return rv

    @apihook("SetLastError", argc=1)
    def SetLastError(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID SetLastError(
            DWORD dwErrCode
        );
        """
        (dwErrCode,) = argv

        emu.set_last_error(dwErrCode)

    def _expand_message(self, text, flags, arguments, cw):
        """
        Expand the inserts and escapes of a message definition. Return None for a
        definition that ends with a lone % or has inserts but no arguments.
        """
        ptr_size = self.get_ptr_size()
        ignore = flags & k32defs.FORMAT_MESSAGE_IGNORE_INSERTS
        wrap = flags & k32defs.FORMAT_MESSAGE_MAX_WIDTH_MASK
        slots = arguments
        if arguments and not flags & k32defs.FORMAT_MESSAGE_ARGUMENT_ARRAY:
            slots = self.read_ptr(arguments)

        out = []
        i = 0
        while i < len(text):
            ch = text[i]
            i += 1
            if ch in "\r\n":
                if ch == "\r" and text[i : i + 1] == "\n":
                    i += 1
                out.append(" " if wrap else "\r\n")
                continue
            if ch != "%":
                out.append(ch)
                continue
            if i == len(text):
                return None
            esc = text[i]
            i += 1
            if esc in "123456789" and not ignore:
                number = int(esc)
                if text[i : i + 1].isdigit():
                    number = number * 10 + int(text[i])
                    i += 1
                spec = "s"
                if text[i : i + 1] == "!" and "!" in text[i + 1 :]:
                    end = text.index("!", i + 1)
                    spec = text[i + 1 : end]
                    i = end + 1
                if not slots:
                    return None
                fmt = "%" + spec
                first = slots + (number - 1) * ptr_size
                values = [self.read_ptr(first + n * ptr_size) for n in range(self.get_va_arg_count(fmt))]
                out.append(self.do_str_format(fmt, values, wide=cw == 2))
            elif esc == "0":
                break
            elif esc == "n":
                out.append("\r\n")
            elif esc == "r":
                out.append("\r")
            elif esc == "t":
                out.append("\t")
            else:
                out.append(("%" if ignore else "") + esc)
        return "".join(out)

    @apihook("FormatMessage", argc=7)
    def FormatMessage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD FormatMessage(
            DWORD dwFlags,
            LPCVOID lpSource,
            DWORD dwMessageId,
            DWORD dwLanguageId,
            LPTSTR lpBuffer,
            DWORD nSize,
            va_list *Arguments
        );
        """
        dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, Arguments = argv
        cw = self.get_char_width(ctx)

        if dwFlags & k32defs.FORMAT_MESSAGE_FROM_STRING:
            text = self.read_mem_string(lpSource, cw)
        elif dwFlags & k32defs.FORMAT_MESSAGE_FROM_SYSTEM and dwMessageId in k32defs.SYSTEM_MESSAGES:
            text = k32defs.SYSTEM_MESSAGES[dwMessageId]
        else:
            emu.set_last_error(windefs.ERROR_MR_MID_NOT_FOUND)
            return 0

        msg = self._expand_message(text, dwFlags, Arguments, cw)
        if msg is None:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        data = self.encode_string(msg, cw) + b"\x00" * cw
        count = len(data) // cw - 1
        if dwFlags & k32defs.FORMAT_MESSAGE_ALLOCATE_BUFFER:
            buf = self.heap_alloc(max(len(data), nSize * cw), heap="LocalAlloc")
            self.mem_write(buf, data)
            self.write_ptr(lpBuffer, buf)
        elif count >= nSize:
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
            return 0
        else:
            self.mem_write(lpBuffer, data)
        return count

    @apihook("SetHandleInformation", argc=3)
    def SetHandleInformation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetHandleInformation(
            HANDLE hObject,
            DWORD dwMask,
            DWORD dwFlags
        );
        """
        # Non-zero value for success.
        rv = 1

        return rv

    @apihook("GetHandleInformation", argc=2)
    def GetHandleInformation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetHandleInformation(
            HANDLE hObject,
            LPDWORD lpdwFlags
        );
        """
        # Non-zero value for success.
        rv = 1

        return rv

    @apihook("ExitProcess", argc=1)
    def ExitProcess(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID ExitProcess(
            UINT uExitCode
        );
        """
        self.exit_process()
        return 0

    @apihook("SystemTimeToTzSpecificLocalTime", argc=3)
    def SystemTimeToTzSpecificLocalTime(
        self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        BOOL SystemTimeToTzSpecificLocalTime(
            const TIME_ZONE_INFORMATION *lpTimeZoneInformation,
            const SYSTEMTIME *lpUniversalTime,
            LPSYSTEMTIME lpLocalTime
        );
        """
        lpTimeZoneInformation, lpUniversalTime, lpLocalTime = argv
        return self.shift_system_time(emu, lpTimeZoneInformation, lpUniversalTime, lpLocalTime, -1)

    @apihook("TzSpecificLocalTimeToSystemTime", argc=3)
    def TzSpecificLocalTimeToSystemTime(
        self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        BOOL TzSpecificLocalTimeToSystemTime(
            const TIME_ZONE_INFORMATION *lpTimeZoneInformation,
            const SYSTEMTIME *lpLocalTime,
            LPSYSTEMTIME lpUniversalTime
        );
        """
        lpTimeZoneInformation, lpLocalTime, lpUniversalTime = argv
        return self.shift_system_time(emu, lpTimeZoneInformation, lpLocalTime, lpUniversalTime, 1)

    def shift_system_time(self, emu, tzi, src, dst, sign):
        """
        Write the SYSTEMTIME at src, moved by sign times the time zone bias, to dst.
        A NULL tzi is the current time zone, which GetTimeZoneInformation reports with no bias.
        """
        bias = 0
        if tzi:
            bias = int.from_bytes(self.mem_read(tzi, 4), "little", signed=True)
        st = self.mem_cast(self.k32types.SYSTEMTIME(emu.get_ptr_size()), src)
        try:
            dt = datetime.datetime(
                st.wYear,
                st.wMonth,
                st.wDay,
                st.wHour,
                st.wMinute,
                st.wSecond,
                st.wMilliseconds * 1000,
                tzinfo=datetime.timezone.utc,
            )
            quad = winemu.get_filetime(dt)
            quad += sign * bias * 60 * 10000000
            out = self.get_system_time_struct(quad) if quad >= 0 else None
        except (ValueError, OverflowError):
            out = None
        if out is None:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0
        self.mem_write(dst, out.get_bytes())
        return 1

    @apihook("FileTimeToSystemTime", argc=2)
    def FileTimeToSystemTime(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL FileTimeToSystemTime(
            const FILETIME *lpFileTime,
            LPSYSTEMTIME lpSystemTime
        );
        """
        lpFileTime, lpSystemTime = argv

        ft = self.k32types.FILETIME(emu.get_ptr_size())
        ft = self.mem_cast(ft, lpFileTime)

        quad = (ft.dwHighDateTime << 32) | ft.dwLowDateTime
        try:
            st = self.get_system_time_struct(quad)
        except OverflowError:
            st = None

        if st is not None and lpSystemTime:
            self.mem_write(lpSystemTime, st.get_bytes())

        return True

    @apihook("GetSystemTimeAsFileTime", argc=1)
    def GetSystemTimeAsFileTime(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID GetSystemTimeAsFileTime(
            LPFILETIME lpSystemTimeAsFileTime
        );
        """
        (lpSystemTimeAsFileTime,) = argv
        ft = self.k32types.FILETIME(emu.get_ptr_size())

        timestamp = self.get_system_time()
        ft.dwLowDateTime = 0xFFFFFFFF & timestamp
        ft.dwHighDateTime = timestamp >> 32

        self.mem_write(lpSystemTimeAsFileTime, self.get_bytes(ft))

    @apihook("SystemTimeToFileTime", argc=2)
    def SystemTimeToFileTime(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SystemTimeToFileTime(
            const SYSTEMTIME *lpSystemTime,
            LPFILETIME lpFileTime
        );
        """
        lpSystemTime, lpFileTime = argv

        st = self.k32types.SYSTEMTIME(emu.get_ptr_size())
        st = self.mem_cast(st, lpSystemTime)
        try:
            dt = datetime.datetime(
                st.wYear,
                st.wMonth,
                st.wDay,
                st.wHour,
                st.wMinute,
                st.wSecond,
                st.wMilliseconds * 1000,
                tzinfo=datetime.timezone.utc,
            )
        except ValueError:
            dt = None
        if not dt or dt.year < 1601:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return False

        timestamp = winemu.get_filetime(dt)

        ft = self.k32types.FILETIME(emu.get_ptr_size())
        ft.dwLowDateTime = 0xFFFFFFFF & timestamp
        ft.dwHighDateTime = timestamp >> 32
        self.mem_write(lpFileTime, self.get_bytes(ft))

        return True

    @apihook("SetThreadErrorMode", argc=2)
    def SetThreadErrorMode(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetThreadErrorMode(
            DWORD dwNewMode,
            LPDWORD lpOldMode
        );
        """
        dwNewMode, lpOldMode = argv

        return True

    @apihook("SetDefaultDllDirectories", argc=1)
    def SetDefaultDllDirectories(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetDefaultDllDirectories(
            DWORD DirectoryFlags
        );
        """
        return True

    @apihook("SetConsoleTitle", argc=1)
    def SetConsoleTitle(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetConsoleTitle(
            LPCTSTR lpConsoleTitle
        );
        """
        (lpConsoleTitle,) = argv
        if lpConsoleTitle:
            cw = self.get_char_width(ctx)
            cs1 = self.read_mem_string(lpConsoleTitle, cw)
            ctx.args["lpConsoleTitle"].display = cs1
        return True

    @apihook("GetLocalTime", argc=1)
    def GetLocalTime(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID GetLocalTime(
            LPSYSTEMTIME lpSystemTime
        );
        """
        # The time zone that GetTimeZoneInformation reports has no bias
        return self.GetSystemTime(emu, argv, ctx)

    @apihook("GetSystemTime", argc=1)
    def GetSystemTime(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID GetSystemTime(
            LPSYSTEMTIME lpSystemTime
        );
        """
        (lpSystemTime,) = argv
        st = self.get_system_time_struct(self.get_system_time())
        self.mem_write(lpSystemTime, self.get_bytes(st))

    @apihook("GetTimeZoneInformation", argc=1)
    def GetTimeZoneInformation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetTimeZoneInformation(
            LPTIME_ZONE_INFORMATION lpTimeZoneInformation
        );
        """
        (lpTimeZoneInformation,) = argv
        if lpTimeZoneInformation:
            self.mem_write(lpTimeZoneInformation, b"\x00" * 168)

        return 0

    @apihook("GetCurrentThreadId", argc=0)
    def GetCurrentThreadId(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetCurrentThreadId();
        """
        thread = emu.get_current_thread()
        rv = thread.id

        return rv

    @apihook("GetCurrentProcessId", argc=0)
    def GetCurrentProcessId(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetCurrentProcessId();
        """
        proc = emu.get_current_process()
        rv = proc.id

        return rv

    @apihook("IsProcessorFeaturePresent", argc=1, conv=e_arch.CALL_CONV_STDCALL)
    def IsProcessorFeaturePresent(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsProcessorFeaturePresent(
            DWORD ProcessorFeature
        );
        """
        """
        Not all the features must return 1, because those can represent a feature which can be unavailable
        for your processor. For example PF_FLOATING_POINT_PRECISION_ERRATA is a Pentium instructions
        which doesn't exist on new ones, and malware developers are using it to see if they are in an
        emulated environment or not.

        To get the correct value you just need write an app to check all the fatures, something like:

        std::cout << IsProcessorFeaturePresent(PF_FLOATING_POINT_PRECISION_ERRATA) << endl;
        std::cout << IsProcessorFeaturePresent(PF_FLOATING_POINT_EMULATED) << endl;
        ...

        """
        lookup = {
            0: {"name": "PF_FLOATING_POINT_PRECISION_ERRATA", "return": 0},
            1: {"name": "PF_FLOATING_POINT_EMULATED", "return": 0},
            2: {"name": "PF_COMPARE_EXCHANGE_DOUBLE", "return": 1},
            3: {"name": "PF_MMX_INSTRUCTIONS_AVAILABLE", "return": 1},
            4: {"name": "PF_PPC_MOVEMEM_64BIT_OK", "return": 0},
            5: {"name": "PF_ALPHA_BYTE_INSTRUCTIONS", "return": 0},
            6: {"name": "PF_XMMI_INSTRUCTIONS_AVAILABLE", "return": 1},
            7: {"name": "PF_3DNOW_INSTRUCTIONS_AVAILABLE", "return": 0},
            8: {"name": "PF_RDTSC_INSTRUCTION_AVAILABLE", "return": 1},
            9: {"name": "PF_PAE_ENABLED", "return": 1},
            10: {"name": "PF_XMMI64_INSTRUCTIONS_AVAILABLE", "return": 1},
            11: {"name": "PF_SSE_DAZ_MODE_AVAILABLE", "return": 0},
            12: {"name": "PF_NX_ENABLED", "return": 1},
            13: {"name": "PF_SSE3_INSTRUCTIONS_AVAILABLE", "return": 1},
            14: {"name": "PF_COMPARE_EXCHANGE128", "return": 1},
            15: {"name": "PF_COMPARE64_EXCHANGE128", "return": 0},
            16: {"name": "PF_CHANNELS_ENABLED", "return": 0},
            17: {"name": "PF_XSAVE_ENABLED", "return": 1},
            18: {"name": "PF_ARM_VFP_32_REGISTERS_AVAILABLE", "return": 0},
            19: {"name": "PF_ARM_NEON_INSTRUCTIONS_AVAILABLE", "return": 0},
            20: {"name": "PF_SECOND_LEVEL_ADDRESS_TRANSLATION", "return": 0},
            21: {"name": "PF_VIRT_FIRMWARE_ENABLED", "return": 1},
            22: {"name": "PF_RDWRFSGSBASE_AVAILABLE", "return": 1},
            23: {"name": "PF_FASTFAIL_AVAILABLE", "return": 1},
            24: {"name": "PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE", "return": 0},
            25: {"name": "PF_ARM_64BIT_LOADSTORE_ATOMIC", "return": 0},
            26: {"name": "PF_ARM_EXTERNAL_CACHE_AVAILABLE", "return": 0},
            27: {"name": "PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE", "return": 0},
            28: {"name": "PF_RDRAND_INSTRUCTION_AVAILABLE", "return": 1},
            29: {"name": "PF_ARM_V8_INSTRUCTIONS_AVAILABLE", "return": 0},
            30: {"name": "PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE", "return": 0},
            31: {"name": "PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE", "return": 0},
            32: {"name": "PF_RDTSCP_INSTRUCTION_AVAILABLE", "return": 1},
            33: {"name": "PF_RDPID_INSTRUCTION_AVAILABLE", "return": 0},
            34: {"name": "PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE", "return": 0},
            35: {"name": "PF_MONITORX_INSTRUCTION_AVAILABLE", "return": 0},
            36: {"name": "PF_SSSE3_INSTRUCTIONS_AVAILABLE", "return": 1},
            37: {"name": "PF_SSE4_1_INSTRUCTIONS_AVAILABLE", "return": 1},
            38: {"name": "PF_SSE4_2_INSTRUCTIONS_AVAILABLE", "return": 1},
            39: {"name": "PF_AVX_INSTRUCTIONS_AVAILABLE", "return": 0},
            40: {"name": "PF_AVX2_INSTRUCTIONS_AVAILABLE", "return": 0},
            41: {"name": "PF_AVX512F_INSTRUCTIONS_AVAILABLE", "return": 0},
        }

        entry = lookup.get(argv[0])
        if not entry:
            return 0

        rv = entry["return"]
        ctx.args["ProcessorFeature"].display = entry["name"]

        return rv

    @apihook("lstrcmpi", argc=2)
    def lstrcmpi(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int lstrcmpi(
            LPCTSTR lpString1,
            LPCTSTR lpString2
        );
        """
        cw = self.get_char_width(ctx)

        lpString1, lpString2 = argv
        if not lpString1:
            return 0 if not lpString2 else -1
        if not lpString2:
            return 1

        cs1 = self.read_mem_string(lpString1, cw)
        cs2 = self.read_mem_string(lpString2, cw)

        ctx.args["lpString1"].display = cs1
        ctx.args["lpString2"].display = cs2

        # lstrcmpi is CompareString with the user locale and NORM_IGNORECASE, minus 2.
        return get_string_order(cs1, cs2, Fold.LINGUISTIC_IGNORE_CASE)

    @apihook("lstrcmp", argc=2)
    def lstrcmp(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int lstrcmp(
            LPCTSTR lpString1,
            LPCTSTR lpString2
        );
        """
        cw = self.get_char_width(ctx)

        lpString1, lpString2 = argv
        if not lpString1:
            return 0 if not lpString2 else -1
        if not lpString2:
            return 1

        cs1 = self.read_mem_string(lpString1, cw)
        cs2 = self.read_mem_string(lpString2, cw)

        ctx.args["lpString1"].display = cs1
        ctx.args["lpString2"].display = cs2

        # lstrcmp is CompareString with the user locale, minus 2.
        return get_string_order(cs1, cs2, Fold.LINGUISTIC)

    @apihook("CompareStringOrdinal", argc=5)
    def CompareStringOrdinal(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int CompareStringOrdinal(
            LPCWCH lpString1,
            int cchCount1,
            LPCWCH lpString2,
            int cchCount2,
            BOOL bIgnoreCase
        );
        """
        lpString1, cchCount1, lpString2, cchCount2, bIgnoreCase = argv
        texts = []
        for i, (ptr, count) in enumerate(((lpString1, cchCount1), (lpString2, cchCount2))):
            count = ct.c_int32(count).value
            if count < -1 or (not ptr and count):
                emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
                return 0
            data = b""
            if count == -1:
                while (unit := self.mem_read(ptr + len(data), 2)) != b"\x00\x00":
                    data += unit
            elif count:
                data = self.mem_read(ptr, 2 * count)
            ctx.args[2 * i].display = data.decode("utf-16le", "replace")
            texts.append(data.decode("utf-16le", "surrogatepass"))
        return 2 + get_string_order(texts[0], texts[1], Fold.UPPER if bIgnoreCase else Fold.NONE)

    def compare_locale_strings(self, emu, argv, cw, ctx):
        flags, string1, count1, string2, count2 = argv
        texts = []
        for i, (ptr, count) in enumerate(((string1, count1), (string2, count2))):
            count = ct.c_int32(count).value
            if count < -1 or (not ptr and count):
                emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
                return 0
            if count == -1:
                text = self.read_mem_string(ptr, cw)
            else:
                text = self.decode_string(self.mem_read(ptr, cw * count), cw)
            ctx.args[2 + 2 * i].display = text
            texts.append(text)
        fold = Fold.LINGUISTIC_IGNORE_CASE if flags & NORM_IGNORECASE else Fold.LINGUISTIC
        return 2 + get_string_order(texts[0], texts[1], fold)

    @apihook("CompareString", argc=6)
    def CompareString(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int CompareString(
            LCID Locale,
            DWORD dwCmpFlags,
            LPCTSTR lpString1,
            int cchCount1,
            LPCTSTR lpString2,
            int cchCount2
        );
        """
        return self.compare_locale_strings(emu, argv[1:6], self.get_char_width(ctx), ctx)

    @apihook("CompareStringEx", argc=9)
    def CompareStringEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int CompareStringEx(
            LPCWSTR lpLocaleName,
            DWORD dwCmpFlags,
            LPCWCH lpString1,
            int cchCount1,
            LPCWCH lpString2,
            int cchCount2,
            LPNLSVERSIONINFO lpVersionInformation,
            LPVOID lpReserved,
            LPARAM lParam
        );
        """
        return self.compare_locale_strings(emu, argv[1:6], 2, ctx)

    @apihook("PathCchRemoveFileSpec", argc=2)
    def PathCchRemoveFileSpec(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT PathCchRemoveFileSpec(
            PWSTR pszPath,
            size_t cchPath
        );
        """
        pszPath, cchPath = argv
        if not pszPath or cchPath > PATHCCH_MAX_CCH:
            return windefs.E_INVALIDARG
        path = shlwapi.get_path_without_file_spec(self.read_mem_string(pszPath, 2))
        if path is None:
            return comdefs.S_FALSE
        self.write_mem_string(path, pszPath, 2)
        return windefs.S_OK

    @apihook("QueryDosDevice", argc=3)
    def QueryDosDevice(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD QueryDosDevice(
            LPCTSTR lpDeviceName,
            LPTSTR lpTargetPath,
            DWORD ucchMax
        );

        Return synthetic DOS device mappings as an ANSI or wide MULTI_SZ.
        """
        lpDeviceName, lpTargetPath, ucchMax = argv
        width = self.get_char_width(ctx)
        mappings = {"C:": "\\Device\\HarddiskVolume1"}
        if not lpTargetPath:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0
        if lpDeviceName:
            name = self.read_mem_string(lpDeviceName, width).upper()
            if name not in mappings:
                emu.set_last_error(windefs.ERROR_FILE_NOT_FOUND)
                return 0
            values = [mappings[name]]
        else:
            values = list(mappings)
        text = "\0".join(values) + "\0\0"
        encoded = self.encode_string(text, width)
        characters = len(encoded) // width
        if ucchMax < characters:
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
            return 0
        self.mem_write(lpTargetPath, encoded)
        return characters

    @apihook("QueryPerformanceCounter", argc=1)
    def QueryPerformanceCounter(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL QueryPerformanceCounter(
            LARGE_INTEGER *lpPerformanceCount
        );
        """
        (lpPerformanceCount,) = argv

        rv = 1

        self.write_qword(lpPerformanceCount, self.get_performance_counter())
        return rv

    @apihook("lstrlen", argc=1)
    def lstrlen(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int lstrlen(
            LPCTSTR lpString
        );
        """
        (lpString,) = argv
        if not lpString or not emu.is_address_valid(lpString):
            return 0
        cw = self.get_char_width(ctx)
        s = self.read_mem_string(lpString, cw)

        ctx.args["lpString"].display = s

        return len(s)

    @apihook("GetModuleHandleEx", argc=3)
    def GetModuleHandleEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetModuleHandleEx(
            DWORD dwFlags,
            LPCTSTR lpModuleName,
            HMODULE *phModule
        );
        """
        dwFlags, lpModuleName, phModule = argv

        if dwFlags & k32defs.GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS:
            ctx.args["lpModuleName"].display = hex(lpModuleName)
            mod = emu.get_mod_from_addr(lpModuleName)
            hmod = mod.base if mod else 0
        else:
            hmod = self.GetModuleHandle(emu, [lpModuleName], ctx)
        if phModule:
            _mod = (hmod).to_bytes(emu.get_ptr_size(), "little")
            self.mem_write(phModule, _mod)
        return hmod

    @apihook("GetModuleHandle", argc=1)
    def GetModuleHandle(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HMODULE GetModuleHandle(
            LPCTSTR lpModuleName
        );
        """
        (lpModuleName,) = argv

        cw = self.get_char_width(ctx)
        rv = 0

        if not lpModuleName:
            proc = emu.get_current_process()
            rv = proc.base
        else:
            lib = self.read_mem_string(lpModuleName, cw)
            ctx.args["lpModuleName"].display = lib
            mods = emu.get_peb_modules()
            if "\\" in lib or "/" in lib:
                path = lib.replace("/", "\\")
                if path.endswith("."):
                    path = path[:-1]
                elif not ntpath.splitext(path)[1]:
                    path += ".dll"
                mods = [mod for mod in mods if mod.emu_path.lower() == path.lower()]
                return mods[0].base if mods else 0
            sname, _ = os.path.splitext(lib)
            sname = winemu.normalize_dll_name(sname)
            for mod in mods:
                img = ntpath.basename(mod.emu_path)
                fname, _ = os.path.splitext(img)
                if fname.lower() == sname.lower():
                    rv = mod.base
                    break

        return rv

    @apihook("GetProcAddress", argc=2)
    def GetProcAddress(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        FARPROC GetProcAddress(
            HMODULE hModule,
            LPCSTR lpProcName
        );
        """
        hModule, lpProcName = argv
        rv = 0

        proc = ""
        if lpProcName:
            if isinstance(lpProcName, int) and lpProcName < 0x10000:
                proc = f"ordinal_{lpProcName}"
            else:
                try:
                    proc = self.read_mem_string(lpProcName, 1)
                    ctx.args["lpProcName"].display = proc
                except Exception:
                    pass

        if proc:
            for mod in emu.modules:
                if mod.base == hModule:
                    rv = emu.resolve_export(mod, proc)
                    break

        if not rv:
            emu.set_last_error(windefs.ERROR_PROC_NOT_FOUND)
        return rv

    @apihook("ResolveDelayLoadedAPI", argc=6)
    def ResolveDelayLoadedAPI(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PVOID ResolveDelayLoadedAPI(
            PVOID ParentModuleBase,
            PCIMAGE_DELAYLOAD_DESCRIPTOR DelayloadDescriptor,
            PDELAYLOAD_FAILURE_DLL_CALLBACK FailureDllHook,
            PDELAYLOAD_FAILURE_SYSTEM_ROUTINE FailureSystemHook,
            PIMAGE_THUNK_DATA ThunkAddress,
            ULONG Flags
        );
        """
        ParentModuleBase, DelayloadDescriptor, FailureDllHook, FailureSystemHook, ThunkAddress, Flags = argv
        ptr_size = emu.get_ptr_size()

        attributes, name_rva, hmod_rva, iat_rva, int_rva = struct.unpack("<5I", self.mem_read(DelayloadDescriptor, 20))
        if not attributes & 1:
            ParentModuleBase = 0
        dll = self.read_mem_string(ParentModuleBase + name_rva, 1)
        index = (ThunkAddress - (ParentModuleBase + iat_rva)) // ptr_size
        thunk = self.read_ptr(ParentModuleBase + int_rva + index * ptr_size)
        if thunk >> (ptr_size * 8 - 1):
            proc = f"ordinal_{thunk & 0xFFFF}"
        else:
            proc = self.read_mem_string(ParentModuleBase + thunk + 2, 1)
        ctx.args[1].display = f"{dll}!{proc}"

        try:
            address = emu.get_proc(dll, proc)
        except WindowsEmuError:
            address = 0
        if not address:
            emu.set_last_error(windefs.ERROR_PROC_NOT_FOUND)
            return 0

        self.write_ptr(ThunkAddress, address)
        module = emu.get_mod_by_name(winemu.normalize_dll_name(module_name(dll))) or emu.get_mod_from_addr(address)
        if hmod_rva and module:
            self.write_ptr(ParentModuleBase + hmod_rva, module.base)
        return address

    @apihook("DelayLoadFailureHook", argc=2)
    def DelayLoadFailureHook(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        FARPROC DelayLoadFailureHook(
            LPCSTR pszDllName,
            LPCSTR pszProcName
        );
        """
        pszDllName, pszProcName = argv
        ctx.args[0].display = self.read_mem_string(pszDllName, 1)
        if pszProcName >> 16:
            ctx.args[1].display = self.read_mem_string(pszProcName, 1)
        else:
            ctx.args[1].display = hex(pszProcName)
        emu.set_last_error(windefs.ERROR_PROC_NOT_FOUND)
        return 0

    @apihook("ApiSetQueryApiSetPresence", argc=2)
    def ApiSetQueryApiSetPresence(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL ApiSetQueryApiSetPresence(
            PCUNICODE_STRING Namespace,
            PBOOLEAN Present
        );
        """
        Namespace, Present = argv
        name = self.read_unicode_string(Namespace)
        ctx.args["Namespace"].display = name
        host = module_name(name)
        present = host.startswith(("api-", "ext-")) and winemu.normalize_dll_name(host) != host
        self.mem_write(Present, bytes([present]))
        return ddk.STATUS_SUCCESS

    @apihook("AllocConsole", argc=0)
    def AllocConsole(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL AllocConsole();
        """
        # On success, return != 0
        return 1

    @apihook("GetConsoleWindow", argc=0)
    def GetConsoleWindow(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HWND GetConsoleWindow();
        """
        console = emu.get_current_process().console
        if console and console.window:
            return console.window.handle
        return 0

    @apihook("Sleep", argc=1)
    def Sleep(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID Sleep(
            DWORD dwMilliseconds
        );
        """
        (dwMilliseconds,) = argv
        if dwMilliseconds != 0xFFFFFFFF:
            self.advance_clock(dwMilliseconds)

    @apihook("SwitchToThread", argc=0)
    def SwitchToThread(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SwitchToThread();
        """
        return 0

    @apihook("SleepEx", argc=2)
    def SleepEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD SleepEx(
            DWORD dwMilliseconds,
            BOOL bAlertable
        );
        """
        dwMilliseconds, bAlertable = argv
        if dwMilliseconds != 0xFFFFFFFF:
            self.advance_clock(dwMilliseconds)

    @apihook("GlobalAlloc", argc=2)
    def GlobalAlloc(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HGLOBAL GlobalAlloc(
            UINT uFlags,
            SIZE_T dwBytes
        );
        """
        uFlags, dwBytes = argv

        chunk = self.heap_alloc(dwBytes, heap="GlobalAlloc")

        return chunk

    @apihook("GlobalSize", argc=1)
    def GlobalSize(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SIZE_T GlobalSize(
            HGLOBAL hMem
        );
        """
        (hMem,) = argv

        size = self.heap_size(hMem)
        if size is None:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return size

    @apihook("GlobalFlags", argc=1)
    def GlobalFlags(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GlobalFlags(
            HGLOBAL hMem
        );
        """
        (hMem,) = argv
        flags = 0
        for mmap in emu.get_mem_maps():
            if hMem == mmap.base:
                flags = mmap.flags
                emu.set_last_error(windefs.ERROR_SUCCESS)

        if not flags:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            flags = 0x8000  # GMEM_INVALID_HANDLE

        return flags

    @apihook("LocalAlloc", argc=2)
    def LocalAlloc(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HLOCAL LocalAlloc(
            UINT uFlags,
            SIZE_T uBytes
        );
        """
        uFlags, uBytes = argv

        chunk = self.heap_alloc(uBytes, heap="LocalAlloc")

        return chunk

    @apihook("HeapAlloc", argc=3)
    def HeapAlloc(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPVOID HeapAlloc(
            HANDLE hHeap,
            DWORD dwFlags,
            SIZE_T dwBytes
        );
        """
        hHeap, dwFlags, dwBytes = argv

        chunk = self.heap_alloc(dwBytes, heap="HeapAlloc")
        if chunk:
            emu.set_last_error(windefs.ERROR_SUCCESS)

        return chunk

    @apihook("HeapSize", argc=3)
    def HeapSize(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SIZE_T HeapSize(
            HANDLE hHeap,
            DWORD dwFlags,
            LPCVOID lpMem
        );
        """
        hHeap, dwFlags, lpMem = argv

        size = self.heap_size(lpMem)
        if size is None:
            return self.get_max_int()
        return size

    @apihook("GetTickCount", argc=0)
    def GetTickCount(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetTickCount();
        """
        self.tick_counter += 20

        return self.tick_counter

    @apihook("GetTickCount64", argc=0)
    def GetTickCount64(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        ULONGLONG GetTickCount64();
        """
        self.tick_counter += 20

        if emu.get_arch() == e_arch.ARCH_X86:
            emu.reg_write(e_arch.X86_REG_EDX, self.tick_counter >> 32)
            return self.tick_counter & 0xFFFFFFFF

        return self.tick_counter

    @apihook("lstrcat", argc=2)
    def lstrcat(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPTSTR lstrcat(
            LPTSTR lpString1,
            LPCTSTR lpString2
        );
        """
        lpString1, lpString2 = argv
        if not lpString1 or not lpString2:
            return 0

        cw = self.get_char_width(ctx)
        s1 = self.read_mem_string(lpString1, cw)
        s2 = self.read_mem_string(lpString2, cw)

        ctx.args["lpString1"].display = s1
        ctx.args["lpString2"].display = s2

        new = self.encode_string(s1 + s2, cw)

        self.mem_write(lpString1, new + b"\x00" * cw)

        return lpString1

    @apihook("lstrcpyn", argc=3)
    def lstrcpyn(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPTSTR lstrcpyn(
            LPTSTR lpString1,
            LPCTSTR lpString2,
            int iMaxLength
        );
        """
        lpString1, lpString2, iMaxLength = argv
        if not lpString1 or not lpString2:
            return 0

        cw = self.get_char_width(ctx)

        s = self.read_mem_string(lpString2, cw)
        ctx.args["lpString2"].display = s
        s = s[: iMaxLength - 1]
        s += "\x00"

        self.write_mem_string(s, lpString1, cw)
        return lpString1

    @apihook("lstrcpy", argc=2)
    def lstrcpy(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPTSTR lstrcpy(
            LPTSTR lpString1,
            LPCTSTR lpString2
        );
        """
        lpString1, lpString2 = argv
        if not lpString1 or not lpString2:
            return 0

        cw = self.get_char_width(ctx)

        s = self.read_mem_string(lpString2, cw)
        ctx.args["lpString2"].display = s
        s += "\x00"

        self.write_mem_string(s, lpString1, cw)
        return lpString1

    @apihook("IsBadReadPtr", argc=2)
    def IsBadReadPtr(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsBadReadPtr(
            const VOID *lp,
            UINT_PTR ucb
        );
        """
        lp, ucb = argv

        rv = True

        if lp and ucb:
            v1 = emu.is_address_valid(lp)
            v2 = emu.is_address_valid(lp + (ucb - 1))

            if v1 and v2:
                rv = False

        return rv

    @apihook("HeapReAlloc", argc=4)
    def HeapReAlloc(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPVOID HeapReAlloc(
            HANDLE hHeap,
            DWORD dwFlags,
            LPVOID lpMem,
            SIZE_T dwBytes
        );
        """
        hHeap, dwFlags, lpMem, dwBytes = argv

        tag_prefix = "api.heap"
        new_buf = 0

        if hHeap and lpMem and dwBytes:
            mm = emu.get_address_map(lpMem)
            if mm and mm.tag.startswith(tag_prefix):
                # Copy the existing data
                data = self.mem_read(lpMem, min(mm.size, dwBytes))
                new_buf = self.heap_alloc(dwBytes, heap="HeapReAlloc")
                if new_buf:
                    self.mem_write(new_buf, data)

        return new_buf

    @apihook("LocalReAlloc", argc=3)
    def LocalReAlloc(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HLOCAL LocalReAlloc(
            HLOCAL hMem,
            SIZE_T uBytes,
            UINT uFlags
        );
        """
        hMem, uBytes, uFlags = argv

        tag_prefix = "api.heap"
        new_buf = 0

        if hMem and uBytes:
            mm = emu.get_address_map(hMem)
            if mm and mm.tag.startswith(tag_prefix):
                # Copy the existing data
                data = self.mem_read(hMem, min(mm.size, uBytes))
                new_buf = self.heap_alloc(uBytes, heap="LocalReAlloc")
                if new_buf:
                    self.mem_write(new_buf, data)

        return new_buf

    @apihook("HeapCreate", argc=3)
    def HeapCreate(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE HeapCreate(
            DWORD flOptions,
            SIZE_T dwInitialSize,
            SIZE_T dwMaximumSize
        );
        """
        flOptions, dwInitialSize, dwMaximumSize = argv

        heap = self.create_heap(emu)

        return heap

    @apihook("GetCurrentThread", argc=0)
    def GetCurrentThread(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE GetCurrentThread();
        """
        return self.get_max_int() - 1

    @apihook("TlsAlloc", argc=0)
    def TlsAlloc(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD TlsAlloc();
        """
        thread = emu.get_current_thread()
        tls = thread.tls

        idx = self.tls_count
        self.tls_count += 1
        tls.extend([0] * (self.tls_count - len(tls)))
        thread.tls = tls

        return idx

    @apihook("TlsSetValue", argc=2)
    def TlsSetValue(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL TlsSetValue(
            DWORD dwTlsIndex,
            LPVOID lpTlsValue
        );
        """
        dwTlsIndex, lpTlsValue = argv
        rv = 0

        thread = emu.get_current_thread()
        tls = thread.tls

        if dwTlsIndex < TLS_SLOT_COUNT:
            tls.extend([0] * (dwTlsIndex + 1 - len(tls)))
            tls[dwTlsIndex] = lpTlsValue
            thread.tls = tls
            rv = 1
            emu.set_last_error(windefs.ERROR_SUCCESS)
        else:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)

        return rv

    @apihook("TlsGetValue", argc=1)
    def TlsGetValue(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPVOID TlsGetValue(
            DWORD dwTlsIndex
        );
        """
        (dwTlsIndex,) = argv
        dwTlsIndex &= 0xFFFFFFFF
        rv = 0

        thread = emu.get_current_thread()
        tls = thread.tls

        if dwTlsIndex < TLS_SLOT_COUNT:
            if dwTlsIndex < len(tls):
                rv = tls[dwTlsIndex]
            emu.set_last_error(windefs.ERROR_SUCCESS)
        else:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)

        return rv

    @apihook("FlsAlloc", argc=1)
    def FlsAlloc(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD FlsAlloc(
            PFLS_CALLBACK_FUNCTION lpCallback
        );
        """
        idx = self.fls_count
        self.fls_count += 1
        return idx

    @apihook("FlsSetValue", argc=2)
    def FlsSetValue(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL FlsSetValue(
            DWORD dwFlsIndex,
            PVOID lpFlsData
        );
        """
        dwFlsIndex, lpFlsData = argv
        rv = 0

        thread = emu.get_current_thread()
        fls = thread.fls

        if dwFlsIndex < max(self.fls_count, 1):
            fls.extend([0] * (dwFlsIndex + 1 - len(fls)))
            fls[dwFlsIndex] = lpFlsData
            thread.fls = fls
            rv = 1
            emu.set_last_error(windefs.ERROR_SUCCESS)
        else:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)

        return rv

    @apihook("FlsGetValue", argc=1)
    def FlsGetValue(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PVOID FlsGetValue(
            DWORD dwFlsIndex
        );
        """
        (dwFlsIndex,) = argv
        rv = 0

        thread = emu.get_current_thread()
        fls = thread.fls

        if dwFlsIndex < max(self.fls_count, 1):
            if dwFlsIndex < len(fls):
                rv = fls[dwFlsIndex]
            emu.set_last_error(windefs.ERROR_SUCCESS)
        else:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)

        return rv

    @apihook("EncodePointer", argc=1)
    def EncodePointer(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PVOID EncodePointer(
            PVOID Ptr
        );
        """
        (Ptr,) = argv
        # Just increment the pointer for now
        rv = Ptr + 1

        return rv

    @apihook("DecodePointer", argc=1)
    def DecodePointer(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PVOID DecodePointer(
            PVOID Ptr
        );
        """
        (Ptr,) = argv
        # Just decrement the pointer for now
        rv = Ptr - 1

        return rv

    @apihook("InitializeCriticalSectionAndSpinCount", argc=2)
    def InitializeCriticalSectionAndSpinCount(
        self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        BOOL InitializeCriticalSectionAndSpinCount(
            LPCRITICAL_SECTION lpCriticalSection,
            DWORD dwSpinCount
        );
        """
        lpCriticalSection, dwSpinCount = argv
        rv = 1

        return rv

    @apihook("EnterCriticalSection", argc=1)
    def EnterCriticalSection(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID EnterCriticalSection(
            LPCRITICAL_SECTION lpCriticalSection
        );
        """
        return

    @apihook("LeaveCriticalSection", argc=1)
    def LeaveCriticalSection(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID LeaveCriticalSection(
            LPCRITICAL_SECTION lpCriticalSection
        );
        """
        return

    @apihook("InterlockedIncrement", argc=1)
    def InterlockedIncrement(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG InterlockedIncrement(
            LONG volatile *Addend
        );
        """
        (Addend,) = argv

        val = self.mem_read(Addend, 4)
        ival = int.from_bytes(val, "little")
        ival = ct.c_long(ival + 1).value & 0xFFFFFFFF
        val = (ival).to_bytes(4, "little")
        self.mem_write(Addend, val)

        return ival

    @apihook("InterlockedDecrement", argc=1)
    def InterlockedDecrement(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG InterlockedDecrement(
            LONG volatile *Addend
        );
        """
        (Addend,) = argv

        val = self.mem_read(Addend, 4)
        ival = int.from_bytes(val, "little")
        ival = ct.c_long(ival - 1).value & 0xFFFFFFFF
        val = (ival).to_bytes(4, "little")
        self.mem_write(Addend, val)

        return ival

    @apihook("InterlockedExchangeAdd", argc=2)
    def InterlockedExchangeAdd(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG InterlockedExchangeAdd(
            LONG volatile *Addend,
            LONG Value
        );
        """
        Addend, Value = argv
        old = self.read_dword(Addend)
        new = (old + (Value & 0xFFFFFFFF)) & 0xFFFFFFFF
        self.write_dword(Addend, new)
        return old

    @apihook("GetCommandLine", argc=0)
    def GetCommandLine(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPTSTR GetCommandLine();
        """
        cw = self.get_char_width(ctx)
        proc = emu.get_current_process()

        # Each process has its own buffer, and each call returns the same buffer, as on Windows.
        cmd_ptr = proc.command_line_buffers.get(cw)
        if cmd_ptr is None:
            data = self.encode_string(proc.cmdline + "\x00", cw)
            cmd_ptr = self.mem_alloc(len(data), tag=f"api.command_line.{ctx.func_name}")
            self.mem_write(cmd_ptr, data)
            proc.command_line_buffers[cw] = cmd_ptr
        return cmd_ptr

    @apihook("ExpandEnvironmentStrings", argc=3)
    def ExpandEnvironmentStrings(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD ExpandEnvironmentStrings(
            LPCTSTR lpSrc,
            LPTSTR lpDst,
            DWORD nSize
        );
        """
        lpSrc, lpDst, nSize = argv
        rv = 0

        cw = self.get_char_width(ctx)
        if lpSrc:
            src = self.read_mem_string(lpSrc, cw)
            dst = src
            ctx.args["lpSrc"].display = src
            for k, v in emu.get_env().items():
                ev = f"%{k.lower()}%"
                if ev in dst.lower():
                    o = dst.lower().find(ev)
                    dst = dst[:o] + v + dst[o + len(ev) :]

            rv = len(dst) + 1
            if lpDst and nSize >= rv:
                self.write_mem_string(dst, lpDst, cw)
                ctx.args["lpDst"].display = dst

        return rv

    @apihook("GetEnvironmentStrings", argc=0)
    def GetEnvironmentStrings(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPCH GetEnvironmentStrings();
        """
        out = ""
        fn = ctx.func_name
        cw = 2 if fn.endswith("W") else 1
        for k, v in emu.get_env().items():
            out += f"{k}={v}\x00"

        out += "\x00"

        env_ptr = self.mem_alloc(len(out) * cw, tag=f"api.environment.{fn}")

        ev = self.encode_string(out, cw)

        self.mem_write(env_ptr, ev)

        return env_ptr

    @apihook("FreeEnvironmentStrings", argc=1)
    def FreeEnvironmentStrings(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL FreeEnvironmentStrings(
            LPTCH penv
        );
        """
        (penv,) = argv

        mm = emu.get_address_map(penv)
        if mm and mm.base == penv and mm.tag and mm.tag.startswith("api.environment."):
            self.mem_free(penv)

        return True

    @apihook("GetFullPathName", argc=4)
    def GetFullPathName(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetFullPathName(
            LPCTSTR lpFileName,
            DWORD nBufferLength,
            LPTSTR lpBuffer,
            LPTSTR *lpFilePart
        );
        """
        lpFileName, nBufferLength, lpBuffer, lpFilePart = argv
        cw = self.get_char_width(ctx)
        rv = 0

        if lpFileName:
            fn = self.read_mem_string(lpFileName, cw)
            bn = ntpath.basename(fn)

            offset = len(fn) - len(bn)
            if not lpBuffer or nBufferLength < len(fn) + 1:
                rv = len(fn) + 1
            else:
                self.write_mem_string(fn, lpBuffer, cw)

                if lpFilePart:
                    ptr = lpBuffer + offset * cw if bn else 0
                    self.write_ptr(lpFilePart, ptr)

                rv = len(fn)

        return rv

    def get_final_path(self, emu, path, flags):
        """
        Return the path of an open file in the form that ``flags`` selects, or
        None when the path has no drive letter or the drive is not known.
        """
        drive, rest = ntpath.splitdrive(path)
        if len(drive) != 2 or not rest.startswith("\\"):
            return None
        drive = drive.upper()
        volume = flags & VOLUME_NAME_MASK
        if volume == VOLUME_NAME_DOS:
            return "\\\\?\\" + drive + rest
        if volume == VOLUME_NAME_NONE:
            return rest
        if volume == VOLUME_NAME_GUID:
            disk = emu.get_drive_manager().get_drive(root_path=drive + "\\")
            return disk.volume_guid_path.rstrip("\\") + rest if disk and disk.volume_guid_path else None
        device = next((dev for link, dev in emu.om.symlinks if link.upper() == "\\??\\" + drive), None)
        return device + rest if device else None

    @apihook("GetFinalPathNameByHandle", argc=4)
    def GetFinalPathNameByHandle(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetFinalPathNameByHandle(
            HANDLE hFile,
            LPTSTR lpszFilePath,
            DWORD cchFilePath,
            DWORD dwFlags
        );
        """
        hFile, lpszFilePath, cchFilePath, dwFlags = argv
        cchFilePath &= 0xFFFFFFFF
        dwFlags &= 0xFFFFFFFF
        cw = self.get_char_width(ctx)

        if dwFlags & ~(VOLUME_NAME_MASK | FILE_NAME_OPENED) or (dwFlags & VOLUME_NAME_MASK) not in (
            VOLUME_NAME_DOS,
            VOLUME_NAME_GUID,
            VOLUME_NAME_NT,
            VOLUME_NAME_NONE,
        ):
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        f = self.get_file(hFile)
        if not f:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        path = self.get_final_path(emu, f.path, dwFlags)
        if path is None:
            emu.set_last_error(windefs.ERROR_PATH_NOT_FOUND)
            return 0

        if not lpszFilePath or cchFilePath <= len(path):
            return len(path) + 1
        self.write_mem_string(path, lpszFilePath, cw)
        return len(path)

    @apihook("GetStartupInfo", argc=1)
    def GetStartupInfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID GetStartupInfo(
            LPSTARTUPINFO lpStartupInfo
        );
        """
        (lpStartupInfo,) = argv

        cw = self.get_char_width(ctx)
        si = self.k32types.STARTUPINFO(emu.get_ptr_size())

        # The desktop and title strings are written once per process and width
        proc = emu.get_current_process()
        ptrs = self.startup_info.get((proc, cw))
        if not ptrs:
            sn = "W" if cw == 2 else "A"
            ptrs = []
            for field, text in (("lpDesktop", proc.get_desktop_name()), ("lpTitle", proc.title or proc.path)):
                size = len(self.encode_string(text, cw)) + cw
                ptr = self.mem_alloc(size, tag=f"api.struct.STARTUPINFO{sn}.{field}")
                self.write_mem_string(text, ptr, cw)
                ptrs.append(ptr)
            self.startup_info[(proc, cw)] = ptrs
        si.lpDesktop, si.lpTitle = ptrs

        si.cb = self.sizeof(si)
        si.hStdInput = 0
        si.hStdOutput = 1
        si.hStdError = 2

        self.mem_write(lpStartupInfo, self.get_bytes(si))

    @apihook("GetStdHandle", argc=1)
    def GetStdHandle(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE GetStdHandle(
            DWORD nStdHandle
        );
        """
        (nStdHandle,) = argv

        proc = emu.get_current_process()
        hnd = proc.get_std_handle(nStdHandle)

        return hnd

    @apihook("SetStdHandle", argc=2)
    def SetStdHandle(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetStdHandle(
            DWORD nStdHandle,
            HANDLE hHandle
        );
        """
        nStdHandle, hHandle = argv

        proc = emu.get_current_process()
        if not proc.set_std_handle(nStdHandle, hHandle):
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        return 1

    @apihook("GetFileType", argc=1)
    def GetFileType(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetFileType(
            HANDLE hFile
        );
        """
        FILE_TYPE_UNKNOWN = 0
        FILE_TYPE_DISK = 1
        FILE_TYPE_CHAR = 2
        FILE_TYPE_PIPE = 3

        (hFile,) = argv

        if self.is_std_handle(emu, hFile):
            return FILE_TYPE_CHAR
        f = emu.get_handle_table().get(hFile, fileman.File)
        if not f:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return FILE_TYPE_UNKNOWN
        if isinstance(f, fileman.NullDevice):
            return FILE_TYPE_CHAR
        if isinstance(f, fileman.Pipe):
            return FILE_TYPE_PIPE
        return FILE_TYPE_DISK

    @apihook("SetHandleCount", argc=1)
    def SetHandleCount(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT SetHandleCount(
            UINT uNumber
        );
        """
        (uNumber,) = argv

        emu.set_last_error(windefs.ERROR_INVALID_HANDLE)

        return uNumber

    @apihook("GetACP", argc=0)
    def GetACP(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetACP();
        """
        return codepage.ANSI_CODE_PAGE

    @apihook("IsValidCodePage", argc=1)
    def IsValidCodePage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsValidCodePage(
            UINT CodePage
        );
        """
        (CodePage,) = argv

        # CP_ACP, CP_OEMCP and CP_THREAD_ACP are not valid here: Windows wants a real code page number.
        return CodePage in (codepage.ANSI_CODE_PAGE, codepage.OEM_CODE_PAGE, codepage.CP_UTF8)

    @apihook("GetCPInfo", argc=2)
    def GetCPInfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetCPInfo(
            UINT CodePage,
            LPCPINFO lpCPInfo
        );
        """
        CodePage, lpCPInfo = argv

        try:
            codepage.get_codec(CodePage)
        except ValueError:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return False

        # typedef struct _cpinfo {
        #     UINT MaxCharSize;
        #     BYTE DefaultChar[2];
        #     BYTE LeadByte[12];
        # } CPINFO;
        max_char_size = 4 if CodePage == codepage.CP_UTF8 else 1
        self.mem_write(lpCPInfo, struct.pack("<I2s12s", max_char_size, b"?", b""))

        return True

    @apihook("WideCharToMultiByte", argc=8)
    def WideCharToMultiByte(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int WideCharToMultiByte(
            UINT CodePage,
            DWORD dwFlags,
            LPCWCH lpWideCharStr,
            int cchWideChar,
            LPSTR lpMultiByteStr,
            int cbMultiByte,
            LPCCH lpDefaultChar,
            LPBOOL lpUsedDefaultChar
        );
        """
        (
            CodePage,
            dwFlags,
            lpWideCharStr,
            cchWideChar,
            lpMultiByteStr,
            cbMultiByte,
            lpDefaultChar,
            lpUsedDefaultChar,
        ) = argv

        cchWideChar = cchWideChar & 0xFFFFFFFF
        cbMultiByte = cbMultiByte & 0xFFFFFFFF

        if not lpWideCharStr or not cchWideChar:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0
        # Windows takes no default character for UTF-8
        if CodePage == codepage.CP_UTF8 and (lpDefaultChar or lpUsedDefaultChar):
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        if cchWideChar == 0xFFFFFFFF:
            wcs = b""
            o = 0
            while emu.is_address_valid(lpWideCharStr + o + 2):
                wcs += self.mem_read(lpWideCharStr + o, 2)
                if wcs.endswith(b"\0\0"):
                    break
                o += 2
        else:
            wcs = self.mem_read(lpWideCharStr, cchWideChar * 2)

        text = wcs.decode("utf-16le", "replace")
        try:
            cs = codepage.encode_code_page(text, CodePage)
        except ValueError:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        emu.set_last_error(windefs.ERROR_SUCCESS)
        if lpMultiByteStr and cbMultiByte and len(cs) > cbMultiByte:
            self.mem_write(lpMultiByteStr, cs[:cbMultiByte])
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
            return 0
        if lpUsedDefaultChar:
            # The encoder puts the default character in place of each character that the code page does not have
            used_default = codepage.decode_code_page(cs, CodePage) != text
            self.mem_write(lpUsedDefaultChar, int(used_default).to_bytes(4, "little"))
        if not lpMultiByteStr or cbMultiByte == 0:
            return len(cs)
        self.mem_write(lpMultiByteStr, cs)
        return len(cs)

    @apihook("MultiByteToWideChar", argc=6)
    def MultiByteToWideChar(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int MultiByteToWideChar(
            UINT CodePage,
            DWORD dwFlags,
            LPCCH lpMultiByteStr,
            int cbMultiByte,
            LPWSTR lpWideCharStr,
            int cchWideChar
        );
        """
        (CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar) = argv

        cchWideChar = cchWideChar & 0xFFFFFFFF
        cbMultiByte = cbMultiByte & 0xFFFFFFFF

        if not lpMultiByteStr or not cbMultiByte or (cchWideChar and not lpWideCharStr):
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        if cbMultiByte == 0xFFFFFFFF:
            cbMultiByte = self.mem_string_len(lpMultiByteStr, 1) + 1
        try:
            mbs = codepage.decode_code_page(self.mem_read(lpMultiByteStr, cbMultiByte), CodePage)
        except ValueError:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0
        ctx.args["lpMultiByteStr"].display = mbs.rstrip("\x00")

        ws = mbs.encode("utf-16le")
        emu.set_last_error(windefs.ERROR_SUCCESS)
        if not cchWideChar:
            return len(ws) // 2
        if len(ws) // 2 > cchWideChar:
            self.mem_write(lpWideCharStr, ws[: cchWideChar * 2])
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
            return 0
        self.mem_write(lpWideCharStr, ws)
        return len(ws) // 2

    @apihook("GetStringTypeA", argc=5)
    def GetStringTypeA(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetStringTypeA(
            LCID Locale,
            DWORD dwInfoType,
            LPCSTR lpSrcStr,
            int cchSrc,
            LPWORD lpCharType
        );
        """
        args = argv[1:]
        return self.GetStringTypeW(emu, args, ctx)

    @apihook("GetStringTypeW", argc=4)
    def GetStringTypeW(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetStringTypeW(
            DWORD dwInfoType,
            LPCWCH lpSrcStr,
            int cchSrc,
            LPWORD lpCharType
        );
        """
        dwInfoType, lpSrcStr, cchSrc, lpCharType = argv
        rv = 0

        cw = self.get_char_width(ctx)
        if not cw:
            cw = 2

        if (cchSrc & 0xFFFFFFFF) == 0xFFFFFFFF:
            cchSrc = self.mem_string_len(lpSrcStr, cw) + 1

        CT_CTYPE1 = 1

        C1_UPPER, C1_LOWER, C1_DIGIT, C1_SPACE = 0x001, 0x0002, 0x0004, 0x0008
        C1_PUNCT, C1_CNTRL, C1_BLANK, C1_XDIGIT = 0x010, 0x0020, 0x0040, 0x0080
        C1_ALPHA, C1_DEFINED = 0x0100, 0x0200

        if dwInfoType == CT_CTYPE1:
            # Walk each 16bit character
            wcs = self.mem_read(lpSrcStr, cchSrc * cw)
            output = b""
            for char in [wcs[i : i + cw] for i in range(0, len(wcs), cw)]:
                ctype = 0
                c = int.from_bytes(char, "little")
                # Is punc?
                if (
                    (c > 0x20 and c < 0x30)
                    or (c >= 0x3A and c <= 0x40)
                    or (c >= 0x5B and c <= 0x60)
                    or (c >= 0x7B and c <= 0x7E)
                ):
                    ctype |= C1_PUNCT
                if c < 0x20 or c == 0x7F:
                    ctype |= C1_CNTRL
                if c >= 0x9 and c <= 0xD:
                    ctype |= C1_SPACE
                if c == 0x20:
                    ctype |= C1_BLANK | C1_SPACE
                if c >= 0x41 and c <= 0x5A:
                    ctype |= C1_UPPER
                if c >= 0x61 and c <= 0x7A:
                    ctype |= C1_LOWER
                if c >= 0x30 and c <= 0x39:
                    ctype |= C1_DIGIT
                if (c >= 0x30 and c <= 0x39) or (c >= 0x41 and c <= 0x46):
                    ctype |= C1_XDIGIT
                if c >= 0x61 and c <= 0x66:
                    ctype |= C1_XDIGIT
                if (ctype & C1_UPPER) or (ctype & C1_LOWER):
                    ctype |= C1_ALPHA
                if c != 0:
                    ctype |= C1_DEFINED

                b = (ctype).to_bytes(2, "little")
                output += b
                rv = 1

            self.mem_write(lpCharType, output)

        return rv

    @apihook("LCMapString", argc=6)
    def LCMapString(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int LCMapString(
            LCID Locale,
            DWORD dwMapFlags,
            LPCTSTR lpSrcStr,
            int cchSrc,
            LPTSTR lpDestStr,
            int cchDest
        );
        """
        (Locale, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest) = argv

        rv = 0
        cw = self.get_char_width(ctx)

        if lpSrcStr and (cchSrc & 0xFFFFFFFF) == 0xFFFFFFFF:
            cchSrc = self.mem_string_len(lpSrcStr, cw) + 1

        if lpSrcStr == 0 or cchSrc == 0:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
        elif lpDestStr == 0 or cchDest == 0:
            emu.set_last_error(windefs.ERROR_SUCCESS)
            rv = cchSrc
        elif cchDest < cchSrc:
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
        else:
            data = self.mem_read(lpSrcStr, cchSrc * cw)
            self.mem_write(lpDestStr, data)
            rv = int(len(data) / cw)

        return rv

    @apihook("LCMapStringEx", argc=9)
    def LCMapStringEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int LCMapStringEx(
            LPCWSTR lpLocaleName,
            DWORD dwMapFlags,
            LPCWSTR lpSrcStr,
            int cchSrc,
            LPWSTR lpDestStr,
            int cchDest,
            LPNLSVERSIONINFO lpVersionInformation,
            LPVOID lpReserved,
            LPARAM sortHandle
        );
        """
        (
            lpLocaleName,
            dwMapFlags,
            lpSrcStr,
            cchSrc,
            lpDestStr,
            cchDest,
            lpVersionInformation,
            lpReserved,
            sortHandle,
        ) = argv

        rv = 0

        if lpSrcStr and (cchSrc & 0xFFFFFFFF) == 0xFFFFFFFF:
            cchSrc = self.mem_string_len(lpSrcStr, 2) + 1

        if lpSrcStr == 0 or cchSrc == 0:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
        elif lpDestStr == 0 or cchDest == 0:
            emu.set_last_error(windefs.ERROR_SUCCESS)
            rv = cchSrc
        elif cchDest < cchSrc:
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
        else:
            data = self.mem_read(lpSrcStr, cchSrc * 2)
            self.mem_write(lpDestStr, data)
            rv = int(len(data) / 2)

        return rv

    @apihook("GetModuleFileName", argc=3)
    def GetModuleFileName(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetModuleFileName(
            HMODULE hModule,
            LPTSTR lpFilename,
            DWORD nSize
        );
        """
        hModule, lpFilename, nSize = argv
        size = 0
        cw = self.get_char_width(ctx)

        filename = ""
        if hModule == 0:
            proc = emu.get_current_process()
            filename = proc.path
        else:
            mods = emu.get_peb_modules()
            cm = emu.get_current_module()
            if cm and cm.base == hModule:
                filename = cm.emu_path
            else:
                for mod in mods:
                    if mod.base == hModule:
                        filename = mod.emu_path

        if filename:
            ctx.args["lpFilename"].display = filename
            out = self.encode_string(filename, cw)

            size = int(len(out) / cw)
            if nSize < size + 1:  # null terminator
                emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
                out = out[: (nSize - 1) * cw] + b"\0" * cw if nSize else b""
                size = nSize
            else:
                out += b"\0" * cw

            if out:
                self.mem_write(lpFilename, out)
        return size

    @apihook("HeapFree", argc=3)
    def HeapFree(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL HeapFree(
            HANDLE hHeap,
            DWORD dwFlags,
            LPVOID lpMem
        );
        """
        hHeap, dwFlags, lpMem = argv

        if lpMem and not self.heap_free(lpMem):
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return 1

    @apihook("LocalFree", argc=1)
    def LocalFree(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HLOCAL LocalFree(
            HLOCAL hMem
        );
        """
        rv = 0
        (hMem,) = argv

        if hMem == 0:
            return rv

        if not self.heap_free(hMem):
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return hMem
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return rv

    @apihook("GlobalHandle", argc=1)
    def GlobalHandle(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HGLOBAL GlobalHandle(
            LPCVOID pMem
        );
        """
        (pMem,) = argv
        return pMem

    @apihook("GlobalUnlock", argc=1)
    def GlobalUnlock(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GlobalUnlock(
            HGLOBAL hMem
        );
        """
        return 0

    @apihook("GlobalFree", argc=1)
    def GlobalFree(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HGLOBAL GlobalFree(
            HGLOBAL hMem
        );
        """
        (hMem,) = argv

        if hMem and not self.heap_free(hMem):
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return hMem
        return 0

    @apihook("GetSystemDirectory", argc=2)
    def GetSystemDirectory(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetSystemDirectory(
            LPTSTR lpBuffer,
            UINT uSize
        );
        """
        rv = 0
        lpBuffer, uSize = argv

        cw = self.get_char_width(ctx)
        fn = ctx.func_name
        if "WindowsDirectory" in fn:
            sysroot = "C:\\Windows"
        else:
            sysroot = "C:\\Windows\\system32"

        ctx.args["lpBuffer"].display = sysroot
        sysroot += "\x00"
        out = self.encode_string(sysroot, cw)

        if len(sysroot) > uSize:
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
            rv = len(sysroot)
        else:
            self.mem_write(lpBuffer, out)
            emu.set_last_error(windefs.ERROR_SUCCESS)
            rv = len(sysroot) - 1

        return rv

    @apihook("IsDBCSLeadByte", argc=1)
    def IsDBCSLeadByte(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsDBCSLeadByte(
            BYTE TestChar
        );
        """
        return False

    @apihook("IsDBCSLeadByteEx", argc=2)
    def IsDBCSLeadByteEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsDBCSLeadByteEx(
            UINT CodePage,
            BYTE TestChar
        );
        """
        return False

    @apihook("SetEnvironmentVariable", argc=2)
    def SetEnvironmentVariable(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetEnvironmentVariable(
            LPCTSTR lpName,
            LPCTSTR lpValue
        );
        """
        lpName, lpValue = argv
        cw = self.get_char_width(ctx)
        if lpName and lpValue:
            name = self.read_mem_string(lpName, cw)
            val = self.read_mem_string(lpValue, cw)
            ctx.args["lpName"].display = name
            ctx.args["lpValue"].display = val
            emu.set_env(name, val)
        return True

    @apihook("SetDllDirectory", argc=1)
    def SetDllDirectory(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetDllDirectory(
            LPCTSTR lpPathName
        );
        """
        (lpPathName,) = argv

        cw = self.get_char_width(ctx)
        if lpPathName:
            ctx.args["lpPathName"].display = self.read_mem_string(lpPathName, cw)
        return True

    @apihook("GetWindowsDirectory", argc=2)
    def GetWindowsDirectory(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetWindowsDirectory(
            LPTSTR lpBuffer,
            UINT uSize
        );
        """
        return self.GetSystemDirectory(emu, argv, ctx)

    @apihook("GetSystemWindowsDirectory", argc=2)
    def GetSystemWindowsDirectory(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetSystemWindowsDirectory(
            LPTSTR lpBuffer,
            UINT uSize
        );
        """
        return self.GetSystemDirectory(emu, argv, ctx)

    @apihook("CreateFileMapping", argc=6)
    def CreateFileMapping(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE CreateFileMapping(
            HANDLE hFile,
            LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
            DWORD flProtect,
            DWORD dwMaximumSizeHigh,
            DWORD dwMaximumSizeLow,
            LPCTSTR lpName
        );
        """
        hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName = argv

        cw = self.get_char_width(ctx)

        # Get to full map size
        size = (dwMaximumSizeHigh << 32) | dwMaximumSizeLow

        name = ""
        if lpName:
            name = self.read_mem_string(lpName, cw)
            ctx.args["lpName"].display = name

        f = None
        if hFile and ct.c_int32(hFile).value != windefs.INVALID_HANDLE_VALUE:
            f = self.get_file(hFile)
            if not f:
                emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
                return 0
        if f and flProtect & PAGE_PROTECTION_FLAGS.SEC_IMAGE:
            try:
                emu.load_pe(data=f.get_contents())
            except WindowsEmuError:
                emu.set_last_error(windefs.ERROR_BAD_EXE_FORMAT)
                return 0

        hmap = self.file_create_mapping(hFile, name, size, flProtect)

        return hmap

    @apihook("MapViewOfFile", argc=5)
    def MapViewOfFile(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPVOID MapViewOfFile(
            HANDLE hFileMappingObject,
            DWORD dwDesiredAccess,
            DWORD dwFileOffsetHigh,
            DWORD dwFileOffsetLow,
            SIZE_T dwNumberOfBytesToMap
        );
        """
        hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap = argv
        return self.map_view(
            emu, hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap, 0
        )

    @apihook("MapViewOfFileEx", argc=6)
    def MapViewOfFileEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPVOID MapViewOfFileEx(
            HANDLE hFileMappingObject,
            DWORD dwDesiredAccess,
            DWORD dwFileOffsetHigh,
            DWORD dwFileOffsetLow,
            SIZE_T dwNumberOfBytesToMap,
            LPVOID lpBaseAddress
        );
        """
        return self.map_view(emu, *argv)

    def map_view(self, emu, hmap, access, offset_high, offset_low, bytes_to_map, base_address):
        """
        Map a view of a file mapping at ``base_address``, or at any free
        address when ``base_address`` is 0.
        """
        fman = emu.get_file_manager()
        mapping = fman.get_mapping(hmap)
        tag_prefix = "api.MapViewOfFile"
        buf = 0

        def get_view_range(size):
            if not base_address:
                base, size = emu.get_valid_ranges(size)
                while base and base & 0xFFF:
                    base, size = emu.get_valid_ranges(size)
                return base, size
            base, size = emu.get_valid_ranges(size, base_address)
            return (base, size) if base == base_address else (0, size)

        if mapping and base_address & 0xFFFF:
            emu.set_last_error(windefs.ERROR_INVALID_ADDRESS)
        elif mapping:
            f = mapping.backed_file
            full_offset = (offset_high << 32) | offset_low
            size = 0
            view_perms = self.map_view_access_to_emu_perms(access, mapping.prot)
            if f:
                data = f.get_contents()
                if bytes_to_map != 0:
                    data = data[full_offset : full_offset + bytes_to_map]
                else:
                    data = data[full_offset:]

                fname = ntpath.basename(f.path)
                fname = fname.replace(".", "_")

                # If the call to CreateFileMapping (done before calling this API)
                # has beed done with SEC_IMAGE protection, the mapping is not
                # done as a contigous stream of bytes, but it is mapped as
                # PE file
                pe_mapping = mapping.prot & PAGE_PROTECTION_FLAGS.SEC_IMAGE
                if pe_mapping:
                    # Now map the file as PE file
                    pe = emu.load_pe(data=data)
                    base, size = get_view_range(pe.image_size)
                    if not base:
                        emu.set_last_error(windefs.ERROR_INVALID_ADDRESS)
                        return 0

                    emu.mem_map(pe.image_size, base=base, perms=view_perms, tag=f"{tag_prefix}.{fname}.0x{base:x}")
                    mapping.add_view(base, full_offset, size, access)
                    self.mem_write(base, pe.mapped_image)
                    buf = base
                else:
                    # Just copy the bytes as they are
                    base, size = get_view_range(len(data))
                    if not base:
                        emu.set_last_error(windefs.ERROR_INVALID_ADDRESS)
                        return 0

                    buf = self.mem_alloc(base=base, size=size, perms=view_perms, shared=True)
                    mm = emu.get_address_map(buf)
                    mm.tag = f"{tag_prefix}.{fname}.0x{buf:x}"
                    mapping.add_view(buf, full_offset, size, access)
                    self.mem_write(buf, data)
                    emu.set_last_error(windefs.ERROR_SUCCESS)
            else:
                if not bytes_to_map:
                    bytes_to_map = mapping.size - full_offset
                try:
                    base, size = get_view_range(bytes_to_map)
                except OutOfMemoryError:
                    emu.set_last_error(windefs.ERROR_NOT_ENOUGH_MEMORY)
                    return 0
                if not base:
                    emu.set_last_error(windefs.ERROR_INVALID_ADDRESS)
                    return 0
                buf = self.mem_alloc(base=base, size=size, perms=view_perms, tag=tag_prefix, shared=True)
                emu.set_last_error(windefs.ERROR_SUCCESS)
                mapping.add_view(buf, full_offset, size, access)

            for base, view in mapping.views.items():
                if base != buf and view.size == size and full_offset == view.offset:
                    data = self.mem_read(base, size)
                    self.mem_write(buf, data)

        else:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)

        return buf

    @apihook("UnmapViewOfFile", argc=1)
    def UnmapViewOfFile(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL UnmapViewOfFile(
            LPCVOID lpBaseAddress
        );
        """
        (lpBaseAddress,) = argv
        rv = False

        mm = emu.get_address_map(lpBaseAddress)
        if mm:
            self.mem_free(lpBaseAddress)
            rv = True
            emu.set_last_error(windefs.ERROR_SUCCESS)
        else:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)

        return rv

    @apihook("GetSystemInfo", argc=1)
    def GetSystemInfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID GetSystemInfo(
            LPSYSTEM_INFO lpSystemInfo
        );
        """
        (lpSystemInfo,) = argv
        ptr_size = emu.get_ptr_size()
        si = self.k32types.SYSTEM_INFO(ptr_size)
        si.dwPageSize = 0x1000
        si.lpMinimumApplicationAddress = 0x10000
        si.lpMaximumApplicationAddress = self.get_max_application_address(emu)
        si.dwActiveProcessorMask = (1 << PROCESSOR_COUNT) - 1
        si.dwNumberOfProcessors = PROCESSOR_COUNT
        si.dwAllocationGranularity = 0x10000
        si.wProcessorLevel = 6

        if ptr_size == 4:
            si.wProcessorArchitecture = k32defs.PROCESSOR_ARCHITECTURE_INTEL
            si.dwProcessorType = k32defs.PROCESSOR_INTEL_PENTIUM
        else:
            si.wProcessorArchitecture = k32defs.PROCESSOR_ARCHITECTURE_AMD64
            si.dwProcessorType = k32defs.PROCESSOR_AMD_X8664

        self.mem_write(lpSystemInfo, si.get_bytes())

    @apihook("GetFileAttributes", argc=1)
    def GetFileAttributes(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetFileAttributes(
            LPCTSTR lpFileName
        );
        """
        (lpFileName,) = argv
        cw = self.get_char_width(ctx)
        rv = windefs.INVALID_FILE_ATTRIBUTES
        if not lpFileName:
            emu.set_last_error(windefs.ERROR_PATH_NOT_FOUND)
            return rv
        target = self.read_mem_string(lpFileName, cw)
        ctx.args["lpFileName"].display = target
        if not target:
            emu.set_last_error(windefs.ERROR_PATH_NOT_FOUND)
        elif emu.get_file_manager().is_directory(target):
            rv = windefs.FILE_ATTRIBUTE_DIRECTORY
        elif self.does_file_exist(target):
            rv = windefs.FILE_ATTRIBUTE_NORMAL
        else:
            emu.set_last_error(windefs.ERROR_FILE_NOT_FOUND)
        return rv

    @apihook("GetFileAttributesEx", argc=3)
    def GetFileAttributesEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetFileAttributesEx(
            LPCTSTR lpFileName,
            GET_FILEEX_INFO_LEVELS fInfoLevelId,
            LPVOID lpFileInformation
        );
        """
        lpFileName, fInfoLevelId, lpFileInformation = argv

        if not lpFileName:
            emu.set_last_error(windefs.ERROR_PATH_NOT_FOUND)
            return False

        cw = self.get_char_width(ctx)

        filename = self.read_mem_string(lpFileName, cw)
        ctx.args["lpFileName"].display = filename
        if not filename:
            emu.set_last_error(windefs.ERROR_PATH_NOT_FOUND)
            return False

        if fInfoLevelId != GET_FILEEX_INFO_LEVELS.GetFileExInfoStandard:
            return False

        ctx.args["fInfoLevelId"].display = decode(GET_FILEEX_INFO_LEVELS, fInfoLevelId)

        file_data = k32defs.WIN32_FILE_ATTRIBUTE_DATA(emu.get_ptr_size())

        # Set WIN32_FILE_ATTRIBUTE_DATA.dwFileAttributes to Normal
        file_data.dwFileAttributes = windefs.FILE_ATTRIBUTE_NORMAL

        timestamp = self.get_system_time()
        for ft in (file_data.ftCreationTime, file_data.ftLastAccessTime, file_data.ftLastWriteTime):
            ft.dwLowDateTime = 0xFFFFFFFF & timestamp
            ft.dwHighDateTime = timestamp >> 32

        if emu.get_file_manager().is_directory(filename):
            file_data.dwFileAttributes = windefs.FILE_ATTRIBUTE_DIRECTORY
            emu.set_last_error(windefs.ERROR_SUCCESS)
            self.mem_write(lpFileInformation, file_data.get_bytes())
            return True

        # Set WIN32_FILE_ATTRIBUTE_DATA.nFileSizeHigh + .nFileSizeLow
        full_size = emu.get_file_manager().get_file_size(filename)
        if full_size is None:
            emu.set_last_error(windefs.ERROR_FILE_NOT_FOUND)
            return False

        file_data.nFileSizeHigh = 0xFFFFFFFF & (full_size >> 32)
        file_data.nFileSizeLow = 0xFFFFFFFF & full_size
        emu.set_last_error(windefs.ERROR_SUCCESS)

        self.mem_write(lpFileInformation, file_data.get_bytes())
        return True

    @apihook("GetFileTime", argc=4)
    def GetFileTime(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetFileTime(
            HANDLE hFile,
            LPFILETIME lpCreationTime,
            LPFILETIME lpLastAccessTime,
            LPFILETIME lpLastWriteTime
        );
        """
        hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime = argv

        ft = self.k32types.FILETIME(emu.get_ptr_size())
        timestamp = self.get_system_time()
        ft.dwLowDateTime = 0xFFFFFFFF & timestamp
        ft.dwHighDateTime = timestamp >> 32
        data = self.get_bytes(ft)

        if lpCreationTime:
            self.mem_write(lpCreationTime, data)
        if lpLastAccessTime:
            self.mem_write(lpLastAccessTime, data)
        if lpLastWriteTime:
            self.mem_write(lpLastWriteTime, data)

        emu.set_last_error(windefs.ERROR_SUCCESS)
        return True

    @apihook("SetFileTime", argc=4)
    def SetFileTime(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetFileTime(
            HANDLE hFile,
            const FILETIME *lpCreationTime,
            const FILETIME *lpLastAccessTime,
            const FILETIME *lpLastWriteTime
        );
        """
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return True

    @apihook("CreateDirectory", argc=2)
    def CreateDirectory(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CreateDirectory(
            LPCTSTR lpPathName,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes
        );
        """
        lpPathName, lpSecurityAttributes = argv
        cw = self.get_char_width(ctx)

        if lpPathName:
            target = self.read_mem_string(lpPathName, cw)
            ctx.args["lpPathName"].display = target
            emu.get_file_manager().create_directory(target)
        return True

    @apihook("RemoveDirectory", argc=1)
    def RemoveDirectory(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL RemoveDirectory(
            LPCTSTR lpPathName
        );
        """
        (lpPathName,) = argv
        cw = self.get_char_width(ctx)

        if lpPathName:
            target = self.read_mem_string(lpPathName, cw)
            ctx.args["lpPathName"].display = target
            emu.get_file_manager().remove_directory(target)

        return True

    @apihook("CopyFile", argc=3)
    def CopyFile(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CopyFile(
            LPCTSTR lpExistingFileName,
            LPCTSTR lpNewFileName,
            BOOL bFailIfExists
        );
        """
        lpExistingFileName, lpNewFileName, bFailIfExists = argv
        cw = self.get_char_width(ctx)

        existing_name = new_name = ""
        if lpExistingFileName:
            existing_name = self.read_mem_string(lpExistingFileName, cw)
            ctx.args["lpExistingFileName"].display = existing_name
        if lpNewFileName:
            new_name = self.read_mem_string(lpNewFileName, cw)
            ctx.args["lpNewFileName"].display = new_name

        if not existing_name or not new_name:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return False

        fm = emu.get_file_manager()
        if bFailIfExists and fm.does_file_exist_by_path(new_name):
            emu.set_last_error(windefs.ERROR_FILE_EXISTS)
            return False

        if fm.copy_file(existing_name, new_name) is None:
            emu.set_last_error(windefs.ERROR_FILE_NOT_FOUND)
            return False
        return True

    @apihook("MoveFile", argc=2)
    def MoveFile(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL MoveFile(
            LPCTSTR lpExistingFileName,
            LPCTSTR lpNewFileName
        );
        """
        lpExistingFileName, lpNewFileName = argv
        cw = self.get_char_width(ctx)

        existing_name = new_name = ""
        if lpExistingFileName:
            existing_name = self.read_mem_string(lpExistingFileName, cw)
            ctx.args["lpExistingFileName"].display = existing_name
        if lpNewFileName:
            new_name = self.read_mem_string(lpNewFileName, cw)
            ctx.args["lpNewFileName"].display = new_name

        if not existing_name or not new_name:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        if emu.get_file_manager().move_file(existing_name, new_name) is None:
            emu.set_last_error(windefs.ERROR_FILE_NOT_FOUND)
            return 0

        emu.set_last_error(windefs.ERROR_SUCCESS)
        return 1

    @apihook("MoveFileEx", argc=3)
    def MoveFileEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL MoveFileEx(
            LPCTSTR lpExistingFileName,
            LPCTSTR lpNewFileName,
            DWORD dwFlags
        );
        """
        lpExistingFileName, lpNewFileName, dwFlags = argv
        cw = self.get_char_width(ctx)

        # The session manager does the move or delete at the next boot.
        if lpExistingFileName and dwFlags & MOVEFILE_DELAY_UNTIL_REBOOT:
            ctx.args["lpExistingFileName"].display = self.read_mem_string(lpExistingFileName, cw)
            if lpNewFileName:
                ctx.args["lpNewFileName"].display = self.read_mem_string(lpNewFileName, cw)
            emu.set_last_error(windefs.ERROR_SUCCESS)
            return 1

        if lpExistingFileName and lpNewFileName and not dwFlags & MOVEFILE_REPLACE_EXISTING:
            target = self.read_mem_string(lpNewFileName, cw)
            if self.does_file_exist(target):
                ctx.args["lpExistingFileName"].display = self.read_mem_string(lpExistingFileName, cw)
                ctx.args["lpNewFileName"].display = target
                emu.set_last_error(windefs.ERROR_ALREADY_EXISTS)
                return 0

        return self.MoveFile(emu, [lpExistingFileName, lpNewFileName], ctx)

    @apihook("CreateFile", argc=7)
    def CreateFile(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE CreateFile(
            LPCTSTR lpFileName,
            DWORD dwDesiredAccess,
            DWORD dwShareMode,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes,
            DWORD dwCreationDisposition,
            DWORD dwFlagsAndAttributes,
            HANDLE hTemplateFile
        );
        """
        (
            lpFileName,
            dwDesiredAccess,
            dwShareMode,
            lpSecurityAttributes,
            dwCreationDisposition,
            dwFlagsAndAttributes,
            hTemplateFile,
        ) = argv
        hnd = self.get_max_int()

        cw = self.get_char_width(ctx)

        if not lpFileName:
            return hnd

        target = self.read_mem_string(lpFileName, cw)
        ctx.args["lpFileName"].display = target

        ad = decode_flags(FILE_ACCESS_FLAGS, dwDesiredAccess) if dwDesiredAccess else None
        ctx.args["dwDesiredAccess"].display = decode(FILE_ACCESS_FLAGS, dwDesiredAccess)

        disp_bytes = dwCreationDisposition.to_bytes(8, "little")
        dwCreationDisposition = int(int.from_bytes(disp_bytes[0:4], "little"))
        cd = decode(FILE_CREATION_DISPOSITION, dwCreationDisposition)
        ctx.args["dwCreationDisposition"].display = cd

        obj = self.get_object_from_name(target)
        if obj:
            hnd = self.get_object_handle(obj)
        else:
            open_flags = {"disposition": [cd] if cd else None, "access": ad}
            if dwCreationDisposition == FILE_CREATION_DISPOSITION.CREATE_NEW:
                exists = emu.get_file_manager().does_file_exist_by_path(target)
            else:
                exists = self.does_file_exist(target)
            if exists:
                if dwCreationDisposition == FILE_CREATION_DISPOSITION.CREATE_ALWAYS:
                    emu.set_last_error(windefs.ERROR_ALREADY_EXISTS)
                    hnd = self.file_open(target, create=True, **open_flags)
                elif dwCreationDisposition == FILE_CREATION_DISPOSITION.CREATE_NEW:
                    # Function fails
                    emu.set_last_error(windefs.ERROR_FILE_EXISTS)
                    emu.get_file_manager().record_open(target, **open_flags)
                elif dwCreationDisposition == FILE_CREATION_DISPOSITION.OPEN_ALWAYS:
                    emu.set_last_error(windefs.ERROR_ALREADY_EXISTS)
                    # Open the file
                    hnd = self.file_open(target, **open_flags)
                elif dwCreationDisposition == FILE_CREATION_DISPOSITION.OPEN_EXISTING:
                    emu.set_last_error(windefs.ERROR_SUCCESS)
                    hnd = self.file_open(target, **open_flags)
                elif dwCreationDisposition == FILE_CREATION_DISPOSITION.TRUNCATE_EXISTING:
                    emu.set_last_error(windefs.ERROR_SUCCESS)
                    hnd = self.file_open(target, truncate=True, **open_flags)

            # We don't have a handler for this file, create it
            elif dwCreationDisposition in (
                FILE_CREATION_DISPOSITION.CREATE_ALWAYS,
                FILE_CREATION_DISPOSITION.CREATE_NEW,
            ):
                emu.set_last_error(windefs.ERROR_SUCCESS)
                hnd = self.file_open(target, create=True, **open_flags)
            elif dwCreationDisposition == FILE_CREATION_DISPOSITION.OPEN_ALWAYS:
                emu.set_last_error(windefs.ERROR_SUCCESS)
                # Open the file
                hnd = self.file_open(target, create=True, **open_flags)
            elif dwCreationDisposition in (
                FILE_CREATION_DISPOSITION.OPEN_EXISTING,
                FILE_CREATION_DISPOSITION.TRUNCATE_EXISTING,
            ):
                emu.set_last_error(windefs.ERROR_FILE_NOT_FOUND)
                emu.get_file_manager().record_open(target, **open_flags)

            f = self.get_file(hnd) if hnd else None
            write_access = (
                FILE_ACCESS_FLAGS.FILE_WRITE_DATA | FILE_ACCESS_FLAGS.GENERIC_WRITE | FILE_ACCESS_FLAGS.GENERIC_ALL
            )
            if f and dwDesiredAccess & FILE_ACCESS_FLAGS.FILE_APPEND_DATA and not dwDesiredAccess & write_access:
                f.append = True
        return hnd

    @apihook("DeleteFile", argc=1)
    def DeleteFile(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL DeleteFile(
            LPCTSTR lpFileName
        );
        """
        (lpFileName,) = argv
        cw = self.get_char_width(ctx)
        if not lpFileName:
            emu.set_last_error(windefs.ERROR_PATH_NOT_FOUND)
            return 0

        target = self.read_mem_string(lpFileName, cw)
        ctx.args["lpFileName"].display = target

        if emu.does_file_exist(target):
            # FIXME : does not handle read-only attribute
            emu.file_delete(target)
            return 1
        emu.set_last_error(windefs.ERROR_FILE_NOT_FOUND)
        return 0

    @apihook("ReadFile", argc=5)
    def ReadFile(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL ReadFile(
            HANDLE hFile,
            LPVOID lpBuffer,
            DWORD nNumberOfBytesToRead,
            LPDWORD lpNumberOfBytesRead,
            LPOVERLAPPED lpOverlapped
        );
        """

        def _write_output(emu, data, pBuffer, pBytesRead):
            self.mem_write(pBuffer, data)

            if pBytesRead:
                read = (len(data)).to_bytes(4, "little")
                self.mem_write(pBytesRead, read)

        hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped = argv
        rv = False

        if lpNumberOfBytesRead:
            self.write_dword(lpNumberOfBytesRead, 0)

        proc = emu.get_current_process()
        # SetStdHandle can make a file handle the standard input, so the table comes first
        if hFile not in emu.get_handle_table() and proc and hFile == proc.stdin:
            # The console has no input, so a read gets the end of input
            emu.set_last_error(windefs.ERROR_SUCCESS)
            return True

        f = emu.get_handle_table().get(hFile, fileman.File)
        if not f:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return rv
        if isinstance(f, fileman.Pipe):
            data = f.get_data(nNumberOfBytesToRead)
            if data and lpBuffer:
                _write_output(emu, data, lpBuffer, lpNumberOfBytesRead)
            emu.set_last_error(windefs.ERROR_SUCCESS)
            return bool(data)

        if lpBuffer:
            data = emu.get_file_manager().read_file(f, nNumberOfBytesToRead, buffer=lpBuffer)
            _write_output(emu, data, lpBuffer, lpNumberOfBytesRead)

            rv = True
            emu.set_last_error(windefs.ERROR_SUCCESS)
        else:
            f.get_data(nNumberOfBytesToRead)
        return rv

    @apihook("WriteFile", argc=5)
    def WriteFile(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL WriteFile(
            HANDLE hFile,
            LPCVOID lpBuffer,
            DWORD nNumberOfBytesToWrite,
            LPDWORD lpNumberOfBytesWritten,
            LPOVERLAPPED lpOverlapped
        );
        """
        hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped = argv

        data = b""
        if lpBuffer and nNumberOfBytesToWrite:
            data = self.mem_read(lpBuffer, nNumberOfBytesToWrite)

        if lpNumberOfBytesWritten:
            self.write_dword(lpNumberOfBytesWritten, 0)

        table = emu.get_handle_table()
        proc = emu.get_current_process()
        # SetStdHandle can make a file handle the standard output, so the table comes first
        if hFile not in table and proc and hFile in (proc.stdout, proc.stderr):
            if lpNumberOfBytesWritten:
                self.write_dword(lpNumberOfBytesWritten, len(data))
            emu.set_last_error(windefs.ERROR_SUCCESS)
            return 1

        f = table.get(hFile, fileman.File)
        if not f:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0
        if isinstance(f, fileman.Pipe):
            if data:
                f.add_data(data)
        elif data:
            emu.get_file_manager().write_file(f, data, buffer=lpBuffer)

            data_hex = data.hex()
            ctx.args["lpBuffer"].display = f"{hex(lpBuffer)} ({data_hex[:0x20]})"

        if lpNumberOfBytesWritten:
            self.write_dword(lpNumberOfBytesWritten, len(data))

        emu.set_last_error(windefs.ERROR_SUCCESS)
        return 1

    @apihook("SetFilePointer", argc=4)
    def SetFilePointer(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD SetFilePointer(
            HANDLE hFile,
            LONG lDistanceToMove,
            PLONG lpDistanceToMoveHigh,
            DWORD dwMoveMethod
        );
        """
        hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod = argv

        f = self.get_file(hFile)
        if not f:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return windefs.INVALID_SET_FILE_POINTER

        if lpDistanceToMoveHigh:
            high = int.from_bytes(self.mem_read(lpDistanceToMoveHigh, 4), "little", signed=True)
            offset = (high << 32) | (lDistanceToMove & 0xFFFFFFFF)
        else:
            offset = ct.c_int32(lDistanceToMove).value

        if dwMoveMethod == windefs.FILE_CURRENT:
            offset += f.tell()
        elif dwMoveMethod == windefs.FILE_END:
            offset += f.get_size()
        if offset < 0:
            emu.set_last_error(windefs.ERROR_NEGATIVE_SEEK)
            return windefs.INVALID_SET_FILE_POINTER

        f.seek(offset, windefs.FILE_BEGIN)
        rv = f.tell()
        if lpDistanceToMoveHigh:
            self.write_dword(lpDistanceToMoveHigh, rv >> 32)
        emu.set_last_error(windefs.ERROR_SUCCESS)

        return rv & 0xFFFFFFFF

    @apihook("SetFilePointerEx", argc=5)
    def SetFilePointerEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetFilePointerEx(
            HANDLE hFile,
            LARGE_INTEGER liDistanceToMove,
            PLARGE_INTEGER lpNewFilePointer,
            DWORD dwMoveMethod
        );

        liDistanceToMove is passed by value: two stack slots on x86, one
        register on x64. argc=5 covers the x86 layout; on x64 the fifth slot
        is unused (the caller owns the stack there, so nothing is over-cleaned).
        """
        if emu.get_ptr_size() == 4:
            hFile, lo, hi, lpNewFilePointer, dwMoveMethod = argv
            lDistanceToMove = (hi << 32) | lo
        else:
            hFile, lDistanceToMove, lpNewFilePointer, dwMoveMethod = argv[:4]
        if lDistanceToMove >= 1 << 63:
            lDistanceToMove -= 1 << 64
        f = self.get_file(hFile)
        if not f:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return False
        if dwMoveMethod == windefs.FILE_CURRENT:
            lDistanceToMove += f.tell()
        elif dwMoveMethod == windefs.FILE_END:
            lDistanceToMove += f.get_size()
        if lDistanceToMove < 0:
            emu.set_last_error(windefs.ERROR_NEGATIVE_SEEK)
            return False
        f.seek(lDistanceToMove, windefs.FILE_BEGIN)
        rv = f.tell()
        if lpNewFilePointer:
            self.write_qword(lpNewFilePointer, rv)
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return True

    @apihook("GetFileSize", argc=2)
    def GetFileSize(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetFileSize(
            HANDLE hFile,
            LPDWORD lpFileSizeHigh
        );
        """
        hFile, lpFileSizeHigh = argv

        f = self.get_file(hFile)
        if not f:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return windefs.INVALID_FILE_SIZE
        full_size = f.get_size()
        if lpFileSizeHigh:
            self.mem_write(lpFileSizeHigh, (full_size >> 32).to_bytes(4, "little"))
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return full_size & 0xFFFFFFFF

    @apihook("GetFileSizeEx", argc=2)
    def GetFileSizeEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetFileSizeEx(
            HANDLE hFile,
            PLARGE_INTEGER lpFileSize
        );
        """
        hFile, lpFileSize = argv
        f = self.get_file(hFile)
        if not f:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0
        full_size = f.get_size()
        if lpFileSize:
            self.mem_write(lpFileSize, full_size.to_bytes(8, "little"))
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return 1

    @apihook("CloseHandle", argc=1)
    def CloseHandle(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CloseHandle(
            HANDLE hObject
        );
        """
        (hObject,) = argv

        reg_key = emu.reg_get_key(handle=hObject)
        if reg_key:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        if self.is_std_handle(emu, hObject):
            emu.set_last_error(windefs.ERROR_SUCCESS)
            return 1

        if not emu.get_handle_table().close(hObject):
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return 1

    @apihook("SetEndOfFile", argc=1)
    def SetEndOfFile(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetEndOfFile(
            HANDLE hFile
        );
        """
        return True

    @apihook("IsDebuggerPresent", argc=0)
    def IsDebuggerPresent(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsDebuggerPresent();
        """
        return False

    @apihook("GetVolumeInformation", argc=8)
    def GetVolumeInformation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetVolumeInformation(
            LPCTSTR lpRootPathName,
            LPTSTR lpVolumeNameBuffer,
            DWORD nVolumeNameSize,
            LPDWORD lpVolumeSerialNumber,
            LPDWORD lpMaximumComponentLength,
            LPDWORD lpFileSystemFlags,
            LPTSTR lpFileSystemNameBuffer,
            DWORD nFileSystemNameSize
        );
        """
        (
            lpRootPathName,
            lpVolumeNameBuffer,
            nVolumeNameSize,
            lpVolumeSerialNumber,
            lpMaximumComponentLength,
            lpFileSystemFlags,
            lpFileSystemNameBuffer,
            nFileSystemNameSize,
        ) = argv

        cw = self.get_char_width(ctx)
        if lpRootPathName:
            root_name = self.read_mem_string(lpRootPathName, cw)
            ctx.args["lpRootPathName"].display = root_name

        if lpVolumeNameBuffer and nVolumeNameSize:
            self.write_mem_string("", lpVolumeNameBuffer, cw)
        if lpVolumeSerialNumber:
            self.write_dword(lpVolumeSerialNumber, VOLUME_SERIAL_NUMBER)
        if lpMaximumComponentLength:
            self.write_dword(lpMaximumComponentLength, 255)
        if lpFileSystemFlags:
            self.write_dword(lpFileSystemFlags, 0x03E706FF)
        if lpFileSystemNameBuffer and nFileSystemNameSize > len("NTFS"):
            self.write_mem_string("NTFS", lpFileSystemNameBuffer, cw)

        return True

    @apihook("CreateEvent", argc=4)
    def CreateEvent(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE CreateEvent(
            LPSECURITY_ATTRIBUTES lpEventAttributes,
            BOOL bManualReset,
            BOOL bInitialState,
            LPCTSTR lpName
        );
        """
        lpEventAttributes, bManualReset, bInitialState, lpName = argv

        return self.create_event(emu, lpName, bool(bManualReset), bool(bInitialState), ctx)

    @apihook("CreateEventEx", argc=4)
    def CreateEventEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE CreateEventEx(
            LPSECURITY_ATTRIBUTES lpEventAttributes,
            LPCTSTR lpName,
            DWORD dwFlags,
            DWORD dwDesiredAccess
        );
        """
        lpEventAttributes, lpName, dwFlags, dwDesiredAccess = argv

        manual_reset = bool(dwFlags & windefs.CREATE_EVENT_MANUAL_RESET)
        initial_set = bool(dwFlags & windefs.CREATE_EVENT_INITIAL_SET)
        return self.create_event(emu, lpName, manual_reset, initial_set, ctx)

    def create_event(self, emu, name, manual_reset, initial_state, ctx):
        cw = self.get_char_width(ctx)
        evt_name = None
        obj = None
        if name:
            evt_name = self.read_mem_string(name, cw)
            ctx.args["lpName"].display = evt_name
            obj = self.get_object_from_name(evt_name)

        if obj:
            hnd = emu.get_object_handle(obj)
            emu.set_last_error(windefs.ERROR_ALREADY_EXISTS)
        else:
            hnd, evt = emu.create_event(evt_name)
            evt.manual_reset = manual_reset
            evt.signaled = initial_state
            emu.set_last_error(windefs.ERROR_SUCCESS)

        return hnd

    @apihook("CreateWaitableTimer", argc=3)
    def CreateWaitableTimer(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE CreateWaitableTimer(
            LPSECURITY_ATTRIBUTES lpTimerAttributes,
            BOOL bManualReset,
            LPCTSTR lpTimerName
        );
        """
        lpTimerAttributes, bManualReset, lpTimerName = argv

        cw = self.get_char_width(ctx)
        timer_name = None
        obj = None
        if lpTimerName:
            timer_name = self.read_mem_string(lpTimerName, cw)
            ctx.args["lpTimerName"].display = timer_name
            obj = self.get_object_from_name(timer_name)

        if obj:
            hnd = emu.get_object_handle(obj)
            emu.set_last_error(windefs.ERROR_ALREADY_EXISTS)
        else:
            hnd, _evt = emu.create_event(timer_name)
            emu.set_last_error(windefs.ERROR_SUCCESS)

        return hnd

    @apihook("CreateWaitableTimerEx", argc=4)
    def CreateWaitableTimerEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE CreateWaitableTimerEx(
            LPSECURITY_ATTRIBUTES lpTimerAttributes,
            LPCTSTR lpTimerName,
            DWORD dwFlags,
            DWORD dwDesiredAccess
        );
        """
        lpTimerAttributes, lpTimerName, dwFlags, dwDesiredAccess = argv

        cw = self.get_char_width(ctx)
        timer_name = None
        obj = None
        if lpTimerName:
            timer_name = self.read_mem_string(lpTimerName, cw)
            ctx.args["lpTimerName"].display = timer_name
            obj = self.get_object_from_name(timer_name)

        if obj:
            hnd = emu.get_object_handle(obj)
            emu.set_last_error(windefs.ERROR_ALREADY_EXISTS)
        else:
            hnd, _evt = emu.create_event(timer_name)
            emu.set_last_error(windefs.ERROR_SUCCESS)

        return hnd

    @apihook("OpenWaitableTimer", argc=3)
    def OpenWaitableTimer(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE OpenWaitableTimer(
            DWORD dwDesiredAccess,
            BOOL bInheritHandle,
            LPCTSTR lpTimerName
        );
        """
        dwDesiredAccess, bInheritHandle, lpTimerName = argv

        cw = self.get_char_width(ctx)
        timer_name = None
        hnd = 0
        if lpTimerName:
            timer_name = self.read_mem_string(lpTimerName, cw)
            ctx.args["lpTimerName"].display = timer_name

        obj = self.get_object_from_name(timer_name)

        if obj:
            hnd = emu.get_object_handle(obj)
            emu.set_last_error(windefs.ERROR_ALREADY_EXISTS)
        else:
            emu.set_last_error(windefs.ERROR_PATH_NOT_FOUND)

        return hnd

    @apihook("SetWaitableTimer", argc=6)
    def SetWaitableTimer(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetWaitableTimer(
            HANDLE hTimer,
            const LARGE_INTEGER *lpDueTime,
            LONG lPeriod,
            PTIMERAPCROUTINE pfnCompletionRoutine,
            LPVOID lpArgToCompletionRoutine,
            BOOL fResume
        );
        """
        hTimer, lpDueTime, lPeriod, pfnCompletionRoutine, lpArgToCompletionRoutine, fResume = argv

        obj = emu.get_handle_table().get(hTimer, objman.Event)
        if not obj:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return False

        emu.set_last_error(windefs.ERROR_SUCCESS)
        return True

    @apihook("CancelWaitableTimer", argc=1)
    def CancelWaitableTimer(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CancelWaitableTimer(
            HANDLE hTimer
        );
        """
        (hTimer,) = argv

        obj = emu.get_handle_table().get(hTimer, objman.Event)
        if not obj:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return False

        emu.set_last_error(windefs.ERROR_SUCCESS)
        return True

    @apihook("OpenEvent", argc=3)
    def OpenEvent(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE OpenEvent(
            DWORD dwDesiredAccess,
            BOOL bInheritHandle,
            LPCTSTR lpName
        );
        """
        dwDesiredAccess, bInheritHandle, lpName = argv

        if not lpName:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        evt_name = self.read_mem_string(lpName, self.get_char_width(ctx))
        ctx.args["lpName"].display = evt_name

        obj = self.get_object_from_name(evt_name)
        if not obj:
            emu.set_last_error(windefs.ERROR_FILE_NOT_FOUND)
            return 0

        return emu.get_object_handle(obj)

    @apihook("SetEvent", argc=1)
    def SetEvent(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetEvent(
            HANDLE hEvent
        );
        """
        (hEvent,) = argv

        obj = emu.get_handle_table().get(hEvent, objman.Event)
        if not obj:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return False
        obj.signaled = True
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return True

    @apihook("PulseEvent", argc=1)
    def PulseEvent(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PulseEvent(
            HANDLE hEvent
        );
        """
        (hEvent,) = argv

        obj = emu.get_handle_table().get(hEvent, objman.Event)
        if not obj:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return False
        obj.signaled = False
        return True

    @apihook("SetUnhandledExceptionFilter", argc=1)
    def SetUnhandledExceptionFilter(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(
            LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter
        );
        """
        (lpTopLevelExceptionFilter,) = argv

        emu.set_unhandled_exception_handler(lpTopLevelExceptionFilter)

        return 0

    @apihook("DeleteCriticalSection", argc=1)
    def DeleteCriticalSection(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID DeleteCriticalSection(
            LPCRITICAL_SECTION lpCriticalSection
        );
        """
        return

    @apihook("FlsFree", argc=1)
    def FlsFree(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL FlsFree(
            DWORD dwFlsIndex
        );
        """
        return True

    @apihook("TlsFree", argc=1)
    def TlsFree(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL TlsFree(
            DWORD dwTlsIndex
        );

        Speakeasy does not reuse TLS indexes, so TlsFree does nothing.
        """
        return True

    @apihook("ProcessIdToSessionId", argc=2)
    def ProcessIdToSessionId(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL ProcessIdToSessionId(
            DWORD dwProcessId,
            DWORD *pSessionId
        );
        """
        dwProcessId, pSessionId = argv

        if pSessionId:
            for p in emu.get_processes():
                if p.id == dwProcessId:
                    self.write_dword(pSessionId, p.session)
                    return True

        emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
        return False

    @apihook("InitializeCriticalSectionEx", argc=3)
    def InitializeCriticalSectionEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL InitializeCriticalSectionEx(
            LPCRITICAL_SECTION lpCriticalSection,
            DWORD dwSpinCount,
            DWORD Flags
        );
        """
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return True

    @apihook("InitializeCriticalSection", argc=1)
    def InitializeCriticalSection(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID InitializeCriticalSection(
            LPCRITICAL_SECTION lpCriticalSection
        );
        """
        emu.set_last_error(windefs.ERROR_SUCCESS)

    @apihook("GetOEMCP", argc=0)
    def GetOEMCP(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetOEMCP();
        """
        return codepage.OEM_CODE_PAGE

    @apihook("GlobalLock", argc=1)
    def GlobalLock(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPVOID GlobalLock(
            HGLOBAL hMem
        );
        """
        (hMem,) = argv

        emu.set_last_error(windefs.ERROR_SUCCESS)
        return hMem

    @apihook("LocalLock", argc=1)
    def LocalLock(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPVOID LocalLock(
            HLOCAL hMem
        );
        """
        (hMem,) = argv

        emu.set_last_error(windefs.ERROR_SUCCESS)
        return hMem

    @apihook("HeapDestroy", argc=1)
    def HeapDestroy(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL HeapDestroy(
            HANDLE hHeap
        );
        """
        return True

    @apihook("InitializeSListHead", argc=1)
    def InitializeSListHead(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID InitializeSListHead(
            PSLIST_HEADER ListHead
        );
        """
        (ListHead,) = argv

        self.mem_write(ListHead, b"\x00" * 8)

    @apihook("FreeLibrary", argc=1)
    def FreeLibrary(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL FreeLibrary(
            HMODULE hLibModule
        );

        Speakeasy does not count module references and does not unload modules, so DllMain does not get
        DLL_PROCESS_DETACH.
        """
        return True

    @apihook("WaitForSingleObject", argc=2)
    def WaitForSingleObject(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD WaitForSingleObject(
            HANDLE hHandle,
            DWORD dwMilliseconds
        );

        Speakeasy models events and threads. A wait on a thread that has not started runs the thread to its end,
        unless the timeout is 0. A wait on another object succeeds, except with a timeout of 1 ms, which times out.
        """
        hHandle, dwMilliseconds = argv
        return self.wait_for_object(emu, hHandle, dwMilliseconds)

    def wait_for_object(self, emu, handle, timeout):
        """Wait on one object, as WaitForSingleObject does."""
        obj = None
        if not self.is_std_handle(emu, handle):
            obj = emu.get_handle_table().get(handle)
            if obj is None:
                emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
                return windefs.WAIT_FAILED
        if isinstance(obj, objman.Event):
            return self.wait_for_events(emu, [obj], False, timeout)

        run = emu.get_unstarted_run(obj) if timeout else None
        if run is not None:
            return self.join_threads(emu, [run], windefs.WAIT_OBJECT_0)

        if timeout == 1:
            return windefs.WAIT_TIMEOUT
        return windefs.WAIT_OBJECT_0

    def join_threads(self, emu, runs, result):
        """Run the threads of the queued runs to their end, then return result from the wait."""
        for run in runs:
            yield from emu.join_thread(run)
        return result

    @apihook("GetConsoleMode", argc=2)
    def GetConsoleMode(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetConsoleMode(
            HANDLE hConsoleHandle,
            LPDWORD lpMode
        );
        """
        hConsoleHandle, lpMode = argv
        ENABLE_INPUT_MODES = 0x1F7
        ENABLE_OUTPUT_MODES = 0x3

        proc = emu.get_current_process()
        mode = ENABLE_INPUT_MODES if hConsoleHandle == proc.stdin else ENABLE_OUTPUT_MODES
        if lpMode:
            self.write_dword(lpMode, mode)
        return True

    @apihook("GetConsoleCP", argc=0)
    def GetConsoleCP(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetConsoleCP();
        """
        return 437

    @apihook("GetConsoleOutputCP", argc=0)
    def GetConsoleOutputCP(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetConsoleOutputCP();
        """
        return 437

    @apihook("WriteConsole", argc=5)
    def WriteConsole(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL WriteConsole(
            HANDLE hConsoleOutput,
            const VOID *lpBuffer,
            DWORD nNumberOfCharsToWrite,
            LPDWORD lpNumberOfCharsWritten,
            LPVOID lpReserved
        );
        """
        hConsoleOutput, lpBuffer, nNumberOfCharsToWrite, lpNumberOfCharsWritten, lpReserved = argv
        cw = self.get_char_width(ctx)

        if lpBuffer and nNumberOfCharsToWrite:
            data = self.mem_read(lpBuffer, nNumberOfCharsToWrite * cw)
            ctx.args["lpBuffer"].display = repr(self.decode_string(data, cw))
        if lpNumberOfCharsWritten:
            self.write_dword(lpNumberOfCharsWritten, nNumberOfCharsToWrite)
        return True

    @apihook("HeapSetInformation", argc=4)
    def HeapSetInformation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL HeapSetInformation(
            HANDLE HeapHandle,
            HEAP_INFORMATION_CLASS HeapInformationClass,
            PVOID HeapInformation,
            SIZE_T HeapInformationLength
        );
        """
        return True

    @apihook("SetErrorMode", argc=1)
    def SetErrorMode(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT SetErrorMode(
            UINT uMode
        );
        """
        return 0

    @apihook("GetErrorMode", argc=0)
    def GetErrorMode(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetErrorMode();
        """
        return 0

    @apihook("WerGetFlags", argc=2)
    def WerGetFlags(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT WerGetFlags(
            HANDLE hProcess,
            PDWORD pdwFlags
        );
        """
        hProcess, pdwFlags = argv
        if pdwFlags:
            self.write_dword(pdwFlags, 0)
        return 0  # S_OK

    @apihook("WerSetFlags", argc=1)
    def WerSetFlags(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT WerSetFlags(
            DWORD dwFlags
        );
        """
        return 0  # S_OK

    @apihook("InterlockedCompareExchange", argc=3)
    def InterlockedCompareExchange(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG InterlockedCompareExchange(
            LONG volatile *Destination,
            LONG ExChange,
            LONG Comperand
        );
        """
        Destination, ExChange, Comperand = argv

        dest_bytes = self.mem_read(Destination, 4)
        dest = int.from_bytes(dest_bytes, "little")

        if dest == Comperand:
            self.write_dword(Destination, ExChange)

        return dest

    @apihook("InterlockedExchange", argc=2)
    def InterlockedExchange(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG InterlockedExchange(
            LONG volatile *Target,
            LONG Value
        );
        """
        Target, Value = argv
        tgt = self.mem_read(Target, 4)
        tgt = int.from_bytes(tgt, "little")

        val = (Value).to_bytes(4, byteorder="little")

        self.mem_write(Target, val)

        return tgt

    @apihook("CreateNamedPipe", argc=8)
    def CreateNamedPipe(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE CreateNamedPipe(
            LPCTSTR lpName,
            DWORD dwOpenMode,
            DWORD dwPipeMode,
            DWORD nMaxInstances,
            DWORD nOutBufferSize,
            DWORD nInBufferSize,
            DWORD nDefaultTimeOut,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes
        );
        """
        (
            lpName,
            dwOpenMode,
            dwPipeMode,
            nMaxInstances,
            nOutBufferSize,
            nInBufferSize,
            nDefaultTimeOut,
            lpSecurityAttributes,
        ) = argv

        cw = self.get_char_width(ctx)

        pipe_name = ""
        if lpName:
            pipe_name = self.read_mem_string(lpName, cw)
            ctx.args["lpName"].display = pipe_name

        hnd = emu.pipe_open(pipe_name, dwOpenMode, nMaxInstances, nOutBufferSize, nInBufferSize)
        if not hnd:
            hnd = self.get_max_int()
        return hnd

    @apihook("CreatePipe", argc=4)
    def CreatePipe(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CreatePipe(
            PHANDLE hReadPipe,
            PHANDLE hWritePipe,
            LPSECURITY_ATTRIBUTES lpPipeAttributes,
            DWORD nSize
        );
        """
        hReadPipe, hWritePipe, lpPipeAttributes, nSize = argv

        if not hReadPipe or not hWritePipe:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        hnd = emu.pipe_open("", 0, 1, nSize, nSize)
        if not hnd:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        self.write_ptr(hReadPipe, hnd)
        self.write_ptr(hWritePipe, hnd)
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return 1

    @apihook("PeekNamedPipe", argc=6)
    def PeekNamedPipe(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL PeekNamedPipe(
            HANDLE hNamedPipe,
            LPVOID lpBuffer,
            DWORD nBufferSize,
            LPDWORD lpBytesRead,
            LPDWORD lpTotalBytesAvail,
            LPDWORD lpBytesLeftThisMessage
        );
        """
        (hNamedPipe, lpBuffer, nBufferSize, lpBytesRead, lpTotalBytesAvail, lpBytesLeftThisMessage) = argv
        pipe = emu.get_file_manager().get_pipe(hNamedPipe)
        if not pipe:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        if lpBytesRead:
            self.write_dword(lpBytesRead, 0)
        if lpTotalBytesAvail:
            self.write_dword(lpTotalBytesAvail, 0)
        if lpBytesLeftThisMessage:
            self.write_dword(lpBytesLeftThisMessage, 0)

        emu.set_last_error(windefs.ERROR_SUCCESS)
        return 1

    @apihook("ConnectNamedPipe", argc=2)
    def ConnectNamedPipe(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL ConnectNamedPipe(
            HANDLE hNamedPipe,
            LPOVERLAPPED lpOverlapped
        );
        """
        hNamedPipe, lpOverlapped = argv
        pipe = emu.get_file_manager().get_pipe(hNamedPipe)
        if not pipe:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return False
        return True

    @apihook("DisconnectNamedPipe", argc=1)
    def DisconnectNamedPipe(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL DisconnectNamedPipe(
            HANDLE hNamedPipe
        );
        """
        (hNamedPipe,) = argv
        pipe = emu.get_file_manager().get_pipe(hNamedPipe)
        if not pipe:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return False
        return True

    @apihook("GetLocaleInfo", argc=4)
    def GetLocaleInfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetLocaleInfo(
            LCID Locale,
            LCTYPE LCType,
            LPTSTR lpLCData,
            int cchData
        );
        """
        Locale, LCType, lpLCData, cchData = argv

        rv = 0
        cw = self.get_char_width(ctx)

        ctx.args["Locale"].display = decode(LCID, Locale)
        ctx.args["LCType"].display = decode(LCTYPE, LCType)
        locale_data = ""
        if LCType == LCTYPE.LOCALE_SENGLISHCOUNTRYNAME:
            locale_data = "United States"
        elif LCType == LCTYPE.LOCALE_SENGLISHLANGUAGENAME:
            locale_data = "English"

        if locale_data:
            rv = len(locale_data) + 1
            if cchData:
                if cchData < rv:
                    emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
                    return 0
                self.write_mem_string(locale_data, lpLCData, cw)

        return rv

    @apihook("IsWow64Process", argc=2)
    def IsWow64Process(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsWow64Process(
            HANDLE hProcess,
            PBOOL Wow64Process
        );
        """
        hProcess, Wow64Process = argv
        rv = False

        if Wow64Process:
            self.write_dword(Wow64Process, 0)
            rv = True

        return rv

    @apihook("IsWow64Process2", argc=3)
    def IsWow64Process2(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsWow64Process2(
            HANDLE hProcess,
            USHORT *pProcessMachine,
            USHORT *pNativeMachine
        );
        """
        hProcess, pProcessMachine, pNativeMachine = argv
        self.mem_write(pProcessMachine, windefs.IMAGE_FILE_MACHINE_UNKNOWN.to_bytes(2, "little"))
        if pNativeMachine:
            self.mem_write(pNativeMachine, emu.get_native_machine().to_bytes(2, "little"))
        return True

    @apihook("CheckRemoteDebuggerPresent", argc=2)
    def CheckRemoteDebuggerPresent(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CheckRemoteDebuggerPresent(
            HANDLE hProcess,
            PBOOL pbDebuggerPresent
        );
        """
        hProcess, pbDebuggerPresent = argv
        rv = False

        if pbDebuggerPresent:
            self.write_dword(pbDebuggerPresent, 0)
            rv = True

        return rv

    @apihook("GetComputerName", argc=2)
    def GetComputerName(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetComputerName(
            LPTSTR lpBuffer,
            LPDWORD nSize
        );
        """
        lpBuffer, nSize = argv
        cw = self.get_char_width(ctx)

        host = emu.config.hostname
        size = self.read_dword(nSize)
        if not lpBuffer or size <= len(host):
            self.write_dword(nSize, len(host) + 1)
            emu.set_last_error(windefs.ERROR_BUFFER_OVERFLOW)
            return False

        self.write_mem_string(host, lpBuffer, cw)
        self.write_dword(nSize, len(host))
        ctx.args["lpBuffer"].display = host
        return True

    @apihook("GetVersionEx", argc=1)
    def GetVersionEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetVersionEx(
            LPOSVERSIONINFO lpVersionInformation
        );
        """
        (lpVersionInformation,) = argv

        cw = self.get_char_width(ctx)
        osver: k32defs.OSVERSIONINFO | k32defs.OSVERSIONINFOEX = self.k32types.OSVERSIONINFOEX(emu.get_ptr_size(), cw)
        if self.read_dword(lpVersionInformation) != osver.sizeof():
            osver = self.k32types.OSVERSIONINFO(emu.get_ptr_size(), cw)
        osver = self.mem_cast(osver, lpVersionInformation)

        ver = emu.config.os_ver
        osver.dwMajorVersion = ver.major or 0
        osver.dwMinorVersion = ver.minor or 0
        osver.dwBuildNumber = ver.build or 0
        osver.dwPlatformId = windefs.VER_PLATFORM_WIN32_NT
        if isinstance(osver, self.k32types.OSVERSIONINFOEX):
            osver.wServicePackMajor = SERVICE_PACK_BUILDS.get(ver.build or 0, 0)
            osver.wServicePackMinor = 0
            osver.wSuiteMask = 0
            osver.wProductType = windefs.VER_NT_WORKSTATION

        rv = 1
        self.mem_write(lpVersionInformation, osver.get_bytes())

        return rv

    @apihook("GetEnvironmentVariable", argc=3)
    def GetEnvironmentVariable(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetEnvironmentVariable(
            LPCTSTR lpName,
            LPTSTR lpBuffer,
            DWORD nSize
        );
        """
        lpName, lpBuffer, nSize = argv
        rv = 0

        cw = self.get_char_width(ctx)

        name = self.read_mem_string(lpName, cw)
        ctx.args["lpName"].display = name
        env = emu.get_env()

        var = env.get(name.lower())
        if var is None:
            emu.set_last_error(windefs.ERROR_ENVVAR_NOT_FOUND)
        elif not lpBuffer or nSize <= len(var):
            rv = len(var) + 1
        else:
            self.write_mem_string(var, lpBuffer, cw)
            rv = len(var)

        return rv

    @apihook("GetCurrentPackageId", argc=2)
    def GetCurrentPackageId(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG GetCurrentPackageId(
            UINT32 *bufferLength,
            BYTE *buffer
        );
        """
        return self.get_no_package(argv[0])

    @apihook("GetCurrentPackageFamilyName", argc=2)
    def GetCurrentPackageFamilyName(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG GetCurrentPackageFamilyName(
            UINT32 *packageFamilyNameLength,
            PWSTR packageFamilyName
        );
        """
        return self.get_no_package(argv[0])

    @apihook("GetCurrentPackageFullName", argc=2)
    def GetCurrentPackageFullName(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG GetCurrentPackageFullName(
            UINT32 *packageFullNameLength,
            PWSTR packageFullName
        );
        """
        return self.get_no_package(argv[0])

    @apihook("GetCurrentPackagePath", argc=2)
    def GetCurrentPackagePath(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG GetCurrentPackagePath(
            UINT32 *pathLength,
            PWSTR path
        );
        """
        return self.get_no_package(argv[0])

    def get_no_package(self, length_ptr):
        """
        The emulated process is a desktop app without package identity.
        """
        if length_ptr:
            self.write_dword(length_ptr, 0)
        return APPMODEL_ERROR_NO_PACKAGE

    @apihook("AreFileApisANSI", argc=0)
    def AreFileApisANSI(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL AreFileApisANSI();
        """
        return True

    @apihook("FindFirstFileEx", argc=6)
    def FindFirstFileEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE FindFirstFileEx(
            LPCTSTR lpFileName,
            FINDEX_INFO_LEVELS fInfoLevelId,
            LPVOID lpFindFileData,
            FINDEX_SEARCH_OPS fSearchOp,
            LPVOID lpSearchFilter,
            DWORD dwAdditionalFlags
        );
        """
        (
            lpFileName,
            fInfoLevelId,
            lpFindFileData,
            fSearchOp,
            lpSearchFilter,
            dwAdditionalFlags,
        ) = argv

        _argv = [lpFileName, lpFindFileData]
        rv = self.FindFirstFile(emu, _argv, ctx)

        return rv

    @apihook("FindFirstFile", argc=2)
    def FindFirstFile(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE FindFirstFile(
            LPCTSTR lpFileName,
            LPWIN32_FIND_DATA lpFindFileData
        );
        """
        lpFileName, lpFindFileData = argv

        cw = self.get_char_width(ctx)

        if not lpFileName or not lpFindFileData:
            return self.get_max_int()

        srch = self.read_mem_string(lpFileName, cw)
        ctx.args["lpFileName"].display = srch
        if srch.startswith("\\\\?\\"):
            srch = srch.replace("\\\\?\\", "")

        fm = emu.get_file_manager()
        walker = fm.find_matching_entries(srch)
        hnd = self.find_files.new_handle({"walker": walker})

        try:
            name, is_dir = next(walker)
        except StopIteration:
            self.find_files.close(hnd)
            emu.set_last_error(windefs.ERROR_FILE_NOT_FOUND)
            return self.get_max_int()

        cfn = self.encode_string(name, cw)

        find_data = k32defs.WIN32_FIND_DATA(emu.get_ptr_size(), cw)
        if is_dir:
            find_data.dwFileAttributes = windefs.FILE_ATTRIBUTE_DIRECTORY
        else:
            find_data.dwFileAttributes = windefs.FILE_ATTRIBUTE_NORMAL
        find_data.cFileName = cfn
        self.mem_write(lpFindFileData, find_data.get_bytes())

        return hnd

    @apihook("FindNextFile", argc=2)
    def FindNextFile(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL FindNextFile(
            HANDLE hFindFile,
            LPWIN32_FIND_DATA lpFindFileData
        );
        """
        hFindFile, lpFindFileData = argv

        cw = self.get_char_width(ctx)

        fsearch = self.find_files.get(hFindFile)

        if not hFindFile or not lpFindFileData or not fsearch:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        walker = fsearch["walker"]
        try:
            name, is_dir = next(walker)
        except StopIteration:
            emu.set_last_error(windefs.ERROR_NO_MORE_FILES)
            return 0

        ctx.args["lpFindFileData"].display = name

        cfn = self.encode_string(name, cw)

        find_data = k32defs.WIN32_FIND_DATA(emu.get_ptr_size(), cw)
        if is_dir:
            find_data.dwFileAttributes = windefs.FILE_ATTRIBUTE_DIRECTORY
        else:
            find_data.dwFileAttributes = windefs.FILE_ATTRIBUTE_NORMAL
        find_data.cFileName = cfn
        self.mem_write(lpFindFileData, find_data.get_bytes())

        return 1

    @apihook("FindClose", argc=1)
    def FindClose(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL FindClose(
            HANDLE hFindFile
        );
        """
        (hFindFile,) = argv
        if not self.find_files.close(hFindFile):
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return False

        return True

    @apihook("GetSystemTimes", argc=3)
    def GetSystemTimes(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetSystemTimes(
            PFILETIME lpIdleTime,
            PFILETIME lpKernelTime,
            PFILETIME lpUserTime
        );
        """
        lpIdleTime, lpKernelTime, lpUserTime = argv

        ft = self.k32types.FILETIME(emu.get_ptr_size())

        times = self.tick_counter * 10000
        ft.dwLowDateTime = 0xFFFFFFFF & times
        ft.dwHighDateTime = times >> 32

        for t in (lpIdleTime, lpKernelTime, lpUserTime):
            if not t:
                continue
            self.mem_write(t, ft.get_bytes())

        return True

    @apihook("GetThreadContext", argc=2)
    def GetThreadContext(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetThreadContext(
            HANDLE hThread,
            LPCONTEXT lpContext
        );
        """
        hThread, lpContext = argv

        obj = emu.get_handle_table().get(hThread, objman.Thread)
        if not obj:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return False

        # Fill only the sections ContextFlags asks for; the current thread's are live
        target = seh.read_context(emu, lpContext)
        source = emu.get_thread_context() if obj is emu.get_current_thread() else obj.get_context()
        thread_context.get_debug_registers(obj, source)
        thread_context.copy_sections(source, target, target.ContextFlags)
        self.mem_write(lpContext, target.get_bytes())
        return True

    @apihook("SetThreadContext", argc=2)
    def SetThreadContext(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetThreadContext(
            HANDLE hThread,
            const CONTEXT *lpContext
        );
        """
        hThread, lpContext = argv

        obj = emu.get_handle_table().get(hThread, objman.Thread)
        if not obj:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return False

        if lpContext:
            # Change only the sections ContextFlags selects
            context = seh.read_context(emu, lpContext)
            stored = obj.get_context()
            thread_context.copy_sections(context, stored, context.ContextFlags)
            obj.set_context(stored)
            if thread_context.has(context.ContextFlags, thread_context.CONTEXT_DEBUG_REGISTERS):
                emu.set_debug_registers(obj, context)
            if obj.process:
                obj.process.is_modified = True

        return True

    @apihook("Wow64SetThreadContext", argc=2)
    def Wow64SetThreadContext(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL Wow64SetThreadContext(
            HANDLE hThread,
            const WOW64_CONTEXT *lpContext
        );
        """
        hThread, lpContext = argv

        obj = emu.get_handle_table().get(hThread, objman.Thread)
        if not obj:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return False

        if lpContext:
            if emu.get_arch() == e_arch.ARCH_X86:
                obj.set_context(self.mem_cast(windefs.CONTEXT(emu.get_ptr_size()), lpContext))
            if obj.process:
                obj.process.is_modified = True

        return True

    @apihook("CompareFileTime", argc=2)
    def CompareFileTime(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG CompareFileTime(
            const FILETIME *lpFileTime1,
            const FILETIME *lpFileTime2
        );
        """
        lpFileTime1, lpFileTime2 = argv
        rv = 0

        ft = self.k32types.FILETIME(emu.get_ptr_size())

        ft1 = self.mem_cast(ft, lpFileTime1)
        ft2 = self.mem_cast(ft, lpFileTime2)

        time1 = (ft1.dwHighDateTime << 32) | ft1.dwLowDateTime
        time2 = (ft2.dwHighDateTime << 32) | ft2.dwLowDateTime

        if time1 == time2:
            rv = 0
        elif time1 < time2:
            rv = -1
        else:
            rv = 1

        return rv

    @apihook("FindResource", argc=3)
    def FindResource(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRSRC FindResource(
            HMODULE hModule,
            LPCTSTR lpName,
            LPCTSTR lpType
        );
        """
        cw = self.get_char_width(ctx)
        hModule, lpName, lpType = argv
        if hModule == 0:
            pe = emu.modules[0] if emu.modules else None
        else:
            pe = emu.get_mod_from_addr(hModule)
            if pe and hModule != pe.base:
                return 0

        if not pe:
            return 0

        name = self.read_res_identifier(emu, ctx, "lpName", cw, lpName)
        type_ = self.read_res_identifier(emu, ctx, "lpType", cw, lpType)
        res = self.find_resource(pe, name, type_)
        if res is None:
            return 0

        # Return RVA of IMAGE_RESOURCE_DATA_ENTRY structure + base
        # This acts as the HRSRC handle which points to the resource entry in mapped memory
        return pe.base + res.entry_rva

    @apihook("FindResourceEx", argc=4)
    def FindResourceEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRSRC FindResourceEx(
            HMODULE hModule,
            LPCTSTR lpType,
            LPCTSTR lpName,
            WORD wLanguage
        );
        """
        # repeats code from FindResource()
        cw = self.get_char_width(ctx)
        hModule, lpType, lpName, wLanguage = argv
        if hModule == 0:
            pe = emu.modules[0] if emu.modules else None
        else:
            pe = emu.get_mod_from_addr(hModule)
            if pe and hModule != pe.base:
                return 0

        if not pe:
            return 0

        name = self.read_res_identifier(emu, ctx, "lpName", cw, lpName)
        type_ = self.read_res_identifier(emu, ctx, "lpType", cw, lpType)
        res = self.find_resource(pe, name, type_)
        if res is None:
            return 0

        return pe.base + res.entry_rva

    @apihook("LoadResource", argc=2)
    def LoadResource(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HGLOBAL LoadResource(
            HMODULE hModule,
            HRSRC hResInfo
        );
        """
        hModule, hResInfo = argv
        if not hResInfo:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        if hModule == 0:
            pe = emu.modules[0] if emu.modules else None
        else:
            pe = emu.get_mod_from_addr(hModule)
            if pe and hModule != pe.base:
                return 0

        if not pe:
            return 0

        return pe.base + self.read_dword(hResInfo)

    @apihook("LockResource", argc=1)
    def LockResource(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPVOID LockResource(
            HGLOBAL hResData
        );
        """
        (hResData,) = argv

        return hResData

    @apihook("SizeofResource", argc=2)
    def SizeofResource(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD SizeofResource(
            HMODULE hModule,
            HRSRC hResInfo
        );
        """
        hModule, hResInfo = argv
        if not hResInfo:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        # We don't strictly need pe here for SizeofResource if we trust hResInfo,
        # but the API takes hModule.
        # Just use hResInfo which points to IMAGE_RESOURCE_DATA_ENTRY
        return self.read_dword(hResInfo + 4)

    def get_resources(self, emu, hModule, type_=None, name=None, lang=0):
        """
        Return the resources of a module that match the type, name and language, or None
        with the last error set
        """
        if hModule == 0:
            pe = emu.modules[0] if emu.modules else None
        else:
            pe = emu.get_mod_from_addr(hModule)
            if pe and hModule != pe.base:
                pe = None
        if not pe:
            emu.set_last_error(windefs.ERROR_RESOURCE_DATA_NOT_FOUND)
            return None
        metadata = pe.get_pe_metadata()
        resources = metadata.resources if metadata else []
        if not resources:
            emu.set_last_error(windefs.ERROR_RESOURCE_DATA_NOT_FOUND)
            return None

        if type_ is not None:
            resources = [r for r in resources if is_same_res_identifier(type_, r.type_id)]
            if not resources:
                emu.set_last_error(windefs.ERROR_RESOURCE_TYPE_NOT_FOUND)
                return None
        if name is not None:
            resources = [r for r in resources if is_same_res_identifier(name, r.id)]
            if not resources:
                emu.set_last_error(windefs.ERROR_RESOURCE_NAME_NOT_FOUND)
                return None
        if lang:
            resources = [r for r in resources if r.lang_id == lang]
        return pe.base, resources

    def enum_resources(self, emu, cw, func, args, ids):
        """
        Call func once for each ID, with the ID in place of None in args. A string ID is
        passed in a buffer that is valid only during the call.
        """
        for id_ in dict.fromkeys(ids):
            buf = 0
            if isinstance(id_, str):
                data = self.encode_string(id_ + "\0", cw)
                buf = self.mem_alloc(len(data), tag="api.enum_resource")
                self.mem_write(buf, data)
            try:
                rv = yield GuestCall(func, tuple(buf or id_ if a is None else a for a in args))
            finally:
                if buf:
                    self.mem_free(buf)
            if not rv & 0xFFFFFFFF:
                emu.set_last_error(windefs.ERROR_RESOURCE_ENUM_USER_STOP)
                return 0
        return 1

    @apihook("EnumResourceTypes", argc=3)
    def EnumResourceTypes(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnumResourceTypes(
            HMODULE hModule,
            ENUMRESTYPEPROC lpEnumFunc,
            LONG_PTR lParam
        );
        """
        hModule, lpEnumFunc, lParam = argv[:3]
        lang = argv[4] if len(argv) > 3 else 0
        found = self.get_resources(emu, hModule, lang=lang)
        if found is None:
            return 0
        base, resources = found
        cw = self.get_char_width(ctx)
        return (
            yield from self.enum_resources(emu, cw, lpEnumFunc, (base, None, lParam), [r.type_id for r in resources])
        )

    @apihook("EnumResourceTypesEx", argc=5)
    def EnumResourceTypesEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnumResourceTypesEx(
            HMODULE hModule,
            ENUMRESTYPEPROC lpEnumFunc,
            LONG_PTR lParam,
            DWORD dwFlags,
            LANGID LangId
        );
        """
        return self.EnumResourceTypes(emu, argv, ctx)

    @apihook("EnumResourceNames", argc=4)
    def EnumResourceNames(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnumResourceNames(
            HMODULE hModule,
            LPCTSTR lpType,
            ENUMRESNAMEPROC lpEnumFunc,
            LONG_PTR lParam
        );
        """
        hModule, lpType, lpEnumFunc, lParam = argv[:4]
        lang = argv[5] if len(argv) > 4 else 0
        cw = self.get_char_width(ctx)
        type_ = self.read_res_identifier(emu, ctx, "lpType", cw, lpType)
        found = self.get_resources(emu, hModule, type_, lang=lang)
        if found is None:
            return 0
        base, resources = found
        return (
            yield from self.enum_resources(emu, cw, lpEnumFunc, (base, lpType, None, lParam), [r.id for r in resources])
        )

    @apihook("EnumResourceNamesEx", argc=6)
    def EnumResourceNamesEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnumResourceNamesEx(
            HMODULE hModule,
            LPCTSTR lpType,
            ENUMRESNAMEPROC lpEnumFunc,
            LONG_PTR lParam,
            DWORD dwFlags,
            LANGID LangId
        );
        """
        return self.EnumResourceNames(emu, argv, ctx)

    @apihook("EnumResourceLanguages", argc=5)
    def EnumResourceLanguages(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnumResourceLanguages(
            HMODULE hModule,
            LPCTSTR lpType,
            LPCTSTR lpName,
            ENUMRESLANGPROC lpEnumFunc,
            LONG_PTR lParam
        );
        """
        hModule, lpType, lpName, lpEnumFunc, lParam = argv[:5]
        lang = argv[6] if len(argv) > 5 else 0
        cw = self.get_char_width(ctx)
        type_ = self.read_res_identifier(emu, ctx, "lpType", cw, lpType)
        name = self.read_res_identifier(emu, ctx, "lpName", cw, lpName)
        found = self.get_resources(emu, hModule, type_, name, lang)
        if found is None:
            return 0
        base, resources = found
        args = (base, lpType, lpName, None, lParam)
        return (yield from self.enum_resources(emu, cw, lpEnumFunc, args, [r.lang_id for r in resources]))

    @apihook("EnumResourceLanguagesEx", argc=7)
    def EnumResourceLanguagesEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnumResourceLanguagesEx(
            HMODULE hModule,
            LPCTSTR lpType,
            LPCTSTR lpName,
            ENUMRESLANGPROC lpEnumFunc,
            LONG_PTR lParam,
            DWORD dwFlags,
            LANGID LangId
        );
        """
        return self.EnumResourceLanguages(emu, argv, ctx)

    @apihook("FreeResource", argc=1)
    def FreeResource(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL FreeResource(
            HGLOBAL hResData
        );
        """
        return 0

    @apihook("GetCurrentDirectory", argc=2)
    def GetCurrentDirectory(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetCurrentDirectory(
            DWORD nBufferLength,
            LPTSTR lpBuffer
        );
        """
        nBufferLength, lpBuffer = argv

        cw = self.get_char_width(ctx)
        cd = emu.get_cd()
        required = len(cd) + 1

        if nBufferLength < required or not lpBuffer:
            return required

        self.write_mem_string(cd, lpBuffer, cw)

        return len(cd)

    @apihook("VirtualAllocExNuma", argc=6)
    def VirtualAllocExNuma(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LPVOID VirtualAllocExNuma(
            HANDLE hProcess,
            LPVOID lpAddress,
            SIZE_T dwSize,
            DWORD flAllocationType,
            DWORD flProtect,
            DWORD nndPreferred
        );
        """
        argv = argv[:-1]
        return self.VirtualAllocEx(emu, argv, ctx)

    @apihook("GetNativeSystemInfo", argc=1)
    def GetNativeSystemInfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID GetNativeSystemInfo(
            LPSYSTEM_INFO lpSystemInfo
        );
        """
        return self.GetSystemInfo(emu, argv, ctx)

    @apihook("GetUserDefaultUILanguage", argc=0)
    def GetUserDefaultUILanguage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LANGID GetUserDefaultUILanguage();
        """
        return 0xFFFF

    @apihook("SetCurrentDirectory", argc=1)
    def SetCurrentDirectory(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetCurrentDirectory(
            LPCTSTR lpPathName
        );
        """
        (lpPathName,) = argv

        if lpPathName:
            cw = self.get_char_width(ctx)
            path_str = self.read_mem_string(lpPathName, cw)
            ctx.args["lpPathName"].display = path_str
            emu.set_cd(path_str)

        return True

    @apihook("OpenThread", argc=3)
    def OpenThread(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE OpenThread(
            DWORD dwDesiredAccess,
            BOOL bInheritHandle,
            DWORD dwThreadId
        );
        """
        dwDesiredAccess, bInheritHandle, dwThreadId = argv
        thread = emu.get_object_from_id(dwThreadId)
        if not thread:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0
        hnd = emu.get_object_handle(thread)
        if not hnd:
            hnd = 0
        return hnd

    @apihook("RaiseException", argc=4)
    def RaiseException(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID RaiseException(
            DWORD dwExceptionCode,
            DWORD dwExceptionFlags,
            DWORD nNumberOfArguments,
            const ULONG_PTR *lpArguments
        );
        """
        dwExceptionCode, dwExceptionFlags, nNumberOfArguments, lpArguments = argv
        if not emu.config.exceptions.dispatch_handlers:
            return None

        count = min(nNumberOfArguments, 15) if lpArguments else 0
        params = [self.read_ptr(lpArguments + emu.get_ptr_size() * i) for i in range(count)]
        return emu.exception_dispatcher().raise_exception(emu, dwExceptionCode, dwExceptionFlags, params)

    @apihook("VerSetConditionMask", argc=4)
    def VerSetConditionMask(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        ULONGLONG VerSetConditionMask(
            ULONGLONG ConditionMask,
            DWORD TypeMask,
            BYTE Condition
        );

        ConditionMask takes two stack slots on x86. On x64 the fourth slot
        is unused.
        """
        if emu.get_ptr_size() == 4:
            lo, hi, type_mask, cond = argv
            con_mask = (hi << 32) | lo
        else:
            con_mask, type_mask, cond = argv[:3]

        type_mask &= 0xFF
        cond &= VER_CONDITION_MASK
        if type_mask and cond:
            # Only the highest type bit gets the condition
            con_mask |= cond << (3 * (type_mask.bit_length() - 1))

        if emu.get_ptr_size() == 4:
            emu.reg_write(e_arch.X86_REG_EDX, con_mask >> 32)
            return con_mask & 0xFFFFFFFF
        return con_mask

    @apihook("VerifyVersionInfo", argc=4)
    def VerifyVersionInfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL VerifyVersionInfo(
            LPOSVERSIONINFOEX lpVersionInformation,
            DWORD dwTypeMask,
            DWORDLONG dwlConditionMask
        );

        dwlConditionMask takes two stack slots on x86. On x64 the fourth slot
        is unused.
        """
        if emu.get_ptr_size() == 4:
            vinfo, type_mask, lo, hi = argv
            con_mask = (hi << 32) | lo
        else:
            vinfo, type_mask, con_mask = argv[:3]

        if not type_mask or not con_mask:
            emu.set_last_error(ERROR_BAD_ARGUMENTS)
            return False

        cw = self.get_char_width(ctx)
        major, minor, build, platform = struct.unpack("<4I", self.mem_read(vinfo + 4, 16))
        sp_major, sp_minor, _, product = struct.unpack("<HHHB", self.mem_read(vinfo + 20 + 128 * cw, 7))
        ver = emu.config.os_ver
        cur_major, cur_minor, cur_build = ver.major or 0, ver.minor or 0, ver.build or 0
        cur_sp = SERVICE_PACK_BUILDS.get(cur_build, 0)

        def check(bit, current, wanted):
            cond = (con_mask >> (3 * (bit.bit_length() - 1))) & VER_CONDITION_MASK
            return VER_COMPARE.get(cond, lambda a, b: False)(current, wanted)

        ok = True
        # The version fields compare as one number: a field that differs decides the result
        for bit, current, wanted in (
            (VER_MAJORVERSION, cur_major, major),
            (VER_MINORVERSION, cur_minor, minor),
            (VER_SERVICEPACKMAJOR, cur_sp, sp_major),
            (VER_SERVICEPACKMINOR, 0, sp_minor),
        ):
            if type_mask & bit:
                ok = check(bit, current, wanted)
                if not ok or current != wanted:
                    break
        for bit, current, wanted in (
            (VER_BUILDNUMBER, cur_build, build),
            (VER_PLATFORMID, windefs.VER_PLATFORM_WIN32_NT, platform),
            (VER_PRODUCT_TYPE, windefs.VER_NT_WORKSTATION, product),
        ):
            if ok and type_mask & bit:
                ok = check(bit, current, wanted)

        if not ok:
            emu.set_last_error(ERROR_OLD_WIN_VERSION)
            return False
        return True

    @apihook("FreeConsole", argc=0)
    def FreeConsole(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL FreeConsole();
        """
        return True

    @apihook("IsBadWritePtr", argc=2)
    def IsBadWritePtr(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsBadWritePtr(
            LPVOID lp,
            UINT_PTR ucb
        );
        """
        lp, ucb = argv

        rv = True

        if lp and ucb:
            v1 = emu.is_address_valid(lp)
            v2 = emu.is_address_valid(lp + (ucb - 1))

            if v1 and v2:
                rv = False

        return rv

    @apihook("IsBadStringPtr", argc=2)
    def IsBadStringPtr(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsBadStringPtr(
            LPCTSTR lpsz,
            UINT_PTR ucchMax
        );
        """
        lpsz, ucchMax = argv
        cw = self.get_char_width(ctx)

        if not ucchMax:
            return False

        addr = lpsz
        remaining = ucchMax
        while remaining:
            count = min(remaining, max(1, (0x1000 - addr % 0x1000) // cw))
            if not emu.is_address_valid(addr) or not emu.is_address_valid(addr + count * cw - 1):
                return True
            data = self.mem_read(addr, count * cw)
            for i in range(0, len(data), cw):
                if not any(data[i : i + cw]):
                    return False
            addr += count * cw
            remaining -= count

        return False

    @apihook("GetSystemFirmwareTable", argc=4)
    def GetSystemFirmwareTable(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetSystemFirmwareTable(
            DWORD FirmwareTableProviderSignature,
            DWORD FirmwareTableID,
            PVOID pFirmwareTableBuffer,
            DWORD BufferSize
        );
        """
        FirmwareTableProviderSignature, FirmwareTableID, pFirmwareTableBuffer, BufferSize = argv

        if FirmwareTableProviderSignature == RSMB_PROVIDER:
            table = get_raw_smbios_data()
            if pFirmwareTableBuffer and BufferSize >= len(table):
                self.mem_write(pFirmwareTableBuffer, table)
            return len(table)

        if FirmwareTableProviderSignature not in (ACPI_PROVIDER, FIRM_PROVIDER):
            emu.set_last_error(windefs.ERROR_INVALID_FUNCTION)
            return 0

        if not pFirmwareTableBuffer:
            rv = 0x100
        else:
            self.mem_write(pFirmwareTableBuffer, b"\x01" * BufferSize)
            rv = BufferSize
        return rv

    @apihook("GetTempPath", argc=2)
    def GetTempPath(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetTempPath(
            DWORD nBufferLength,
            LPTSTR lpBuffer
        );
        """
        nBufferLength, lpBuffer = argv
        rv = 0
        cw = self.get_char_width(ctx)
        tempdir = emu.get_env().get("temp", "C:\\Windows\\temp")
        if not tempdir.endswith("\\"):
            tempdir += "\\"
        new = self.encode_string(tempdir, cw) + b"\x00" * cw
        if not lpBuffer or nBufferLength <= len(tempdir):
            return len(tempdir) + 1
        rv = len(tempdir)
        ctx.args[1].display = tempdir
        self.mem_write(lpBuffer, new)
        return rv

    @apihook("GetTempPath2", argc=2)
    def GetTempPath2(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetTempPath2(
            DWORD BufferLength,
            LPTSTR Buffer
        );
        """
        return self.GetTempPath(emu, argv, ctx)

    @apihook("QueryInformationJobObject", argc=5)
    def QueryInformationJobObject(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL QueryInformationJobObject(
            HANDLE hJob,
            JOBOBJECTINFOCLASS JobObjectInformationClass,
            LPVOID lpJobObjectInformation,
            DWORD cbJobObjectInformationLength,
            LPDWORD lpReturnLength
        );
        """
        hJob, JobObjectInformationClass, lpJobObjectInformation, cbJobObjectInformationLength, lpReturnLength = argv
        x64 = self.get_ptr_size() == 8
        sizes = {
            JobObjectBasicAccountingInformation: 0x30,
            JobObjectBasicLimitInformation: 0x40 if x64 else 0x30,
            JobObjectExtendedLimitInformation: 0x90 if x64 else 0x70,
        }
        size = sizes.get(JobObjectInformationClass)
        if size is None:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0
        if not lpJobObjectInformation or cbJobObjectInformationLength < size:
            emu.set_last_error(windefs.ERROR_BAD_LENGTH)
            return 0
        # The job has no limits and no accounting data
        self.mem_write(lpJobObjectInformation, b"\x00" * size)
        if lpReturnLength:
            self.write_dword(lpReturnLength, size)
        return 1

    @apihook("SetPriorityClass", argc=2)
    def SetPriorityClass(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetPriorityClass(
            HANDLE hProcess,
            DWORD dwPriorityClass
        );
        """
        return 1

    @apihook("SetProcessPriorityBoost", argc=2)
    def SetProcessPriorityBoost(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetProcessPriorityBoost(
            HANDLE hProcess,
            BOOL bDisablePriorityBoost
        );
        """
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return 1

    @apihook("GetDriveType", argc=1)
    def GetDriveType(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetDriveType(
            LPCTSTR lpRootPathName
        );
        """
        (lpRootPathName,) = argv

        if not lpRootPathName:
            # A NULL path means the root of the current directory.
            name = ntpath.splitdrive(emu.get_cd())[0] + "\\"
        else:
            cw = self.get_char_width(ctx)
            name = self.read_mem_string(lpRootPathName, cw)
            if name:
                ctx.args["lpRootPathName"].display = name

        if name.startswith("\\\\?\\"):
            name = name.replace("\\\\?\\", "")

        if name.endswith(":"):
            name += "\\"

        dm = emu.get_drive_manager()
        return dm.get_drive_type(name)

    @apihook("GetExitCodeProcess", argc=2)
    def GetExitCodeProcess(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetExitCodeProcess(
            HANDLE hProcess,
            LPDWORD lpExitCode
        );
        """
        hProcess, lpExitCode = argv
        if lpExitCode:
            self.mem_write(lpExitCode, b"\x00" * 4)
        return 1

    @apihook("SetThreadPriority", argc=2)
    def SetThreadPriority(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetThreadPriority(
            HANDLE hThread,
            int nPriority
        );
        """
        return 1

    @apihook("ReleaseMutex", argc=1)
    def ReleaseMutex(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL ReleaseMutex(
            HANDLE hMutex
        );

        Speakeasy does not model the owner or the count of a mutex.
        """
        return 1

    @apihook("GetShortPathName", argc=3)
    def GetShortPathName(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetShortPathName(
            LPCTSTR lpszLongPath,
            LPTSTR lpszShortPath,
            DWORD cchBuffer
        );

        https://en.wikipedia.org/wiki/8.3_filename#VFAT_and_Computer-generated_8.3_filenames
        """
        lpszLongPath, lpszShortPath, cchBuffer = argv
        cw = self.get_char_width(ctx)
        s = self.read_mem_string(lpszLongPath, cw)
        ctx.args["lpszLongPath"].display = s
        files = s.split("\\")
        out = files[0] + "\\"
        for i, file in enumerate(files):
            if i == 0:
                continue

            file = file.upper()
            file = file.lstrip(".")
            file = file.rstrip(".")
            file = file.replace("+", "_")
            file = file.replace(" ", "")
            parts = file.rsplit(".", 1)
            if len(parts) == 2:
                file, ext = parts
            else:
                ext = None

            if len(file) > 8:
                file = file[:6]
                file += "~1"

            if ext:
                ext = ext[:3]
                file += "." + ext

            out += file
            if i != len(files) - 1:
                out += "\\"

        if lpszShortPath and len(out) + 1 <= cchBuffer:
            ctx.args["lpszShortPath"].display = out
            self.write_mem_string(out, lpszShortPath, cw)
            return len(out)

        return len(out) + 1

    @apihook("GetLongPathName", argc=3)
    def GetLongPathName(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetLongPathName(
            LPCTSTR lpszShortPath,
            LPTSTR lpszLongPath,
            DWORD cchBuffer
        );
        """
        lpszShortPath, lpszLongPath, cchBuffer = argv

        # Not an accurate implementation, just a placeholder for now
        cw = self.get_char_width(ctx)
        s = self.read_mem_string(lpszShortPath, cw)
        ctx.args["lpszShortPath"].display = s

        if not lpszLongPath or cchBuffer <= len(s):
            return len(s) + 1

        self.write_mem_string(s, lpszLongPath, cw)
        ctx.args["lpszLongPath"].display = s

        return len(s)

    @apihook("QueueUserAPC", argc=3)
    def QueueUserAPC(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD QueueUserAPC(
            PAPCFUNC pfnAPC,
            HANDLE hThread,
            ULONG_PTR dwData
        );
        """
        pfnAPC, hThread, dwData = argv
        self.create_thread(pfnAPC, dwData, 0, name="apc")
        return 1

    @apihook("DuplicateHandle", argc=7)
    def DuplicateHandle(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL DuplicateHandle(
            HANDLE hSourceProcessHandle,
            HANDLE hSourceHandle,
            HANDLE hTargetProcessHandle,
            LPHANDLE lpTargetHandle,
            DWORD dwDesiredAccess,
            BOOL bInheritHandle,
            DWORD dwOptions
        );
        """
        (
            hSourceProcessHandle,
            hSourceHandle,
            hTargetProcessHandle,
            lpTargetHandle,
            dwDesiredAccess,
            bInheritHandle,
            dwOptions,
        ) = argv
        source = self._get_process_handle_table(emu, hSourceProcessHandle)
        target = self._get_process_handle_table(emu, hTargetProcessHandle)
        if source is None or target is None:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        if self.is_std_handle(emu, hSourceHandle):
            # A standard handle has no object, so its duplicate is the same value
            hnd = hSourceHandle
        else:
            obj = source.get(hSourceHandle)
            if obj is None:
                emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
                return 0
            hnd = target.new_handle(obj)
            if dwOptions & DUPLICATE_CLOSE_SOURCE:
                source.close(hSourceHandle)

        if lpTargetHandle:
            self.write_ptr(lpTargetHandle, hnd)
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return 1

    @apihook("GetBinaryType", argc=2)
    def GetBinaryType(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetBinaryType(
            LPCTSTR lpApplicationName,
            LPDWORD lpBinaryType
        );
        """
        return 0

    @apihook("GetThreadUILanguage", argc=0)
    def GetThreadUILanguage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LANGID GetThreadUILanguage();
        """
        return 0xFFFF

    @apihook("SetConsoleHistoryInfo", argc=1)
    def SetConsoleHistoryInfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetConsoleHistoryInfo(
            PCONSOLE_HISTORY_INFO lpConsoleHistoryInfo
        );
        """
        return 1

    @apihook("GetFileInformationByHandle", argc=2)
    def GetFileInformationByHandle(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetFileInformationByHandle(
            HANDLE hFile,
            LPBY_HANDLE_FILE_INFORMATION lpFileInformation
        );
        """
        hFile, lpFileInformation = argv

        f = self.get_file(hFile)
        if not f:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        info = k32defs.BY_HANDLE_FILE_INFORMATION(emu.get_ptr_size())
        if f.is_dir or emu.get_file_manager().is_directory(f.path):
            info.dwFileAttributes = windefs.FILE_ATTRIBUTE_DIRECTORY
        else:
            info.dwFileAttributes = windefs.FILE_ATTRIBUTE_ARCHIVE
            size = f.get_size()
            info.nFileSizeHigh = 0xFFFFFFFF & (size >> 32)
            info.nFileSizeLow = 0xFFFFFFFF & size
        timestamp = self.get_system_time()
        for ft in (info.ftCreationTime, info.ftLastAccessTime, info.ftLastWriteTime):
            ft.dwLowDateTime = 0xFFFFFFFF & timestamp
            ft.dwHighDateTime = timestamp >> 32
        info.dwVolumeSerialNumber = VOLUME_SERIAL_NUMBER
        info.nNumberOfLinks = 1
        info.nFileIndexLow = zlib.crc32(f.path.lower().encode("utf-8"))
        self.mem_write(lpFileInformation, info.get_bytes())
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return 1

    @apihook("GetCommProperties", argc=2)
    def GetCommProperties(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetCommProperties(
            HANDLE hFile,
            LPCOMMPROP lpCommProp
        );
        """
        return 0

    @apihook("GetCommTimeouts", argc=2)
    def GetCommTimeouts(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetCommTimeouts(
            HANDLE hFile,
            LPCOMMTIMEOUTS lpCommTimeouts
        );
        """
        return 0

    @apihook("AddAtom", argc=1)
    def AddAtom(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        ATOM AddAtom(
            LPCTSTR lpString
        );
        """
        ATOM_RESERVED = 0xC000
        (lpString,) = argv
        cw = self.get_char_width(ctx)
        s = self.read_mem_string(lpString, cw)
        if len(s) == 0:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        ctx.args["lpString"].display = s
        if s[0] == "#" and int(s[1:]) < ATOM_RESERVED:
            return int(s[1:])

        return self.add_local_atom(s)

    @apihook("FindAtom", argc=1)
    def FindAtom(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        ATOM FindAtom(
            LPCTSTR lpString
        );
        """
        ATOM_RESERVED = 0xC000
        (lpString,) = argv
        cw = self.get_char_width(ctx)
        s = self.read_mem_string(lpString, cw)
        if len(s) == 0:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        ctx.args["lpString"].display = s
        if s[0] == "#" and int(s[1:]) < ATOM_RESERVED:
            return int(s[1:])

        atom = self.find_local_atom(s)
        if atom is None:
            emu.set_last_error(windefs.ERROR_FILE_NOT_FOUND)
            return 0

        return atom

    @apihook("GetAtomName", argc=3)
    def GetAtomName(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetAtomName(
            ATOM nAtom,
            LPTSTR lpBuffer,
            int nSize
        );
        """
        ATOM_RESERVED = 0xC000
        nAtom, lpBuffer, nSize = argv
        cw = self.get_char_width(ctx)
        if nAtom < ATOM_RESERVED:
            s = f"#{nAtom}"
        elif nAtom not in self.local_atom_table:
            emu.set_last_error(windefs.ERROR_FILE_NOT_FOUND)
            return 0
        else:
            s = self.get_local_atom_name(nAtom)

        ctx.args["lpBuffer"].display = s
        s += "\0"
        if len(s) > nSize:
            s = s[: nSize - 1] + "\0"

        self.write_mem_string(s, lpBuffer, cw)
        return len(s) - 1

    @apihook("DeleteAtom", argc=1)
    def DeleteAtom(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        ATOM DeleteAtom(
            ATOM nAtom
        );
        """
        ATOM_RESERVED = 0xC000
        (nAtom,) = argv

        if nAtom < ATOM_RESERVED:
            return 0

        if self.delete_local_atom(nAtom):
            return 0

        emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
        return nAtom

    @apihook("GetProcessHandleCount", argc=2)
    def GetProcessHandleCount(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetProcessHandleCount(
            HANDLE hProcess,
            PDWORD pdwHandleCount
        );
        """
        return 0

    @apihook("GetMailslotInfo", argc=5)
    def GetMailslotInfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetMailslotInfo(
            HANDLE hMailslot,
            LPDWORD lpMaxMessageSize,
            LPDWORD lpNextSize,
            LPDWORD lpMessageCount,
            LPDWORD lpReadTimeout
        );
        """
        return 0

    @apihook("RtlZeroMemory", argc=2)
    def RtlZeroMemory(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void RtlZeroMemory(
            void *Destination,
            size_t Length
        );
        """
        Destination, Length = argv
        buf = b"\x00" * Length
        self.mem_write(Destination, buf)

    @apihook("RtlMoveMemory", argc=3)
    def RtlMoveMemory(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void RtlMoveMemory(
            void *Destination,
            const void *Source,
            size_t Length
        );
        """
        Destination, Source, Length = argv
        buf = self.mem_read(Source, Length)
        self.mem_write(Destination, buf)

    @apihook("QueryPerformanceFrequency", argc=1)
    def QueryPerformanceFrequency(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL QueryPerformanceFrequency(
            LARGE_INTEGER *lpFrequency
        );
        """
        (lpFrequency,) = argv
        self.write_qword(lpFrequency, windefs.PERF_FREQUENCY)
        return 1

    @apihook("FindFirstVolume", argc=2)
    def FindFirstVolume(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE FindFirstVolume(
            LPTSTR lpszVolumeName,
            DWORD cchBufferLength
        );
        """
        lpszVolumeName, cchBufferLength = argv

        cw = self.get_char_width(ctx)

        dm = emu.get_drive_manager()
        dw = (d.volume_guid_path for d in dm.walk_drives() if d.volume_guid_path)

        # Each drive contains a single volume
        volume_guid_path = next(dw, None)
        if volume_guid_path is None:
            emu.set_last_error(windefs.ERROR_NO_MORE_FILES)
            return self.get_max_int()

        hnd = self.find_volumes.new_handle({"walker": dw})
        ctx.args["lpszVolumeName"].display = volume_guid_path
        self.write_mem_string(volume_guid_path + "\x00", lpszVolumeName, cw)

        return hnd

    @apihook("FindNextVolume", argc=3)
    def FindNextVolume(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL FindNextVolume(
            HANDLE hFindVolume,
            LPTSTR lpszVolumeName,
            DWORD cchBufferLength
        );
        """
        hFindVolume, lpszVolumeName, cchBufferLength = argv

        cw = self.get_char_width(ctx)

        dsearch = self.find_volumes.get(hFindVolume)
        if not hFindVolume or not dsearch:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        # Get next drive; each drive contains one volume
        walker = dsearch["walker"]
        try:
            volume_guid_path = next(walker)
        except StopIteration:
            emu.set_last_error(windefs.ERROR_NO_MORE_FILES)
            return 0

        ctx.args["lpszVolumeName"].display = volume_guid_path
        self.write_mem_string(volume_guid_path + "\x00", lpszVolumeName, cw)

        return 1

    @apihook("FindVolumeClose", argc=1)
    def FindVolumeClose(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL FindVolumeClose(
            HANDLE hFindVolume
        );
        """
        (hFindVolume,) = argv
        if not self.find_volumes.close(hFindVolume):
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        return 1

    @apihook("CreateIoCompletionPort", argc=4)
    def CreateIoCompletionPort(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE CreateIoCompletionPort(
            HANDLE FileHandle,
            HANDLE ExistingCompletionPort,
            ULONG_PTR CompletionKey,
            DWORD NumberOfConcurrentThreads
        );
        """
        FileHandle, ExistingCompletionPort, CompletionKey, NumberOfConcurrentThreads = argv

        # TODO: Implement completion port creation
        hnd = emu.get_handle_table().new_handle(IoCompletionPort())

        return hnd

    @apihook("GetVolumePathNamesForVolumeName", argc=4)
    def GetVolumePathNamesForVolumeName(
        self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        BOOL GetVolumePathNamesForVolumeName(
            LPCTSTR lpszVolumeName,
            LPTCH lpszVolumePathNames,
            DWORD cchBufferLength,
            PDWORD lpcchReturnLength
        );
        """
        lpszVolumeName, lpszVolumePathNames, cchBufferLength, lpcchReturnLength = argv

        cw = self.get_char_width(ctx)

        volume_guid_path = self.read_mem_string(lpszVolumeName, cw)
        if volume_guid_path:
            ctx.args["lpszVolumeName"].display = volume_guid_path

        rv = 1
        dm = emu.get_drive_manager()
        drive = dm.get_drive(volume_guid_path=volume_guid_path)
        if drive:
            root_path = drive.root_path
            names = root_path + "\x00\x00"  # additional NULL to terminate list

            if lpszVolumePathNames and cchBufferLength >= len(names):
                self.write_mem_string(names, lpszVolumePathNames, cw)
                ctx.args["lpszVolumePathNames"].display = root_path
            else:
                emu.set_last_error(windefs.ERROR_MORE_DATA)
                rv = 0
            if lpcchReturnLength:
                self.write_dword(lpcchReturnLength, len(names))

        return rv

    @apihook("GetLogicalDrives", argc=0)
    def GetLogicalDrives(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetLogicalDrives();
        """
        dm = emu.get_drive_manager()
        rv = 0
        for i, dl in enumerate(string.ascii_uppercase):
            if dl in dm.drive_letters:
                rv |= 1 << i

        return rv

    @apihook("GetLogicalDriveStrings", argc=2)
    def GetLogicalDriveStrings(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetLogicalDriveStrings(
            DWORD nBufferLength,
            LPTSTR lpBuffer
        );
        """
        nBufferLength, lpBuffer = argv
        cw = self.get_char_width(ctx)
        dm = emu.get_drive_manager()
        roots = "".join(f"{dl}:\\\0" for dl in string.ascii_uppercase if dl in dm.drive_letters)
        if nBufferLength <= len(roots) or not lpBuffer:
            return len(roots) + 1
        self.write_mem_string(roots + "\0", lpBuffer, cw)
        return len(roots)

    @apihook("GlobalMemoryStatus", argc=1)
    def GlobalMemoryStatus(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID GlobalMemoryStatus(
            LPMEMORYSTATUS lpBuffer
        );
        """
        (lpBuffer,) = argv
        GB = 1024 * 1024 * 1024
        total_virtual = 0x7FFE0000 if emu.get_ptr_size() == 4 else 0x7FFFFFFE0000
        sizes = [8 * GB, 5 * GB, 8 * GB, 4 * GB, total_virtual, total_virtual - 0x10000000]
        limits = [self.get_max_int()] * len(sizes)
        if emu.get_ptr_size() == 4 and not self.is_large_address_aware(emu):
            # Windows reports at most 2 GB of memory and address space to these images
            limits[0:2] = limits[4:6] = [0x7FFFFFFF] * 2
        fmt = "<II" + ("I" if emu.get_ptr_size() == 4 else "Q") * len(sizes)
        buf = struct.pack(fmt, struct.calcsize(fmt), 80, *(min(n, lim) for n, lim in zip(sizes, limits)))
        emu.mem_write(lpBuffer, buf)

    def is_large_address_aware(self, emu):
        proc = emu.get_current_process()
        base = proc.base if proc else 0
        if not base or not emu.is_address_valid(base + 0x3C):
            return False
        characteristics = base + self.read_dword(base + 0x3C) + 0x16
        if not emu.is_address_valid(characteristics):
            return False
        return bool(int.from_bytes(emu.mem_read(characteristics, 2), "little") & IMAGE_FILE_LARGE_ADDRESS_AWARE)

    @apihook("GlobalMemoryStatusEx", argc=1)
    def GlobalMemoryStatusEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GlobalMemoryStatusEx(
            LPMEMORYSTATUSEX lpBuffer
        );

        typedef struct _MEMORYSTATUSEX {
            DWORD     dwLength;
            DWORD     dwMemoryLoad;
            DWORDLONG ullTotalPhys;
            DWORDLONG ullAvailPhys;
            DWORDLONG ullTotalPageFile;
            DWORDLONG ullAvailPageFile;
            DWORDLONG ullTotalVirtual;
            DWORDLONG ullAvailVirtual;
            DWORDLONG ullAvailExtendedVirtual;
        } MEMORYSTATUSEX, *LPMEMORYSTATUSEX;
        """
        (lpBuffer,) = argv
        if self.mem_read(lpBuffer, 4) != struct.pack("<I", 64):
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0
        GB = 1024 * 1024 * 1024
        buf = struct.pack(
            "<IIQQQQQQQ",
            64,  # dwLength
            80,  # dwMemoryLoad
            8 * GB,  # ullTotalPhys
            5 * GB,  # ullAvailPhys
            8 * GB,  # ullTotalPageFile
            4 * GB,  # ullAvailPageFile
            8 * GB,  # ullTotalVirtual
            7 * GB,  # ullAvailVirtual
            0,  # ullAvailExtendedVirtual
        )

        emu.mem_write(lpBuffer, buf)
        return 1

    @apihook("GetDiskFreeSpaceEx", argc=4)
    def GetDiskFreeSpaceEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetDiskFreeSpaceEx(
            LPCTSTR lpDirectoryName,
            PULARGE_INTEGER lpFreeBytesAvailableToCaller,
            PULARGE_INTEGER lpTotalNumberOfBytes,
            PULARGE_INTEGER lpTotalNumberOfFreeBytes
        );
        """
        lpDirectoryName, lpFreeBytesAvailableToCaller, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes = argv
        GB = 1024 * 1024 * 1024
        for ptr, size in (
            (lpFreeBytesAvailableToCaller, 40 * GB),
            (lpTotalNumberOfBytes, 100 * GB),
            (lpTotalNumberOfFreeBytes, 40 * GB),
        ):
            if ptr:
                self.write_qword(ptr, size)
        return True

    @apihook("GetSystemDefaultLangID", argc=0)
    def GetSystemDefaultLangID(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LANGID GetSystemDefaultLangID();
        """
        return True

    @apihook("ResetEvent", argc=1)
    def ResetEvent(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL ResetEvent(
            HANDLE hEvent
        );
        """
        (hEvent,) = argv

        obj = emu.get_handle_table().get(hEvent, objman.Event)
        if not obj:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return False
        obj.signaled = False
        return True

    @apihook("WaitForMultipleObjects", argc=4)
    def WaitForMultipleObjects(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD WaitForMultipleObjects(
            DWORD nCount,
            const HANDLE *lpHandles,
            BOOL bWaitAll,
            DWORD dwMilliseconds
        );

        Speakeasy models events and threads. A wait on a thread that has not started runs the thread to its end,
        unless the timeout is 0. Other objects are signaled.
        """
        nCount, lpHandles, bWaitAll, dwMilliseconds = argv

        ptr_size = emu.get_ptr_size()
        table = emu.get_handle_table()
        objs: list[Any] = []
        if lpHandles:
            for i in range(nCount):
                hnd = self.read_ptr(lpHandles + i * ptr_size)
                if self.is_std_handle(emu, hnd):
                    objs.append(None)
                    continue
                obj = table.get(hnd)
                if obj is None:
                    emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
                    return windefs.WAIT_FAILED
                objs.append(obj)

        if objs and all(isinstance(obj, objman.Event) for obj in objs):
            return self.wait_for_events(emu, objs, bool(bWaitAll), dwMilliseconds)

        runs = [emu.get_unstarted_run(obj) for obj in objs] if dwMilliseconds else []
        if not any(runs):
            return windefs.WAIT_OBJECT_0
        if bWaitAll:
            return self.join_threads(emu, [run for run in runs if run], windefs.WAIT_OBJECT_0)
        for i, (obj, run) in enumerate(zip(objs, runs)):
            if run is None and not (isinstance(obj, objman.Event) and not obj.signaled):
                if isinstance(obj, objman.Event) and not obj.manual_reset:
                    obj.signaled = False
                return windefs.WAIT_OBJECT_0 + i
        # No object is signaled, so the wait returns when the first thread ends.
        index = next(i for i, run in enumerate(runs) if run)
        return self.join_threads(emu, [runs[index]], windefs.WAIT_OBJECT_0 + index)

    def wait_for_events(self, emu, events, wait_all, timeout):
        """
        Wait on event objects. Threads run one after another, so the wait times out only
        when the timeout is finite and no queued run is left that could set an event.
        """
        if wait_all:
            ready = events if all(evt.signaled for evt in events) else []
            rv = windefs.WAIT_OBJECT_0
        else:
            index = next((i for i, evt in enumerate(events) if evt.signaled), None)
            ready = [] if index is None else [events[index]]
            rv = windefs.WAIT_OBJECT_0 + (index or 0)

        if ready:
            for evt in ready:
                if not evt.manual_reset:
                    evt.signaled = False
            return rv

        if timeout != 0xFFFFFFFF and not emu.run_queue:
            self.advance_clock(timeout)
            return windefs.WAIT_TIMEOUT
        return windefs.WAIT_OBJECT_0

    @apihook("GetComputerNameEx", argc=3)
    def GetComputerNameEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetComputerNameEx(
            COMPUTER_NAME_FORMAT NameType,
            LPTSTR lpBuffer,
            LPDWORD nSize
        );
        """
        NameType, lpBuffer, nSize = argv

        cw = self.get_char_width(ctx)

        ctx.args["NameType"].display = decode(COMPUTER_NAME_FORMAT, NameType)

        hostname = emu.config.hostname
        size = self.read_dword(nSize)
        if not lpBuffer or size <= len(hostname):
            self.write_dword(nSize, len(hostname) + 1)
            emu.set_last_error(windefs.ERROR_MORE_DATA)
            return 0

        self.write_mem_string(hostname, lpBuffer, cw)
        self.write_dword(nSize, len(hostname))
        ctx.args["lpBuffer"].display = hostname
        return 1

    @apihook("GetDateFormat", argc=6)
    def GetDateFormat(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetDateFormat(
            LCID Locale,
            DWORD dwFlags,
            const SYSTEMTIME *lpDate,
            LPCTSTR lpFormat,
            LPTSTR lpDateStr,
            int cchDate
        );
        """
        Locale, dwFlags, lpDate, lpFormat, lpDateStr, cchDate = argv

        cw = self.get_char_width(ctx)

        ctx.args["Locale"].display = decode(LCID, Locale)

        if lpFormat:
            date_format = self.read_mem_string(lpFormat, cw)
            if date_format:
                ctx.args["lpFormat"].display = date_format
        else:
            # Using this as default; TODO: use proper string based on locale
            date_format = "MM/dd/yyyy"

        # Working from example "ddd, dd MMM yyyy "; TODO: expand this
        date_format = date_format.replace("ddd", "%a")
        date_format = date_format.replace("dd", "%d")
        date_format = date_format.replace("MMM", "%b")
        date_format = date_format.replace("MM", "%m")
        date_format = date_format.replace("yyyy", "%Y")

        try:
            if lpDate:
                sys_time = self.k32types.SYSTEMTIME(emu.get_ptr_size())
                sys_time = self.mem_cast(sys_time, lpDate)
                date = datetime.date(sys_time.wYear, sys_time.wMonth, sys_time.wDay)
            else:
                date = self.get_local_time().date()
            date_str = date.strftime(date_format)
        except Exception:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        if cchDate == 0:
            return len(date_str) + 1
        if cchDate <= len(date_str):
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
            return 0

        self.write_mem_string(date_str, lpDateStr, cw)
        ctx.args["lpDateStr"].display = date_str

        return len(date_str) + 1

    @apihook("DeviceIoControl", argc=8)
    def DeviceIoControl(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL DeviceIoControl(
            HANDLE hDevice,
            DWORD dwIoControlCode,
            LPVOID lpInBuffer,
            DWORD nInBufferSize,
            LPVOID lpOutBuffer,
            DWORD nOutBufferSize,
            LPDWORD lpBytesReturned,
            LPOVERLAPPED lpOverlapped
        );
        """
        (
            hDevice,
            dwIoControlCode,
            lpInBuffer,
            nInBufferSize,
            lpOutBuffer,
            nOutBufferSize,
            lpBytesReturned,
            lpOverlapped,
        ) = argv
        nts = ddk.STATUS_SUCCESS
        out_written = 0

        if lpBytesReturned:
            self.write_dword(lpBytesReturned, 0)

        obj = emu.get_handle_table().get(hDevice)
        if not obj:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        in_buf = b""
        if lpInBuffer:
            in_buf = self.mem_read(lpInBuffer, nInBufferSize)

        nts, outbuf = emu.dev_ioctl(emu.get_ptr_size(), obj, dwIoControlCode, in_buf)

        if lpOutBuffer:
            if nOutBufferSize < len(outbuf):
                nts = ddk.STATUS_BUFFER_TOO_SMALL
            else:
                self.mem_write(lpOutBuffer, outbuf)
                out_written = len(outbuf)

        if lpBytesReturned:
            self.write_dword(lpBytesReturned, out_written)

        if nts == ddk.STATUS_SUCCESS:
            emu.set_last_error(windefs.ERROR_SUCCESS)
            return 1

        if nts == ddk.STATUS_BUFFER_TOO_SMALL:
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
        elif nts == ddk.STATUS_INVALID_DEVICE_REQUEST:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
        else:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
        return 0

    @apihook("GetTimeFormat", argc=6)
    def GetTimeFormat(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetTimeFormat(
            LCID Locale,
            DWORD dwFlags,
            const SYSTEMTIME *lpTime,
            LPCTSTR lpFormat,
            LPTSTR lpTimeStr,
            int cchTime
        );
        """
        Locale, dwFlags, lpTime, lpFormat, lpTimeStr, cchTime = argv

        cw = self.get_char_width(ctx)

        ctx.args["Locale"].display = decode(LCID, Locale)

        if lpFormat:
            time_format = self.read_mem_string(lpFormat, cw)
            if time_format:
                ctx.args["lpFormat"].display = time_format
        else:
            # Using this as default; TODO: use proper string based on locale
            time_format = "hh:mm:ss"

        # Working from "hh:mm:ss"; TODO: expand this
        time_format = time_format.replace("hh", "%I")
        time_format = time_format.replace("HH", "%H")
        time_format = time_format.replace("mm", "%M")
        time_format = time_format.replace("ss", "%S")

        try:
            if lpTime:
                sys_time = self.k32types.SYSTEMTIME(emu.get_ptr_size())
                sys_time = self.mem_cast(sys_time, lpTime)
                t = datetime.time(hour=sys_time.wHour, minute=sys_time.wMinute, second=sys_time.wSecond)
            else:
                t = self.get_local_time().time()
            time_str = t.strftime(time_format)
        except Exception:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        if cchTime == 0:
            return len(time_str) + 1
        if cchTime <= len(time_str):
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
            return 0

        self.write_mem_string(time_str, lpTimeStr, cw)
        ctx.args["lpTimeStr"].display = time_str

        return len(time_str) + 1

    @apihook("FlushFileBuffers", argc=1)
    def FlushFileBuffers(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL FlushFileBuffers(
            HANDLE hFile
        );
        """
        (hFile,) = argv
        rv = 1
        emu.set_last_error(windefs.ERROR_SUCCESS)

        return rv

    @apihook("GetExitCodeThread", argc=2)
    def GetExitCodeThread(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetExitCodeThread(
            HANDLE hThread,
            LPDWORD lpExitCode
        );
        """
        hThread, lpExitCode = argv
        obj = emu.get_handle_table().get(hThread, objman.Thread)
        if not obj:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return False
        if lpExitCode:
            # Threads run one after another, so a thread that has not run yet has ended
            # when another run asks. A wait on the thread runs it first.
            if obj is emu.get_current_thread():
                exit_code = windefs.STILL_ACTIVE
            else:
                exit_code = obj.exit_code or 0
            self.write_dword(lpExitCode, exit_code)
        return True

    @apihook("InitializeConditionVariable", argc=1)
    def InitializeConditionVariable(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID InitializeConditionVariable(
            PCONDITION_VARIABLE ConditionVariable
        );
        """
        (ConditionVariable,) = argv
        rv = 0

        return rv

    @apihook("WakeAllConditionVariable", argc=1)
    def WakeAllConditionVariable(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID WakeAllConditionVariable(
            PCONDITION_VARIABLE ConditionVariable
        );
        """
        return

    @apihook("WaitOnAddress", argc=4)
    def WaitOnAddress(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL WaitOnAddress(
            volatile VOID *Address,
            PVOID CompareAddress,
            SIZE_T AddressSize,
            DWORD dwMilliseconds
        );

        Threads run one after another, so no other thread can change the value or wake
        this thread during the wait. A finite wait times out at once. An INFINITE wait
        ends the run of the thread, so that the queued runs can execute.
        """
        Address, CompareAddress, AddressSize, dwMilliseconds = argv
        if AddressSize not in (1, 2, 4, 8):
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return False

        if self.mem_read(Address, AddressSize) != self.mem_read(CompareAddress, AddressSize):
            return True

        if dwMilliseconds == 0xFFFFFFFF:
            emu.exit_process()
            return True

        self.advance_clock(dwMilliseconds)
        emu.set_last_error(windefs.ERROR_TIMEOUT)
        return False

    @apihook("WakeByAddressSingle", argc=1)
    def WakeByAddressSingle(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID WakeByAddressSingle(
            PVOID Address
        );
        """
        return

    @apihook("WakeByAddressAll", argc=1)
    def WakeByAddressAll(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID WakeByAddressAll(
            PVOID Address
        );
        """
        return

    @apihook("Wow64DisableWow64FsRedirection", argc=1)
    def Wow64DisableWow64FsRedirection(
        self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        BOOL Wow64DisableWow64FsRedirection(
            PVOID *OldValue
        );
        """
        (OldValue,) = argv
        rv = 1

        return rv

    @apihook("Wow64RevertWow64FsRedirection", argc=1)
    def Wow64RevertWow64FsRedirection(
        self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        BOOL Wow64RevertWow64FsRedirection(
            PVOID OlValue
        );
        """
        (OlValue,) = argv
        rv = 1

        return rv

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

        lpidProcess_cursor = lpidProcess
        lim = min(cb // 4, len(processes))

        for i in range(lim):
            pid = processes[i].pid.to_bytes(4, "little")
            self.mem_write(lpidProcess_cursor, pid)
            lpidProcess_cursor += 4

        pcbNeeded = lim * 4
        if lpcbNeeded:
            self.write_dword(lpcbNeeded, pcbNeeded)

        return 1

    @apihook("GetModuleFileNameExA", argc=4)
    def GetModuleFileNameExA(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetModuleFileNameExA(
            HANDLE hProcess,
            HMODULE hModule,
            LPSTR lpFilename,
            DWORD nSize
        );
        """
        hProcess, hModule, lpFilename, nSize = argv

        if hModule:
            return self.GetModuleFileName(emu, [hModule, lpFilename, nSize], ctx)

        size = 0
        cw = self.get_char_width(ctx)

        proc = emu.get_handle_table().get(hProcess, objman.Process)

        if proc is None:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        filename = proc.path

        if filename:
            out = self.encode_string(filename, cw)

            size = len(out) // cw
            if nSize < size + 1 * cw:  # null terminator
                emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
                out = out[: nSize - 1 * cw] + b"\0" * cw
            else:
                out += b"\0" * cw

            self.mem_write(lpFilename, out)

        return size

    @apihook("GetThreadPriority", argc=1)
    def GetThreadPriority(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetThreadPriority(
            HANDLE hThread
        );
        """
        return k32defs.THREAD_PRIORITY_NORMAL

    @apihook("UnhandledExceptionFilter", argc=1)
    def UnhandledExceptionFilter(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG UnhandledExceptionFilter(
            struct _EXCEPTION_POINTERS *ExceptionInfo
        );
        """
        return windefs.EXCEPTION_EXECUTE_HANDLER

    @apihook("GetSystemTimePreciseAsFileTime", argc=1)
    def GetSystemTimePreciseAsFileTime(
        self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        VOID GetSystemTimePreciseAsFileTime(
            LPFILETIME lpSystemTimeAsFileTime
        );
        """
        (lpSystemTimeAsFileTime,) = argv
        ft = self.k32types.FILETIME(emu.get_ptr_size())

        timestamp = self.get_system_time()
        ft.dwLowDateTime = 0xFFFFFFFF & timestamp
        ft.dwHighDateTime = timestamp >> 32

        self.mem_write(lpSystemTimeAsFileTime, self.get_bytes(ft))

    @apihook("AddVectoredExceptionHandler", argc=2)
    def AddVectoredExceptionHandler(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PVOID AddVectoredExceptionHandler(
            ULONG First,
            PVECTORED_EXCEPTION_HANDLER Handler
        );
        """
        First, Handler = argv

        emu.add_vectored_exception_handler(First, Handler)

        return Handler

    @apihook("AddVectoredContinueHandler", argc=2)
    def AddVectoredContinueHandler(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PVOID AddVectoredContinueHandler(
            ULONG First,
            PVECTORED_EXCEPTION_HANDLER Handler
        );
        """
        First, Handler = argv
        return Handler

    @apihook("RemoveVectoredExceptionHandler", argc=1)
    def RemoveVectoredExceptionHandler(
        self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        ULONG RemoveVectoredExceptionHandler(
            PVOID Handle
        );
        """
        (Handle,) = argv
        if Handle not in emu.get_veh_handlers():
            return 0
        emu.remove_vectored_exception_handler(Handle)
        return 1

    @apihook("GetSystemDefaultUILanguage", argc=0)
    def GetSystemDefaultUILanguage(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LANGID GetSystemDefaultUILanguage();
        """
        return LANG_EN_US

    @apihook("GetUserDefaultLangID", argc=0)
    def GetUserDefaultLangID(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LANGID GetUserDefaultLangID();
        """
        return LANG_EN_US

    @apihook("GetUserDefaultLCID", argc=0)
    def GetUserDefaultLCID(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LCID GetUserDefaultLCID();
        """
        # https://docs.microsoft.com/en-us/windows/win32/intl/locale-user-default
        return LCID.LOCALE_USER_DEFAULT

    @apihook("GetSystemDefaultLCID", argc=0)
    def GetSystemDefaultLCID(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LCID GetSystemDefaultLCID();
        """
        # https://learn.microsoft.com/en-us/windows/win32/intl/locale-system-default
        return LCID.LOCALE_SYSTEM_DEFAULT

    @apihook("GetTempFileName", argc=4)
    def GetTempFileName(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetTempFileName(
            LPCTSTR lpPathName,
            LPCTSTR lpPrefixString,
            UINT uUnique,
            LPTSTR lpTempFileName
        );
        """
        lpPathName, lpPrefixString, uUnique, lpTempFileName = argv

        cw = self.get_char_width(ctx)
        path = self.read_mem_string(lpPathName, cw)
        prefix = self.read_mem_string(lpPrefixString, cw) if lpPrefixString else ""

        unique = uUnique & 0xFFFF
        create = not unique
        if create:
            unique = self.get_tick_count() & 0xFFFF or 1
        out = path.rstrip("\\") + f"\\{prefix[:3]}{unique:X}.TMP"
        ctx.args["lpTempFileName"].display = out
        self.write_mem_string(out, lpTempFileName, cw)
        if create:
            self.file_open(out, create=True)

        return unique

    @apihook("_llseek", argc=3)
    def _llseek(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LONG _llseek(
            HFILE hFile,
            LONG lOffset,
            int iOrigin
        );
        """
        # _llseek is 16-bit variant of SetFilePointer
        # code replicates SetFilePointer()
        hFile, lOffset, iOrigin = argv

        f = self.get_file(hFile)
        if not f:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return windefs.HFILE_ERROR

        offset = ct.c_int32(lOffset).value
        if iOrigin == windefs.FILE_CURRENT:
            offset += f.tell()
        elif iOrigin == windefs.FILE_END:
            offset += f.get_size()
        if offset < 0:
            emu.set_last_error(windefs.ERROR_NEGATIVE_SEEK)
            return windefs.HFILE_ERROR

        f.seek(offset, windefs.FILE_BEGIN)
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return f.tell() & 0xFFFFFFFF

    @apihook("_lopen", argc=2)
    def _lopen(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HFILE _lopen(
            LPCSTR lpPathName,
            int iReadWrite
        );
        """
        lpPathName, iReadWrite = argv
        filename = self.read_mem_string(lpPathName, 1)
        fHandle = self.file_open(filename)
        if not fHandle:
            return windefs.HFILE_ERROR
        return fHandle

    @apihook("_lclose", argc=1)
    def _lclose(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HFILE _lclose(
            HFILE hFile
        );
        """
        (hFile,) = argv
        if not emu.get_handle_table().close(hFile):
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return windefs.HFILE_ERROR
        return 0

    @apihook("GetConsoleTitle", argc=2)
    def GetConsoleTitle(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetConsoleTitle(
            LPTSTR lpConsoleTitle,
            DWORD nSize
        );
        """
        lpConsoleTitle, nSize = argv
        cw = self.get_char_width(ctx)

        # TODO: consider enumeration logic
        title = "explorer.exe"

        if lpConsoleTitle and nSize:
            out = title[: nSize - 1]
            self.write_mem_string(out, lpConsoleTitle, cw)
            ctx.args["lpConsoleTitle"].display = out

        return len(title)

    @apihook("InitializeSRWLock", argc=1)
    def InitializeSRWLock(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID InitializeSRWLock(
            PSRWLOCK SRWLock
        );
        """
        return

    @apihook("AcquireSRWLockShared", argc=1)
    def AcquireSRWLockShared(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID AcquireSRWLockShared(
            PSRWLOCK SRWLock
        );
        """
        return

    @apihook("ReleaseSRWLockShared", argc=1)
    def ReleaseSRWLockShared(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID ReleaseSRWLockShared(
            PSRWLOCK SRWLock
        );
        """
        return

    @apihook("AcquireSRWLockExclusive", argc=1)
    def AcquireSRWLockExclusive(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID AcquireSRWLockExclusive(
            PSRWLOCK SRWLock
        );
        """
        return

    @apihook("ReleaseSRWLockExclusive", argc=1)
    def ReleaseSRWLockExclusive(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID ReleaseSRWLockExclusive(
            PSRWLOCK SRWLock
        );
        """
        return

    @apihook("GetPhysicallyInstalledSystemMemory", argc=1)
    def GetPhysicallyInstalledSystemMemory(
        self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        BOOL GetPhysicallyInstalledSystemMemory(
            PULONGLONG TotalMemoryInKilobytes
        );
        """
        (TotalMemoryInKilobytes,) = argv

        # 2GB
        self.write_qword(TotalMemoryInKilobytes, 0x200000)
        return 1

    @apihook("CreateWaitableTimerExW", argc=4)
    def CreateWaitableTimerExW(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE CreateWaitableTimerExW(
            LPSECURITY_ATTRIBUTES lpTimerAttributes,
            LPCWSTR lpTimerName,
            DWORD dwFlags,
            DWORD dwDesiredAccess
        );
        """
        lpTimerAttributes, lpTimerName, dwFlags, dwDesiredAccess = argv

        timer_name = None
        obj = None
        if lpTimerName:
            timer_name = self.read_mem_string(lpTimerName, 2)
            ctx.args["lpTimerName"].display = timer_name
            obj = self.get_object_from_name(timer_name)

        if obj:
            hnd = emu.get_object_handle(obj)
            emu.set_last_error(windefs.ERROR_ALREADY_EXISTS)
        else:
            hnd, _evt = emu.create_event(timer_name)
            emu.set_last_error(windefs.ERROR_SUCCESS)

        return hnd

    @apihook("GetProcessAffinityMask", argc=3)
    def GetProcessAffinityMask(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetProcessAffinityMask(
            HANDLE hProcess,
            PDWORD_PTR lpProcessAffinityMask,
            PDWORD_PTR lpSystemAffinityMask
        );
        """
        hProcess, lpProcessAffinityMask, lpSystemAffinityMask = argv
        mask = (1 << PROCESSOR_COUNT) - 1
        if lpProcessAffinityMask:
            self.write_ptr(lpProcessAffinityMask, mask)
        if lpSystemAffinityMask:
            self.write_ptr(lpSystemAffinityMask, mask)
        return 1

    @apihook("GetActiveProcessorGroupCount", argc=0)
    def GetActiveProcessorGroupCount(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        WORD GetActiveProcessorGroupCount();
        """
        return 1

    @apihook("GetMaximumProcessorGroupCount", argc=0)
    def GetMaximumProcessorGroupCount(
        self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        WORD GetMaximumProcessorGroupCount();
        """
        return 1

    @apihook("GetActiveProcessorCount", argc=1)
    def GetActiveProcessorCount(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetActiveProcessorCount(
            WORD GroupNumber
        );
        """
        (GroupNumber,) = argv
        if GroupNumber & 0xFFFF in (0, ALL_PROCESSOR_GROUPS):
            return PROCESSOR_COUNT
        emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
        return 0

    @apihook("GetMaximumProcessorCount", argc=1)
    def GetMaximumProcessorCount(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetMaximumProcessorCount(
            WORD GroupNumber
        );
        """
        return self.GetActiveProcessorCount(emu, argv, ctx)

    @apihook("SetConsoleCtrlHandler", argc=2)
    def SetConsoleCtrlHandler(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetConsoleCtrlHandler(
            PHANDLER_ROUTINE HandlerRoutine,
            BOOL Add
        );
        """
        return 1

    @apihook("WTSGetActiveConsoleSessionId", argc=0)
    def WTSGetActiveConsoleSessionId(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD WTSGetActiveConsoleSessionId();
        """
        return emu.get_current_process().session

    @apihook("WaitForSingleObjectEx", argc=3)
    def WaitForSingleObjectEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD WaitForSingleObjectEx(
            HANDLE hHandle,
            DWORD dwMilliseconds,
            BOOL bAlertable
        );

        The wait is as for WaitForSingleObject. Speakeasy does not queue APCs, so an alertable wait is not alerted.
        """
        hHandle, dwMilliseconds, bAlertable = argv
        return self.wait_for_object(emu, hHandle, dwMilliseconds)

    @apihook("GetProfileInt", argc=3)
    def GetProfileInt(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        UINT GetProfileInt(
            LPCTSTR lpAppName,
            LPCTSTR lpKeyName,
            INT nDefault
        );
        """
        lpAppName, lpKeyName, nDefault = argv
        return nDefault

    @apihook("CreateSemaphore", argc=4)
    def CreateSemaphore(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE CreateSemaphore(
            LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,
            LONG lInitialCount,
            LONG lMaximumCount,
            LPCTSTR lpName
        );
        """
        lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName = argv
        lInitialCount = ct.c_int32(lInitialCount).value
        lMaximumCount = ct.c_int32(lMaximumCount).value

        if lMaximumCount <= 0 or not 0 <= lInitialCount <= lMaximumCount:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        name = ""
        if lpName:
            name = self.read_mem_string(lpName, self.get_char_width(ctx))
            ctx.args["lpName"].display = name
            obj = self.get_object_from_name(name)
            if obj:
                emu.set_last_error(windefs.ERROR_ALREADY_EXISTS)
                return emu.get_object_handle(obj)

        emu.set_last_error(windefs.ERROR_SUCCESS)
        hnd, _ = emu.create_semaphore(name)
        return hnd

    @apihook("OpenSemaphore", argc=3)
    def OpenSemaphore(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HANDLE OpenSemaphore(
            DWORD dwDesiredAccess,
            BOOL bInheritHandle,
            LPCTSTR lpName
        );
        """
        dwDesiredAccess, bInheritHandle, lpName = argv

        if not lpName:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        obj_name = self.read_mem_string(lpName, self.get_char_width(ctx))
        ctx.args["lpName"].display = obj_name

        obj = self.get_object_from_name(obj_name)
        if not obj:
            emu.set_last_error(windefs.ERROR_FILE_NOT_FOUND)
            return 0

        emu.set_last_error(windefs.ERROR_SUCCESS)
        return emu.get_object_handle(obj)

    @apihook("SetThreadStackGuarantee", argc=1)
    def SetThreadStackGuarantee(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetThreadStackGuarantee(
            PULONG StackSizeInBytes
        );
        """
        return 1

    @apihook("SetThreadDescription", argc=2)
    def SetThreadDescription(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT SetThreadDescription(
            HANDLE hThread,
            PCWSTR lpThreadDescription
        );
        """
        return windefs.ERROR_SUCCESS

    @apihook("InitOnceBeginInitialize", argc=4)
    def InitOnceBeginInitialize(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL InitOnceBeginInitialize(
            LPINIT_ONCE lpInitOnce,
            DWORD dwFlags,
            PBOOL fPending,
            LPVOID *lpContext
        );
        """
        lpInitOnce, dwFlags, fPending, lpContext = argv
        state = self.read_ptr(lpInitOnce)
        is_async = bool(dwFlags & k32defs.INIT_ONCE_ASYNC)
        if state & 3 == 2:
            if lpContext:
                self.write_ptr(lpContext, state & ~3)
            pending = 0
        elif dwFlags & k32defs.INIT_ONCE_CHECK_ONLY:
            emu.set_last_error(windefs.ERROR_GEN_FAILURE)
            return 0
        elif (state & 3 == 1 and is_async) or (state & 3 == 3 and not is_async):
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0
        else:
            self.write_ptr(lpInitOnce, 3 if is_async else 1)
            pending = 1
        if fPending:
            self.write_dword(fPending, pending)
        return 1

    @apihook("InitOnceComplete", argc=3)
    def InitOnceComplete(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL InitOnceComplete(
            LPINIT_ONCE lpInitOnce,
            DWORD dwFlags,
            LPVOID lpContext
        );
        """
        lpInitOnce, dwFlags, lpContext = argv
        state = self.read_ptr(lpInitOnce)
        if lpContext & 3:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0
        if not state & 1:
            emu.set_last_error(windefs.ERROR_GEN_FAILURE)
            return 0
        if dwFlags & k32defs.INIT_ONCE_INIT_FAILED:
            state = 0
        else:
            state = lpContext | 2
        self.write_ptr(lpInitOnce, state)
        return 1

    @apihook("InitOnceExecuteOnce", argc=4)
    def InitOnceExecuteOnce(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL InitOnceExecuteOnce(
            PINIT_ONCE InitOnce,
            PINIT_ONCE_FN InitFn,
            PVOID Parameter,
            LPVOID *Context
        );

        The result of InitFn is not read back, so the initialization always succeeds.
        """
        InitOnce, InitFn, Parameter, Context = argv
        state = self.read_ptr(InitOnce)
        if state & 3 == 2:
            return 1
        self.write_ptr(InitOnce, 2)
        self.setup_callback(InitFn, (InitOnce, Parameter, Context))
        return 1

    @apihook("FlsGetValue2", argc=1)
    def FlsGetValue2(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PVOID FlsGetValue2(
            DWORD dwTlsIndex
        );
        """
        (dwTlsIndex,) = argv
        fls = emu.get_current_thread().fls
        if dwTlsIndex < len(fls):
            return fls[dwTlsIndex]
        return 0

    @apihook("MulDiv", argc=3)
    def MulDiv(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int MulDiv(
            int nNumber,
            int nNumerator,
            int nDenominator
        );
        """
        nNumber, nNumerator, nDenominator = argv
        try:
            if nDenominator == 0:
                return 0
            return int((nNumber * nNumerator) / nDenominator)
        except Exception:
            return 0

    @apihook("GlobalAddAtomA", argc=1)
    def GlobalAddAtomA(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        ATOM GlobalAddAtomA(
            LPCSTR lpString
        );
        """
        # Return a fake ATOM value. ATOMs are 16-bit identifiers.
        return 0x1234
