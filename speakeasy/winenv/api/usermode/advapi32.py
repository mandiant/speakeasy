# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import base64
import hashlib
import struct
from typing import TYPE_CHECKING

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.registry.reg as regdefs
import speakeasy.winenv.defs.windows.advapi32 as adv32defs
import speakeasy.winenv.defs.windows.kernel32 as k32defs
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.errors import FileSystemEmuError
from speakeasy.profiler_events import EventType
from speakeasy.report import RunType
from speakeasy.windows import objman
from speakeasy.windows.cryptman import CIPHER_MODES, CryptoApiError, CryptoApiKey
from speakeasy.winenv.api.token import query_token_information
from speakeasy.winenv.codepage import encode_ansi
from speakeasy.winenv.defs.enums import (
    ENUM_SERVICE_STATE,
    ENUM_SERVICE_TYPE,
    PROCESS_CREATION_FLAGS,
    REG_VALUE_TYPE,
    SERVICE_STATUS_CURRENT_STATE,
)
from speakeasy.winenv.defs.lookup import decode
from speakeasy.winenv.defs.nt import ddk

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator

MD5_INITIAL_STATE = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
TOKEN_QUERY_ERRORS = {
    ddk.STATUS_BUFFER_TOO_SMALL: windefs.ERROR_INSUFFICIENT_BUFFER,
    ddk.STATUS_INFO_LENGTH_MISMATCH: windefs.ERROR_BAD_LENGTH,
    ddk.STATUS_ACCESS_VIOLATION: windefs.ERROR_NOACCESS,
}


class AdvApi32(api.ApiHandler):
    """
    Implements exported functions from advapi32.dll
    """

    name = "advapi32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        self.funcs = {}
        self.data = {}
        self.md5_contexts: dict[int, hashlib._Hash] = {}
        self.k32types = k32defs
        self.win = adv32defs

        super().__get_hook_attrs__(self)

    @apihook("RegOpenKey", argc=3, conv=_arch.CALL_CONV_STDCALL)
    def RegOpenKey(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LSTATUS RegOpenKey(
            HKEY hKey,
            LPCTSTR lpSubKey,
            PHKEY phkResult
        );
        """
        hKey, lpSubKey, phkResult = argv

        return self.open_key(hKey, lpSubKey, phkResult, ctx)

    @apihook("RegOpenKeyEx", argc=5, conv=_arch.CALL_CONV_STDCALL)
    def RegOpenKeyEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LSTATUS RegOpenKeyEx(
            HKEY hKey,
            LPCTSTR lpSubKey,
            DWORD ulOptions,
            REGSAM samDesired,
            PHKEY phkResult
        );
        """
        hKey, lpSubKey, ulOptions, samDesired, phkResult = argv

        return self.open_key(hKey, lpSubKey, phkResult, ctx, new_handle=True, access=samDesired)

    def open_key(self, hKey, lpSubKey, phkResult, ctx, new_handle=False, access=None):
        """
        Open ``lpSubKey`` below ``hKey`` and write the new handle to
        ``phkResult``. Without a subkey, the handle is ``hKey`` itself, or
        a new handle to the same key when ``new_handle`` is set.
        ``access`` is the REGSAM value of the call, for the event.
        """
        rv = windefs.ERROR_SUCCESS

        hkey_name = regdefs.get_hkey_type(hKey)
        if hkey_name:
            ctx.args["hKey"].display = hkey_name
        else:
            key_obj = self.get_reg_key(hKey)
            if not key_obj:
                return windefs.ERROR_INVALID_HANDLE
            hkey_name = key_obj.get_path()

        hnd = hKey
        cw = self.get_char_width(ctx)
        if lpSubKey:
            lpSubKey = self.read_mem_string(lpSubKey, cw)
            ctx.args["lpSubKey"].display = lpSubKey

        if lpSubKey:
            if not lpSubKey.startswith("\\"):
                lpSubKey = "\\" + lpSubKey
            lpSubKey = hkey_name + lpSubKey

            hnd = self.reg_open_key(lpSubKey, create=False, access=access)
            if not hnd:
                rv = windefs.ERROR_FILE_NOT_FOUND
        elif new_handle:
            hnd = self.reg_open_key(hkey_name, create=False, access=access)

        if phkResult:
            self.write_ptr(phkResult, hnd or 0)

        return rv

    def write_value_type(self, val, lpType, arg):
        code = val.get_type()
        if not lpType or not isinstance(code, int):
            return
        self.write_dword(lpType, code)
        arg.display = decode(REG_VALUE_TYPE, code)

    @apihook("RegQueryValueEx", argc=6, conv=_arch.CALL_CONV_STDCALL)
    def RegQueryValueEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LSTATUS RegQueryValueEx(
            HKEY hKey,
            LPCTSTR lpValueName,
            LPDWORD lpReserved,
            LPDWORD lpType,
            LPBYTE lpData,
            LPDWORD lpcbData
        );
        """
        hKey, lpValueName, lpReserved, lpType, lpData, lpcbData = argv
        rv = windefs.ERROR_SUCCESS

        cw = self.get_char_width(ctx)
        value_name = ""
        if lpValueName:
            value_name = self.read_mem_string(lpValueName, cw)
            ctx.args["lpValueName"].display = value_name

        length = 0
        if lpcbData:
            length = self.mem_read(lpcbData, 4)
            length = int.from_bytes(length, "little")
            ctx.args["lpcbData"].display = hex(length)

        key = self.get_reg_key(hKey)
        if not key:
            return windefs.ERROR_INVALID_HANDLE
        val = emu.regman.read_value(key, value_name, cw, handle=hKey, buffer=lpData, size=length)
        if val:
            self.write_value_type(val, lpType, ctx.args["lpType"])
            output = val.get_bytes(cw)
            if lpcbData:
                self.write_dword(lpcbData, len(output))
            if lpData:
                if not lpcbData:
                    rv = windefs.ERROR_INVALID_PARAMETER
                elif len(output) > length:
                    rv = windefs.ERROR_MORE_DATA
                else:
                    self.mem_write(lpData, output)

        # For now, return an empty buffer
        else:
            output = b"\x00" * length
            if lpData:
                try:
                    self.mem_write(lpData, output)
                except Exception:
                    return windefs.ERROR_INVALID_PARAMETER
            if lpcbData:
                self.write_dword(lpcbData, len(output))
            rv = windefs.ERROR_SUCCESS

        return rv

    @apihook("RegSetValueEx", argc=6, conv=_arch.CALL_CONV_STDCALL)
    def RegSetValueEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LSTATUS RegSetValueEx(
            HKEY hKey,
            LPCTSTR lpValueName,
            DWORD Reserved,
            DWORD dwType,
            const BYTE *lpData,
            DWORD cbData
        );
        """
        hKey, lpValueName, Reserved, dwType, lpData, cbData = argv
        dwType &= 0xFFFFFFFF
        cbData &= 0xFFFFFFFF

        key = self.get_reg_key(hKey)
        if not key:
            return windefs.ERROR_INVALID_HANDLE

        cw = self.get_char_width(ctx)
        value_name = ""
        if lpValueName:
            value_name = self.read_mem_string(lpValueName, cw)
            ctx.args["lpValueName"].display = value_name

        value_data: str | int | bytes = ""
        raw = b""
        if lpData and cbData:
            raw = self.mem_read(lpData, cbData)
            if dwType in (REG_VALUE_TYPE.REG_SZ, REG_VALUE_TYPE.REG_EXPAND_SZ, REG_VALUE_TYPE.REG_MULTI_SZ):
                value_data = self.decode_string(raw, cw).rstrip("\x00")
            elif dwType == REG_VALUE_TYPE.REG_DWORD:
                value_data = int.from_bytes(raw[:4].ljust(4, b"\x00"), "little")
            elif dwType == REG_VALUE_TYPE.REG_QWORD:
                value_data = int.from_bytes(raw[:8].ljust(8, b"\x00"), "little")
            else:
                value_data = raw
            if isinstance(value_data, str):
                ctx.args["lpData"].display = value_data

        emu.regman.write_value(key, value_name, dwType, value_data, raw=raw, handle=hKey, buffer=lpData)

        return windefs.ERROR_SUCCESS

    @apihook("RegCloseKey", argc=1, conv=_arch.CALL_CONV_STDCALL)
    def RegCloseKey(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LSTATUS RegCloseKey(
            HKEY hKey
        );
        """
        (hKey,) = argv

        if not emu.regman.close_key(hKey):
            return windefs.ERROR_INVALID_HANDLE

        return windefs.ERROR_SUCCESS

    @apihook("RegEnumKey", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def RegEnumKey(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LSTATUS RegEnumKey(
            HKEY hKey,
            DWORD dwIndex,
            LPTSTR lpName,
            DWORD cchName
        );
        """
        hKey, dwIndex, lpName, cchName = argv

        rv, _ = self.enum_key(hKey, dwIndex & 0xFFFFFFFF, lpName, cchName & 0xFFFFFFFF, ctx)

        return rv

    @apihook("RegEnumKeyEx", argc=8, conv=_arch.CALL_CONV_STDCALL)
    def RegEnumKeyEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LSTATUS RegEnumKeyEx(
            HKEY hKey,
            DWORD dwIndex,
            LPTSTR lpName,
            LPDWORD lpcchName,
            LPDWORD lpReserved,
            LPTSTR lpClass,
            LPDWORD lpcchClass,
            PFILETIME lpftLastWriteTime
        );
        """
        hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime = argv

        cch = self.read_dword(lpcchName) if lpcchName else 0
        rv, name = self.enum_key(hKey, dwIndex & 0xFFFFFFFF, lpName, cch, ctx)
        if rv == windefs.ERROR_SUCCESS:
            self.write_dword(lpcchName, len(name))
        return rv

    def enum_key(self, hKey, dwIndex, lpName, cch, ctx):
        """
        Write the name of subkey ``dwIndex`` to ``lpName``, a buffer of
        ``cch`` characters. Return the status and the name.
        """
        cw = self.get_char_width(ctx)
        rv = windefs.ERROR_INVALID_HANDLE
        name = ""
        if hKey:
            key = self.get_reg_key(hKey)
            if not key:
                rv = windefs.ERROR_INVALID_HANDLE
            else:
                ctx.args["hKey"].display = key.get_path()
                subkeys = self.emu.regman.list_subkeys(key, handle=hKey)
                if (dwIndex + 1) > len(subkeys):
                    rv = windefs.ERROR_NO_MORE_ITEMS
                elif not lpName:
                    rv = windefs.ERROR_INVALID_PARAMETER
                else:
                    name = subkeys[dwIndex]
                    if cch < len(name) + 1:
                        rv = windefs.ERROR_MORE_DATA
                    else:
                        self.write_mem_string(name, lpName, cw)
                        rv = windefs.ERROR_SUCCESS
        return rv, name

    @apihook("RegCreateKey", argc=3)
    def RegCreateKey(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LSTATUS RegCreateKey(
            HKEY hKey,
            LPCTSTR lpSubKey,
            PHKEY phkResult
        );
        """
        hKey, lpSubKey, phkResult = argv
        rv = windefs.ERROR_INVALID_HANDLE
        if hKey:
            key = self.get_reg_key(hKey)
            if not key:
                rv = windefs.ERROR_INVALID_HANDLE
            else:
                ctx.args["hKey"].display = key.get_path()
                cw = self.get_char_width(ctx)
                sub_key = ""
                if lpSubKey:
                    sub_key = self.read_mem_string(lpSubKey, cw)
                    ctx.args["lpSubKey"].display = sub_key
                hnd = hKey
                if sub_key:
                    sub_key_path = key.get_path() + "\\" + sub_key.lstrip("\\")
                    hnd = self.reg_open_key(sub_key_path, create=True)
                if phkResult:
                    self.write_ptr(phkResult, hnd)
                rv = windefs.ERROR_SUCCESS
        return rv

    @apihook("RegCreateKeyEx", argc=9, conv=_arch.CALL_CONV_STDCALL)
    def RegCreateKeyEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LSTATUS RegCreateKeyEx(
            HKEY hKey,
            LPCTSTR lpSubKey,
            DWORD Reserved,
            LPTSTR lpClass,
            DWORD dwOptions,
            REGSAM samDesired,
            const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
            PHKEY phkResult,
            LPDWORD lpdwDisposition
        );
        """
        hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition = (
            argv
        )

        key_path = ""
        hkey_name = regdefs.get_hkey_type(hKey)
        if hkey_name:
            ctx.args["hKey"].display = hkey_name
            key_path = hkey_name
        else:
            key_obj = self.get_reg_key(hKey)
            if not key_obj:
                return windefs.ERROR_INVALID_HANDLE
            key_path = key_obj.get_path()

        cw = self.get_char_width(ctx)
        if lpSubKey:
            sub_key = self.read_mem_string(lpSubKey, cw)
            ctx.args["lpSubKey"].display = sub_key
            if key_path and sub_key:
                if not sub_key.startswith("\\"):
                    sub_key = "\\" + sub_key
                key_path = key_path + sub_key

        existing = self.emu.reg_get_key(path=key_path)
        disp = regdefs.REG_OPENED_EXISTING_KEY if existing else regdefs.REG_CREATED_NEW_KEY
        hnd = self.reg_open_key(key_path, create=True, disposition=disp, access=samDesired)
        if not hnd:
            return windefs.ERROR_PATH_NOT_FOUND

        if phkResult:
            self.write_ptr(phkResult, hnd)

        if lpdwDisposition:
            self.write_dword(lpdwDisposition, disp)

        return windefs.ERROR_SUCCESS

    @apihook("RegDeleteValue", argc=2, conv=_arch.CALL_CONV_STDCALL)
    def RegDeleteValue(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LSTATUS RegDeleteValue(
            HKEY hKey,
            LPCTSTR lpValueName
        );
        """
        hKey, lpValueName = argv

        key = self.get_reg_key(hKey)
        if not key:
            return windefs.ERROR_INVALID_HANDLE

        cw = self.get_char_width(ctx)
        value_name = ""
        if lpValueName:
            value_name = self.read_mem_string(lpValueName, cw)
            ctx.args["lpValueName"].display = value_name

        if not emu.regman.delete_value(key, value_name, handle=hKey):
            return windefs.ERROR_FILE_NOT_FOUND
        return windefs.ERROR_SUCCESS

    @apihook("RegQueryInfoKey", argc=12, conv=_arch.CALL_CONV_STDCALL)
    def RegQueryInfoKey(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        # TODO: stub
        """
        LSTATUS RegQueryInfoKey(
            HKEY hKey,
            LPTSTR lpClass,
            LPDWORD lpcchClass,
            LPDWORD lpReserved,
            LPDWORD lpcSubKeys,
            LPDWORD lpcbMaxSubKeyLen,
            LPDWORD lpcbMaxClassLen,
            LPDWORD lpcValues,
            LPDWORD lpcbMaxValueNameLen,
            LPDWORD lpcbMaxValueLen,
            LPDWORD lpcbSecurityDescriptor,
            PFILETIME lpftLastWriteTime
        );
        """
        (
            hKey,
            lpClass,
            lpcchClass,
            lpReserved,
            lpcSubKeys,
            lpcbMaxSubKeyLen,
            lpcbMaxClassLen,
            lpcValues,
            lpcbMaxValueNameLen,
            lpcbMaxValueLen,
            lpcbSecurityDescriptor,
            lpftLastWriteTime,
        ) = argv

        rv = windefs.ERROR_SUCCESS

        hkey_name = regdefs.get_hkey_type(hKey)
        if hkey_name:
            ctx.args["hKey"].display = hkey_name

        key = self.get_reg_key(hKey)
        if not key:
            return windefs.ERROR_INVALID_HANDLE

        cw = self.get_char_width(ctx)
        subkey_names = self.reg_get_subkeys(key)
        key_values = key.get_values()
        if lpClass:
            self.write_mem_string("", lpClass, cw)
        for ptr, val in (
            (lpcchClass, 0),
            (lpcSubKeys, len(subkey_names)),
            (lpcbMaxSubKeyLen, max((len(n) for n in subkey_names), default=0)),
            (lpcbMaxClassLen, 0),
            (lpcValues, len(key_values)),
            (lpcbMaxValueNameLen, max((len(v.get_name()) for v in key_values), default=0)),
            (lpcbMaxValueLen, max((len(v.get_bytes(cw)) for v in key_values), default=0)),
            (lpcbSecurityDescriptor, 0),
        ):
            if ptr:
                self.write_dword(ptr, val)
        if lpftLastWriteTime:
            self.mem_write(lpftLastWriteTime, b"\x00" * 8)

        return rv

    @apihook("OpenProcessToken", argc=3, conv=_arch.CALL_CONV_STDCALL)
    def OpenProcessToken(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL OpenProcessToken(
            HANDLE ProcessHandle,
            DWORD DesiredAccess,
            PHANDLE TokenHandle
        );
        """
        ProcessHandle, DesiredAccess, TokenHandle = argv
        rv = 0

        obj = emu.get_handle_table().get(ProcessHandle, objman.Process)

        if obj:
            hToken = emu.get_object_manager(ctx.func_name).new_handle(obj.token)

            if TokenHandle:
                hnd = (hToken).to_bytes(self.get_ptr_size(), "little")
                self.mem_write(TokenHandle, hnd)
                rv = 1
                emu.set_last_error(windefs.ERROR_SUCCESS)
            else:
                emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
        else:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)

        return rv

    @apihook("OpenThreadToken", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def OpenThreadToken(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL OpenThreadToken(
            HANDLE ThreadHandle,
            DWORD DesiredAccess,
            BOOL OpenAsSelf,
            PHANDLE TokenHandle
        );
        """
        ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle = argv
        rv = 0

        obj = emu.get_handle_table().get(ThreadHandle, objman.Thread)

        if obj:
            hToken = emu.get_object_manager(ctx.func_name).new_handle(obj.token)

            if TokenHandle:
                hnd = (hToken).to_bytes(self.get_ptr_size(), "little")
                self.mem_write(TokenHandle, hnd)
                rv = 1
                emu.set_last_error(windefs.ERROR_SUCCESS)
            else:
                emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
        else:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)

        return rv

    @apihook("DuplicateTokenEx", argc=6, conv=_arch.CALL_CONV_STDCALL)
    def DuplicateTokenEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL DuplicateTokenEx(
            HANDLE hExistingToken,
            DWORD dwDesiredAccess,
            LPSECURITY_ATTRIBUTES lpTokenAttributes,
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            TOKEN_TYPE TokenType,
            PHANDLE phNewToken
        );
        """
        (hExistingToken, dwDesiredAccess, lpTokenAttributes, ImpersonationLevel, TokenType, phNewToken) = argv
        rv = 0

        obj = emu.get_handle_table().get(hExistingToken, objman.Token)

        if obj:
            new_token = emu.new_object(objman.Token)
            hnd_new_token = emu.get_object_manager(ctx.func_name).new_handle(new_token)

            if phNewToken:
                hnd = (hnd_new_token).to_bytes(self.get_ptr_size(), "little")
                self.mem_write(phNewToken, hnd)
                rv = 1
                emu.set_last_error(windefs.ERROR_SUCCESS)
            else:
                emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
        else:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)

        return rv

    @apihook("SetTokenInformation", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def SetTokenInformation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetTokenInformation(
            HANDLE TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            LPVOID TokenInformation,
            DWORD TokenInformationLength
        );
        """
        TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength = argv

        rv = 1

        return rv

    @apihook("StartServiceCtrlDispatcher", argc=1)
    def StartServiceCtrlDispatcher(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL StartServiceCtrlDispatcher(
            const SERVICE_TABLE_ENTRY *lpServiceStartTable
        );
        """
        (lpServiceStartTable,) = argv

        cw = self.get_char_width(ctx)

        ste = self.win.SERVICE_TABLE_ENTRY(emu.get_ptr_size())
        entry = self.mem_cast(ste, lpServiceStartTable)

        table = "lpServiceStartTable=["

        # The table ends at a NULL name; a name that cannot be read ends it too
        while entry.lpServiceName != windefs.NULL and emu.is_address_valid(entry.lpServiceName):
            service_name = self.read_mem_string(entry.lpServiceName, cw)
            table += f" {{ lpServiceName={service_name}"

            if entry.lpServiceProc != windefs.NULL:
                service_main = entry.lpServiceProc
                table += f", lpServiceProc={hex(service_main)} }} "
                argc, svc_argv = emu.build_service_main_args(service_name, char_width=cw)
                self.queue_run(RunType.SERVICE_MAIN, service_main, [argc, svc_argv], name=service_name)
            else:
                table += ", lpServiceProc=NULL } "

            lpServiceStartTable += self.sizeof(ste)
            ste = self.win.SERVICE_TABLE_ENTRY(emu.get_ptr_size())
            entry = self.mem_cast(ste, lpServiceStartTable)

        table += "]"
        ctx.args["lpServiceStartTable"].display = table

        rv = True
        emu.set_last_error(windefs.ERROR_SUCCESS)

        return rv

    @apihook("RegisterServiceCtrlHandler", argc=2)
    def RegisterServiceCtrlHandler(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SERVICE_STATUS_HANDLE RegisterServiceCtrlHandler(
            LPCTSTR lpServiceName,
            LPHANDLER_FUNCTION lpHandlerProc
        );
        """
        lpServiceName, lpHandlerProc = argv

        # dummy SERVICE_STATUS_HANDLE
        hnd = emu.handle_allocator.allocate_handle()

        emu.set_last_error(windefs.ERROR_SUCCESS)

        return hnd

    @apihook("RegisterServiceCtrlHandlerEx", argc=3)
    def RegisterServiceCtrlHandlerEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SERVICE_STATUS_HANDLE RegisterServiceCtrlHandlerEx(
            LPCTSTR lpServiceName,
            LPHANDLER_FUNCTION_EX lpHandlerProc,
            LPVOID lpContext
        );
        """
        lpServiceName, lpHandlerProc, lpContext = argv

        return self.RegisterServiceCtrlHandler(emu, [lpServiceName, lpHandlerProc], ctx)

    @apihook("SetServiceStatus", argc=2)
    def SetServiceStatus(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL SetServiceStatus(
            SERVICE_STATUS_HANDLE hServiceStatus,
            LPSERVICE_STATUS lpServiceStatus
        );
        """
        hServiceStatus, lpServiceStatus = argv

        emu.set_last_error(windefs.ERROR_SUCCESS)

        return 0x1

    @apihook("RevertToSelf", argc=0)
    def RevertToSelf(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL RevertToSelf();
        """
        return 1

    @apihook("ImpersonateLoggedOnUser", argc=1)
    def ImpersonateLoggedOnUser(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL ImpersonateLoggedOnUser(
            HANDLE hToken
        );
        """
        return 1

    @apihook("OpenSCManager", argc=3)
    def OpenSCManager(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SC_HANDLE OpenSCManager(
            LPCTSTR lpMachineName,
            LPCTSTR lpDatabaseName,
            DWORD dwDesiredAccess
        );
        """
        lpMachineName, lpDatabaseName, dwDesiredAccess = argv

        hScm = self.mem_alloc(size=8)
        emu.set_last_error(windefs.ERROR_SUCCESS)

        return hScm

    @apihook("CreateService", argc=13)
    def CreateService(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SC_HANDLE CreateService(
            SC_HANDLE hSCManager,
            LPCTSTR lpServiceName,
            LPCTSTR lpDisplayName,
            DWORD dwDesiredAccess,
            DWORD dwServiceType,
            DWORD dwStartType,
            DWORD dwErrorControl,
            LPCTSTR lpBinaryPathName,
            LPCTSTR lpLoadOrderGroup,
            LPDWORD lpdwTagId,
            LPCTSTR lpDependencies,
            LPCTSTR lpServiceStartName,
            LPCTSTR lpPassword
        );
        """
        (
            hSCManager,
            lpServiceName,
            lpDisplayName,
            dwDesiredAccess,
            dwServiceType,
            dwStartType,
            dwErrorControl,
            lpBinaryPathName,
            lpLoadOrderGroup,
            lpdwTagId,
            lpDependencies,
            lpServiceStartName,
            lpPassword,
        ) = argv

        cw = self.get_char_width(ctx)

        if lpServiceName:
            _sname = self.read_mem_string(lpServiceName, cw)
            ctx.args["lpServiceName"].display = _sname
        if lpDisplayName:
            _dname = self.read_mem_string(lpDisplayName, cw)
            ctx.args["lpDisplayName"].display = _dname
        _bpname = ""
        if lpBinaryPathName:
            _bpname = self.read_mem_string(lpBinaryPathName, cw)
            ctx.args["lpBinaryPathName"].display = _bpname

        if lpServiceName:
            key = emu.regman.create_key(f"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\{_sname}")
            key.create_value("Type", REG_VALUE_TYPE.REG_DWORD, dwServiceType)
            key.create_value("Start", REG_VALUE_TYPE.REG_DWORD, dwStartType)
            key.create_value("ErrorControl", REG_VALUE_TYPE.REG_DWORD, dwErrorControl)
            key.create_value("ImagePath", REG_VALUE_TYPE.REG_EXPAND_SZ, _bpname)
            if lpDisplayName:
                key.create_value("DisplayName", REG_VALUE_TYPE.REG_SZ, _dname)

        hSvc = self.mem_alloc(size=8)
        emu.set_last_error(windefs.ERROR_SUCCESS)

        return hSvc

    @apihook("StartService", argc=3)
    def StartService(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL StartService(
            SC_HANDLE hService,
            DWORD dwNumServiceArgs,
            LPCTSTR *lpServiceArgVectors
        );

        Speakeasy does not model the state of services. StartService only returns success.
        """
        hService, dwNumServiceArgs, lpServiceArgVectors = argv

        rv = 1

        emu.set_last_error(windefs.ERROR_SUCCESS)

        return rv

    @apihook("StartServiceA", argc=3)
    def StartServiceA(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL StartServiceA(
            SC_HANDLE hService,
            DWORD dwNumServiceArgs,
            LPCSTR *lpServiceArgVectors
        );
        """
        return self.StartService(emu, argv, ctx)

    @apihook("ControlService", argc=3)
    def ControlService(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL ControlService(
            SC_HANDLE hService,
            DWORD dwControl,
            LPSERVICE_STATUS lpServiceStatus
        );

        Speakeasy does not model the state of services. ControlService only returns success.
        """
        hService, dwControl, lpServiceStatus = argv

        rv = 1

        emu.set_last_error(windefs.ERROR_SUCCESS)

        return rv

    @apihook("QueryServiceStatus", argc=2)
    def QueryServiceStatus(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL QueryServiceStatus(
            SC_HANDLE hService,
            LPSERVICE_STATUS lpServiceStatus
        );

        Speakeasy does not model the state of services. Each service is SERVICE_RUNNING.
        """
        hService, lpServiceStatus = argv

        if not hService:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        if lpServiceStatus:
            service_status = (
                (0x10).to_bytes(4, "little")
                + (0x4).to_bytes(4, "little")
                + (0x1).to_bytes(4, "little")
                + (0x0).to_bytes(4, "little")
                + (0x0).to_bytes(4, "little")
                + (0x0).to_bytes(4, "little")
                + (0x0).to_bytes(4, "little")
            )
            self.mem_write(lpServiceStatus, service_status)

        emu.set_last_error(windefs.ERROR_SUCCESS)
        return 1

    @apihook("QueryServiceConfig", argc=4)
    def QueryServiceConfig(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL QueryServiceConfig(
            SC_HANDLE hService,
            LPQUERY_SERVICE_CONFIG lpServiceConfig,
            DWORD cbBufSize,
            LPDWORD pcbBytesNeeded
        );
        """
        hService, lpServiceConfig, cbBufSize, pcbBytesNeeded = argv

        if not hService:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        ptr_size = self.get_ptr_size()
        required = (4 * 4) + (5 * ptr_size)

        if pcbBytesNeeded:
            self.write_dword(pcbBytesNeeded, required)

        if not lpServiceConfig or cbBufSize < required:
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
            return 0

        buf = bytearray()
        buf.extend((0x10).to_bytes(4, "little"))
        buf.extend((0x2).to_bytes(4, "little"))
        buf.extend((0x1).to_bytes(4, "little"))
        buf.extend((0).to_bytes(ptr_size, "little"))
        buf.extend((0).to_bytes(ptr_size, "little"))
        buf.extend((0).to_bytes(4, "little"))
        buf.extend((0).to_bytes(ptr_size, "little"))
        buf.extend((0).to_bytes(ptr_size, "little"))
        buf.extend((0).to_bytes(ptr_size, "little"))

        self.mem_write(lpServiceConfig, bytes(buf))
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return 1

    @apihook("CloseServiceHandle", argc=1)
    def CloseServiceHandle(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CloseServiceHandle(
            SC_HANDLE hSCObject
        );

        Speakeasy does not model the state of services, so it does not free the handle. A free with mem_free would
        free any guest allocation that contains the value.
        """
        rv = 1

        emu.set_last_error(windefs.ERROR_SUCCESS)

        return rv

    @apihook("ChangeServiceConfig", argc=11)
    def ChangeServiceConfig(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL ChangeServiceConfig(
            SC_HANDLE hService,
            DWORD dwServiceType,
            DWORD dwStartType,
            DWORD dwErrorControl,
            LPCTSTR lpBinaryPathName,
            LPCTSTR lpLoadOrderGroup,
            LPDWORD lpdwTagId,
            LPCTSTR lpDependencies,
            LPCTSTR lpServiceStartName,
            LPCTSTR lpPassword,
            LPCTSTR lpDisplayName
        );
        """
        (
            hService,
            dwServiceType,
            dwStartType,
            dwErrorControl,
            lpBinaryPathName,
            lpLoadOrderGroup,
            lpdwTagId,
            lpDependencies,
            lpServiceStartName,
            lpPassword,
            lpDisplayName,
        ) = argv

        cw = self.get_char_width(ctx)

        if lpBinaryPathName:
            ctx.args["lpBinaryPathName"].display = self.read_mem_string(lpBinaryPathName, cw)
        if lpLoadOrderGroup:
            ctx.args["lpLoadOrderGroup"].display = self.read_mem_string(lpLoadOrderGroup, cw)
        if lpDependencies:
            ctx.args["lpDependencies"].display = self.read_mem_string(lpDependencies, cw)
        if lpServiceStartName:
            ctx.args["lpServiceStartName"].display = self.read_mem_string(lpServiceStartName, cw)
        if lpPassword:
            ctx.args["lpPassword"].display = self.read_mem_string(lpPassword, cw)
        if lpDisplayName:
            ctx.args["lpDisplayName"].display = self.read_mem_string(lpDisplayName, cw)

        emu.set_last_error(windefs.ERROR_SUCCESS)
        return 1

    @apihook("ChangeServiceConfig2", argc=3)
    def ChangeServiceConfig2(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL ChangeServiceConfig2(
            SC_HANDLE hService,
            DWORD dwInfoLevel,
            LPVOID lpInfo
        );
        """
        hService, dwInfoLevel, lpInfo = argv

        rv = 1

        emu.set_last_error(windefs.ERROR_SUCCESS)

        return rv

    @apihook("SystemFunction036", argc=2)
    def RtlGenRandom(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLEAN SystemFunction036(
            PVOID RandomBuffer,
            ULONG RandomBufferLength
        );

        Exported as RtlGenRandom.
        """
        RandomBuffer, RandomBufferLength = argv

        rv = False
        if RandomBuffer and RandomBufferLength:
            self.mem_write(RandomBuffer, emu.rng.randbytes(RandomBufferLength))
            rv = True

        return rv

    @apihook("CryptAcquireContext", argc=5)
    def CryptAcquireContext(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CryptAcquireContext(
            HCRYPTPROV *phProv,
            LPCTSTR szContainer,
            LPCTSTR szProvider,
            DWORD dwProvType,
            DWORD dwFlags
        );
        """
        phProv, szContainer, szProvider, dwProvType, dwFlags = argv
        cont_str, prov_str = "", ""
        cw = self.get_char_width(ctx)
        rv = False

        if szContainer:
            cont_str = self.read_mem_string(szContainer, cw)
            ctx.args["szContainer"].display = cont_str
        if szProvider:
            prov_str = self.read_mem_string(szProvider, cw)
            ctx.args["szProvider"].display = prov_str

        cm = emu.get_crypt_manager()
        hnd = cm.crypt_open(cname=cont_str, pname=prov_str, ptype=dwProvType, flags=dwFlags)

        if hnd and phProv:
            self.write_ptr(phProv, hnd)
            rv = True
            emu.set_last_error(windefs.ERROR_SUCCESS)

        return rv

    @apihook("CryptGenRandom", argc=3)
    def CryptGenRandom(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CryptGenRandom(
            HCRYPTPROV hProv,
            DWORD dwLen,
            BYTE *pbBuffer
        );
        """
        hProv, dwLen, pbBuffer = argv
        rv = False

        if pbBuffer:
            self.mem_write(pbBuffer, emu.rng.randbytes(dwLen))
            rv = True

        return rv

    @apihook("AllocateAndInitializeSid", argc=11)
    def AllocateAndInitializeSid(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL AllocateAndInitializeSid(
            PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
            BYTE nSubAuthorityCount,
            DWORD nSubAuthority0,
            DWORD nSubAuthority1,
            DWORD nSubAuthority2,
            DWORD nSubAuthority3,
            DWORD nSubAuthority4,
            DWORD nSubAuthority5,
            DWORD nSubAuthority6,
            DWORD nSubAuthority7,
            PSID *pSid
        );
        """
        pIdentifierAuthority, nSubAuthorityCount, *subauthorities, pSid = argv
        nSubAuthorityCount &= 0xFF
        if not pSid or not pIdentifierAuthority or nSubAuthorityCount > 8:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return False

        sid = self.mem_alloc(0x100, tag="api.struct.SID")
        data = bytes([1, nSubAuthorityCount]) + self.mem_read(pIdentifierAuthority, 6)
        data += b"".join((sa & 0xFFFFFFFF).to_bytes(4, "little") for sa in subauthorities[:nSubAuthorityCount])
        self.mem_write(sid, data)
        self.write_ptr(pSid, sid)
        return True

    @apihook("InitializeSid", argc=3)
    def InitializeSid(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL InitializeSid(
            PSID Sid,
            PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
            BYTE nSubAuthorityCount
        );
        """
        Sid, pIdentifierAuthority, nSubAuthorityCount = argv
        nSubAuthorityCount &= 0xFF
        if not Sid or not pIdentifierAuthority or nSubAuthorityCount > 15:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return False
        self.mem_write(Sid, bytes([1, nSubAuthorityCount]) + self.mem_read(pIdentifierAuthority, 6))
        return True

    @apihook("GetSidLengthRequired", argc=1)
    def GetSidLengthRequired(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetSidLengthRequired(
            UCHAR nSubAuthorityCount
        );
        """
        (nSubAuthorityCount,) = argv
        return 8 + 4 * (nSubAuthorityCount & 0xFF)

    def get_sid_length(self, emu, sid):
        if not sid or not emu.is_address_valid(sid + 1):
            return 0
        return 8 + 4 * self.mem_read(sid + 1, 1)[0]

    @apihook("GetLengthSid", argc=1)
    def GetLengthSid(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetLengthSid(
            PSID pSid
        );
        """
        (pSid,) = argv
        return self.get_sid_length(emu, pSid)

    @apihook("IsValidSid", argc=1)
    def IsValidSid(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL IsValidSid(
            PSID pSid
        );
        """
        (pSid,) = argv
        if not self.get_sid_length(emu, pSid):
            return False
        revision, count = self.mem_read(pSid, 2)
        return revision == 1 and count <= 15

    @apihook("CopySid", argc=3)
    def CopySid(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CopySid(
            DWORD nDestinationSidLength,
            PSID pDestinationSid,
            PSID pSourceSid
        );
        """
        nDestinationSidLength, pDestinationSid, pSourceSid = argv
        size = self.get_sid_length(emu, pSourceSid)
        if not size:
            emu.set_last_error(windefs.ERROR_INVALID_SID)
            return False
        if nDestinationSidLength < size:
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
            return False
        self.mem_write(pDestinationSid, self.mem_read(pSourceSid, size))
        return True

    @apihook("CheckTokenMembership", argc=3)
    def CheckTokenMembership(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CheckTokenMembership(
            HANDLE TokenHandle,
            PSID SidToCheck,
            PBOOL IsMember
        );
        """
        TokenHandle, SidToCheck, IsMember = argv
        rv = False

        if IsMember:
            self.write_dword(IsMember, 1)
            rv = True
        return rv

    @apihook("FreeSid", argc=1)
    def FreeSid(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PVOID FreeSid(
            PSID pSid
        );
        """
        (pSid,) = argv
        rv = pSid

        if pSid:
            self.mem_free(pSid)
            rv = 0
        return rv

    @apihook("GetSecurityInfo", argc=8)
    def GetSecurityInfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetSecurityInfo(
            HANDLE handle,
            SE_OBJECT_TYPE ObjectType,
            SECURITY_INFORMATION SecurityInfo,
            PSID *ppsidOwner,
            PSID *ppsidGroup,
            PACL *ppDacl,
            PACL *ppSacl,
            PSECURITY_DESCRIPTOR *ppSecurityDescriptor
        );
        """
        handle = argv[0]
        if not handle:
            return windefs.ERROR_INVALID_HANDLE
        # Objects carry no security descriptor, so every requested part is NULL
        for out in argv[3:]:
            if out:
                self.mem_write(out, b"\x00" * self.get_ptr_size())
        return windefs.ERROR_SUCCESS

    @apihook("SetSecurityInfo", argc=7)
    def SetSecurityInfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD SetSecurityInfo(
            HANDLE handle,
            SE_OBJECT_TYPE ObjectType,
            SECURITY_INFORMATION SecurityInfo,
            PSID psidOwner,
            PSID psidGroup,
            PACL pDacl,
            PACL pSacl
        );
        """
        handle = argv[0]
        if not handle:
            return windefs.ERROR_INVALID_HANDLE
        return windefs.ERROR_SUCCESS

    @apihook("CryptReleaseContext", argc=2)
    def CryptReleaseContext(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CryptReleaseContext(
            HCRYPTPROV hProv,
            DWORD dwFlags
        );
        """
        hProv, dwFlags = argv
        rv = True

        if not emu.get_crypt_manager().crypt_close(hProv):
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return False

        return rv

    @apihook("GetCurrentHwProfile", argc=1)
    def GetCurrentHwProfile(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetCurrentHwProfile(
            LPHW_PROFILE_INFO lpHwProfileInfo
        );
        """
        (lpHwProfileInfo,) = argv

        if not lpHwProfileInfo:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
            return 0

        cw = self.get_char_width(ctx)
        guid = "{00000000-0000-0000-0000-000000000000}"
        profile_name = "Speakeasy HW Profile"

        if cw == 2:
            guid_bytes = (guid + "\x00").encode("utf-16le")
            name_bytes = (profile_name + "\x00").encode("utf-16le")
            guid_bytes = guid_bytes.ljust(39 * 2, b"\x00")[: 39 * 2]
            name_bytes = name_bytes.ljust(80 * 2, b"\x00")[: 80 * 2]
        else:
            guid_bytes = encode_ansi(guid + "\x00")
            name_bytes = encode_ansi(profile_name + "\x00")
            guid_bytes = guid_bytes.ljust(39, b"\x00")[:39]
            name_bytes = name_bytes.ljust(80, b"\x00")[:80]

        out = (0).to_bytes(4, "little") + guid_bytes + name_bytes
        self.mem_write(lpHwProfileInfo, out)
        emu.set_last_error(windefs.ERROR_SUCCESS)
        return 1

    @apihook("GetUserName", argc=2)
    def GetUserName(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetUserName(
            LPTSTR lpBuffer,
            LPDWORD pcbBuffer
        );
        """
        lpBuffer, pcbBuffer = argv
        rv = False
        cw = self.get_char_width(ctx)

        user_name = emu.config.user.name
        ctx.args["lpBuffer"].display = user_name

        need = len(user_name) + 1
        size = self.read_dword(pcbBuffer) if pcbBuffer else 0
        if pcbBuffer:
            self.write_dword(pcbBuffer, need)
        if not lpBuffer or size < need:
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
            return rv

        self.write_mem_string(user_name, lpBuffer, cw)
        rv = True

        return rv

    @apihook("LookupPrivilegeValue", argc=3)
    def LookupPrivilegeValue(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL LookupPrivilegeValue(
            LPCTSTR lpSystemName,
            LPCTSTR lpName,
            PLUID lpLuid
        );
        """
        lpSystemName, lpName, lpLuid = argv
        rv = False
        cw = self.get_char_width(ctx)

        if lpSystemName:
            ctx.args["lpSystemName"].display = self.read_mem_string(lpSystemName, cw)
        if lpName:
            ctx.args["lpName"].display = self.read_mem_string(lpName, cw)
            rv = True

        return rv

    @apihook("AdjustTokenPrivileges", argc=6)
    def AdjustTokenPrivileges(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL AdjustTokenPrivileges(
            HANDLE TokenHandle,
            BOOL DisableAllPrivileges,
            PTOKEN_PRIVILEGES NewState,
            DWORD BufferLength,
            PTOKEN_PRIVILEGES PreviousState,
            PDWORD ReturnLength
        );
        """
        rv = True

        return rv

    @apihook("GetTokenInformation", argc=5)
    def GetTokenInformation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetTokenInformation(
            HANDLE TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            LPVOID TokenInformation,
            DWORD TokenInformationLength,
            PDWORD ReturnLength
        );
        """
        TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength = argv

        status, size = query_token_information(
            self, emu, TokenInformationClass, TokenInformation, TokenInformationLength
        )
        if ReturnLength:
            self.write_dword(ReturnLength, size)
        if status == ddk.STATUS_SUCCESS:
            return True
        emu.set_last_error(TOKEN_QUERY_ERRORS[status])
        return False

    @apihook("ConvertSidToStringSid", argc=2)
    def ConvertSidToStringSid(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL ConvertSidToStringSid(
            PSID Sid,
            LPTSTR *StringSid
        );
        """
        Sid, StringSid = argv
        length = self.get_sid_length(emu, Sid)
        if not length or not StringSid:
            emu.set_last_error(windefs.ERROR_INVALID_SID if not length else windefs.ERROR_INVALID_PARAMETER)
            return False

        data = self.mem_read(Sid, length)
        subauthorities = struct.unpack_from(f"<{data[1]}I", data, 8)
        text = "-".join(["S", str(data[0]), str(int.from_bytes(data[2:8], "big")), *map(str, subauthorities)])
        cw = self.get_char_width(ctx)
        buf = self.heap_alloc((len(text) + 1) * cw, heap="LocalAlloc")
        self.write_mem_string(text, buf, cw)
        self.write_ptr(StringSid, buf)
        ctx.args["Sid"].display = text
        return True

    @apihook("EqualSid", argc=2)
    def EqualSid(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EqualSid(
            PSID pSid1,
            PSID pSid2
        );
        """
        pSid1, pSid2 = argv
        len1, len2 = self.get_sid_length(emu, pSid1), self.get_sid_length(emu, pSid2)
        if not len1 or len1 != len2:
            return False
        return self.mem_read(pSid1, len1) == self.mem_read(pSid2, len2)

    @apihook("GetSidIdentifierAuthority", argc=1)
    def GetSidIdentifierAuthority(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PSID_IDENTIFIER_AUTHORITY GetSidIdentifierAuthority(
            PSID pSid
        );
        """
        (pSid,) = argv

        # IdentifierAuthority is at offset 0x02 in the SID structure
        return pSid + 2

    @apihook("GetSidSubAuthorityCount", argc=1)
    def GetSidSubAuthorityCount(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PUCHAR GetSidSubAuthorityCount(
            PSID pSid
        );
        """
        (pSid,) = argv
        rv = 0

        if pSid:
            rv = pSid + 1

        return rv

    @apihook("GetSidSubAuthority", argc=2)
    def GetSidSubAuthority(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PDWORD GetSidSubAuthority(
            PSID pSid,
            DWORD nSubAuthority
        );
        """
        pSid, nSubAuthority = argv

        # SubAuthorities begin at offset 0x8
        return pSid + 8 + (nSubAuthority * 4)

    @apihook("LookupAccountName", argc=7)
    def LookupAccountName(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL LookupAccountName(
            LPCTSTR lpSystemName,
            LPCTSTR lpAccountName,
            PSID Sid,
            LPDWORD cbSid,
            LPTSTR ReferencedDomainName,
            LPDWORD cchReferencedDomainName,
            PSID_NAME_USE peUse
        );
        """
        lpSystemName, lpAccountName, Sid, cbSid, ReferencedDomainName, cchReferencedDomainName, peUse = argv
        rv = 0

        cw = self.get_char_width(ctx)

        if lpSystemName:
            sn = self.read_mem_string(lpSystemName, cw)
            ctx.args["lpSystemName"].display = sn

        if not lpAccountName:
            return rv

        acctname = self.read_mem_string(lpAccountName, cw)
        ctx.args["lpAccountName"].display = acctname

        user = emu.config.user.name
        # Currently only supporting user SIDs specified in the config
        if user != acctname:
            return rv

        str_sid = emu.config.user.sid
        if not str_sid:
            return rv

        ctx.args["Sid"].display = str_sid
        sid_struct = windefs.convert_sid_str_to_struct(emu.get_ptr_size(), str_sid)
        side_struct_size = sid_struct.sizeof()

        cbsid = self.mem_read(cbSid, 4)
        cbsid = int.from_bytes(cbsid, "little")
        ctx.args["cbSid"].display = hex(cbsid)

        domain = emu.config.system.domain or ""
        cchdomname = self.mem_read(cchReferencedDomainName, 4)
        cbcchdomname = int.from_bytes(cchdomname, "little")
        ctx.args["cchReferencedDomainName"].display = hex(cbcchdomname)

        if not Sid or cbsid < side_struct_size or not ReferencedDomainName or cbcchdomname < len(domain) + 1:
            self.write_dword(cbSid, side_struct_size)
            self.write_dword(cchReferencedDomainName, len(domain) + 1)
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
            return rv

        rv = 1

        self.mem_write(Sid, self.get_bytes(sid_struct))

        self.write_mem_string(domain, ReferencedDomainName, cw)
        self.write_dword(cchReferencedDomainName, len(domain))
        ctx.args["ReferencedDomainName"].display = domain

        # Currently only supporting user SIDs (SidTypeUser = 1)
        self.write_dword(peUse, 1)
        ctx.args["peUse"].display = hex(1)

        return rv

    @apihook("LookupAccountSid", argc=7)
    def LookupAccountSid(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL LookupAccountSid(
            LPCTSTR lpSystemName,
            PSID Sid,
            LPTSTR Name,
            LPDWORD cchName,
            LPTSTR ReferencedDomainName,
            LPDWORD cchReferencedDomainName,
            PSID_NAME_USE peUse
        );
        """
        lpSystemName, Sid, Name, cchName, ReferencedDomainName, cchReferencedDomainName, peUse = argv
        rv = False

        cw = self.get_char_width(ctx)

        if lpSystemName:
            sn = self.read_mem_string(lpSystemName, cw)
            ctx.args["lpSystemName"].display = sn

        if not cchName or not cchReferencedDomainName:
            return rv

        name_size = self.mem_read(cchName, 4)
        name_size = int.from_bytes(name_size, "little")

        dom_size = self.mem_read(cchReferencedDomainName, 4)
        dom_size = int.from_bytes(dom_size, "little")

        user, domain = "myuser", "mydomain"
        if not Name or not ReferencedDomainName or name_size < len(user) + 1 or dom_size < len(domain) + 1:
            self.write_dword(cchName, len(user) + 1)
            self.write_dword(cchReferencedDomainName, len(domain) + 1)
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
            return rv

        self.write_mem_string(user, Name, cw)
        self.write_mem_string(domain, ReferencedDomainName, cw)
        self.write_dword(cchName, len(user))
        self.write_dword(cchReferencedDomainName, len(domain))
        if peUse:
            self.write_dword(peUse, 1)
        rv = True

        return rv

    @apihook("CreateProcessAsUser", argc=11, conv=_arch.CALL_CONV_STDCALL)
    def CreateProcessAsUser(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CreateProcessAsUser(
            HANDLE hToken,
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
            hToken,
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
        _pi.dwProcessId = proc.pid
        _pi.dwThreadId = thread.tid

        self.mem_write(lpProcessInformation, self.get_bytes(data))

        rv = 1

        self.record_process_event(proc, EventType.PROCESS_CREATE)
        return rv

    @apihook("CryptCreateHash", argc=5)
    def CryptCreateHash(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CryptCreateHash(
            HCRYPTPROV hProv,
            ALG_ID Algid,
            HCRYPTKEY hKey,
            DWORD dwFlags,
            HCRYPTHASH *phHash
        );
        """
        hash_algs = {
            0x00008004: ("CALG_SHA1", hashlib.sha1),
            0x0000800C: ("CALG_SHA_256", hashlib.sha256),
            0x0000800D: ("CALG_SHA_384", hashlib.sha384),
            0x0000800E: ("CALG_SHA_512", hashlib.sha512),
            0x00008003: ("CALG_MD5", hashlib.md5),
        }

        hProv, Algid, hKey, dwFlags, phHash = argv
        if Algid in hash_algs:
            ctx.args["Algid"].display = hash_algs[Algid][0]

        if hKey != 0:
            return 0

        if Algid not in hash_algs:
            emu.set_last_error(adv32defs.NTE_BAD_ALGID)
            return 0

        hnd = emu.get_crypt_manager().create_hash(hash_algs[Algid][1]())
        self.write_ptr(phHash, hnd)
        return 1

    @apihook("CryptHashData", argc=4)
    def CryptHashData(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CryptHashData(
            HCRYPTHASH hHash,
            const BYTE *pbData,
            DWORD dwDataLen,
            DWORD dwFlags
        );
        """
        hHash, pbData, dwDataLen, dwFlags = argv
        hnd = emu.get_crypt_manager().get_hash(hHash)
        if hnd is None:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        if dwDataLen == 0:
            return 1

        data = self.mem_read(pbData, dwDataLen)
        hnd.update(data)
        return 1

    @apihook("CryptGetHashParam", argc=5)
    def CryptGetHashParam(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CryptGetHashParam(
            HCRYPTHASH hHash,
            DWORD dwParam,
            BYTE *pbData,
            DWORD *pdwDataLen,
            DWORD dwFlags
        );
        """
        hHash, dwParam, pbData, pdwDataLen, dwFlags = argv

        param_enums = {1: "HP_ALGID", 2: "HP_HASHVAL", 4: "HP_HASHSIZE", 5: "HP_HMAC_INFO"}

        if dwParam in param_enums.keys():
            ctx.args["dwParam"].display = param_enums[dwParam]

        hnd = emu.get_crypt_manager().get_hash(hHash)
        if hnd is None:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        if dwParam == adv32defs.HP_HASHVAL:
            value = hnd.digest()
        elif dwParam == adv32defs.HP_HASHSIZE:
            value = hnd.digest_size.to_bytes(4, "little")
        else:
            return 1

        size = self.read_dword(pdwDataLen)
        self.write_dword(pdwDataLen, len(value))
        if not pbData:
            return 1
        if size < len(value):
            emu.set_last_error(windefs.ERROR_MORE_DATA)
            return 0
        self.mem_write(pbData, value)
        return 1

    def get_md5_context(self, ctx_addr):
        md5 = self.md5_contexts.get(ctx_addr)
        if md5 is None:
            md5 = self.md5_contexts[ctx_addr] = hashlib.md5()
        return md5

    @apihook("MD5Init", argc=1)
    def MD5Init(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void MD5Init(
            MD5_CTX *context
        );
        """
        (context,) = argv
        self.md5_contexts[context] = hashlib.md5()
        self.mem_write(context, struct.pack("<2I4I", 0, 0, *MD5_INITIAL_STATE) + b"\x00" * 80)

    @apihook("MD5Update", argc=3)
    def MD5Update(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void MD5Update(
            MD5_CTX *context,
            const unsigned char *input,
            unsigned int inlen
        );

        Write the bit count and the input buffer into the context. The
        handler keeps the hash state in a hashlib object.
        """
        context, input, inlen = argv
        bits = int.from_bytes(self.mem_read(context, 8), "little")
        block = self.mem_read(input, inlen) if inlen else b""
        self.get_md5_context(context).update(block)
        buffered = bits // 8 % 64
        pending = (self.mem_read(context + 24, buffered) if buffered else b"") + block
        partial = pending[len(pending) - (bits // 8 + inlen) % 64 :]
        self.write_qword(context, (bits + inlen * 8) & 0xFFFFFFFFFFFFFFFF)
        self.mem_write(context + 24, partial)

    @apihook("MD5Final", argc=1)
    def MD5Final(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void MD5Final(
            MD5_CTX *context
        );

        Write the digest into the buf and digest members of the context.
        """
        (context,) = argv
        digest = self.get_md5_context(context).digest()
        self.mem_write(context + 8, digest)
        self.mem_write(context + 88, digest)
        self.md5_contexts.pop(context, None)

    @apihook("CryptDestroyHash", argc=1)
    def CryptDestroyHash(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CryptDestroyHash(
            HCRYPTHASH hHash
        );

        Speakeasy does not model the lifetime of hash objects, so the handle stays valid.
        """
        return 1

    @apihook("CryptDeriveKey", argc=5)
    def CryptDeriveKey(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CryptDeriveKey(
            HCRYPTPROV hProv,
            ALG_ID Algid,
            HCRYPTHASH hBaseData,
            DWORD dwFlags,
            HCRYPTKEY *phKey
        );

        Derive RC4 keys only.
        """
        hProv, Algid, hBaseData, dwFlags, phKey = argv

        if Algid != adv32defs.CALG_RC4:
            emu.set_last_error(adv32defs.NTE_BAD_ALGID)
            return 0

        cm = emu.get_crypt_manager()
        prov = cm.get_context(hProv)
        hnd = cm.get_hash(hBaseData)
        if prov is None or hnd is None:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        # The upper 16 bits of dwFlags give the key length in bits.
        digest = hnd.digest()
        key_bits = dwFlags >> 16 or prov.get_default_rc4_bits()
        secret = digest[: key_bits // 8] if 40 < key_bits <= len(digest) * 8 else digest[:5]
        self.write_ptr(phKey, prov.add_key(CryptoApiKey(prov, Algid, dwFlags, secret=secret)))
        return 1

    @apihook("CryptImportKey", argc=6)
    def CryptImportKey(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CryptImportKey(
            HCRYPTPROV hProv,
            const BYTE *pbData,
            DWORD dwDataLen,
            HCRYPTKEY hPubKey,
            DWORD dwFlags,
            HCRYPTKEY *phKey
        );
        """
        hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey = argv
        dwDataLen &= 0xFFFFFFFF

        prov = emu.get_crypt_manager().get_context(hProv)
        if prov is None:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        blob = self.mem_read(pbData, dwDataLen) if dwDataLen else b""
        try:
            key = CryptoApiKey.from_blob(prov, blob, dwFlags)
        except CryptoApiError as e:
            emu.set_last_error(e.code)
            return 0
        self.write_ptr(phKey, prov.add_key(key))
        return 1

    @apihook("CryptGenKey", argc=4)
    def CryptGenKey(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CryptGenKey(
            HCRYPTPROV hProv,
            ALG_ID Algid,
            DWORD dwFlags,
            HCRYPTKEY *phKey
        );

        The key bytes come from the random number generator of the emulator.
        """
        hProv, Algid, dwFlags, phKey = argv

        prov = emu.get_crypt_manager().get_context(hProv)
        if prov is None:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        try:
            key = CryptoApiKey.from_random(prov, Algid, dwFlags, emu.rng.randbytes)
        except CryptoApiError as e:
            emu.set_last_error(e.code)
            return 0
        self.write_ptr(phKey, prov.add_key(key))
        return 1

    @apihook("CryptExportKey", argc=6)
    def CryptExportKey(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CryptExportKey(
            HCRYPTKEY hKey,
            HCRYPTKEY hExpKey,
            DWORD dwBlobType,
            DWORD dwFlags,
            BYTE *pbData,
            DWORD *pdwDataLen
        );
        """
        hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen = argv

        key = emu.get_crypt_manager().get_crypto_api_key(hKey)
        if key is None:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        try:
            blob = key.get_blob(dwBlobType)
        except CryptoApiError as e:
            emu.set_last_error(e.code)
            return 0

        size = self.read_dword(pdwDataLen)
        self.write_dword(pdwDataLen, len(blob))
        if not pbData:
            return 1
        if size < len(blob):
            emu.set_last_error(windefs.ERROR_MORE_DATA)
            return 0
        self.mem_write(pbData, blob)
        return 1

    @apihook("CryptSetKeyParam", argc=4)
    def CryptSetKeyParam(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CryptSetKeyParam(
            HCRYPTKEY hKey,
            DWORD dwParam,
            const BYTE *pbData,
            DWORD dwFlags
        );

        Set KP_IV, KP_MODE and KP_PADDING. Other parameters do not change the key.
        """
        hKey, dwParam, pbData, dwFlags = argv

        key = emu.get_crypt_manager().get_crypto_api_key(hKey)
        if key is None:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        if dwParam == adv32defs.KP_IV:
            key.iv = self.mem_read(pbData, key.block_len) if key.block_len else b""
        elif dwParam == adv32defs.KP_MODE:
            mode = self.read_dword(pbData)
            if mode not in CIPHER_MODES:
                emu.set_last_error(adv32defs.NTE_BAD_DATA)
                return 0
            key.mode = mode
        elif dwParam == adv32defs.KP_PADDING and self.read_dword(pbData) != adv32defs.PKCS5_PADDING:
            emu.set_last_error(adv32defs.NTE_BAD_DATA)
            return 0
        else:
            return 1
        key.reset()
        return 1

    @apihook("CryptEncrypt", argc=7)
    def CryptEncrypt(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CryptEncrypt(
            HCRYPTKEY hKey,
            HCRYPTHASH hHash,
            BOOL Final,
            DWORD dwFlags,
            BYTE *pbData,
            DWORD *pdwDataLen,
            DWORD dwBufLen
        );
        """
        hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen = argv
        dwBufLen &= 0xFFFFFFFF
        final = bool(Final & 0xFFFFFFFF)

        cm = emu.get_crypt_manager()
        key = cm.get_crypto_api_key(hKey)
        hnd = cm.get_hash(hHash) if hHash else None
        if key is None or (hHash and hnd is None):
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        size = self.read_dword(pdwDataLen)
        try:
            out_size = key.get_encrypted_size(size, final)
            if not pbData:
                self.write_dword(pdwDataLen, out_size)
                return 1
            if dwBufLen < out_size:
                self.write_dword(pdwDataLen, out_size)
                emu.set_last_error(windefs.ERROR_MORE_DATA)
                return 0
            data = self.mem_read(pbData, size) if size else b""
            out = key.encrypt(data, final, emu.rng.randbytes)
        except CryptoApiError as e:
            emu.set_last_error(e.code)
            return 0

        if hnd is not None:
            hnd.update(data)
        ctx.args["pbData"].display = base64.b64encode(data).decode("utf-8")
        if out:
            self.mem_write(pbData, out)
        self.write_dword(pdwDataLen, len(out))
        return 1

    @apihook("CryptDecrypt", argc=6)
    def CryptDecrypt(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CryptDecrypt(
            HCRYPTKEY hKey,
            HCRYPTHASH hHash,
            BOOL Final,
            DWORD dwFlags,
            BYTE *pbData,
            DWORD *pdwDataLen
        );
        """
        hKey, hHash, Final, dwFlags, pbData, pdwDataLen = argv
        final = bool(Final & 0xFFFFFFFF)

        cm = emu.get_crypt_manager()
        key = cm.get_crypto_api_key(hKey)
        hnd = cm.get_hash(hHash) if hHash else None
        if key is None or (hHash and hnd is None):
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        size = self.read_dword(pdwDataLen)
        data = self.mem_read(pbData, size) if size else b""
        try:
            out = key.decrypt(data, final)
        except CryptoApiError as e:
            emu.set_last_error(e.code)
            return 0

        if hnd is not None:
            hnd.update(out)
        ctx.args["pbData"].display = base64.b64encode(out).decode("utf-8")
        if out:
            self.mem_write(pbData, out)
        self.write_dword(pdwDataLen, len(out))
        return 1

    @apihook("CryptDestroyKey", argc=1)
    def CryptDestroyKey(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL CryptDestroyKey(
            HCRYPTKEY hKey
        );
        """
        (hKey,) = argv
        if not emu.get_crypt_manager().destroy_crypto_api_key(hKey):
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0
        return 1

    @apihook("RegGetValue", argc=7, conv=_arch.CALL_CONV_STDCALL)
    def RegGetValue(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        LSTATUS RegGetValue(
            HKEY hkey,
            LPCTSTR lpSubKey,
            LPCTSTR lpValue,
            DWORD dwFlags,
            LPDWORD pdwType,
            PVOID pvData,
            LPDWORD pcbData
        );
        """
        lpSubKey: int | str
        hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData = argv
        rv = windefs.ERROR_SUCCESS

        cw = self.get_char_width(ctx)
        if lpSubKey:
            lpSubKey = self.read_mem_string(lpSubKey, cw)
            ctx.args["lpSubKey"].display = lpSubKey

        value_name = ""
        if lpValue:
            value_name = self.read_mem_string(lpValue, cw)
            ctx.args["lpValue"].display = value_name

        length = 0
        if pcbData:
            length = self.mem_read(pcbData, 4)
            length = int.from_bytes(length, "little")

        key = self.get_reg_key(hkey)
        if not key:
            return windefs.ERROR_INVALID_HANDLE
        hnd = hkey
        if lpSubKey:
            hnd = self.reg_open_key(key.get_path() + "\\" + lpSubKey)
            if not hnd:
                return windefs.ERROR_FILE_NOT_FOUND
            key = self.get_reg_key(hnd)
        if key:
            val = emu.regman.read_value(key, value_name, cw, handle=hnd, buffer=pvData, size=length)
            if val:
                self.write_value_type(val, pdwType, ctx.args["pdwType"])
                output = val.get_bytes(cw)
                if pcbData:
                    self.write_dword(pcbData, len(output))
                if pvData:
                    if not pcbData:
                        rv = windefs.ERROR_INVALID_PARAMETER
                    elif len(output) > length:
                        rv = windefs.ERROR_MORE_DATA
                    else:
                        self.mem_write(pvData, output)

            # For now, return an empty buffer
            else:
                output = b"\x00" * length
                if pvData:
                    self.mem_write(pvData, output)
                rv = windefs.ERROR_SUCCESS

        return rv

    @apihook("EnumServicesStatus", argc=8, conv=_arch.CALL_CONV_STDCALL)
    def EnumServicesStatus(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL EnumServicesStatus(
            SC_HANDLE hSCManager,
            DWORD dwServiceType,
            DWORD dwServiceState,
            LPENUM_SERVICE_STATUS lpServices,
            DWORD cbBufSize,
            LPDWORD pcbBytesNeeded,
            LPDWORD lpServicesReturned,
            LPDWORD lpResumeHandle
        );
        """
        (
            hSCManager,
            dwServiceType,
            dwServiceState,
            lpServices,
            cbBufSize,
            pcbBytesNeeded,
            lpServicesReturned,
            lpResumeHandle,
        ) = argv

        ctx.args["dwServiceType"].display = decode(ENUM_SERVICE_TYPE, dwServiceType)
        ctx.args["dwServiceState"].display = decode(ENUM_SERVICE_STATE, dwServiceState)

        cw = self.get_char_width(ctx)
        ptr_size = emu.get_ptr_size()
        entry_size = (2 * ptr_size + 28 + ptr_size - 1) & ~(ptr_size - 1)
        services = [
            service
            for service in adv32defs.EMULATED_SERVICES
            if service[2] & dwServiceType
            and dwServiceState
            & (
                ENUM_SERVICE_STATE.SERVICE_ACTIVE
                if service[3] == SERVICE_STATUS_CURRENT_STATE.SERVICE_RUNNING
                else ENUM_SERVICE_STATE.SERVICE_INACTIVE
            )
        ]
        start = self.read_dword(lpResumeHandle) if lpResumeHandle else 0
        services = services[start:]

        def encode(text):
            return self.encode_string(text + "\0", cw)

        sizes = [entry_size + len(encode(name)) + len(encode(display)) for name, display, _, _ in services]
        count = 0
        while count < len(sizes) and sum(sizes[: count + 1]) <= cbBufSize:
            count += 1

        strings = lpServices + count * entry_size
        for index, (name, display, service_type, state) in enumerate(services[:count]):
            entry = bytearray(entry_size)
            for offset, text in ((0, name), (ptr_size, display)):
                data = encode(text)
                self.mem_write(strings, data)
                entry[offset : offset + ptr_size] = strings.to_bytes(ptr_size, "little")
                strings += len(data)
            accepted = adv32defs.SERVICE_ACCEPT_STOP if state == SERVICE_STATUS_CURRENT_STATE.SERVICE_RUNNING else 0
            struct.pack_into("<7I", entry, 2 * ptr_size, service_type, state, accepted, 0, 0, 0, 0)
            self.mem_write(lpServices + index * entry_size, bytes(entry))

        needed = sum(sizes[count:])
        for ptr, value in (
            (pcbBytesNeeded, needed),
            (lpServicesReturned, count),
            (lpResumeHandle, start + count if needed else 0),
        ):
            if ptr:
                self.write_dword(ptr, value)
        if needed:
            emu.set_last_error(windefs.ERROR_MORE_DATA)
            return 0
        return 1

    @apihook("OpenService", argc=3, conv=_arch.CALL_CONV_STDCALL)
    def OpenService(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SC_HANDLE OpenService(
            SC_HANDLE hSCManager,
            LPCTSTR lpServiceName,
            DWORD dwDesiredAccess
        );
        """
        hSCManager, lpServiceName, dwDesiredAccess = argv
        cw = self.get_char_width(ctx)
        svcname = self.read_mem_string(lpServiceName, cw)
        ctx.args["lpServiceName"].display = svcname
        return emu.handle_allocator.allocate_handle()

    @apihook("DeleteService", argc=1, conv=_arch.CALL_CONV_STDCALL)
    def DeleteService(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL DeleteService(
            SC_HANDLE hService
        );

        Speakeasy does not model the state of services. DeleteService only returns success.
        """
        return 1
