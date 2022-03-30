# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.registry.reg as regdefs
import speakeasy.winenv.defs.windows.windows as windefs

import speakeasy.winenv.defs.windows.kernel32 as k32
import speakeasy.winenv.defs.windows.advapi32 as adv32
import speakeasy.windows.objman as objman
from speakeasy.const import PROC_CREATE, REG_OPEN, REG_READ, REG_LIST, REG_CREATE

from .. import api
from Crypto.Cipher import ARC4
import hashlib

SERVICE_STATUS_HANDLE_BASE = 0x1000


class AdvApi32(api.ApiHandler):
    """
    Implements exported functions from advapi32.dll
    """

    name = 'advapi32'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super(AdvApi32, self).__init__(emu)
        self.funcs = {}
        self.data = {}
        self.hash_objects = {}
        self.key_objects = {}
        self.k32types = k32
        self.win = adv32
        self.curr_rand = 0
        self.curr_handle = 0x2800
        self.service_status_handle = SERVICE_STATUS_HANDLE_BASE

        self.rc4 = None

        super(AdvApi32, self).__get_hook_attrs__(self)

    def get_handle(self):
        self.curr_handle += 4
        return self.curr_handle

    @apihook('RegOpenKey', argc=3, conv=_arch.CALL_CONV_STDCALL)
    def RegOpenKey(self, emu, argv, ctx={}):
        '''
        LSTATUS RegOpenKeyA(
          HKEY   hKey,
          LPCSTR lpSubKey,
          PHKEY  phkResult
        );
        '''

        hKey, lpSubKey, phkResult = argv
        rv = windefs.ERROR_SUCCESS
        hnd = 0

        hkey_name = regdefs.get_hkey_type(hKey)
        if hkey_name:
            argv[0] = hkey_name
            if not hnd and not lpSubKey:
                hnd = hKey
        else:
            key_obj = emu.regman.get_key_from_handle(hKey)
            if not key_obj:
                return windefs.ERROR_PATH_NOT_FOUND
            hkey_name = key_obj.path

        cw = self.get_char_width(ctx)
        if lpSubKey:
            lpSubKey = self.read_mem_string(lpSubKey, cw)
            argv[1] = lpSubKey

            if hkey_name and lpSubKey:
                if not lpSubKey.startswith('\\'):
                    lpSubKey = '\\' + lpSubKey
                lpSubKey = hkey_name + lpSubKey

            hnd = self.reg_open_key(lpSubKey, create=False)
            if not hnd:
                rv = windefs.ERROR_PATH_NOT_FOUND

            self.log_registry_access(lpSubKey, REG_OPEN, handle=hnd)

        if phkResult and hnd:
            self.mem_write(phkResult, hnd.to_bytes(self.get_ptr_size(), 'little'))

        return rv

    @apihook('RegOpenKeyEx', argc=5, conv=_arch.CALL_CONV_STDCALL)
    def RegOpenKeyEx(self, emu, argv, ctx={}):
        '''
        LSTATUS RegOpenKeyEx(
          HKEY   hKey,
          LPTSTR lpSubKey,
          DWORD  ulOptions,
          REGSAM samDesired,
          PHKEY  phkResult
        );
        '''

        hKey, lpSubKey, ulOptions, samDesired, phkResult = argv
        rv = windefs.ERROR_SUCCESS

        hnd = 0

        hkey_name = regdefs.get_hkey_type(hKey)
        if hkey_name:
            argv[0] = hkey_name
            if not hnd and not lpSubKey:
                hnd = hKey

        cw = self.get_char_width(ctx)
        if lpSubKey:
            lpSubKey = self.read_mem_string(lpSubKey, cw)
            argv[1] = lpSubKey

            if hkey_name and lpSubKey:
                if not lpSubKey.startswith('\\'):
                    lpSubKey = '\\' + lpSubKey
                lpSubKey = hkey_name + lpSubKey

            hnd = self.reg_open_key(lpSubKey, create=False)
            if not hnd:
                rv = windefs.ERROR_PATH_NOT_FOUND

            self.log_registry_access(lpSubKey, REG_OPEN, handle=hnd)

        if phkResult and hnd:
            self.mem_write(phkResult, hnd.to_bytes(self.get_ptr_size(), 'little'))

        return rv

    @apihook('RegQueryValueEx', argc=6, conv=_arch.CALL_CONV_STDCALL)
    def RegQueryValueEx(self, emu, argv, ctx={}):
        '''
        LSTATUS RegQueryValueEx(
          HKEY    hKey,
          LPTSTR  lpValueName,
          LPDWORD lpReserved,
          LPDWORD lpType,
          LPBYTE  lpData,
          LPDWORD lpcbData
        );
        '''

        hKey, lpValueName, lpReserved, lpType, lpData, lpcbData = argv
        rv = windefs.ERROR_SUCCESS

        cw = self.get_char_width(ctx)
        if lpValueName:
            lpValueName = self.read_mem_string(lpValueName, cw)
            argv[1] = lpValueName

        type_name = regdefs.get_value_type(lpType)
        if type_name:
            argv[3] = type_name

        length = 0
        if lpcbData:
            length = self.mem_read(lpcbData, 4)
            length = int.from_bytes(length, 'little')
            argv[5] = length

        key = self.reg_get_key(hKey)
        if key:
            val = key.get_value(lpValueName)
            if val:
                output = b''
                typ = val.get_type()
                data = val.get_data()
                if typ == 'REG_SZ':
                    output = data.encode('utf-8')

                if lpcbData:
                    self.mem_write(lpcbData, len(output).to_bytes(4, 'little'))

                if len(output) > length:
                    rv = windefs.ERROR_INSUFFICIENT_BUFFER
                else:
                    if lpData:
                        self.mem_write(lpData, output)

            # For now, return an empty buffer
            else:
                output = b'\x00' * length
                if lpData:
                    try:
                        self.mem_write(lpData, output)
                    except Exception:
                        return windefs.ERROR_INVALID_PARAMETER
                if lpcbData:
                    self.mem_write(lpcbData, len(output).to_bytes(4, 'little'))
                rv = windefs.ERROR_SUCCESS

            kp = key.get_path()
            self.log_registry_access(kp, REG_READ, value_name=lpValueName, size=length,
                                     buffer=lpData)

        return rv

    @apihook('RegCloseKey', argc=1, conv=_arch.CALL_CONV_STDCALL)
    def RegCloseKey(self, emu, argv, ctx={}):
        '''
        LSTATUS RegCloseKey(
          HKEY hKey
        );
        '''

        hKey, = argv
        rv = windefs.ERROR_SUCCESS

        key = self.reg_get_key(hKey)
        if not key:
            rv = windefs.ERROR_INVALID_HANDLE

        return rv

    @apihook('RegEnumKey', argc=4, conv=_arch.CALL_CONV_STDCALL)
    def RegEnumKey(self, emu, argv, ctx={}):
        '''
        LSTATUS RegEnumKey(
          HKEY  hKey,
          DWORD dwIndex,
          LPTSTR lpName,
          DWORD cchName
        );
        '''

        hKey, dwIndex, lpName, cchName = argv

        _argv = argv + [0, 0, 0, 0]
        rv = self.RegEnumKeyEx(emu, _argv, ctx)
        argv[:] = _argv[: 4]

        return rv

    @apihook('RegEnumKeyEx', argc=8, conv=_arch.CALL_CONV_STDCALL)
    def RegEnumKeyEx(self, emu, argv, ctx={}):
        '''
        LSTATUS RegEnumKeyEx(
            HKEY      hKey,
            DWORD     dwIndex,
            LPSTR     lpName,
            LPDWORD   lpcchName,
            LPDWORD   lpReserved,
            LPSTR     lpClass,
            LPDWORD   lpcchClass,
            PFILETIME lpftLastWriteTime
        );
        '''

        hKey, dwIndex, lpName, cchName, res, pcls, cchcls, last_write = argv

        cw = self.get_char_width(ctx)
        rv = windefs.ERROR_INVALID_HANDLE
        if hKey:
            key = self.reg_get_key(hKey)
            argv[0] = key.get_path()
            if not key:
                rv = windefs.ERROR_INVALID_HANDLE
            else:
                subkeys = self.reg_get_subkeys(key)
                if (dwIndex + 1) > len(subkeys):
                    rv = windefs.ERROR_NO_MORE_ITEMS
                else:
                    if lpName:
                        sk = subkeys[dwIndex]
                        name = sk.get_path()
                        if cw == 2:
                            name = name.encode('utf-16le')
                        else:
                            name = name.encode('utf-8')
                        self.mem_write(lpName, name)
                        rv = windefs.ERROR_SUCCESS
            self.log_registry_access(key.get_path(), REG_LIST)
        return rv

    @apihook('RegCreateKey', argc=3)
    def RegCreateKey(self, emu, argv, ctx={}):
        """
        LSTATUS RegCreateKey(
            HKEY    hKey,
            LPCWSTR lpSubKey,
            PHKEY   phkResult
        );
        """
        hkey, lpSubKey, phkResult = argv
        rv = windefs.ERROR_INVALID_HANDLE
        if hkey:
            key = self.reg_get_key(hkey)
            argv[0] = key.get_path()
            if not key:
                rv = windefs.ERROR_INVALID_HANDLE
            else:
                cw = self.get_char_width(ctx)
                if lpSubKey:
                    lpSubKey = self.read_mem_string(lpSubKey, cw)
                    argv[1] = lpSubKey
                    sub_key_path = key.get_path() + '\\' + lpSubKey
                    self.emu.reg_create_key(sub_key_path)
                    self.log_registry_access(sub_key_path, REG_CREATE)
                else:
                    hkey = (hkey).to_bytes(self.get_ptr_size(), 'little')
                    self.mem_write(phkResult, hkey)
                    rv = windefs.ERROR_SUCCESS
        return rv

    @apihook('RegQueryInfoKey', argc=12, conv=_arch.CALL_CONV_STDCALL)
    def RegQueryInfoKey(self, emu, argv, ctx={}):
        # TODO: stub
        '''
        LSTATUS RegQueryInfoKeyA(
          HKEY      hKey,
          LPSTR     lpClass,
          LPDWORD   lpcchClass,
          LPDWORD   lpReserved,
          LPDWORD   lpcSubKeys,
          LPDWORD   lpcbMaxSubKeyLen,
          LPDWORD   lpcbMaxClassLen,
          LPDWORD   lpcValues,
          LPDWORD   lpcbMaxValueNameLen,
          LPDWORD   lpcbMaxValueLen,
          LPDWORD   lpcbSecurityDescriptor,
          PFILETIME lpftLastWriteTime
        );
        '''

        hKey, lpClass, lpcchClass, _, subkeys, max_subkey_len, max_class_len, \
            values, max_value_name_len, max_value_len, sec_desc, last_write = argv

        rv = windefs.ERROR_SUCCESS

        hkey_name = regdefs.get_hkey_type(hKey)
        if hkey_name:
            argv[0] = hkey_name

        key = self.reg_get_key(hKey)
        if not key:
            rv = windefs.ERROR_INVALID_HANDLE

        return rv

    @apihook('OpenProcessToken', argc=3, conv=_arch.CALL_CONV_STDCALL)
    def OpenProcessToken(self, emu, argv, ctx={}):
        '''
        BOOL OpenProcessToken(
          HANDLE  ProcessHandle,
          DWORD   DesiredAccess,
          PHANDLE pTokenHandle
        );
        '''

        hProcess, DesiredAccess, pTokenHandle = argv
        rv = 0

        if hProcess == self.get_max_int():
            obj = emu.get_current_process()
        else:
            obj = self.get_object_from_handle(hProcess)

        if obj:
            token = obj.get_token()
            hToken = token.get_handle()

            if pTokenHandle:
                hnd = (hToken).to_bytes(self.get_ptr_size(), 'little')
                self.mem_write(pTokenHandle, hnd)
                rv = 1
                emu.set_last_error(windefs.ERROR_SUCCESS)
            else:
                emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)

        return rv

    @apihook('OpenThreadToken', argc=4, conv=_arch.CALL_CONV_STDCALL)
    def OpenThreadToken(self, emu, argv, ctx={}):
        '''
        BOOL OpenThreadToken(
            HANDLE  ThreadHandle,
            DWORD   DesiredAccess,
            BOOL    OpenAsSelf,
            PHANDLE TokenHandle
        );
        '''

        ThreadHandle, DesiredAccess, OpenAsSelf, pTokenHandle = argv
        rv = 0

        if ThreadHandle == self.get_max_int():
            obj = emu.get_current_thread()
        else:
            obj = self.get_object_from_handle(ThreadHandle)

        if obj:
            token = obj.get_token()
            hToken = token.get_handle()

            if pTokenHandle:
                hnd = (hToken).to_bytes(self.get_ptr_size(), 'little')
                self.mem_write(pTokenHandle, hnd)
                rv = 1
                emu.set_last_error(windefs.ERROR_SUCCESS)
            else:
                emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)

        return rv

    @apihook('DuplicateTokenEx', argc=6, conv=_arch.CALL_CONV_STDCALL)
    def DuplicateTokenEx(self, emu, argv, ctx={}):
        '''
        BOOL DuplicateTokenEx(
          HANDLE                       hExistingToken,
          DWORD                        dwDesiredAccess,
          LPSECURITY_ATTRIBUTES        lpTokenAttributes,
          SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
          TOKEN_TYPE                   TokenType,
          PHANDLE                      phNewToken
        );
        '''

        (hExistingToken, access, token_attrs, imp_level, toktype,
         phNewToken) = argv
        rv = 0

        obj = self.get_object_from_handle(hExistingToken)

        if obj:

            new_token = emu.new_object(objman.Token)
            hnd_new_token = new_token.get_handle()

            if phNewToken:
                hnd = (hnd_new_token).to_bytes(self.get_ptr_size(), 'little')
                self.mem_write(phNewToken, hnd)
                rv = 1
                emu.set_last_error(windefs.ERROR_SUCCESS)
            else:
                emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)

        return rv

    @apihook('SetTokenInformation', argc=4, conv=_arch.CALL_CONV_STDCALL)
    def SetTokenInformation(self, emu, argv, ctx={}):
        '''
        BOOL SetTokenInformation(
          HANDLE                  TokenHandle,
          TOKEN_INFORMATION_CLASS TokenInformationClass,
          LPVOID                  TokenInformation,
          DWORD                   TokenInformationLength
        );
        '''

        handle, info_class, info, info_len = argv

        rv = 1

        return rv

    @apihook('StartServiceCtrlDispatcher', argc=1)
    def StartServiceCtrlDispatcher(self, emu, argv, ctx={}):
        '''
        BOOL StartServiceCtrlDispatcher(
          const SERVICE_TABLE_ENTRY *lpServiceStartTable
        );
        '''
        lpServiceStartTable, = argv

        cw = self.get_char_width(ctx)

        ste = self.win.SERVICE_TABLE_ENTRY(emu.get_ptr_size())
        entry = self.mem_cast(ste, lpServiceStartTable)

        argv[0] = "lpServiceStartTable=["

        while (entry.lpServiceName != windefs.NULL or
                entry.lpServiceProc != windefs.NULL):
            # Get the service name
            if entry.lpServiceName != windefs.NULL:
                name = self.read_mem_string(entry.lpServiceName, cw) # noqa
                argv[0] += " {{ lpServiceName={}".format(name)
            else:
                argv[0] += " { lpServiceName=NULL"
            # Get the ServiceMain function
            if entry.lpServiceProc != windefs.NULL:
                service_main = entry.lpServiceProc
                argv[0] += ", lpServiceProc={} }} ".format(hex(service_main))
                handle, obj = self.create_thread(service_main, windefs.NULL,
                                                 emu.get_current_process())
            else:
                argv[0] += ", lpServiceProc=NULL } "
            # next entry
            lpServiceStartTable += self.sizeof(ste)
            ste = self.win.SERVICE_TABLE_ENTRY(emu.get_ptr_size())
            entry = self.mem_cast(ste, lpServiceStartTable)

        argv[0] += "]"

        rv = True
        emu.set_last_error(windefs.ERROR_SUCCESS)

        return rv

    @apihook('RegisterServiceCtrlHandler', argc=2)
    def RegisterServiceCtrlHandler(self, emu, argv, ctx={}):
        '''
        SERVICE_STATUS_HANDLE RegisterServiceCtrlHandlerA(
            LPCSTR             lpServiceName,
            LPHANDLER_FUNCTION lpHandlerProc
            );
        '''

        lpServiceName, lpHandlerProc = argv

        # dummy SERVICE_STATUS_HANDLE
        self.service_status_handle += 1

        emu.set_last_error(windefs.ERROR_SUCCESS)

        return self.service_status_handle

    @apihook('SetServiceStatus', argc=2)
    def SetServiceStatus(self, emu, argv, ctx={}):
        '''
        BOOL SetServiceStatus(
            SERVICE_STATUS_HANDLE hServiceStatus,
            LPSERVICE_STATUS      lpServiceStatus
            );
        '''

        hServiceStatus, lpServiceStatus = argv

        emu.set_last_error(windefs.ERROR_SUCCESS)

        return 0x1

    @apihook('RevertToSelf', argc=0)
    def RevertToSelf(self, emu, argv, ctx={}):
        '''
        BOOL RevertToSelf();
        '''
        return 1

    @apihook('ImpersonateLoggedOnUser', argc=1)
    def ImpersonateLoggedOnUser(self, emu, argv, ctx={}):
        '''
        BOOL ImpersonateLoggedOnUser(
        HANDLE hToken
        );
        '''
        return 1

    @apihook('OpenSCManager', argc=3)
    def OpenSCManager(self, emu, argv, ctx={}):
        '''
        SC_HANDLE OpenSCManager(
          LPCSTR lpMachineName,
          LPCSTR lpDatabaseName,
          DWORD  dwDesiredAccess
        );
        '''
        lpMachineName, lpDatabaseName, dwDesiredAccess = argv

        hScm = self.mem_alloc(size=8)
        emu.set_last_error(windefs.ERROR_SUCCESS)

        return hScm

    @apihook('CreateService', argc=13)
    def CreateService(self, emu, argv, ctx={}):
        '''
        SC_HANDLE CreateServiceA(
          SC_HANDLE hSCManager,
          LPCSTR    lpServiceName,
          LPCSTR    lpDisplayName,
          DWORD     dwDesiredAccess,
          DWORD     dwServiceType,
          DWORD     dwStartType,
          DWORD     dwErrorControl,
          LPCSTR    lpBinaryPathName,
          LPCSTR    lpLoadOrderGroup,
          LPDWORD   lpdwTagId,
          LPCSTR    lpDependencies,
          LPCSTR    lpServiceStartName,
          LPCSTR    lpPassword
        );
        '''
        (hScm, svc_name, disp_name, access,
         svc_type, start_type, error_ctrl, bin_path,
         load_group, tag_id, deps, svc_start_name,
         password) = argv

        cw = self.get_char_width(ctx)

        if svc_name:
            _sname = self.read_mem_string(svc_name, cw)
            argv[1] = _sname
        if disp_name:
            _dname = self.read_mem_string(disp_name, cw)
            argv[2] = _dname
        if bin_path:
            _bpname = self.read_mem_string(bin_path, cw)
            argv[7] = _bpname

        hSvc = self.mem_alloc(size=8)
        emu.set_last_error(windefs.ERROR_SUCCESS)

        return hSvc

    @apihook('StartService', argc=3)
    def StartService(self, emu, argv, ctx={}):
        '''
        BOOL StartService(
          SC_HANDLE hService,
          DWORD     dwNumServiceArgs,
          LPCSTR    *lpServiceArgVectors
        );
        '''
        hService, dwNumServiceArgs, lpServiceArgVectors = argv

        rv = 1

        emu.set_last_error(windefs.ERROR_SUCCESS)

        return rv

    @apihook('CloseServiceHandle', argc=1)
    def CloseServiceHandle(self, emu, argv, ctx={}):
        '''
        BOOL CloseServiceHandle(
          SC_HANDLE hSCObject
        );
        '''
        CloseServiceHandle, = argv

        self.mem_free(CloseServiceHandle)

        rv = 1

        emu.set_last_error(windefs.ERROR_SUCCESS)

        return rv

    @apihook('ChangeServiceConfig2', argc=3)
    def ChangeServiceConfig2(self, emu, argv, ctx={}):
        '''
        BOOL ChangeServiceConfig2(
          SC_HANDLE hService,
          DWORD     dwInfoLevel,
          LPVOID    lpInfo
        );
        '''
        hService, dwInfoLevel, lpInfo = argv

        rv = 1

        emu.set_last_error(windefs.ERROR_SUCCESS)

        return rv

    @apihook('SystemFunction036', argc=2)
    def RtlGenRandom(self, emu, argv, ctx={}):
        '''
        BOOLEAN RtlGenRandom(
            PVOID RandomBuffer,
            ULONG RandomBufferLength
        );
        '''
        RandomBuffer, RandomBufferLength = argv

        rv = False
        if RandomBuffer and RandomBufferLength:
            buf = bytes([i for i in range(RandomBufferLength)])
            self.mem_write(RandomBuffer, buf)
            rv = True

        return rv

    @apihook('CryptAcquireContext', argc=5)
    def CryptAcquireContext(self, emu, argv, ctx={}):
        '''
        BOOL CryptAcquireContext(
            HCRYPTPROV *phProv,
            LPCSTR     szContainer,
            LPCSTR     szProvider,
            DWORD      dwProvType,
            DWORD      dwFlags
        );
        '''
        phProv, szContainer, szProvider, dwProvType, dwFlags = argv
        cont_str, prov_str = '', ''
        cw = self.get_char_width(ctx)
        rv = False

        if szContainer:
            cont_str = self.read_mem_string(szContainer, cw)
            argv[1] = cont_str
        if szProvider:
            prov_str = self.read_mem_string(szProvider, cw)
            argv[2] = prov_str

        cm = emu.get_crypt_manager()
        hnd = cm.crypt_open(cname=cont_str, pname=prov_str, ptype=dwProvType, flags=dwFlags)

        if hnd and phProv:
            self.mem_write(phProv, hnd.to_bytes(emu.get_ptr_size(), 'little'))
            rv = True
            emu.set_last_error(windefs.ERROR_SUCCESS)

        return rv

    @apihook('CryptGenRandom', argc=3)
    def CryptGenRandom(self, emu, argv, ctx={}):
        '''
        BOOL CryptGenRandom(
            HCRYPTPROV hProv,
            DWORD      dwLen,
            BYTE       *pbBuffer
        );
        '''
        hProv, dwLen, pbBuffer = argv
        rv = False

        if pbBuffer:
            out = b'A' * dwLen
            self.mem_write(pbBuffer, out)
            rv = True

        return rv

    @apihook('AllocateAndInitializeSid', argc=11)
    def AllocateAndInitializeSid(self, emu, argv, ctx={}):
        '''
        BOOL AllocateAndInitializeSid(
            PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
            BYTE                      nSubAuthorityCount,
            DWORD                     nSubAuthority0,
            DWORD                     nSubAuthority1,
            DWORD                     nSubAuthority2,
            DWORD                     nSubAuthority3,
            DWORD                     nSubAuthority4,
            DWORD                     nSubAuthority5,
            DWORD                     nSubAuthority6,
            DWORD                     nSubAuthority7,
            PSID                      *pSid
        );
        '''
        auth, count, sa0, sa1, sa2, sa3, sa4, sa5, sa6, sa7, pSid = argv
        rv = False

        if pSid:
            sid = self.mem_alloc(0x100, tag='api.struct.SID')
            self.mem_write(pSid, sid.to_bytes(emu.get_ptr_size(), 'little'))
            rv = True

        return rv

    @apihook('CheckTokenMembership', argc=3)
    def CheckTokenMembership(self, emu, argv, ctx={}):
        '''
        BOOL CheckTokenMembership(
            HANDLE TokenHandle,
            PSID   SidToCheck,
            PBOOL  IsMember
        );
        '''
        TokenHandle, SidToCheck, IsMember = argv
        rv = False

        if IsMember:
            self.mem_write(IsMember, (1).to_bytes(4, 'little'))
            rv = True
        return rv

    @apihook('FreeSid', argc=1)
    def FreeSid(self, emu, argv, ctx={}):
        '''
        PVOID FreeSid(
            PSID pSid
        );
        '''
        pSid,  = argv
        rv = pSid

        if pSid:
            self.mem_free(pSid)
            rv = 0
        return rv

    @apihook('CryptReleaseContext', argc=2)
    def CryptReleaseContext(self, emu, argv, ctx={}):
        '''
        BOOL CryptReleaseContext(
            HCRYPTPROV hProv,
            DWORD      dwFlags
        );
        '''
        hProv, dwFlags = argv
        rv = True

        cm = emu.get_crypt_manager()
        cm.crypt_close(hProv)

        return rv

    @apihook('GetUserName', argc=2)
    def GetUserName(self, emu, argv, ctx={}):
        '''
        BOOL GetUserName(
            LPSTR   lpBuffer,
            LPDWORD pcbBuffer
        );
        '''
        lpBuffer, pcbBuffer = argv
        rv = False
        cw = self.get_char_width(ctx)

        user = emu.get_user()
        user_name = user.get('name')
        argv[0] = user_name

        if lpBuffer:
            if cw == 2:
                out = user_name.encode('utf-16le')
            elif cw == 1:
                out = user_name.encode('utf-8')
            self.mem_write(lpBuffer, out)
            rv = True
        if pcbBuffer:
            self.mem_write(pcbBuffer, (len(user_name)).to_bytes(4, 'little'))

        return rv

    @apihook('LookupPrivilegeValue', argc=3)
    def LookupPrivilegeValue(self, emu, argv, ctx={}):
        '''
        BOOL LookupPrivilegeValue(
            LPCSTR lpSystemName,
            LPCSTR lpName,
            PLUID  lpLuid
        );
        '''
        sysname, name, luid = argv
        rv = False
        cw = self.get_char_width(ctx)

        if sysname:
            sysname = self.read_mem_string(sysname, cw)
            argv[0] = sysname
        if name:
            name = self.read_mem_string(name, cw)
            argv[1] = name
            rv = True

        return rv

    @apihook('AdjustTokenPrivileges', argc=6)
    def AdjustTokenPrivileges(self, emu, argv, ctx={}):
        '''
        BOOL AdjustTokenPrivileges(
            HANDLE            TokenHandle,
            BOOL              DisableAllPrivileges,
            PTOKEN_PRIVILEGES NewState,
            DWORD             BufferLength,
            PTOKEN_PRIVILEGES PreviousState,
            PDWORD            ReturnLength
        );
        '''
        rv = True

        return rv

    @apihook('GetTokenInformation', argc=5)
    def GetTokenInformation(self, emu, argv, ctx={}):
        '''
        BOOL GetTokenInformation(
            HANDLE                  TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            LPVOID                  TokenInformation,
            DWORD                   TokenInformationLength,
            PDWORD                  ReturnLength
        );
        '''
        hnd, info_class, info, info_len, ret_len = argv
        rv = True

        if not info_len:
            rv = False
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)

        if info_class == 20 and info and emu.get_user().get('is_admin', True):
            self.mem_write(info, (1).to_bytes(4, 'little'))

        if ret_len:
            self.mem_write(ret_len, (4).to_bytes(4, 'little'))

        return rv

    @apihook('EqualSid', argc=2)
    def EqualSid(self, emu, argv, ctx={}):
        '''
        BOOL EqualSid(
            PSID pSid1,
            PSID pSid2
        );
        '''
        sid1, sid2 = argv
        rv = False

        if sid1 and sid2:
            s1 = self.mem_read(sid1, 10)
            s2 = self.mem_read(sid2, 10)
            if s1 == s2:
                rv = True

        return rv

    @apihook('GetSidIdentifierAuthority', argc=1)
    def GetSidIdentifierAuthority(self, emu, argv, ctx={}):
        '''
        PSID_IDENTIFIER_AUTHORITY GetSidIdentifierAuthority(
          [in] PSID pSid
        );
        '''
        sid, = argv

        # IdentifierAuthority is at offset 0x02 in the SID structure
        return sid + 2

    @apihook('GetSidSubAuthorityCount', argc=1)
    def GetSidSubAuthorityCount(self, emu, argv, ctx={}):
        '''
        PUCHAR GetSidSubAuthorityCount(
            PSID pSid
        );
        '''
        sid, = argv
        rv = 0

        if sid:
            rv = sid + 1

        return rv

    @apihook('GetSidSubAuthority', argc=2)
    def GetSidSubAuthority(self, emu, argv, ctx={}):
        '''
        PDWORD GetSidSubAuthority(
          [in] PSID  pSid,
          [in] DWORD nSubAuthority
        );
        '''
        sid, nsub = argv

        # SubAuthorities begin at offset 0x8
        return sid + 8 + (nsub * 4)

    @apihook('LookupAccountName', argc=7)
    def LookupAccountName(self, emu, argv, ctx={}):
        '''
        BOOL LookupAccountNameA(
          [in, optional]  LPCSTR        lpSystemName,
          [in]            LPCSTR        lpAccountName,
          [out, optional] PSID          Sid,
          [in, out]       LPDWORD       cbSid,
          [out, optional] LPSTR         ReferencedDomainName,
          [in, out]       LPDWORD       cchReferencedDomainName,
          [out]           PSID_NAME_USE peUse
        );
        '''

        ptr_sysname, ptr_acctname, ptr_sid, ptr_cbsid, ptr_domname, ptr_cchdomname, ptr_peuse = argv
        rv = 0

        cw = self.get_char_width(ctx)

        if ptr_sysname:
            sn = self.read_mem_string(ptr_sysname, cw)
            argv[0] = sn

        if not ptr_acctname:
            return rv

        acctname = self.read_mem_string(ptr_acctname, cw)
        argv[1] = acctname

        user = emu.get_user().get('name')
        # Currently only supporting user SIDs specified in the config
        if user != acctname:
            return rv

        str_sid = emu.get_user().get('sid')
        if not str_sid:
            return rv

        argv[2] = str_sid
        sid_struct = windefs.convert_sid_str_to_struct(emu.get_ptr_size(), str_sid)
        side_struct_size = sid_struct.sizeof()

        cbsid = self.mem_read(ptr_cbsid, 4)
        cbsid = int.from_bytes(cbsid, 'little')
        argv[3] = cbsid
        if not cbsid:
            self.mem_write(ptr_cbsid, side_struct_size.to_bytes(4, 'little'))
            return rv

        if cbsid < side_struct_size:
            return rv

        domain = emu.get_domain()
        cchdomname = self.mem_read(ptr_cchdomname, 4)
        cbcchdomname = int.from_bytes(cchdomname, 'little')
        argv[5] = cbcchdomname
        if not cbcchdomname:
            buf_size = len(domain) + 1
            self.mem_write(ptr_cchdomname, buf_size.to_bytes(4, 'little'))
            return rv

        rv = 1

        self.mem_write(ptr_sid, self.get_bytes(sid_struct))

        self.write_mem_string(domain, ptr_domname, cw)
        argv[4] = domain

        # Currently only supporting user SIDs (SidTypeUser = 1)
        self.mem_write(ptr_peuse, (1).to_bytes(4, 'little'))
        argv[6] = 1

        return rv

    @apihook('LookupAccountSid', argc=7)
    def LookupAccountSid(self, emu, argv, ctx={}):
        '''
        BOOL LookupAccountSid(
            LPCSTR        lpSystemName,
            PSID          Sid,
            LPSTR         Name,
            LPDWORD       cchName,
            LPSTR         ReferencedDomainName,
            LPDWORD       cchReferencedDomainName,
            PSID_NAME_USE peUse
        );
        '''
        sysname, sid, name, cchname, domname, cchdomname, peuse = argv
        rv = False

        cw = self.get_char_width(ctx)

        if not cchname or not cchdomname:
            return rv

        name_size = self.mem_read(cchname, 4)
        name_size = int.from_bytes(name_size, 'little')

        dom_size = self.mem_read(cchdomname, 4)
        dom_size = int.from_bytes(dom_size, 'little')

        self.write_mem_string('myuser', name, cw)
        self.write_mem_string('mydomain', domname, cw)
        rv = True

        if sysname:
            sn = self.read_mem_string(sysname, cw)
            argv[0] = sn

        return rv

    @apihook('CreateProcessAsUser', argc=11, conv=_arch.CALL_CONV_STDCALL)
    def CreateProcessAsUser(self, emu, argv, ctx={}):
        '''
        BOOL CreateProcessAsUser(
          HANDLE                hToken,
          LPCSTR                lpApplicationName,
          LPSTR                 lpCommandLine,
          LPSECURITY_ATTRIBUTES lpProcessAttributes,
          LPSECURITY_ATTRIBUTES lpThreadAttributes,
          BOOL                  bInheritHandles,
          DWORD                 dwCreationFlags,
          LPVOID                lpEnvironment,
          LPCSTR                lpCurrentDirectory,
          LPSTARTUPINFOA        lpStartupInfo,
          LPPROCESS_INFORMATION lpProcessInformation
        );
        '''
        token, app, cmd, pa, ta, inherit, flags, env, cd, si, ppi = argv

        cw = self.get_char_width(ctx)
        cmdstr = ''
        appstr = ''
        if app:
            appstr = self.read_mem_string(app, cw)
            argv[1] = appstr
        if cmd:
            cmdstr = self.read_mem_string(cmd, cw)
            if not appstr:
                appstr = cmdstr.split(' ')[0]
            argv[2] = cmdstr

        proc = emu.create_process(path=appstr, cmdline=cmdstr)
        proc_hnd = self.get_object_handle(proc)

        thread = proc.threads[0]
        thread_hnd = self.get_object_handle(thread)

        _pi = self.k32types.PROCESS_INFORMATION(emu.get_ptr_size())
        data = self.mem_cast(_pi, ppi)
        _pi.hProcess = proc_hnd
        _pi.hThread = thread_hnd
        _pi.dwProcessId = proc.pid
        _pi.dwThreadId = thread.tid

        self.mem_write(ppi, self.get_bytes(data))

        rv = 1

        self.log_process_event(proc, PROC_CREATE)
        return rv

    @apihook('CryptCreateHash', argc=5)
    def CryptCreateHash(self, emu, argv, ctx={}):
        '''
        BOOL CryptCreateHash(
          HCRYPTPROV hProv,
          ALG_ID     Algid,
          HCRYPTKEY  hKey,
          DWORD      dwFlags,
          HCRYPTHASH *phHash
        );
        '''

        hash_algs = {
            0x00008004: ('CALG_SHA1', hashlib.sha1),
            0x0000800c: ('CALG_SHA_256', hashlib.sha256),
            0x0000800d: ('CALG_SHA_384', hashlib.sha384),
            0x0000800e: ('CALG_SHA_512', hashlib.sha512),
            0x00008003: ('CALG_MD5', hashlib.md5)
        }

        hProv, Algid, hKey, dwFlags, phHash = argv
        argv[1] = hash_algs.get(Algid, Algid)[0]

        if hKey != 0:
            return 0

        if Algid not in hash_algs:
            emu.set_last_error(adv32.NTE_BAD_ALGID)
            return 0

        hnd = self.get_handle()
        self.hash_objects.update({hnd: hash_algs[Algid][1]()})
        self.mem_write(phHash, hnd.to_bytes(self.get_ptr_size(), 'little'))
        return 1

    @apihook('CryptHashData', argc=4)
    def CryptHashData(self, emu, argv, ctx={}):
        '''
        BOOL CryptHashData(
          HCRYPTHASH hHash,
          const BYTE *pbData,
          DWORD      dwDataLen,
          DWORD      dwFlags
        );
        '''

        hHash, pbData, dwDataLen, dwFlags = argv
        hnd = self.hash_objects.get(hHash, None)
        if hnd is None:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        if dwDataLen <= 0:
            return 0

        data = self.mem_read(pbData, dwDataLen)
        hnd.update(data)
        return 1

    @apihook('CryptGetHashParam', argc=5)
    def CryptGetHashParam(self, emu, argv, ctx={}):
        '''
        BOOL CryptGetHashParam(
          HCRYPTHASH hHash,
          DWORD      dwParam,
          BYTE       *pbData,
          DWORD      *pdwDataLen,
          DWORD      dwFlags
        );
        '''
        hHash, dwParam, pbData, pdwDataLen, dwFlags = argv

        param_enums = {
            1: "HP_ALGID",
            2: "HP_HASHVAL",
            4: "HP_HASHSIZE",
            5: "HP_HMAC_INFO"
        }

        if dwParam in param_enums.keys():
            argv[1] = param_enums[dwParam]

        return 1

    @apihook('CryptDestroyHash', argc=1)
    def CryptDestroyHash(self, emu, argv, ctx={}):
        """
        BOOL CryptDestroyHash(
          HCRYPTHASH hHash
        );
        """
        hHash = argv

        return 1

    @apihook('CryptDeriveKey', argc=5)
    def CryptDeriveKey(self, emu, argv, ctx={}):
        """
        BOOL CryptDeriveKey(
          HCRYPTPROV hProv,
          ALG_ID     Algid,
          HCRYPTHASH hBaseData,
          DWORD      dwFlags,
          HCRYPTKEY  *phKey
        );
        """

        hProv, Algid, hBaseData, dwFlags, phKey = argv

        # Only RC4 supported right now
        if Algid != 0x6801:
            return 0

        hnd = self.hash_objects.get(hBaseData, None)

        if hnd is None:
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return 0

        # CryptDeriveKey zeroes out the last 11 bytes of the hash,
        # so we gotta do the same before it is written to the
        # phKey structure
        fixed_digest = hnd.digest()[:5] + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

        ptrsz = emu.get_ptr_size()

        hKey = self.win.HCRYPTKEY(ptrsz)
        hKey.Algid = Algid
        hKey.keylen = hnd.digest_size
        hKey.keyp = self.mem_alloc(hKey.keylen)

        hKeyp = self.mem_alloc(hKey.sizeof())

        self.mem_write(hKey.keyp, fixed_digest)

        self.mem_write(hKeyp, hKey.get_bytes())
        self.mem_write(phKey, hKeyp.to_bytes(ptrsz, "little"))

        return 1

    @apihook('CryptDecrypt', argc=6)
    def CryptDecrypt(self, emu, argv, ctx={}):
        """
        BOOL CryptDecrypt(
          HCRYPTKEY  hKey,
          HCRYPTHASH hHash,
          BOOL       Final,
          DWORD      dwFlags,
          BYTE       *pbData,
          DWORD      *pdwDataLen
        );
        """

        hKey, hHash, Final, dwFlags, pbData, pdwDataLen = argv

        # Hashing not supported
        if hHash:
            return 0

        ptrsz = emu.get_ptr_size()

        hKey = self.mem_cast(self.win.HCRYPTKEY(ptrsz), hKey)

        # Only RC4 supported right now
        if hKey.Algid != 0x6801:
            return 0

        encdatalen_b = self.mem_read(pdwDataLen, 4)
        encdatalen = int.from_bytes(encdatalen_b, "little")

        encdata = self.mem_read(pbData, encdatalen)

        key = self.mem_read(hKey.keyp, hKey.keylen)

        if self.rc4 is None:
            self.rc4 = ARC4.new(key)

        dec = self.rc4.decrypt(encdata)
        declen = len(dec)

        self.mem_write(pbData, dec)
        self.mem_write(pdwDataLen, int.to_bytes(declen, 4, "little"))

        if Final == True:
            self.rc4 = None

        return 1

    @apihook('RegGetValue', argc=7, conv=_arch.CALL_CONV_STDCALL)
    def RegGetValue(self, emu, argv, ctx={}):
        '''
        LSTATUS RegGetValueW(
            HKEY    hkey,
            LPCWSTR lpSubKey,
            LPCWSTR lpValue,
            DWORD   dwFlags,
            LPDWORD pdwType,
            PVOID   pvData,
            LPDWORD pcbData
            );
        '''

        hKey, lpSubKey, lpValue, dwFlags, lpType, lpData, lpcbData = argv
        rv = windefs.ERROR_SUCCESS

        cw = self.get_char_width(ctx)
        if lpSubKey:
            lpSubKey = self.read_mem_string(lpSubKey, cw)
            argv[1] = lpSubKey

        if lpValue:
            lpValue = self.read_mem_string(lpValue, cw)
            argv[2] = lpValue

        type_name = regdefs.get_value_type(lpType)
        if type_name:
            argv[4] = type_name

        length = 0
        if lpcbData:
            length = self.mem_read(lpcbData, 4)
            length = int.from_bytes(length, 'little')

        key = self.reg_get_key(hKey)
        if key:
            val = key.get_value(lpValue)
            if val:
                output = b''

                if lpcbData:
                    self.mem_write(lpcbData, len(output).to_bytes(4, 'little'))

                if len(output) > length:
                    rv = windefs.ERROR_INSUFFICIENT_BUFFER
                else:
                    self.mem_write(lpData, output)

            # For now, return an empty buffer
            else:
                output = b'\x00' * length
                self.mem_write(lpData, output)
                rv = windefs.ERROR_SUCCESS

            kp = key.get_path()
            self.log_registry_access(kp, REG_READ, value_name=lpValue, size=length,
                                     buffer=lpData)

        return rv

    @apihook('EnumServicesStatus', argc=8, conv=_arch.CALL_CONV_STDCALL)
    def EnumServicesStatus(self, emu, argv, ctx={}):
        '''
        BOOL EnumServicesStatusA(
          SC_HANDLE              hSCManager,
          DWORD                  dwServiceType,
          DWORD                  dwServiceState,
          LPENUM_SERVICE_STATUSA lpServices,
          DWORD                  cbBufSize,
          LPDWORD                pcbBytesNeeded,
          LPDWORD                lpServicesReturned,
          LPDWORD                lpResumeHandle
        );
        '''
        hSCManager, dwServiceType, dwServiceState, lpServices, cbBufSize, \
            pcbBytesNeeded, lpServicesReturned, lpResumeHandle = argv

        service_type_str = adv32.get_define_int(dwServiceType, 'SERVICE_')
        if service_type_str:
            argv[1] = service_type_str

        service_state_str = adv32.get_define_int(dwServiceState, 'SERVICE_')
        if service_state_str:
            argv[2] = service_state_str

        # TODO: Populate service status output
        return 1

    @apihook('OpenService', argc=3, conv=_arch.CALL_CONV_STDCALL)
    def OpenService(self, emu, argv, ctx={}):
        '''
        SC_HANDLE OpenServiceA(
          SC_HANDLE hSCManager,
          LPCSTR    lpServiceName,
          DWORD     dwDesiredAccess
        );
        '''
        hSCManager, lpServiceName, dwDesiredAccess = argv
        cw = self.get_char_width(ctx)
        svcname = self.read_mem_string(lpServiceName, cw)
        argv[1] = svcname
        return self.get_handle()
