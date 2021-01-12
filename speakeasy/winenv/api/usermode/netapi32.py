# Copyright (C) 2021 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.defs.windows.kernel32 as k32types
import speakeasy.winenv.defs.windows.netapi32 as netapi32defs
import speakeasy.winenv.arch as _arch

from .. import api


class NetApi32(api.ApiHandler):
    name = 'NETAPI32'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super(NetApi32, self).__init__(emu)
        super(NetApi32, self).__get_hook_attrs__(self)

    @apihook('NetGetJoinInformation', argc=3, conv=_arch.CALL_CONV_STDCALL)
    def NetGetJoinInformation(self, emu, argv, ctx={}):
        """
        NET_API_STATUS NET_API_FUNCTION NetGetJoinInformation(
         LPCWSTR lpServer,
         LPWSTR *lpNameBuffer,
         PNETSETUP_JOIN_STATUS BufferType
         );
            lpServer: Pointer to a constant string that specifies the DNS or NetBIOS name of the computer on which to call the function.
            If this parameter is NULL, the local computer is used.

            lpNameBuffer: Pointer to the buffer that receives the NetBIOS name of the domain or workgroup to which the computer is joined.
            This buffer is allocated by the system and must be freed using the NetApiBufferFree function.

            BufferType: Receives the join status of the specified computer. This parameter can have one of the following values.
        """
        lpServer, lpNameBuffer, BufferType = argv

        name = 'FLARE_Test_Domain'
        name_bytes = str.encode(name)

        lpServer = 0
        lpNameBuffer = name_bytes
        BufferType = k32types.NetSetupWorkgroupName

        return netapi32defs.NERR_Success

    @apihook('NetWkstaGetInfo', argc=3)
    def NetWkstaGetInfo(self, emu, argv, ctx={}):
        """
        NET_API_STATUS NET_API_FUNCTION NetWkstaGetInfo(
          LMSTR  servername,
          DWORD  level,
          LPBYTE *bufptr
        );
        """
        servername, level, bufptr = argv

        if level not in [100, 101, 102]:
            return netapi32defs.ERROR_INVALID_LEVEL

        if level == 100:
            wki = netapi32defs.WKSTA_INFO_100(emu.get_ptr_size())
        elif level == 101:
            wki = netapi32defs.WKSTA_INFO_101(emu.get_ptr_size())

            # Using empty string
            lanroot_ptr = self.mem_alloc(2)
            self.mem_write(lanroot_ptr, b'\x00\x00')
            wki.wki_lanroot = lanroot_ptr
        else:
            wki = netapi32defs.WKSTA_INFO_102(emu.get_ptr_size())

            # Using empty string
            lanroot_ptr = self.mem_alloc(2)
            self.mem_write(lanroot_ptr, b'\x00\x00')
            wki.wki_lanroot = lanroot_ptr

            wki.wki_logged_on_users = 2

        wki_addr = self.mem_alloc(wki.sizeof())
        self.mem_cast(wki, wki_addr)

        platform_id = 500  # PLATFORM_ID_NT
        wki.wki_platform_id = platform_id

        hostname = emu.get_hostname()
        computername_ptr = self.mem_alloc(2 + (len(hostname) * 2))
        # Assuming Unicode; "This string is Unicode if _WIN32_WINNT or
        # FORCE_UNICODE are defined."
        self.write_mem_string(hostname, computername_ptr, width=2)
        wki.wki_computername = computername_ptr

        domain = emu.get_domain()
        langroup_ptr = self.mem_alloc(2 + (len(domain) * 2))
        self.write_mem_string(domain, langroup_ptr, width=2)
        wki.wki_langroup = langroup_ptr

        osver = emu.get_os_version()
        wki.wki_ver_major = osver['major']
        wki.wki_ver_minor = osver['minor']

        self.mem_write(wki_addr, wki.get_bytes())
        self.mem_write(bufptr, wki_addr.to_bytes(emu.get_ptr_size(), 'little'))

        return netapi32defs.NERR_Success

    @apihook('NetApiBufferFree', argc=1)
    def NetApiBufferFree(self, emu, argv, ctx={}):
        """
        NET_API_STATUS NET_API_FUNCTION NetApiBufferFree(
          _Frees_ptr_opt_ LPVOID Buffer
        );
        """
        return netapi32defs.NERR_Success
