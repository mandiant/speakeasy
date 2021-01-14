# Copyright (C) 2021 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.defs.windows.windows as windefs
import speakeasy.winenv.defs.windows.netapi32 as netapi32defs

from .. import api


class NetApi32(api.ApiHandler):
    """
    Implements exported functions from netapi32.dll
    """
    name = 'netapi32'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super(NetApi32, self).__init__(emu)
        super(NetApi32, self).__get_hook_attrs__(self)

    @apihook('NetGetJoinInformation', argc=3)
    def NetGetJoinInformation(self, emu, argv, ctx={}):
        """
        NET_API_STATUS NET_API_FUNCTION NetGetJoinInformation(
          LPCWSTR lpServer,
          LPWSTR *lpNameBuffer,
          PNETSETUP_JOIN_STATUS BufferType
        );
        """
        lpServer, lpNameBuffer, BufferType = argv

        if lpServer:
            server = self.read_wide_string(lpServer)
            argv[0] = server

        # Assumes the server being queried is the local computer
        domain = emu.get_domain()
        argv[1] = domain
        namebuf = self.mem_alloc(emu.get_ptr_size())
        self.write_wide_string(domain, namebuf)
        self.mem_write(lpNameBuffer, namebuf.to_bytes(emu.get_ptr_size(), 'little'))

        argv[2] = netapi32defs.NetSetupDomainName
        self.mem_write(BufferType, netapi32defs.NetSetupDomainName.to_bytes(4, 'little'))

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
            return windefs.ERROR_INVALID_LEVEL

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
