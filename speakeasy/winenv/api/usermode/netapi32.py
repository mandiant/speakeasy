# Copyright (C) 2021 FireEye, Inc. All Rights Reserved.

from typing import TYPE_CHECKING

import speakeasy.winenv.defs.windows.netapi32 as netapi32defs
import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.windows.common import FILETIME_UNIX_EPOCH
from speakeasy.winenv.api.compare import Fold, get_string_order

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator


class NetApi32(api.ApiHandler):
    """
    Implements exported functions from netapi32.dll
    """

    name = "netapi32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        super().__get_hook_attrs__(self)

    @apihook("NetGetJoinInformation", argc=3)
    def NetGetJoinInformation(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NET_API_STATUS NetGetJoinInformation(
            LPCWSTR lpServer,
            LPWSTR *lpNameBuffer,
            PNETSETUP_JOIN_STATUS BufferType
        );
        """
        lpServer, lpNameBuffer, BufferType = argv

        if lpServer:
            server = self.read_wide_string(lpServer)
            ctx.args["lpServer"].display = server

        # Assumes the server being queried is the local computer
        domain = emu.config.domain or ""
        ctx.args["lpNameBuffer"].display = domain
        namebuf = self.mem_alloc((len(domain) + 1) * 2)
        self.write_wide_string(domain, namebuf)
        self.write_ptr(lpNameBuffer, namebuf)

        ctx.args["BufferType"].display = "NetSetupDomainName"
        self.write_dword(BufferType, netapi32defs.NetSetupDomainName)

        return netapi32defs.NERR_Success

    @apihook("NetWkstaGetInfo", argc=3)
    def NetWkstaGetInfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NET_API_STATUS NetWkstaGetInfo(
            LMSTR servername,
            DWORD level,
            LPBYTE *bufptr
        );
        """
        servername, level, bufptr = argv

        if level not in [100, 101, 102]:
            return windefs.ERROR_INVALID_LEVEL

        wki: netapi32defs.WKSTA_INFO_100 | netapi32defs.WKSTA_INFO_101 | netapi32defs.WKSTA_INFO_102
        if level == 100:
            wki = netapi32defs.WKSTA_INFO_100(emu.get_ptr_size())
        elif level == 101:
            wki = netapi32defs.WKSTA_INFO_101(emu.get_ptr_size())

            # Using empty string
            lanroot_ptr = self.mem_alloc(2)
            self.mem_write(lanroot_ptr, b"\x00\x00")
            wki.wki_lanroot = lanroot_ptr
        else:
            wki = netapi32defs.WKSTA_INFO_102(emu.get_ptr_size())

            # Using empty string
            lanroot_ptr = self.mem_alloc(2)
            self.mem_write(lanroot_ptr, b"\x00\x00")
            wki.wki_lanroot = lanroot_ptr

            wki.wki_logged_on_users = 2

        wki_addr = self.mem_alloc(wki.sizeof())

        platform_id = 500  # PLATFORM_ID_NT
        wki.wki_platform_id = platform_id

        hostname = emu.config.hostname
        computername_ptr = self.mem_alloc(2 + (len(hostname) * 2))
        # Assuming Unicode; "This string is Unicode if _WIN32_WINNT or
        # FORCE_UNICODE are defined."
        self.write_mem_string(hostname, computername_ptr, width=2)
        wki.wki_computername = computername_ptr

        domain = emu.config.domain or ""
        langroup_ptr = self.mem_alloc(2 + (len(domain) * 2))
        self.write_mem_string(domain, langroup_ptr, width=2)
        wki.wki_langroup = langroup_ptr

        osver = emu.config.os_ver
        wki.wki_ver_major = osver.major or 0
        wki.wki_ver_minor = osver.minor or 0

        self.mem_write(wki_addr, wki.get_bytes())
        self.write_ptr(bufptr, wki_addr)

        return netapi32defs.NERR_Success

    @apihook("NetStatisticsGet", argc=5)
    def NetStatisticsGet(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NET_API_STATUS NetStatisticsGet(
            LMSTR ServerName,
            LMSTR Service,
            DWORD Level,
            DWORD Options,
            LPBYTE *Buffer
        );

        The statistics start when the system starts. All counters are zero.
        """
        ServerName, Service, Level, Options, Buffer = argv

        if ServerName:
            ctx.args["ServerName"].display = self.read_wide_string(ServerName)
        service = ""
        if Service:
            service = self.read_wide_string(Service)
            ctx.args["Service"].display = service

        self.write_ptr(Buffer, 0)

        stats: netapi32defs.STAT_WORKSTATION_0 | netapi32defs.STAT_SERVER_0
        if get_string_order(service, netapi32defs.SERVICE_WORKSTATION, Fold.ASCII_LOWER) == 0:
            stats = netapi32defs.STAT_WORKSTATION_0(emu.get_ptr_size())
        elif get_string_order(service, netapi32defs.SERVICE_SERVER, Fold.ASCII_LOWER) == 0:
            stats = netapi32defs.STAT_SERVER_0(emu.get_ptr_size())
        else:
            return windefs.ERROR_NOT_SUPPORTED

        if Level != 0:
            return windefs.ERROR_INVALID_LEVEL
        if Options != 0:
            return windefs.ERROR_INVALID_PARAMETER

        boot_time = emu.api.load_api_handler("kernel32").boot_time
        start = (boot_time - FILETIME_UNIX_EPOCH) // 10_000_000
        if isinstance(stats, netapi32defs.STAT_WORKSTATION_0):
            stats.StatisticsStartTime = start
        else:
            stats.sts0_start = start

        buf = self.heap_alloc(stats.sizeof(), heap="NetApiBufferAllocate")
        if not buf:
            return windefs.ERROR_NOT_ENOUGH_MEMORY
        self.mem_write(buf, stats.get_bytes())
        self.write_ptr(Buffer, buf)

        return netapi32defs.NERR_Success

    @apihook("NetUserAdd", argc=4)
    def NetUserAdd(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NET_API_STATUS NetUserAdd(
            LPCWSTR servername,
            DWORD level,
            LPBYTE buf,
            LPDWORD parm_err
        );
        """
        servername, level, buf, parm_err = argv

        if servername:
            server = self.read_wide_string(servername)
            ctx.args["servername"].display = server

        return netapi32defs.NERR_Success

    @apihook("NetApiBufferFree", argc=1)
    def NetApiBufferFree(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NET_API_STATUS NetApiBufferFree(
            LPVOID Buffer
        );
        """
        return netapi32defs.NERR_Success
