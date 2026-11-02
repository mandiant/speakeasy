# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
import re
import struct
from socket import htonl, htons, inet_aton, inet_ntoa, inet_ntop, inet_pton, ntohl, ntohs
from typing import TYPE_CHECKING

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.windows.windows as windefs
import speakeasy.winenv.defs.winsock.ws2_32 as wstypes
from speakeasy.winenv.defs.lookup import decode
from speakeasy.winenv.defs.winsock import winsock
from speakeasy.winenv.defs.winsock.winsock import ADDRESS_FAMILY, SOCKET_OPTION, SOCKET_OPTION_LEVEL, SOCKET_TYPE

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.netman import NetworkManager
    from speakeasy.windows.win32 import Win32Emulator


class Ws2_32(api.ApiHandler):
    """
    Implements winsock functions from ws2_32.dll
    """

    name = "ws2_32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs = {}
        self.data = {}
        self.addr_bufs: dict[str, int] = {}
        self.netman: NetworkManager = emu.get_network_manager()
        self.wstypes = wstypes

        super().__get_hook_attrs__(self)

    @apihook("WSAStartup", argc=2, conv=_arch.CALL_CONV_STDCALL, ordinal=115)
    def WSAStartup(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int WSAStartup(
            WORD wVersionRequested,
            LPWSADATA lpWSAData
        );
        """
        wVersionRequested, lpWSAData = argv

        data = self.wstypes.WSAData(emu.get_ptr_size())

        data.wVersion = (
            0x0202 if (wVersionRequested & 0xFF, (wVersionRequested >> 8) & 0xFF) >= (2, 2) else wVersionRequested
        )
        data.wHighVersion = 0x0202
        data.iMaxSockets = 0x1000
        data.iMaxUdpDg = 0x1000
        data.szDescription = b"WinSock 2.0"
        data.szSystemStatus = b"Running"

        self.mem_write(lpWSAData, self.get_bytes(data))

        rv = windefs.ERROR_SUCCESS
        return rv

    @apihook("WSACleanup", argc=0, ordinal=116)
    def WSACleanup(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int WSACleanup();
        """
        return 0

    @apihook("WSASocket", argc=6)
    def WSASocket(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SOCKET WSASocket(
            int af,
            int type,
            int protocol,
            LPWSAPROTOCOL_INFO lpProtocolInfo,
            GROUP g,
            DWORD dwFlags
        );
        """
        af, type, protocol, lpProtocolInfo, g, dwFlags = argv

        sock = self.netman.new_socket(af, type, protocol, dwFlags)

        fd = sock.fd

        ctx.args["af"].display = decode(ADDRESS_FAMILY, af)
        ctx.args["type"].display = decode(SOCKET_TYPE, type)

        return fd

    @apihook("WSAIoctl", argc=9, conv=_arch.CALL_CONV_STDCALL)
    def WSAIoctl(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int WSAIoctl(
            SOCKET s,
            DWORD dwIoControlCode,
            LPVOID lpvInBuffer,
            DWORD cbInBuffer,
            LPVOID lpvOutBuffer,
            DWORD cbOutBuffer,
            LPDWORD lpcbBytesReturned,
            LPWSAOVERLAPPED lpOverlapped,
            LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
        );
        """
        # TODO: Add actual function logic. However, for now, returning 0 (success) should cover most use cases.

        return windefs.ERROR_SUCCESS

    @apihook("WSAConnect", argc=7, conv=_arch.CALL_CONV_STDCALL)
    def WSAConnect(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int WSAConnect(
            SOCKET s,
            const struct sockaddr *name,
            int namelen,
            LPWSABUF lpCallerData,
            LPWSABUF lpCalleeData,
            LPQOS lpSQOS,
            LPQOS lpGQOS
        );
        """
        # TODO: Add actual function logic. However, for now, just call connect()

        return self.connect(emu, argv[:3], ctx)

    @apihook("socket", argc=3, conv=_arch.CALL_CONV_STDCALL, ordinal=23)
    def socket(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SOCKET socket(
            int af,
            int type,
            int protocol
        );
        """
        af, type, protocol = argv

        sock = self.netman.new_socket(af, type, protocol, 0)

        fd = sock.fd

        ctx.args["af"].display = decode(ADDRESS_FAMILY, af)
        ctx.args["type"].display = decode(SOCKET_TYPE, type)

        return fd

    @apihook("inet_addr", argc=1, ordinal=11)
    def inet_addr(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        unsigned long inet_addr(
            const char *cp
        );
        """
        (cp,) = argv
        rv = winsock.INADDR_NONE

        if cp:
            addr = self.read_mem_string(cp, 1)
            ctx.args["cp"].display = addr
            try:
                rv = int.from_bytes(inet_aton(addr), "little")
            except OSError:
                rv = winsock.INADDR_NONE

        return rv

    @apihook("htons", argc=1, conv=_arch.CALL_CONV_STDCALL, ordinal=9)
    def htons(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        u_short htons(
            u_short hostshort
        );
        """
        (hostshort,) = argv

        netshort = htons(hostshort & 0xFFFF)

        return netshort

    @apihook("ntohs", argc=1, ordinal=15)
    def ntohs(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        u_short ntohs(
            u_short netshort
        );
        """
        (netshort,) = argv

        return ntohs(netshort & 0xFFFF)

    @apihook("ntohl", argc=1, ordinal=14)
    def ntohl(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        u_long ntohl(
            u_long netlong
        );
        """
        (netlong,) = argv

        return ntohl(netlong & 0xFFFFFFFF)

    @apihook("setsockopt", argc=5, ordinal=21)
    def setsockopt(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int setsockopt(
            SOCKET s,
            int level,
            int optname,
            const char *optval,
            int optlen
        );
        """
        s, level, optname, optval, optlen = argv
        rv = 0

        ctx.args["level"].display = decode(SOCKET_OPTION_LEVEL, level)

        ctx.args["optname"].display = decode(SOCKET_OPTION, optname)

        if optname in (SOCKET_OPTION.SO_RCVBUF, SOCKET_OPTION.SO_SNDBUF):
            opt_val = self.mem_read(optval, optlen)
            ctx.args["optval"].display = hex(struct.unpack("<I", opt_val)[0])

        return rv

    @apihook("WSASetLastError", argc=1, ordinal=112)
    def WSASetLastError(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        void WSASetLastError(
            int iError
        );
        """
        (iError,) = argv

        emu.set_last_error(iError)

    @apihook("WSAGetLastError", argc=0, ordinal=111)
    def WSAGetLastError(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int WSAGetLastError();
        """
        return emu.get_last_error() or 0

    @apihook("gethostname", argc=2, ordinal=57)
    def gethostname(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int gethostname(
            char *name,
            int namelen
        );
        """
        (
            name,
            namelen,
        ) = argv
        rv = -1

        host = emu.config.hostname
        if name and host:
            host += "\x00"
            if namelen >= len(host):
                out = host.encode("utf-8")
                self.mem_write(name, out)
                rv = 0
        return rv

    @apihook("gethostbyname", argc=1, conv=_arch.CALL_CONV_STDCALL, ordinal=52)
    def gethostbyname(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        struct hostent *gethostbyname(
            const char *name
        );
        """
        (name,) = argv

        name = self.read_mem_string(name, 1)
        ptr_hostent = 0

        ip = self.netman.name_lookup(name)

        if ip:
            hostent = self.wstypes.hostent(emu.get_ptr_size())
            ptr_hostent = self.mem_alloc(hostent.sizeof(), tag="api.struct.HOSTENT")
            hostent.h_name = argv[0]

            # List contains no aliases so just the NULL terminator
            ptr_h_aliases = self.mem_alloc(emu.get_ptr_size(), tag="api.struct.HOSTENT.h_aliases")
            hostent.h_aliases = ptr_h_aliases

            hostent.h_addrtype = ADDRESS_FAMILY.AF_INET
            hostent.h_length = 4

            # List contains one addr pointer and the NULL terminator
            ptr_h_addr_list = self.mem_alloc(emu.get_ptr_size() * 2, tag="api.struct.HOSTENT.h_addr_list")
            ptr_h_addr_0 = self.mem_alloc(hostent.h_length, tag="api.struct.HOSTENT.h_addr_0")
            ip_bytes = inet_aton(ip)
            self.mem_write(ptr_h_addr_0, ip_bytes)
            self.write_ptr(ptr_h_addr_list, ptr_h_addr_0)
            hostent.h_addr_list = ptr_h_addr_list

            # Write the hostent struct
            self.mem_write(ptr_hostent, self.get_bytes(hostent))
        else:
            ip = ""

        ctx.args["name"].display = name
        self.record_dns_event(name, ip)

        return ptr_hostent

    @apihook("connect", argc=3, conv=_arch.CALL_CONV_STDCALL, ordinal=4)
    def connect(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int connect(
            SOCKET s,
            const struct sockaddr *name,
            int namelen
        );
        """
        s, name, namelen = argv

        rv = windefs.ERROR_SUCCESS

        sockaddr = self.wstypes.sockaddr_in(emu.get_ptr_size())
        sa = self.mem_cast(sockaddr, name)

        raddr = inet_ntoa(sa.sin_addr.to_bytes(4, "little"))
        rport = ntohs(sa.sin_port)

        socket = self.netman.get_socket(s)
        if not socket:
            emu.set_last_error(winsock.WSAENOTSOCK)
            return winsock.SOCKET_ERROR
        stype = socket.type
        proto = "unknown"
        if stype == SOCKET_TYPE.SOCK_STREAM:
            proto = "tcp"
        elif stype == SOCKET_TYPE.SOCK_DGRAM:
            proto = "udp"
        elif stype == SOCKET_TYPE.SOCK_RAW:
            proto = "raw"

        socket.set_connection_info(raddr, rport)

        self.record_network_event(raddr, rport, typ="connect", proto=proto, method="winsock.connect")

        ctx.args["name"].display = f"{raddr}:{rport}"

        return rv

    @apihook("bind", argc=3, ordinal=2)
    def bind(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int bind(
            SOCKET s,
            const struct sockaddr *name,
            int namelen
        );
        """
        s, name, namelen = argv
        rv = windefs.ERROR_SUCCESS

        sockaddr = self.wstypes.sockaddr_in(emu.get_ptr_size())
        sa = self.mem_cast(sockaddr, name)
        raddr = inet_ntoa(sa.sin_addr.to_bytes(4, "little"))
        rport = ntohs(sa.sin_port)

        socket = self.netman.get_socket(s)
        if not socket:
            emu.set_last_error(winsock.WSAENOTSOCK)
            return winsock.SOCKET_ERROR
        stype = socket.type
        proto = "unknown"
        if stype == SOCKET_TYPE.SOCK_STREAM:
            proto = "tcp"
        elif stype == SOCKET_TYPE.SOCK_DGRAM:
            proto = "udp"
        elif stype == SOCKET_TYPE.SOCK_RAW:
            proto = "raw"

        socket.set_connection_info(raddr, rport)
        self.record_network_event(raddr, rport, typ="bind", proto=proto, method="winsock.bind")

        ctx.args["name"].display = f"{raddr}:{rport}"

        return rv

    @apihook("listen", argc=2, ordinal=13)
    def listen(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int listen(
            SOCKET s,
            int backlog
        );
        """
        s, backlog = argv
        rv = windefs.ERROR_SUCCESS

        return rv

    @apihook("select", argc=5, ordinal=18)
    def select(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int select(
            int nfds,
            fd_set *readfds,
            fd_set *writefds,
            fd_set *exceptfds,
            const struct timeval *timeout
        );
        """
        nfds, readfds, writefds, exceptfds, timeout = argv
        fd_count = 0

        for fds in (readfds, writefds):
            if fds:
                fd_count += self.read_dword(fds)

        if exceptfds:
            self.mem_write(exceptfds, b"\x00" * 4)

        return fd_count

    @apihook("accept", argc=3, ordinal=1)
    def accept(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        SOCKET accept(
            SOCKET s,
            struct sockaddr *addr,
            int *addrlen
        );
        """
        s, addr, addrlen = argv

        socket = self.netman.get_socket(s)
        if not socket:
            emu.set_last_error(winsock.WSAENOTSOCK)
            return self.get_max_int()
        stype = socket.type
        proto = "unknown"
        if stype == SOCKET_TYPE.SOCK_STREAM:
            proto = "tcp"
        elif stype == SOCKET_TYPE.SOCK_DGRAM:
            proto = "udp"
        elif stype == SOCKET_TYPE.SOCK_RAW:
            proto = "raw"

        new_sock = self.netman.new_socket(socket.family, socket.type, socket.protocol, 0)
        aip = self.netman.name_lookup("default")
        if not aip:
            aip = "127.0.0.1"

        port = socket.connected_port
        nip = inet_aton(aip)
        nip = int.from_bytes(nip, "little")

        new_sock.set_connection_info(aip, port)

        self.record_network_event(aip, port, typ="accept", proto=proto, method="winsock.accept")

        if addr:
            sockaddr = self.wstypes.sockaddr_in(emu.get_ptr_size())
            sockaddr = self.mem_cast(sockaddr, addr)
            sockaddr.sin_family = ADDRESS_FAMILY.AF_INET
            sockaddr.sin_addr = nip
            sockaddr.sin_port = htons(port)
            self.mem_write(addr, sockaddr.get_bytes())

        return new_sock.fd

    def write_sockaddr(self, emu, name, namelen, host, port):
        size = self.wstypes.sockaddr_in(emu.get_ptr_size()).sizeof()
        if not name or not namelen or self.read_dword(namelen) < size:
            emu.set_last_error(winsock.WSAEFAULT)
            return winsock.SOCKET_ERROR
        sockaddr = self.wstypes.sockaddr_in(emu.get_ptr_size())
        sockaddr.sin_family = ADDRESS_FAMILY.AF_INET
        sockaddr.sin_addr = int.from_bytes(inet_aton(host), "little")
        sockaddr.sin_port = htons(port)
        self.mem_write(name, sockaddr.get_bytes())
        self.write_dword(namelen, size)
        return 0

    @apihook("getpeername", argc=3, ordinal=5)
    def getpeername(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int getpeername(
            SOCKET s,
            struct sockaddr *name,
            int *namelen
        );
        """
        s, name, namelen = argv
        socket = self.netman.get_socket(s)
        if not socket:
            emu.set_last_error(winsock.WSAENOTSOCK)
            return winsock.SOCKET_ERROR
        if not socket.connected_host:
            emu.set_last_error(winsock.WSAENOTCONN)
            return winsock.SOCKET_ERROR
        return self.write_sockaddr(emu, name, namelen, socket.connected_host, socket.connected_port)

    @apihook("getsockname", argc=3, ordinal=6)
    def getsockname(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int getsockname(
            SOCKET s,
            struct sockaddr *name,
            int *namelen
        );
        """
        s, name, namelen = argv
        socket = self.netman.get_socket(s)
        if not socket:
            emu.set_last_error(winsock.WSAENOTSOCK)
            return winsock.SOCKET_ERROR
        adapters = emu.config.network.adapters
        host = next((a.ip_address for a in adapters if a.ip_address), "127.0.0.1")
        return self.write_sockaddr(emu, name, namelen, host, 49152 + socket.fd % 16384)

    @apihook("inet_ntoa", argc=1, ordinal=12)
    def inet_ntoa(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        char *inet_ntoa(
            struct in_addr in
        );
        """
        (in_,) = argv

        raddr = inet_ntoa(in_.to_bytes(4, "little"))
        buf = self.addr_bufs.get(raddr)
        if not buf:
            buf = self.mem_alloc(len(raddr) + 1, tag=f"api.ws2_32.inet_ntoa.{raddr}")
            self.mem_write(buf, raddr.encode("utf-8") + b"\0")
            self.addr_bufs.update({raddr: buf})
        return buf

    @apihook("inet_ntop", argc=4)
    def inet_ntop(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        PCSTR inet_ntop(
            INT Family,
            const VOID *pAddr,
            PSTR pStringBuf,
            size_t StringBufSize
        );
        """
        Family, pAddr, pStringBuf, StringBufSize = argv

        ctx.args["Family"].display = decode(ADDRESS_FAMILY, Family)

        # TODO: implement case AF_INET6
        if Family == ADDRESS_FAMILY.AF_INET:
            ipv4_bytes = self.mem_read(pAddr, 4)
            ctx.args["pAddr"].display = hex(int.from_bytes(ipv4_bytes, "big"))
            try:
                ipv4_str = inet_ntop(Family, ipv4_bytes)
            except OSError:
                return 0

            self.write_string(ipv4_str, pStringBuf)
            return pStringBuf

        return 0

    @apihook("inet_pton", argc=3)
    def inet_pton(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        INT inet_pton(
            INT Family,
            PCSTR pszAddrString,
            PVOID pAddrBuf
        );
        """
        Family, pszAddrString, pAddrBuf = argv

        ctx.args["Family"].display = decode(ADDRESS_FAMILY, Family)

        # TODO: implement case AF_INET6
        if Family == ADDRESS_FAMILY.AF_INET:
            ipv4_str = self.read_string(pszAddrString)
            ctx.args["pszAddrString"].display = ipv4_str
            try:
                ipv4_bytes = inet_pton(Family, ipv4_str)
            except OSError:
                return 0

            self.mem_write(pAddrBuf, ipv4_bytes)
            return 1

        return 0

    @apihook("htonl", argc=1, ordinal=8)
    def htonl(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        u_long htonl(
            u_long hostlong
        );
        """
        (hostlong,) = argv
        return htonl(hostlong & 0xFFFFFFFF)

    @apihook("__WSAFDIsSet", argc=2, ordinal=151)
    def __WSAFDIsSet(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int __WSAFDIsSet(
            SOCKET fd,
            fd_set *set
        );
        """
        fd, set = argv
        if not set:
            return 0
        ptr_size = emu.get_ptr_size()
        count = min(self.read_dword(set), 64)
        fds = self.mem_read(set + ptr_size, count * ptr_size)
        return int(any(int.from_bytes(fds[i : i + ptr_size], "little") == fd for i in range(0, len(fds), ptr_size)))

    @apihook("shutdown", argc=2, ordinal=22)
    def shutdown(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int shutdown(
            SOCKET s,
            int how
        );
        """
        return 0

    @apihook("recv", argc=4, ordinal=16)
    def recv(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int recv(
            SOCKET s,
            char *buf,
            int len,
            int flags
        );
        """
        s, buf, blen, flags = argv
        rv = 0

        peek = flags & winsock.MSG_PEEK

        sock = self.netman.get_socket(s)
        if not sock:
            emu.set_last_error(winsock.WSAENOTSOCK)
            return winsock.SOCKET_ERROR
        data = sock.get_recv_data(blen, peek)
        rv = len(data)

        self.mem_write(buf, data)

        stype = sock.type
        proto = "unknown"
        if stype == SOCKET_TYPE.SOCK_STREAM:
            proto = "tcp"
        elif stype == SOCKET_TYPE.SOCK_DGRAM:
            proto = "udp"
        elif stype == SOCKET_TYPE.SOCK_RAW:
            proto = "raw"

        raddr, rport = sock.get_connection_info()
        self.record_network_event(raddr, rport, typ="data_in", proto=proto, method="winsock.recv", data=data)

        return rv

    @apihook("send", argc=4, ordinal=19)
    def send(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int send(
            SOCKET s,
            const char *buf,
            int len,
            int flags
        );
        """
        s, buf, blen, flags = argv
        data = b""

        socket = self.netman.get_socket(s)
        if not socket:
            emu.set_last_error(winsock.WSAENOTSOCK)
            return winsock.SOCKET_ERROR
        stype = socket.type
        proto = "unknown"
        if stype == SOCKET_TYPE.SOCK_STREAM:
            proto = "tcp"
        elif stype == SOCKET_TYPE.SOCK_DGRAM:
            proto = "udp"
        elif stype == SOCKET_TYPE.SOCK_RAW:
            proto = "raw"

        if buf:
            data = self.mem_read(buf, blen)
        raddr, rport = socket.get_connection_info()

        self.record_network_event(raddr, rport, typ="data_out", proto=proto, method="winsock.send", data=data)

        return len(data)

    @apihook("closesocket", argc=1, ordinal=3)
    def closesocket(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int closesocket(
            SOCKET s
        );
        """
        (s,) = argv

        rv = 0

        socket = self.netman.get_socket(s)
        if not socket:
            emu.set_last_error(winsock.WSAENOTSOCK)
            rv = winsock.SOCKET_ERROR
        else:
            self.netman.close_socket(s)

        return rv

    @apihook("ioctlsocket", argc=3, ordinal=10)
    def ioctlsocket(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int ioctlsocket(
            SOCKET s,
            long cmd,
            u_long *argp
        );
        """
        s, cmd, argp = argv

        socket = self.netman.get_socket(s)
        if not socket:
            emu.set_last_error(winsock.WSAENOTSOCK)
            return winsock.SOCKET_ERROR
        rv = 0

        return rv

    @apihook("getaddrinfo", argc=4)
    def getaddrinfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        INT getaddrinfo(
            PCSTR pNodeName,
            PCSTR pServiceName,
            const ADDRINFOA *pHints,
            PADDRINFOA *ppResult
        );
        """
        pNodeName, pServiceName, pHints, ppResult = argv
        rv = 0

        host = ""
        if pNodeName:
            host = self.read_string(pNodeName)
            ctx.args["pNodeName"].display = host

        port = 0
        if pServiceName:
            service_name = self.read_string(pServiceName)
            ctx.args["pServiceName"].display = service_name
            if service_name.isnumeric():
                port = int(service_name)
            elif service_name in winsock.SERVICE_PORTS:
                port = winsock.SERVICE_PORTS[service_name]
            else:
                return winsock.WSATYPE_NOT_FOUND

        hints_ai = self.wstypes.addrinfo(emu.get_ptr_size())
        if pHints:
            hints_ai = self.mem_cast(hints_ai, pHints)

        # Handles a specific case where an IP address is converted as part of a URL
        # TODO: handle additional cases
        ip_url_re = re.compile(r"https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        match = re.match(ip_url_re, host)
        if match:
            ip_addr = match.group(1)
        else:
            # Use default IP address
            ip_addr = self.netman.name_lookup("default")
            if not ip_addr:
                ip_addr = "127.0.0.1"

        ip_bytes = inet_aton(ip_addr)

        # Populate sockaddr_in
        sockaddr_in = self.wstypes.sockaddr_in(emu.get_ptr_size())
        sockaddr_in.sin_family = ADDRESS_FAMILY.AF_INET
        sockaddr_in.sin_port = htons(port)
        sockaddr_in.sin_addr = htonl(int(ip_bytes.hex(), 16))
        p_sockaddr = self.mem_alloc(sockaddr_in.sizeof(), tag="api.struct.sockaddr_in")
        self.mem_write(p_sockaddr, sockaddr_in.get_bytes())

        # Populate addrinfo with sockaddr_in and pHints data
        addrinfo = self.wstypes.addrinfo(emu.get_ptr_size())
        # TODO: Update ai_flags as additional cases are added
        addrinfo.ai_flags = winsock.AI_NUMERICHOST
        addrinfo.ai_family = ADDRESS_FAMILY.AF_INET
        addrinfo.ai_socktype = hints_ai.ai_socktype
        addrinfo.ai_protocol = hints_ai.ai_protocol
        addrinfo.ai_addrlen = sockaddr_in.sizeof()
        addrinfo.ai_addr = p_sockaddr

        # Populate ppResult with addrinfo
        pResult = self.mem_alloc(addrinfo.sizeof(), tag="api.struct.addrinfo")
        self.mem_write(pResult, addrinfo.get_bytes())
        self.write_ptr(ppResult, pResult)

        return rv

    @apihook("freeaddrinfo", argc=1)
    def freeaddrinfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID freeaddrinfo(
            PADDRINFOA pAddrInfo
        );
        """
        self.mem_free(argv[0])

    @apihook("getsockopt", argc=5, ordinal=7)
    def getsockopt(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int getsockopt(
            SOCKET s,
            int level,
            int optname,
            char *optval,
            int *optlen
        );
        """
        s, level, optname, optval, optlen = argv
        rv = 0

        ctx.args["level"].display = decode(SOCKET_OPTION_LEVEL, level)

        opt_len = self.mem_read(optlen, 4)
        opt_len = struct.unpack("<I", opt_len)[0]
        ctx.args["optlen"].display = hex(opt_len)

        ctx.args["optname"].display = decode(SOCKET_OPTION, optname)
        if optname in (SOCKET_OPTION.SO_RCVBUF, SOCKET_OPTION.SO_SNDBUF):
            opt_val = winsock.SOCK_BUF_SIZE
            self.mem_write(optval, opt_val.to_bytes(opt_len, "little"))

        return rv
