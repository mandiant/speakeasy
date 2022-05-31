# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
import re
import struct

from socket import inet_ntoa, inet_aton, inet_pton, inet_ntop, ntohs, htons, ntohl, htonl

import speakeasy.winenv.arch as _arch

import speakeasy.winenv.defs.windows.windows as windefs
import speakeasy.winenv.defs.winsock.winsock as winsock
import speakeasy.winenv.defs.winsock.ws2_32 as wstypes

from .. import api

INADDR_NONE = 0xFFFFFFFF
HOST_NOT_FOUND = 11001
WSAENOTSOCK = 10038


class Ws2_32(api.ApiHandler):
    """
    Implements winsock functions from ws2_32.dll
    """

    name = 'ws2_32'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Ws2_32, self).__init__(emu)

        self.funcs = {}
        self.data = {}
        self.addr_bufs = {}
        self.last_error = 0
        self.win = None
        self.netman = emu.get_network_manager()
        self.wstypes = wstypes

        super(Ws2_32, self).__get_hook_attrs__(self)

    @apihook('WSAStartup', argc=2, conv=_arch.CALL_CONV_STDCALL, ordinal=115)
    def WSAStartup(self, emu, argv, ctx={}):
        """
        int WSAStartup(
          WORD      wVersionRequired,
          LPWSADATA lpWSAData
        );
        """
        ver, lpWSAData = argv

        wsa = self.wstypes.WSAData(emu.get_ptr_size())
        data = self.mem_cast(wsa, lpWSAData)

        data.wVersion = 0x0101
        data.wHighVersion = 0x0202
        data.iMaxSockets = 0x1000
        data.iMaxUdpDg = 0x1000

        self.mem_write(lpWSAData, self.get_bytes(data))

        rv = windefs.ERROR_SUCCESS
        return rv

    @apihook('WSACleanup', argc=0, ordinal=116)
    def WSACleanup(self, emu, argv, ctx={}):
        """
        int WSACleanup();
        """

        return 0

    @apihook('WSASocket', argc=6)
    def WSASocket(self, emu, argv, ctx={}):
        """
        SOCKET WSAAPI WSASocket(
          int                 af,
          int                 type,
          int                 protocol,
          LPWSAPROTOCOL_INFO  lpProtocolInfo,
          GROUP               g,
          DWORD               dwFlags
        );
        """
        af, typ, protocol, lpProtocolInfo, g, dwFlags = argv

        fam_str = winsock.get_addr_family(af)
        sock_str = winsock.get_sock_type(typ)

        sock = self.netman.new_socket(fam_str, sock_str, protocol, dwFlags)

        fd = sock.get_fd()

        argv[0] = fam_str
        argv[1] = sock_str

        return fd

    @apihook('WSAIoctl', argc=9, conv=_arch.CALL_CONV_STDCALL)
    def WSAIoctl(self, emu, argv, ctx={}):
        """
        int WSAAPI WSAIoctl(
          SOCKET                             s,
          DWORD                              dwIoControlCode,
          LPVOID                             lpvInBuffer,
          DWORD                              cbInBuffer,
          LPVOID                             lpvOutBuffer,
          DWORD                              cbOutBuffer,
          LPDWORD                            lpcbBytesReturned,
          LPWSAOVERLAPPED                    lpOverlapped,
          LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
        );
        """

        # TODO: Add actual function logic. However, for now, returning 0 (success) should cover most use cases.

        return windefs.ERROR_SUCCESS

    @apihook('socket', argc=3, conv=_arch.CALL_CONV_STDCALL, ordinal=23)
    def socket(self, emu, argv, ctx={}):
        """
        SOCKET WSAAPI socket(
          int af,
          int type,
          int protocol
        );
        """
        af, typ, protocol = argv

        fam_str = winsock.get_addr_family(af)
        sock_str = winsock.get_sock_type(typ)

        sock = self.netman.new_socket(fam_str, sock_str, protocol, 0)

        fd = sock.get_fd()

        argv[0] = fam_str
        argv[1] = sock_str

        return fd

    @apihook('inet_addr', argc=1, ordinal=11)
    def inet_addr(self, emu, argv, ctx={}):
        """
    unsigned long inet_addr(
      _In_ const char *cp
    );
        """
        a, = argv

        if a:
            a = self.read_mem_string(a, 1)
            argv[0] = a
            try:
                rv = inet_aton(a)
                rv = int.from_bytes(rv, 'little')
            except OSError:
                rv = INADDR_NONE

        return rv

    @apihook('htons', argc=1, conv=_arch.CALL_CONV_STDCALL, ordinal=9)
    def htons(self, emu, argv, ctx={}):
        """
        u_short htons(
          u_short hostshort
        );
        """
        hostshort, = argv

        netshort = htons(hostshort)

        return netshort

    @apihook('ntohs', argc=1, ordinal=15)
    def ntohs(self, emu, argv, ctx={}):
        """
        u_short ntohs(
            u_short netshort
        );
        """
        netshort, = argv

        return ntohs(netshort)

    @apihook('ntohl', argc=1, ordinal=14)
    def ntohl(self, emu, argv, ctx={}):
        """
        u_long ntohl(
            u_long netlong
        );
        """
        netlong, = argv

        return ntohl(netlong)

    @apihook('setsockopt', argc=5, ordinal=21)
    def setsockopt(self, emu, argv, ctx={}):
        """
        int setsockopt(
          SOCKET     s,
          int        level,
          int        optname,
          const char *optval,
          int        optlen
        );
        """
        s, level, optname, optval, optlen = argv
        rv = 0

        opt_level = winsock.get_define(level, 'SOL_')
        if opt_level:
            argv[1] = opt_level

        opt_name = winsock.get_define(optname, 'SO_')
        if opt_name:
            argv[2] = opt_name

        if opt_name == 'SO_RCVBUF' or opt_name == 'SO_SNDBUF':
            opt_val = self.mem_read(optval, optlen)
            argv[3] = struct.unpack('<I', opt_val)[0]

        return rv

    @apihook('WSASetLastError', argc=1, ordinal=112)
    def WSASetLastError(self, emu, argv, ctx={}):
        """
        void WSASetLastError(
            int iError
        );
        """
        iError, = argv

        self.last_error = iError
        return

    @apihook('gethostname', argc=2, ordinal=57)
    def gethostname(self, emu, argv, ctx={}):
        """
        int gethostname(
            char *name,
            int  namelen
        );
        """
        name, namelen, = argv
        rv = -1

        host = emu.get_hostname()
        if name and host:
            host += '\x00'
            if namelen > len(host):
                out = host.encode('utf-8')
                self.mem_write(name, out)
                rv = 0
        return rv

    @apihook('gethostbyname', argc=1, conv=_arch.CALL_CONV_STDCALL, ordinal=52)
    def gethostbyname(self, emu, argv, ctx={}):
        """
        struct hostent * gethostbyname(const char FAR * name);
        """
        name, = argv

        name = self.read_mem_string(name, 1)
        ptr_hostent = 0

        ip = self.netman.name_lookup(name)

        if ip:
            hostent = self.wstypes.hostent(emu.get_ptr_size())
            ptr_hostent = self.mem_alloc(hostent.sizeof(), tag='api.struct.HOSTENT')
            hostent.h_name = argv[0]

            # List contains no aliases so just the NULL terminator
            ptr_h_aliases = self.mem_alloc(emu.get_ptr_size(), tag='api.struct.HOSTENT.h_aliases')
            hostent.h_aliases = ptr_h_aliases

            hostent.h_addrtype = winsock.AF_INET
            hostent.h_length = 4

            # List contains one addr pointer and the NULL terminator
            ptr_h_addr_list = self.mem_alloc(emu.get_ptr_size() * 2, tag='api.struct.HOSTENT.h_addr_list')
            ptr_h_addr_0 = self.mem_alloc(hostent.h_length, tag='api.struct.HOSTENT.h_addr_0')
            ip_bytes = inet_aton(ip)
            self.mem_write(ptr_h_addr_0, ip_bytes)
            self.mem_write(ptr_h_addr_list, ptr_h_addr_0.to_bytes(self.get_ptr_size(), 'little'))
            hostent.h_addr_list = ptr_h_addr_list

            # Write the hostent struct
            self.mem_write(ptr_hostent, self.get_bytes(hostent))
        else:
            ip = ''

        argv[0] = name
        self.log_dns(name, ip)

        return ptr_hostent

    @apihook('connect', argc=3, conv=_arch.CALL_CONV_STDCALL, ordinal=4)
    def connect(self, emu, argv, ctx={}):
        """
        int WSAAPI connect(
          SOCKET         s,
          const sockaddr *name,
          int            namelen
        );
        """

        s, pname, namelen = argv

        rv = windefs.ERROR_SUCCESS

        sockaddr = self.wstypes.sockaddr_in(emu.get_ptr_size())
        sa = self.mem_cast(sockaddr, pname)

        raddr = inet_ntoa(sa.sin_addr.to_bytes(4, 'little'))
        rport = ntohs(sa.sin_port)

        socket = self.netman.get_socket(s)
        if not socket:
            return 0xFFFFFFFF
        stype = socket.get_type()
        proto = 'unknown'
        if stype == 'SOCK_STREAM':
            proto = 'tcp'
        elif stype == 'SOCK_DGRAM':
            proto = 'udp'
        elif stype == 'SOCK_RAW':
            proto = 'raw'

        socket.set_connection_info(raddr, rport)

        self.log_network(raddr, rport, typ='connect', proto=proto, method='winsock.connect')

        argv[1] = '%s:%d' % (raddr, rport)

        return rv

    @apihook('bind', argc=3, ordinal=2)
    def bind(self, emu, argv, ctx={}):
        """
        int bind(
            SOCKET         s,
            const sockaddr *addr,
            int            namelen
        );
        """
        s, pname, namelen = argv
        rv = windefs.ERROR_SUCCESS

        sockaddr = self.wstypes.sockaddr_in(emu.get_ptr_size())
        sa = self.mem_cast(sockaddr, pname)
        raddr = inet_ntoa(sa.sin_addr.to_bytes(4, 'little'))
        rport = ntohs(sa.sin_port)

        socket = self.netman.get_socket(s)
        stype = socket.get_type()
        proto = 'unknown'
        if stype == 'SOCK_STREAM':
            proto = 'tcp'
        elif stype == 'SOCK_DGRAM':
            proto = 'udp'
        elif stype == 'SOCK_RAW':
            proto = 'raw'

        socket.set_connection_info(raddr, rport)
        self.log_network(raddr, rport, typ='bind', proto=proto, method='winsock.bind')

        argv[1] = '%s:%d' % (raddr, rport)

        return rv

    @apihook('listen', argc=2, ordinal=13)
    def listen(self, emu, argv, ctx={}):
        """
        int WSAAPI listen(
            SOCKET s,
            int    backlog
        );
        """
        s, backlog = argv
        rv = windefs.ERROR_SUCCESS

        return rv

    @apihook('select', argc=5, ordinal=18)
    def select(self, emu, argv, ctx={}):
        """
        int WSAAPI select(
            int           nfds,
            fd_set        *readfds,
            fd_set        *writefds,
            fd_set        *exceptfds,
            const timeval *timeout
        );
        """
        nfds, readfds, writefds, exceptfds, timeout = argv
        fd_count = 0

        if readfds:
            fds = self.mem_read(readfds, 4)
            fds = int.from_bytes(fds, 'little')
            fd_count += fds

        if writefds:
            fds = self.mem_read(writefds, 4)
            fds = int.from_bytes(fds, 'little')
            fd_count += fds

        if exceptfds:
            fds = self.mem_read(exceptfds, 4)
            fds = int.from_bytes(fds, 'little')
            fd_count += fds

        return fd_count

    @apihook('accept', argc=3, ordinal=1)
    def accept(self, emu, argv, ctx={}):
        """
        SOCKET WSAAPI accept(
            SOCKET   s,
            sockaddr *addr,
            int      *addrlen
        );
        """
        s, addr, addrlen = argv

        socket = self.netman.get_socket(s)
        stype = socket.get_type()
        proto = 'unknown'
        if stype == 'SOCK_STREAM':
            proto = 'tcp'
        elif stype == 'SOCK_DGRAM':
            proto = 'udp'
        elif stype == 'SOCK_RAW':
            proto = 'raw'

        new_sock = self.netman.new_socket(socket.family, socket.type, socket.protocol, 0)
        aip = self.netman.name_lookup('default')
        if not aip:
            aip = '127.0.0.1'

        port = socket.connected_port
        nip = inet_aton(aip)
        nip = int.from_bytes(nip, 'little')

        new_sock.set_connection_info(aip, port)

        self.log_network(aip, port, typ='accept', proto=proto, method='winsock.accept')

        if addr:
            sockaddr = self.wstypes.sockaddr_in(emu.get_ptr_size())
            sockaddr = self.mem_cast(sockaddr, addr)
            sockaddr.sin_addr = nip
            sockaddr.sin_port = port
            self.mem_write(addr, sockaddr.get_bytes())

        return new_sock.get_fd()

    @apihook('inet_ntoa', argc=1, ordinal=12)
    def inet_ntoa(self, emu, argv, ctx={}):
        """
        char FAR* inet_ntoa(struct in_addr in);
        """
        in_addr, = argv

        raddr = inet_ntoa(in_addr.to_bytes(4, 'little'))
        rv = self.addr_bufs.get(raddr)
        if not rv:
            buf = self.mem_alloc(len(raddr), tag='api.ws2_32.inet_ntoa.%s' % (raddr))
            self.mem_write(buf, raddr.encode('utf-8'))
            self.addr_bufs.update({raddr: buf})
        return buf

    @apihook('inet_ntop', argc=4, ordinal=180)
    def inet_ntop(self, emu, argv, ctx={}):
        """
        PCSTR WSAAPI inet_ntop(
          [in]  INT        Family,
          [in]  const VOID *pAddr,
          [out] PSTR       pStringBuf,
          [in]  size_t     StringBufSize
        );
        """
        family, pAddr, pStringBuf, StringBufSize = argv

        fam_str = winsock.get_addr_family(family)
        argv[0] = fam_str

        # TODO: implement case AF_INET6
        if fam_str == 'AF_INET':
            ipv4_bytes = self.mem_read(pAddr, 4)
            argv[1] = int.from_bytes(ipv4_bytes, 'big')
            try:
                ipv4_str = inet_ntop(family, ipv4_bytes)
            except OSError:
                return 0

            self.write_string(ipv4_str, pStringBuf)
            return pStringBuf

        return 0

    @apihook('inet_pton', argc=3, ordinal=181)
    def inet_pton(self, emu, argv, ctx={}):
        """
        INT WSAAPI inet_pton(
          [in]  INT   Family,
          [in]  PCSTR pszAddrString,
          [out] PVOID pAddrBuf
        );
        """

        family, pszAddrString, pAddrBuf = argv

        fam_str = winsock.get_addr_family(family)
        argv[0] = fam_str

        # TODO: implement case AF_INET6
        if fam_str == 'AF_INET':
            ipv4_str = self.read_string(pszAddrString)
            argv[1] = ipv4_str
            try:
                ipv4_bytes = inet_pton(family, ipv4_str)
            except OSError:
                return 0

            self.mem_write(pAddrBuf, ipv4_bytes)
            return 1

        return 0

    @apihook('htonl', argc=1, ordinal=8)
    def htonl(self, emu, argv, ctx={}):
        """
        uint32_t htonl(uint32_t hostlong);
        """
        hostlong, = argv
        return htonl(hostlong)

    @apihook('__WSAFDIsSet', argc=2, ordinal=151)
    def __WSAFDIsSet(self, emu, argv, ctx={}):
        """
        int __WSAFDIsSet(
            SOCKET ,
            fd_set *
        );
        """
        sock, fd_set = argv
        return 1

    @apihook('shutdown', argc=2, ordinal=22)
    def shutdown(self, emu, argv, ctx={}):
        """
        int shutdown(
            SOCKET s,
            int    how
        );
        """
        return 0

    @apihook('recv', argc=4, ordinal=16)
    def recv(self, emu, argv, ctx={}):
        """
        int recv(
          SOCKET s,
          char   *buf,
          int    len,
          int    flags
        );
        """

        s, buf, blen, flags = argv
        rv = 0

        peek = flags & winsock.MSG_PEEK

        sock = self.netman.get_socket(s)
        data = sock.get_recv_data(blen, peek)
        rv = len(data)

        self.mem_write(buf, data)

        stype = sock.get_type()
        proto = 'unknown'
        if stype == 'SOCK_STREAM':
            proto = 'tcp'
        elif stype == 'SOCK_DGRAM':
            proto = 'udp'
        elif stype == 'SOCK_RAW':
            proto = 'raw'

        raddr, rport = sock.get_connection_info()
        self.log_network(raddr, rport, typ='data_in', proto=proto, method='winsock.recv',
                         data=data)

        return rv

    @apihook('send', argc=4, ordinal=19)
    def send(self, emu, argv, ctx={}):
        """
        int WSAAPI send(
          SOCKET     s,
          const char *buf,
          int        len,
          int        flags
        );
        """
        s, buf, blen, flags = argv
        data = b''

        socket = self.netman.get_socket(s)
        stype = socket.get_type()
        proto = 'unknown'
        if stype == 'SOCK_STREAM':
            proto = 'tcp'
        elif stype == 'SOCK_DGRAM':
            proto = 'udp'
        elif stype == 'SOCK_RAW':
            proto = 'raw'

        if buf:
            data = self.mem_read(buf, blen)
        raddr, rport = socket.get_connection_info()

        self.log_network(raddr, rport, typ='data_out', proto=proto, method='winsock.send',
                         data=data)

        return len(data)

    @apihook('closesocket', argc=1, ordinal=3)
    def closesocket(self, emu, argv, ctx={}):
        """
        int closesocket(
          IN SOCKET s
        );
        """
        s, = argv

        rv = 0

        socket = self.netman.get_socket(s)
        if not socket:
            # This isnt a valid socket, return invalid
            rv = winsock.WSAENOTSOCK
        else:
            self.netman.close_socket(s)

        return rv

    @apihook('ioctlsocket', argc=3, ordinal=10)
    def ioctlsocket(self, emu, argv, ctx={}):
        """
        int ioctlsocket(
            SOCKET s,
            long   cmd,
            u_long *argp
        );
        """
        s, cmd, argp = argv
        rv = winsock.WSAENOTSOCK

        socket = self.netman.get_socket(s)
        if socket:
            rv = 0

        return rv

    @apihook('getaddrinfo', argc=4, ordinal=178)
    def getaddrinfo(self, emu, argv, ctx={}):
        """
        INT WSAAPI getaddrinfo(
          PCSTR           pNodeName,
          PCSTR           pServiceName,
          const ADDRINFOA *pHints,
          PADDRINFOA      *ppResult
        );
        """
        pNodeName, pServiceName, pHints, ppResult = argv
        rv = 0

        host = self.read_string(pNodeName)
        argv[0] = host

        service_name = self.read_string(pServiceName)
        argv[1] = service_name
        if service_name.isnumeric():
            port = int(service_name)
        else:
            port = winsock.SERVICE_PORTS.get(service_name)

        if not port:
            return rv

        hints_ai = self.wstypes.addrinfo(emu.get_ptr_size())
        hints_ai = self.mem_cast(hints_ai, pHints)

        # Handles a specific case where an IP address is converted as part of a URL
        # TODO: handle additional cases
        ip_url_re = re.compile(r'https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        match = re.match(ip_url_re, host)
        if match:
            ip_addr = match.group(1)
        else:
            # Use default IP address
            ip_addr = self.netman.name_lookup('default')
            if not ip_addr:
                ip_addr = '127.0.0.1'

        ip_bytes = inet_aton(ip_addr)

        # Populate sockaddr_in
        sockaddr_in = self.wstypes.sockaddr_in(emu.get_ptr_size())
        sockaddr_in.sin_family = hints_ai.ai_family
        sockaddr_in.sin_port = htons(port)
        sockaddr_in.sin_addr = htonl(int(ip_bytes.hex(), 16))
        p_sockaddr = self.mem_alloc(emu.get_ptr_size())
        self.mem_write(p_sockaddr, sockaddr_in.get_bytes())

        # Populate addrinfo with sockaddr_in and pHints data
        addrinfo = self.wstypes.addrinfo(emu.get_ptr_size())
        # TODO: Update ai_flags as additional cases are added
        addrinfo.ai_flags = winsock.AI_NUMERICHOST
        addrinfo.ai_family = hints_ai.ai_family
        addrinfo.ai_socktype = hints_ai.ai_socktype
        addrinfo.ai_protocol = hints_ai.ai_protocol
        addrinfo.ai_addrlen = sockaddr_in.sizeof()
        addrinfo.ai_addr = p_sockaddr

        # Populate ppResult with addrinfo
        pResult = self.mem_alloc(emu.get_ptr_size())
        self.mem_write(pResult, addrinfo.get_bytes())
        self.mem_write(ppResult, pResult.to_bytes(emu.get_ptr_size(), 'little'))

        return rv

    @apihook('freeaddrinfo', argc=1, ordinal=177)
    def freeaddrinfo(self, emu, argv, ctx={}):
        """
        VOID WSAAPI freeaddrinfo(
          PADDRINFOA pAddrInfo
        );
        """
        self.mem_free(argv[0])

        return

    @apihook('getsockopt', argc=5, ordinal=7)
    def getsockopt(self, emu, argv, ctx={}):
        """
        int getsockopt(
          SOCKET s,
          int    level,
          int    optname,
          char   *optval,
          int    *optlen
        );
        """
        s, level, optname, optval, optlen = argv
        rv = 0

        opt_level = winsock.get_define(level, 'SOL_')
        if opt_level:
            argv[1] = opt_level

        opt_len = self.mem_read(optlen, 4)
        opt_len = struct.unpack('<I', opt_len)[0]
        argv[4] = opt_len

        opt_name = winsock.get_define(optname, 'SO_')
        if opt_name:
            argv[2] = opt_name
            if opt_name == 'SO_RCVBUF' or opt_name == 'SO_SNDBUF':
                opt_val = winsock.SOCK_BUF_SIZE
                self.mem_write(optval, opt_val.to_bytes(opt_len, 'little'))

        return rv
