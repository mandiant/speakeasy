# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from socket import inet_ntoa, ntohs, htons, ntohl, htonl, inet_aton

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

        return 0

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

        hostent = 0
        ip = self.netman.name_lookup(name)

        if ip:
            hostent = self.wstypes.hostent(emu.get_ptr_size())
            buflen = len(name)
            buflen += 8
            buflen += len(ip)
            ptr_hostent = self.mem_alloc(buflen, tag='api.struct.HOSTENT')
            hostent.h_name = argv[0]
            hostent.h_length = len(ip)
            ip_bytes = inet_aton(ip)
            ptr_h_addr = self.mem_alloc(len(ip_bytes)*3, tag='api.struct.HOSTENT.h_addr')

            ptr = (ptr_h_addr + self.get_ptr_size())
            self.mem_write(ptr_h_addr, ptr.to_bytes(self.get_ptr_size(), 'little'))
            self.mem_write(ptr, ip_bytes)
            hostent.h_addr_list = ptr_h_addr

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
