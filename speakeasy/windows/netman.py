# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

import io
import os
from io import BytesIO
from socket import inet_aton
from typing import TYPE_CHECKING, TypeVar
from urllib.parse import ParseResult, urlparse

from speakeasy.errors import NetworkEmuError
from speakeasy.windows.handles import HandleTable
from speakeasy.winenv.defs.enums import INTERNET_FLAGS, SOCKET_TYPE

if TYPE_CHECKING:
    from speakeasy.config import DnsConfig, NetworkConfig
    from speakeasy.windows.winemu import WindowsEmulator

SOCKET_PROTOCOLS: dict[int, str] = {
    SOCKET_TYPE.SOCK_STREAM: "tcp",
    SOCKET_TYPE.SOCK_DGRAM: "udp",
    SOCKET_TYPE.SOCK_RAW: "raw",
}

T = TypeVar("T", bound="WininetComponent")


def is_ip_address(ip):
    try:
        inet_aton(ip)
        return True
    except Exception:
        return False


def normalize_response_path(path):
    def _get_speakeasy_root():
        return os.path.join(os.path.dirname(__file__), os.pardir)

    root_var = "$ROOT$"

    if root_var in path:
        root = _get_speakeasy_root()
        return path.replace(root_var, root)

    return path


class Socket:
    """Represents a Windows network socket."""

    def __init__(self, family, stype, protocol, flags):
        self.fd: int = 0
        self.family: int = family
        self.type: int = stype
        self.protocol: int = protocol
        self.flags: int = flags
        self.connected_host: str = ""
        self.connected_port: int = 0
        self.curr_packet: BytesIO = BytesIO(b"")

    def set_connection_info(self, host, port):
        self.connected_host = host
        self.connected_port = port

    def get_connection_info(self):
        return (self.connected_host, self.connected_port)

    def get_protocol(self):
        """Get the name of the protocol of the socket type, for example ``tcp``."""
        return SOCKET_PROTOCOLS.get(self.type, "unknown")

    def fill_recv_queue(self, responses):
        for resp in responses:
            mode = getattr(resp, "mode", "") or ""
            if mode.lower() == "default":
                default_resp_path = getattr(resp, "path", None)
                if default_resp_path:
                    default_resp_path = normalize_response_path(default_resp_path)
                    with open(default_resp_path, "rb") as f:
                        self.curr_packet = BytesIO(f.read())

    def get_recv_data(self, size, peek=False):
        data = self.curr_packet.read(size)
        if peek:
            self.curr_packet.seek(-len(data), os.SEEK_CUR)
        return data


class WininetComponent:
    """Base class used for WinInet connections."""

    def __init__(self, handles):
        super().__init__()
        self.handles: HandleTable = handles
        self.handle: int = self.handles.new_handle(self)
        self.children: list[WininetComponent] = []

    def get_handle(self):
        return self.handle


class WininetRequest(WininetComponent):
    """WinInet request object."""

    def __init__(self, handles, session, verb, objname, ver, ref, accepts, flags, ctx):
        super().__init__(handles)

        # The WiniNet APIs default to a HTTP "GET" if no verb is specified
        self.verb: str
        if not verb:
            self.verb = "get"
        else:
            self.verb = verb.lower()

        self.objname: ParseResult = urlparse(objname or "")

        self.session: WininetSession = session

        if not ver:
            ver = "HTTP/1.1"
        self.ver: str = ver
        self.referrer: str | int | None = ref
        self.accept_types: int | None = accepts
        self.flags: int = flags
        self.ctx: int = ctx
        self.response: BytesIO | None = None

    def get_server(self):
        return self.session.server

    def get_port(self):
        return self.session.port

    def get_instance(self):
        return self.session.instance

    def is_secure(self):
        # WINHTTP_FLAG_SECURE has the same value, so this test is also correct for WinHTTP requests
        return bool(self.flags & INTERNET_FLAGS.INTERNET_FLAG_SECURE)

    def format_http_request(self, headers=None):
        request_string = ""
        action = f"{self.verb.upper()} {self.objname.path} {self.ver.upper()}\n"

        request_string += action
        if headers:
            request_string += headers

        inst = self.get_instance()

        host = self.session.server
        request_string += f"Host: {host}\n"

        ua = inst.user_agent
        if ua:
            request_string += f"User-Agent: {ua}\n"

        if self.flags & INTERNET_FLAGS.INTERNET_FLAG_KEEP_CONNECTION:
            request_string += "Connection: Keep-Alive\n"
        else:
            request_string += "Connection: Close\n"

        if self.flags & INTERNET_FLAGS.INTERNET_FLAG_DONT_CACHE:
            request_string += "Cache-Control: no-cache\n"

        return request_string

    def get_response_headers(self):
        """Get the status line and the header lines of the response."""
        return ["HTTP/1.1 200 OK", f"Content-Length: {len(self.get_response().getvalue())}"]

    def get_response_size(self):
        resp = self.get_response()
        off = resp.tell()
        size = len(resp.read())
        resp.seek(off, io.SEEK_SET)
        return size

    def get_response(self):
        """Check the configuration file for a handler for the current WinInet request."""
        cfg = self.get_instance().config

        if self.response:
            return self.response

        http = cfg.http if cfg else None
        if not http:
            raise NetworkEmuError("No HTTP configuration supplied")
        resps = http.responses
        if not resps:
            raise NetworkEmuError("No HTTP responses supplied")

        self.response = None
        default_resp_path = None
        for res in resps:
            verb = res.verb or ""
            if verb.lower() == self.verb:
                resp_files = res.files
                if resp_files:
                    for file in resp_files:
                        mode = file.mode
                        if mode == "by_ext":
                            ext = getattr(file, "ext", "") or ""
                            fn, obj_ext = os.path.splitext(self.objname.path)

                            if ext.lower().strip(".") == obj_ext.lower().strip("."):
                                path = getattr(file, "path", None)
                                if path:
                                    path = normalize_response_path(path)
                                    with open(path, "rb") as f:
                                        self.response = BytesIO(f.read())
                        elif mode == "default":
                            default_resp_path = getattr(file, "path", None)
                            if default_resp_path:
                                default_resp_path = normalize_response_path(default_resp_path)

                    if not self.response and default_resp_path:
                        with open(default_resp_path, "rb") as f:
                            self.response = BytesIO(f.read())

        if self.response is None:
            self.response = BytesIO(b"")

        return self.response


class WininetSession(WininetComponent):
    def __init__(self, handles, instance, server, port, user, password, service, flags, ctx):
        super().__init__(handles)
        self.server: str | int = server
        self.port: int = port
        self.user: str | int = user
        self.password: str | int = password
        self.service: int | str = service
        self.flags: int = flags
        self.ctx: int = ctx

        self.instance: WininetInstance = instance

    def new_request(self, verb, objname, ver, ref, accepts, flags, ctx):
        req = WininetRequest(self.handles, self, verb, objname, ver, ref, accepts, flags, ctx)
        self.children.append(req)
        return req


class WininetInstance(WininetComponent):
    def __init__(self, handles, config, user_agent, access, proxy, bypass, flags):
        super().__init__(handles)
        self.config: NetworkConfig | None = config
        self.user_agent: str | int = user_agent
        self.access: int = access
        self.proxy: str | int = proxy
        self.bypass: str | int = bypass
        self.flags: int = flags

    def new_session(self, server, port, user, password, service, flags, ctx):
        sess = WininetSession(self.handles, self, server, port, user, password, service, flags, ctx)
        self.children.append(sess)
        return sess


class NetworkManager:
    """
    Class that manages network connections during emulation.

    Sockets and WinInet objects are not kernel objects, so their handles are in tables of the
    manager and not in the process handle table. Each WinInet level (instance, session and
    request) has its own handle.

    With an ``emu``, the name lookup, socket and HTTP methods record their events in the report.
    """

    def __init__(self, allocator, config, emu=None):
        super().__init__()
        self.sockets: HandleTable = HandleTable(allocator, release=lambda obj: None)
        self.wininets: HandleTable = HandleTable(allocator, release=lambda obj: None)
        self.config: NetworkConfig = config
        self.dns: DnsConfig | None = None
        self.emu: WindowsEmulator | None = emu

        if config:
            self.dns = config.dns

    def new_socket(self, family, stype, protocol, flags):
        sock = Socket(family, stype, protocol, flags)

        if self.config and self.config.winsock:
            responses = self.config.winsock.responses
            if responses:
                sock.fill_recv_queue(responses)

        sock.fd = self.sockets.new_handle(sock)
        return sock

    def name_lookup(self, domain):
        """Get the IP address of a domain name, or None when the config has no address, and record the lookup."""
        ip = self.get_address(domain)
        if self.emu:
            self.emu.record_dns_event(domain, ip or "")
        return ip

    def get_address(self, domain):
        """Get the IP address of a domain name, or the default address of the config, or None."""
        if not self.dns:
            return None

        names = self.dns.names

        # Do we have an IP for this name?
        if domain.lower() not in names.keys():
            # use the default IP (if any)
            return names.get("default")

        return names.get(domain.lower())

    def get_dns_txt(self, domain):
        """Return a configured DNS TXT record (if any)."""

        def _read_txt_data(txt):
            path = txt.path
            if path:
                path = normalize_response_path(path)
                with open(path, "rb") as f:
                    return f.read()

        if not self.dns:
            return None

        txts = self.dns.txt or []
        txt = [t for t in txts if (t.name or "") == domain]
        if txt:
            return _read_txt_data(txt[0])
        txt = [t for t in txts if (t.name or "") == "default"]
        if txt:
            return _read_txt_data(txt[0])

    def new_wininet_inst(self, user_agent, access, proxy, bypass, flags):
        return WininetInstance(self.wininets, self.config, user_agent, access, proxy, bypass, flags)

    def get_wininet(self, handle, cls: type[T]) -> T | None:
        """Get the WinInet object of an open handle, or None if the handle refers to no ``cls`` object."""
        return self.wininets.get(handle, cls)

    def close_wininet_object(self, handle) -> bool:
        """
        Close a WinInet handle and the open handles of the objects under it.

        Return False if the handle is not an open WinInet handle.
        """
        obj = self.get_wininet(handle, WininetComponent)
        if obj is None:
            return False
        for child in obj.children:
            if child.handle in self.wininets:
                self.close_wininet_object(child.handle)
        return self.wininets.close(handle)

    def get_socket(self, fd) -> Socket | None:
        """Get the socket of an open socket handle, else None."""
        return self.sockets.get(fd, Socket)

    def record_traffic(self, sock, typ, method, data=b""):
        if self.emu:
            host, port = sock.get_connection_info()
            self.emu.record_network_event(host, port, typ=typ, proto=sock.get_protocol(), data=data, method=method)

    def connect(self, sock, host, port):
        """Connect a socket to a remote address."""
        sock.set_connection_info(host, port)
        self.record_traffic(sock, "connect", "winsock.connect")

    def bind(self, sock, host, port):
        """Bind a socket to a local address."""
        sock.set_connection_info(host, port)
        self.record_traffic(sock, "bind", "winsock.bind")

    def accept(self, sock):
        """
        Accept a connection on a listening socket, and return the new socket.

        The peer has the default address of the config, or 127.0.0.1.
        """
        new_sock = self.new_socket(sock.family, sock.type, sock.protocol, 0)
        new_sock.set_connection_info(self.get_address("default") or "127.0.0.1", sock.connected_port)
        self.record_traffic(new_sock, "accept", "winsock.accept")
        return new_sock

    def recv(self, sock, size, peek=False):
        """Get the next data that a socket receives."""
        data = sock.get_recv_data(size, peek)
        self.record_traffic(sock, "data_in", "winsock.recv", data=data)
        return data

    def send(self, sock, data):
        """Send data on a socket."""
        self.record_traffic(sock, "data_out", "winsock.send", data=data)

    def record_http_request(self, server, port, headers="", body=b"", secure=False):
        if self.emu:
            self.emu.record_http_event(server, port, headers=headers, body=body, secure=secure)

    def send_request(self, req, headers=None, body=b""):
        """
        Send an HTTP request.

        A server name gets a name lookup first.
        """
        srv = req.get_server()
        if not is_ip_address(srv):
            self.name_lookup(srv)
        req_str = req.format_http_request(headers=headers)
        self.record_http_request(srv, req.get_port(), headers=req_str, body=body, secure=req.is_secure())

    def open_url(self, inst, url, server, port, headers, flags, ctx):
        """Open a session and a GET request for a URL, and return the request."""
        self.record_http_request(server, port, headers=headers)
        sess = inst.new_session(server, port, "", "", "", flags, ctx)
        return sess.new_request("GET", url, None, None, None, flags, ctx)

    def close_socket(self, fd) -> bool:
        """Close a socket handle. Return False if the socket handle is not open."""
        return self.sockets.close(fd)
