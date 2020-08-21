# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import io
import os
from urllib.parse import urlparse
from io import BytesIO
from speakeasy.errors import NetworkEmuError


def is_empty(bio):
    if len(bio.getbuffer()) == bio.tell():
        return True
    return False


def normalize_response_path(path):
    def _get_speakeasy_root():
        return os.path.join(os.path.dirname(__file__), os.pardir)

    root_var = '$ROOT$'

    if root_var in path:
        root = _get_speakeasy_root()
        return path.replace(root_var, root)

    return path


class Socket(object):
    """
    Represents a Windows network socket
    """
    def __init__(self, fd, family, stype, protocol, flags):
        self.fd = fd
        self.family = family
        self.type = stype
        self.protocol = protocol
        self.flags = flags
        self.connected_host = ''
        self.connected_port = 0
        self.curr_packet = BytesIO(b'')
        self.packet_queue = []

    def get_fd(self):
        return self.fd

    def get_type(self):
        return self.type

    def set_connection_info(self, host, port):
        self.connected_host = host
        self.connected_port = port

    def get_connection_info(self):
        return (self.connected_host, self.connected_port)

    def fill_recv_queue(self, responses):

        for resp in responses:
            mode = resp.get('mode', '')
            if mode.lower() == 'default':
                default_resp_path = resp.get('path')
                if default_resp_path:
                    default_resp_path = normalize_response_path(default_resp_path)
                    with open(default_resp_path, 'rb') as f:
                        self.curr_packet = BytesIO(f.read())

    def get_recv_data(self, size, peek=False):

        data = self.curr_packet.read(size)
        if not peek:
            return data
        elif peek:
            self.curr_packet.seek(-size, os.SEEK_CUR)
        return data


class WSKSocket(Socket):
    """
    Represents a WSK socket used in kernel mode applications
    """
    def __init__(self, fd, family, stype, protocol, flags):
        super(WSKSocket, self).__init__(self, fd, family, stype,
                                        protocol, flags)


class WininetComponent(object):
    """
    Base class used for WinInet connections
    """

    curr_handle = 0x20
    config = None

    def __init__(self):
        super(WininetComponent, self).__init__()
        self.handle = self.new_handle()

    def new_handle(self):
        tmp = WininetComponent.curr_handle
        WininetComponent.curr_handle += 4
        return tmp

    def get_handle(self):
        return self.handle


class WininetRequest(WininetComponent):
    """
    WinInet request object
    """
    def __init__(self, session, verb, objname, ver, ref, accepts, flags, ctx):
        super(WininetRequest, self).__init__()

        # The WiniNet APIs default to a HTTP "GET" if no verb is specified
        if not verb:
            self.verb = 'get'
        else:
            self.verb = verb.lower()

        self.objname = objname
        if not self.objname:
            self.objname = ''
        self.objname = urlparse(self.objname)

        self.session = session

        if not ver:
            ver = 'HTTP/1.1'
        self.ver = ver
        self.referrer = ref
        self.accept_types = accepts
        self.flags = flags
        self.ctx = ctx
        self.response = None

    def get_session(self):
        return self.session

    def get_server(self):
        return self.get_session().server

    def get_port(self):
        return self.get_session().port

    def get_instance(self):
        sess = self.get_session()
        return sess.get_instance()

    def is_secure(self):
        if 'INTERNET_FLAG_SECURE' in self.flags:
            return True
        return False

    def format_http_request(self, headers=None):
        request_string = ''
        action = '%s %s %s\n' % (self.verb.upper(), self.objname.path,
                                 self.ver.upper())

        request_string += action
        if headers:
            request_string += headers

        inst = self.get_instance()
        sess = self.get_session()

        host = sess.server
        request_string += 'Host: %s\n' % (host)

        ua = inst.get_user_agent()
        if ua:
            request_string += 'User-Agent: %s\n' % (ua)

        if 'INTERNET_FLAG_KEEP_CONNECTION' in self.flags:
            request_string += 'Connection: Keep-Alive\n'
        else:
            request_string += 'Connection: Close\n'

        if 'INTERNET_FLAG_DONT_CACHE' in self.flags:
            request_string += 'Cache-Control: no-cache\n'

        return request_string

    def get_response_size(self):
        resp = self.get_response()
        off = resp.tell()
        size = len(resp.read())
        resp.seek(off, io.SEEK_SET)
        return size

    def get_response(self):
        """
        Check the configuration file so see if there is a
        handler for the current WinInet request
        """

        cfg = WininetComponent.config

        if self.response:
            return self.response

        http = cfg.get('http')
        if not http:
            raise NetworkEmuError('No HTTP configuration supplied')
        resps = http.get('responses')
        if not resps:
            raise NetworkEmuError('No HTTP responses supplied')

        self.response = None
        for res in resps:
            verb = res.get('verb', '')
            if verb.lower() == self.verb:

                resp_files = res.get('files', [])
                if resp_files:
                    for file in resp_files:
                        mode = file.get('mode', '')
                        if mode.lower() == 'by_ext':
                            ext = file.get('ext', '')
                            fn, obj_ext = os.path.splitext(self.objname.path)

                            if (ext.lower().strip('.') ==
                               obj_ext.lower().strip('.')):
                                path = file.get('path')
                                path = normalize_response_path(path)

                                with open(path, 'rb') as f:
                                    self.response = BytesIO(f.read())
                        elif mode.lower() == 'default':

                            default_resp_path = file.get('path')
                            default_resp_path = normalize_response_path(default_resp_path)

                    if not self.response and default_resp_path:
                        default_resp_path = normalize_response_path(default_resp_path)
                        with open(default_resp_path, 'rb') as f:
                            self.response = BytesIO(f.read())

        return self.response

    def get_object_path(self):
        return self.objname


class WininetSession(WininetComponent):
    def __init__(self, instance, server, port, user,
                 password, service, flags, ctx):
        super(WininetSession, self).__init__()
        self.server = server
        self.port = port
        self.user = user
        self.password = password
        self.service = service
        self.flags = flags
        self.ctx = ctx
        self.requests = {}

        self.instance = instance

    def get_instance(self):
        return self.instance

    def get_flags(self):
        return self.flags

    def new_request(self, verb, objname, ver, ref, accepts, flags, ctx):
        req = WininetRequest(self, verb, objname, ver, ref,
                             accepts, flags, ctx)
        hdl = req.get_handle()
        self.requests.update({hdl: req})
        return req


class WininetInstance(WininetComponent):
    def __init__(self, user_agent, access, proxy, bypass, flags):
        super(WininetInstance, self).__init__()
        self.user_agent = user_agent
        self.access = access
        self.proxy = proxy
        self.bypass = bypass
        self.flags = flags
        self.sessions = {}

    def get_session(self, sess_handle):
        self.sessions.get(sess_handle)

    def add_session(self, handle, session):
        self.sessions.update({handle: session})

    def new_session(self, server, port, user, password, service, flags, ctx):
        sess = WininetSession(self, server, port, user,
                              password, service, flags, ctx)
        hdl = sess.get_handle()
        self.sessions.update({hdl: sess})
        return sess

    def get_user_agent(self):
        return self.user_agent


class NetworkManager(object):
    """
    Class that manages network connections during emulation
    """
    def __init__(self, config):
        super(NetworkManager, self).__init__()
        self.sockets = {}
        self.wininets = {}
        self.curr_fd = 4
        self.curr_handle = 0x20
        self.config = config
        self.dns = {}

        WininetComponent.config = config
        self.dns = self.config.get('dns')

    def new_socket(self, family, stype, protocol, flags):

        fd = self.curr_fd

        sock = Socket(fd, family, stype, protocol, flags)
        self.curr_fd += 4

        if self.config:
            winsock = self.config.get('winsock')
            if winsock:
                responses = winsock.get('responses')
                if responses:
                    sock.fill_recv_queue(responses)

        self.sockets.update({fd: sock})
        return sock

    def name_lookup(self, domain):

        if not self.dns:
            return None

        names = self.dns.get('names')

        # Do we have an IP for this name?
        if domain.lower() not in names.keys():
            # use the default IP (if any)
            return names.get('default')

        return names.get(domain)

    def get_dns_txt(self, domain):
        """
        Return a configured DNS TXT record (if any)
        """
        def _read_txt_data(txt):
            path = txt.get('path')
            if path:
                path = normalize_response_path(path)
                with open(path, 'rb') as f:
                    return f.read()

        if not self.dns:
            return None

        txts = self.dns.get('txt', [])
        txt = [t for t in txts if t.get('name', '') == domain]
        if txt:
            return _read_txt_data(txt[0])
        txt = [t for t in txts if t.get('name', '') == 'default']
        if txt:
            return _read_txt_data(txt[0])

    def ip_lookup(self, ip):
        for item in self.dns:
            if item['response'] == ip:
                return item['query']
        return None

    def new_wininet_inst(self, user_agent, access, proxy, bypass, flags):
        wini = WininetInstance(user_agent, access, proxy, bypass, flags)

        self.wininets.update({wini.get_handle(): wini})
        return wini

    def get_wininet_object(self, handle):

        for hinst, inst in self.wininets.items():
            if hinst == handle:
                return inst
            for hsess, sess in inst.sessions.items():
                if hsess == handle:
                    return sess
                for hreq, req in sess.requests.items():
                    if hreq == handle:
                        return req

    def close_wininet_object(self, handle):
        if self.wininets.get(handle):
            self.wininets.pop(handle)

    def get_socket(self, fd):
        return self.sockets.get(fd)

    def close_socket(self, fd):
        self.sockets.pop(fd)
