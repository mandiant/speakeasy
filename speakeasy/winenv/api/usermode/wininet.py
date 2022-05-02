# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from socket import inet_aton
from urllib.parse import urlparse
import speakeasy.winenv.arch as _arch

import speakeasy.windows.netman as netman
import speakeasy.winenv.defs.wininet as windefs

from .. import api


def is_ip_address(ip):
    try:
        inet_aton(ip)
        return True
    except Exception:
        return False


class Wininet(api.ApiHandler):

    """
    Implements network functions from wininet.dll
    """

    name = 'wininet'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Wininet, self).__init__(emu)

        self.funcs = {}
        self.data = {}
        self.win = None
        self.netman = netman.NetworkManager(config=emu.get_network_config())
        super(Wininet, self).__get_hook_attrs__(self)

    @apihook('InternetOpen', argc=5, conv=_arch.CALL_CONV_STDCALL)
    def InternetOpen(self, emu, argv, ctx={}):
        """
        void InternetOpenA(
          LPTSTR lpszAgent,
          DWORD  dwAccessType,
          LPTSTR lpszProxy,
          LPTSTR lpszProxyBypass,
          DWORD  dwFlags
        );
        """
        ua, access, proxy, bypass, flags = argv

        cw = self.get_char_width(ctx)
        if ua:
            ua = self.read_mem_string(ua, cw)
            argv[0] = ua
        if proxy:
            proxy = self.read_mem_string(proxy, cw)
            argv[2] = proxy
        if bypass:
            bypass = self.read_mem_string(bypass, cw)
            argv[3] = bypass

        conn = self.netman.new_wininet_inst(ua, access, proxy, bypass, flags)
        hnd = conn.get_handle()
        return hnd

    @apihook('InternetConnect', argc=8, conv=_arch.CALL_CONV_STDCALL)
    def InternetConnect(self, emu, argv, ctx={}):
        """
        void InternetConnect(
          HINTERNET     hInternet,
          LPTSTR        lpszServerName,
          INTERNET_PORT nServerPort,
          LPTSTR        lpszUserName,
          LPTSTR        lpszPassword,
          DWORD         dwService,
          DWORD         dwFlags,
          DWORD_PTR     dwContext
        );
        """
        hnd, server, port, user, password, service, flags, dwctx = argv

        cw = self.get_char_width(ctx)
        if server:
            server = self.read_mem_string(server, cw)
            argv[1] = server
        if user:
            user = self.read_mem_string(user, cw)
            argv[3] = user
        if password:
            password = self.read_mem_string(password, cw)
            argv[4] = password

        wini = self.netman.get_wininet_object(hnd)

        if not wini:
            return 0

        sess = wini.new_session(server, port, user, password,
                                service, flags, dwctx)
        hdl = sess.get_handle()
        return hdl

    @apihook('HttpOpenRequest', argc=8, conv=_arch.CALL_CONV_STDCALL)
    def HttpOpenRequest(self, emu, argv, ctx={}):
        """
        void HttpOpenRequest(
          HINTERNET hConnect,
          LPTSTR    lpszVerb,
          LPTSTR    lpszObjectName,
          LPTSTR    lpszVersion,
          LPTSTR    lpszReferrer,
          LPTSTR    *lplpszAcceptTypes,
          DWORD     dwFlags,
          DWORD_PTR dwContext
        );
        """
        hnd, verb, objname, ver, ref, accepts, flags, dwctx = argv

        cw = self.get_char_width(ctx)
        if verb:
            verb = self.read_mem_string(verb, cw)
            argv[1] = verb
        if objname:
            objname = self.read_mem_string(objname, cw)
            argv[2] = objname
        if ver:
            ver = self.read_mem_string(ver, cw)
            argv[3] = ver
        if ref:
            ref = self.read_mem_string(ref, cw)
            argv[4] = ref

        defs = windefs.get_flag_defines(flags)
        argv[6] = ' | '.join(defs)

        sess = self.netman.get_wininet_object(hnd)
        req = sess.new_request(verb, objname, ver, ref, accepts, defs, dwctx)
        hdl = req.get_handle()
        return hdl

    @apihook('InternetCrackUrl', argc=4, conv=_arch.CALL_CONV_STDCALL)
    def InternetCrackUrl(self, emu, argv, ctx={}):
        """
        BOOLAPI InternetCrackUrl(
            LPCSTR            lpszUrl,
            DWORD             dwUrlLength,
            DWORD             dwFlags,
            LPURL_COMPONENTSA lpUrlComponents
        );
        """
        lpszUrl, dwUrlLength, dwFlags, lpUrlComponents = argv

        rv = False
        cw = self.get_char_width(ctx)

        if lpszUrl and lpUrlComponents:
            url = self.read_mem_string(lpszUrl, cw)
            argv[0] = url
            rv = True

            uc = windefs.URL_COMPONENTS(emu.get_ptr_size())
            url_comp = self.mem_cast(uc, lpUrlComponents)

            crack = urlparse(url)
            if crack.scheme == 'https':
                url_comp.nScheme = windefs.INTERNET_SCHEME_HTTPS
            elif crack.scheme == 'http':
                url_comp.nScheme = windefs.INTERNET_SCHEME_HTTP
            if url_comp.dwHostNameLength > 0:
                if url_comp.lpszHostName:
                    host = crack.netloc + '\x00'
                    enc = self.get_encoding(cw)
                    self.mem_write(url_comp.lpszHostName, host.encode(enc))
                else:
                    offset = url.find(crack.netloc)
                    ptr = lpszUrl + (offset * cw)
                    url_comp.lpszHostName = ptr
                    url_comp.dwHostNameLength = len(crack.netloc)

            self.mem_write(lpUrlComponents, url_comp.get_bytes())

        return rv

    @apihook('InternetSetOption', argc=4, conv=_arch.CALL_CONV_STDCALL)
    def InternetSetOption(self, emu, argv, ctx={}):
        """
        BOOLAPI InternetSetOption(
          HINTERNET hInternet,
          DWORD     dwOption,
          LPVOID    lpBuffer,
          DWORD     dwBufferLength
        );
        """
        hnd, option, buf, length = argv

        rv = 1

        return rv

    @apihook('HttpSendRequest', argc=5, conv=_arch.CALL_CONV_STDCALL)
    def HttpSendRequest(self, emu, argv, ctx={}):
        """
        BOOLAPI HttpSendRequest(
          HINTERNET hRequest,
          LPTSTR    lpszHeaders,
          DWORD     dwHeadersLength,
          LPVOID    lpOptional,
          DWORD     dwOptionalLength
        );
        """
        hnd, headers, hdrlen, lpOptional, dwOptionalLength = argv

        body = b''

        cw = self.get_char_width(ctx)
        if headers:
            headers = self.read_mem_string(headers, cw)
            argv[1] = headers

        if lpOptional:
            body = self.mem_read(lpOptional, dwOptionalLength)

        req = self.netman.get_wininet_object(hnd)
        srv = req.get_server()
        port = req.get_port()

        if not is_ip_address(srv):
            self.log_dns(srv)

        rv = 1
        req_str = req.format_http_request(headers=headers)

        self.log_http(srv, port, headers=req_str,
                      body=body, secure=req.is_secure())
        return rv

    @apihook('InternetErrorDlg', argc=5, conv=_arch.CALL_CONV_STDCALL)
    def InternetErrorDlg(self, emu, argv, ctx={}):
        """
        void InternetErrorDlg(
          HWND      hWnd,
          HINTERNET hRequest,
          DWORD     dwError,
          DWORD     dwFlags,
          LPVOID    *lppvData
        );
        """
        hWnd, req, error, flags, data = argv

        return

    @apihook('InternetQueryOption', argc=4)
    def InternetQueryOption(self, emu, argv, ctx={}):
        """
        BOOLAPI InternetQueryOption(
            HINTERNET hInternet,
            DWORD     dwOption,
            LPVOID    lpBuffer,
            LPDWORD   lpdwBufferLength
        );
        """
        hInternet, dwOption, lpBuffer, lpdwBufferLength = argv
        rv = False
        opt = windefs.get_option_define(dwOption)
        if opt:
            argv[1] = opt

        if dwOption == windefs.INTERNET_OPTION_SECURITY_FLAGS:
            if lpBuffer:
                sec_flags = windefs.SECURITY_FLAG_SECURE
                self.mem_write(lpBuffer, (sec_flags).to_bytes(4, 'little'))
                rv = True

        return rv

    @apihook('InternetReadFile', argc=4, conv=_arch.CALL_CONV_STDCALL)
    def InternetReadFile(self, emu, argv, ctx={}):
        """
        BOOLAPI InternetReadFile(
          HINTERNET hFile,
          LPVOID    lpBuffer,
          DWORD     dwNumberOfBytesToRead,
          LPDWORD   lpdwNumberOfBytesRead
        );
        """
        hFile, buf, size, bytes_read = argv

        rv = 1

        req = self.netman.get_wininet_object(hFile)
        resp = req.get_response()
        data = resp.read(size)

        if buf:
            self.mem_write(buf, data)

        if bytes_read:
            self.mem_write(bytes_read, (len(data)).to_bytes(4, 'little'))

        return rv

    @apihook('HttpQueryInfo', argc=5)
    def HttpQueryInfo(self, emu, argv, ctx={}):
        """
        BOOLAPI HttpQueryInfo(
            HINTERNET hRequest,
            DWORD     dwInfoLevel,
            LPVOID    lpBuffer,
            LPDWORD   lpdwBufferLength,
            LPDWORD   lpdwIndex
        );
        """
        hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex = argv
        cw = self.get_char_width(ctx)

        rv = False
        info_str = windefs.get_header_query(dwInfoLevel)
        if info_str:
            argv[1] = info_str
        if not lpBuffer:
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
        if windefs.WINHTTP_QUERY_STATUS_CODE == dwInfoLevel:
            if lpBuffer:
                buf_len = self.mem_read(lpdwBufferLength, 4)
                buf_len = int.from_bytes(buf_len, 'little')

                if cw == 2:
                    enc = 'utf-16le'
                elif cw == 1:
                    enc = 'utf-8'
                out = windefs.HTTP_STATUS_OK.encode(enc)
                self.mem_write(lpBuffer, out)
                rv = True

        return rv

    @apihook('InternetQueryDataAvailable', argc=4)
    def InternetQueryDataAvailable(self, emu, argv, ctx={}):
        """
        BOOLAPI InternetQueryDataAvailable(
            HINTERNET hFile,
            LPDWORD   lpdwNumberOfBytesAvailable,
            DWORD     dwFlags,
            DWORD_PTR dwContext
        );
        """
        hFile, lpdwNumberOfBytesAvailable, dwFlags, dwContext = argv
        rv = False

        req = self.netman.get_wininet_object(hFile)
        avail = req.get_response_size()

        if lpdwNumberOfBytesAvailable:
            self.mem_write(lpdwNumberOfBytesAvailable, (avail.to_bytes(4, 'little')))
            rv = True

        return rv

    @apihook('InternetCloseHandle', argc=1)
    def InternetCloseHandle(self, emu, argv, ctx={}):
        """
        BOOLAPI InternetCloseHandle(
            HINTERNET hInternet
        );
        """
        hInternet, = argv
        rv = True

        self.netman.close_wininet_object(hInternet)

        return rv

    @apihook('InternetOpenUrl', argc=6)
    def InternetOpenUrl(self, emu, argv, ctx={}):
        """
        void InternetOpenUrlA(
            HINTERNET hInternet,
            LPCSTR    lpszUrl,
            LPCSTR    lpszHeaders,
            DWORD     dwHeadersLength,
            DWORD     dwFlags,
            DWORD_PTR dwContext
        );
        """
        hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext = argv
        cw = self.get_char_width(ctx)
        if lpszUrl:
            url = self.read_mem_string(lpszUrl, cw)
            argv[1] = url
        if lpszHeaders:
            headers = self.read_mem_string(lpszHeaders, cw)
            argv[2] = headers

        defs = windefs.get_flag_defines(dwFlags)
        argv[4] = ' | '.join(defs)

        wini = self.netman.get_wininet_object(hInternet)
        if not wini:
            return 0
        crack = urlparse(url)
        if crack.scheme == "http":
            # FIXME : parse port in url netloc
            port = 80
        else:
            port = 443
        self.log_http(crack.netloc, port, headers=lpszHeaders)
        sess = wini.new_session(crack.netloc, port, '', '', '', defs, dwContext)
        if not sess:
            return 0
        req = sess.new_request("GET", url, None, None, None, defs, dwContext)
        return req.get_handle()
