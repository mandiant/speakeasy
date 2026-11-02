# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from typing import TYPE_CHECKING
from urllib.parse import urlparse

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.wininet as windefs
from speakeasy.windows import netman
from speakeasy.winenv.defs.lookup import decode
from speakeasy.winenv.defs.wininet import INTERNET_FLAGS

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator

ERROR_INTERNET_UNRECOGNIZED_SCHEME = 12006
DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21}


class Wininet(api.ApiHandler):
    """
    Implements network functions from wininet.dll
    """

    name = "wininet"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs = {}
        self.data = {}
        self.netman: netman.NetworkManager = netman.NetworkManager(emu.handle_allocator, config=emu.config.network)
        super().__get_hook_attrs__(self)

    @apihook("InternetOpen", argc=5, conv=_arch.CALL_CONV_STDCALL)
    def InternetOpen(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HINTERNET InternetOpen(
            LPCTSTR lpszAgent,
            DWORD dwAccessType,
            LPCTSTR lpszProxy,
            LPCTSTR lpszProxyBypass,
            DWORD dwFlags
        );
        """
        lpszAgent: int | str
        lpszProxy: int | str
        lpszProxyBypass: int | str
        lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags = argv

        cw = self.get_char_width(ctx)
        if lpszAgent:
            lpszAgent = self.read_mem_string(lpszAgent, cw)
            ctx.args["lpszAgent"].display = lpszAgent
        if lpszProxy:
            lpszProxy = self.read_mem_string(lpszProxy, cw)
            ctx.args["lpszProxy"].display = lpszProxy
        if lpszProxyBypass:
            lpszProxyBypass = self.read_mem_string(lpszProxyBypass, cw)
            ctx.args["lpszProxyBypass"].display = lpszProxyBypass

        conn = self.netman.new_wininet_inst(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags)
        hnd = conn.get_handle()
        return hnd

    @apihook("InternetConnect", argc=8, conv=_arch.CALL_CONV_STDCALL)
    def InternetConnect(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HINTERNET InternetConnect(
            HINTERNET hInternet,
            LPCTSTR lpszServerName,
            INTERNET_PORT nServerPort,
            LPCTSTR lpszUserName,
            LPCTSTR lpszPassword,
            DWORD dwService,
            DWORD dwFlags,
            DWORD_PTR dwContext
        );
        """
        lpszServerName: int | str
        lpszUserName: int | str
        lpszPassword: int | str
        hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext = argv
        nServerPort &= 0xFFFF

        cw = self.get_char_width(ctx)
        if lpszServerName:
            lpszServerName = self.read_mem_string(lpszServerName, cw)
            ctx.args["lpszServerName"].display = lpszServerName
        if lpszUserName:
            lpszUserName = self.read_mem_string(lpszUserName, cw)
            ctx.args["lpszUserName"].display = lpszUserName
        if lpszPassword:
            lpszPassword = self.read_mem_string(lpszPassword, cw)
            ctx.args["lpszPassword"].display = lpszPassword

        wini = self.netman.get_wininet_object(hInternet)

        if not wini:
            return 0

        sess = wini.new_session(lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext)
        hdl = sess.get_handle()
        return hdl

    @apihook("HttpOpenRequest", argc=8, conv=_arch.CALL_CONV_STDCALL)
    def HttpOpenRequest(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HINTERNET HttpOpenRequest(
            HINTERNET hConnect,
            LPCTSTR lpszVerb,
            LPCTSTR lpszObjectName,
            LPCTSTR lpszVersion,
            LPCTSTR lpszReferrer,
            LPCTSTR *lplpszAcceptTypes,
            DWORD dwFlags,
            DWORD_PTR dwContext
        );
        """
        lpszVerb: int | str
        lpszObjectName: int | str
        lpszVersion: int | str
        lpszReferrer: int | str
        hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext = argv

        cw = self.get_char_width(ctx)
        if lpszVerb:
            lpszVerb = self.read_mem_string(lpszVerb, cw)
            ctx.args["lpszVerb"].display = lpszVerb
        if lpszObjectName:
            lpszObjectName = self.read_mem_string(lpszObjectName, cw)
            ctx.args["lpszObjectName"].display = lpszObjectName
        if lpszVersion:
            lpszVersion = self.read_mem_string(lpszVersion, cw)
            ctx.args["lpszVersion"].display = lpszVersion
        if lpszReferrer:
            lpszReferrer = self.read_mem_string(lpszReferrer, cw)
            ctx.args["lpszReferrer"].display = lpszReferrer

        ctx.args["dwFlags"].display = decode(INTERNET_FLAGS, dwFlags)

        sess = self.netman.get_wininet_object(hConnect)
        req = sess.new_request(
            lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext
        )
        hdl = req.get_handle()
        return hdl

    @apihook("InternetCrackUrl", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def InternetCrackUrl(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL InternetCrackUrl(
            LPCTSTR lpszUrl,
            DWORD dwUrlLength,
            DWORD dwFlags,
            LPURL_COMPONENTS lpUrlComponents
        );
        """
        lpszUrl, dwUrlLength, dwFlags, lpUrlComponents = argv

        rv = False
        cw = self.get_char_width(ctx)

        if lpszUrl and lpUrlComponents:
            url = self.read_mem_string(lpszUrl, cw)
            ctx.args["lpszUrl"].display = url
            rv = True

            uc = windefs.URL_COMPONENTS(emu.get_ptr_size())
            url_comp = self.mem_cast(uc, lpUrlComponents)

            crack = urlparse(url)
            if crack.scheme == "https":
                url_comp.nScheme = windefs.INTERNET_SCHEME_HTTPS
            elif crack.scheme == "http":
                url_comp.nScheme = windefs.INTERNET_SCHEME_HTTP
            port, parts = windefs.crack_url(url)
            if not url_comp.dwExtraInfoLength:
                path_start = parts["UrlPath"][1]
                parts["UrlPath"] = (url[path_start:], path_start)
            url_comp.nPort = port
            for part, (text, offset) in parts.items():
                length = getattr(url_comp, f"dw{part}Length")
                if not length:
                    continue
                buf = getattr(url_comp, f"lpsz{part}")
                if buf:
                    if length <= len(text):
                        setattr(url_comp, f"dw{part}Length", len(text) + 1)
                        self.mem_write(lpUrlComponents, url_comp.get_bytes())
                        emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
                        return False
                    self.write_mem_string(text, buf, cw)
                else:
                    setattr(url_comp, f"lpsz{part}", lpszUrl + offset * cw)
                setattr(url_comp, f"dw{part}Length", len(text))

            self.mem_write(lpUrlComponents, url_comp.get_bytes())

        return rv

    @apihook("InternetSetOption", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def InternetSetOption(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL InternetSetOption(
            HINTERNET hInternet,
            DWORD dwOption,
            LPVOID lpBuffer,
            DWORD dwBufferLength
        );
        """
        hInternet, dwOption, lpBuffer, dwBufferLength = argv

        rv = 1

        return rv

    @apihook("InternetGetConnectedState", argc=2, conv=_arch.CALL_CONV_STDCALL)
    def InternetGetConnectedState(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL InternetGetConnectedState(
            LPDWORD lpdwFlags,
            DWORD dwReserved
        );
        """
        lpdwFlags, dwReserved = argv

        rv = True
        flags = windefs.INTERNET_CONNECTION_LAN

        if lpdwFlags:
            self.write_dword(lpdwFlags, flags)
            ctx.args["lpdwFlags"].display = "INTERNET_CONNECTION_LAN"

        return rv

    @apihook("HttpSendRequest", argc=5, conv=_arch.CALL_CONV_STDCALL)
    def HttpSendRequest(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL HttpSendRequest(
            HINTERNET hRequest,
            LPCTSTR lpszHeaders,
            DWORD dwHeadersLength,
            LPVOID lpOptional,
            DWORD dwOptionalLength
        );
        """
        lpszHeaders: int | str
        hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength = argv

        body = b""

        cw = self.get_char_width(ctx)
        if lpszHeaders:
            lpszHeaders = self.read_mem_string(lpszHeaders, cw)
            ctx.args["lpszHeaders"].display = lpszHeaders

        if lpOptional:
            body = self.mem_read(lpOptional, dwOptionalLength)

        req = self.netman.get_wininet_object(hRequest)
        srv = req.get_server()
        port = req.get_port()

        if not netman.is_ip_address(srv):
            self.record_dns_event(srv)

        rv = 1
        req_str = req.format_http_request(headers=lpszHeaders)

        self.record_http_event(srv, port, headers=req_str, body=body, secure=req.is_secure())
        return rv

    @apihook("InternetErrorDlg", argc=5, conv=_arch.CALL_CONV_STDCALL)
    def InternetErrorDlg(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD InternetErrorDlg(
            HWND hWnd,
            HINTERNET hRequest,
            DWORD dwError,
            DWORD dwFlags,
            LPVOID *lppvData
        );
        """
        hWnd, hRequest, dwError, dwFlags, lppvData = argv

    @apihook("InternetQueryOption", argc=4)
    def InternetQueryOption(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL InternetQueryOption(
            HINTERNET hInternet,
            DWORD dwOption,
            LPVOID lpBuffer,
            LPDWORD lpdwBufferLength
        );
        """
        hInternet, dwOption, lpBuffer, lpdwBufferLength = argv
        rv = False
        opt = windefs.get_option_define(dwOption)
        if opt:
            ctx.args["dwOption"].display = opt

        if dwOption == windefs.INTERNET_OPTION_SECURITY_FLAGS:
            if lpBuffer:
                sec_flags = windefs.SECURITY_FLAG_SECURE
                self.write_dword(lpBuffer, sec_flags)
                rv = True

        return rv

    @apihook("InternetReadFile", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def InternetReadFile(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL InternetReadFile(
            HINTERNET hFile,
            LPVOID lpBuffer,
            DWORD dwNumberOfBytesToRead,
            LPDWORD lpdwNumberOfBytesRead
        );
        """
        hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead = argv

        rv = 1

        req = self.netman.get_wininet_object(hFile)
        if not isinstance(req, netman.WininetRequest):
            emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
            return False
        resp = req.get_response()
        data = resp.read(dwNumberOfBytesToRead)

        if lpBuffer:
            self.mem_write(lpBuffer, data)

        if lpdwNumberOfBytesRead:
            self.write_dword(lpdwNumberOfBytesRead, len(data))

        return rv

    @apihook("HttpQueryInfo", argc=5)
    def HttpQueryInfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL HttpQueryInfo(
            HINTERNET hRequest,
            DWORD dwInfoLevel,
            LPVOID lpBuffer,
            LPDWORD lpdwBufferLength,
            LPDWORD lpdwIndex
        );
        """
        hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex = argv
        cw = self.get_char_width(ctx)

        header_id = dwInfoLevel & windefs.HTTP_QUERY_HEADER_MASK
        as_number = bool(dwInfoLevel & windefs.WINHTTP_QUERY_FLAG_NUMBER)
        info_str = windefs.get_header_query(header_id)
        if info_str:
            if as_number:
                info_str += " | WINHTTP_QUERY_FLAG_NUMBER"
            ctx.args["dwInfoLevel"].display = info_str

        if header_id == windefs.WINHTTP_QUERY_STATUS_CODE:
            text = windefs.HTTP_STATUS_OK
        else:
            req = self.netman.get_wininet_object(hRequest)
            if not isinstance(req, netman.WininetRequest):
                emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
                return False
            text = windefs.get_header_text(header_id, req.get_response_headers())
            if text is None:
                emu.set_last_error(windefs.ERROR_HTTP_HEADER_NOT_FOUND)
                return False

        if as_number:
            if not text.isdigit():
                emu.set_last_error(windefs.ERROR_HTTP_INVALID_QUERY_REQUEST)
                return False
            out = int(text).to_bytes(4, "little")
            out_len = len(out)
        else:
            out = (text + "\x00").encode(self.get_encoding(cw))
            out_len = len(out) - cw
        if not lpBuffer or self.read_dword(lpdwBufferLength) < len(out):
            self.write_dword(lpdwBufferLength, len(out))
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
            return False
        self.mem_write(lpBuffer, out)
        self.write_dword(lpdwBufferLength, out_len)
        return True

    @apihook("InternetQueryDataAvailable", argc=4)
    def InternetQueryDataAvailable(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL InternetQueryDataAvailable(
            HINTERNET hFile,
            LPDWORD lpdwNumberOfBytesAvailable,
            DWORD dwFlags,
            DWORD_PTR dwContext
        );
        """
        hFile, lpdwNumberOfBytesAvailable, dwFlags, dwContext = argv
        rv = False

        req = self.netman.get_wininet_object(hFile)
        avail = req.get_response_size()

        if lpdwNumberOfBytesAvailable:
            self.write_dword(lpdwNumberOfBytesAvailable, avail)
            rv = True

        return rv

    @apihook("InternetCloseHandle", argc=1)
    def InternetCloseHandle(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL InternetCloseHandle(
            HINTERNET hInternet
        );
        """
        (hInternet,) = argv
        rv = True

        self.netman.close_wininet_object(hInternet)

        return rv

    @apihook("InternetOpenUrl", argc=6)
    def InternetOpenUrl(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HINTERNET InternetOpenUrl(
            HINTERNET hInternet,
            LPCTSTR lpszUrl,
            LPCTSTR lpszHeaders,
            DWORD dwHeadersLength,
            DWORD dwFlags,
            DWORD_PTR dwContext
        );
        """
        hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext = argv
        cw = self.get_char_width(ctx)
        if not lpszUrl:
            return 0
        url = self.read_mem_string(lpszUrl, cw)
        ctx.args["lpszUrl"].display = url
        headers = ""
        if lpszHeaders:
            headers = self.read_mem_string(lpszHeaders, cw)
            ctx.args["lpszHeaders"].display = headers

        ctx.args["dwFlags"].display = decode(INTERNET_FLAGS, dwFlags)

        wini = self.netman.get_wininet_object(hInternet)
        if not wini:
            return 0
        crack = urlparse(url)
        default_port = DEFAULT_PORTS.get(crack.scheme.lower())
        server = crack.netloc.rpartition("@")[2]
        if default_port is None or not server:
            emu.set_last_error(ERROR_INTERNET_UNRECOGNIZED_SCHEME)
            return 0
        try:
            explicit_port = crack.port
        except ValueError:
            explicit_port = None
        port = explicit_port or default_port
        if explicit_port:
            server = server.rpartition(":")[0]
        self.record_http_event(server, port, headers=headers)
        sess = wini.new_session(server, port, "", "", "", dwFlags, dwContext)
        if not sess:
            return 0
        req = sess.new_request("GET", url, None, None, None, dwFlags, dwContext)
        return req.get_handle()
