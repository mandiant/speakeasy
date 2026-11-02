# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from typing import TYPE_CHECKING
from urllib.parse import urlparse

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.wininet as windefs
from speakeasy.windows import netman
from speakeasy.winenv.defs.lookup import decode
from speakeasy.winenv.defs.wininet import WINHTTP_OPEN_REQUEST_FLAGS

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator


class WinHttp(api.ApiHandler):
    """
    Implements HTTP functions from winhttp.dll
    """

    name = "winhttp"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs = {}
        self.data = {}
        self.netman: netman.NetworkManager = netman.NetworkManager(emu.handle_allocator, config=emu.config.network)
        super().__get_hook_attrs__(self)

    @apihook("WinHttpOpen", argc=5, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpOpen(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HINTERNET WinHttpOpen(
            LPCWSTR pszAgentW,
            DWORD dwAccessType,
            LPCWSTR pszProxyW,
            LPCWSTR pszProxyBypassW,
            DWORD dwFlags
        );
        """
        pszAgentW: int | str
        pszProxyW: int | str
        pszProxyBypassW: int | str
        pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags = argv

        if pszAgentW:
            pszAgentW = self.read_mem_string(pszAgentW, 2)
            ctx.args["pszAgentW"].display = pszAgentW
        if pszProxyW:
            pszProxyW = self.read_mem_string(pszProxyW, 2)
            ctx.args["pszProxyW"].display = pszProxyW
        if pszProxyBypassW:
            pszProxyBypassW = self.read_mem_string(pszProxyBypassW, 2)
            ctx.args["pszProxyBypassW"].display = pszProxyBypassW

        conn = self.netman.new_wininet_inst(pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags)
        hnd = conn.get_handle()
        return hnd

    @apihook("WinHttpConnect", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpConnect(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HINTERNET WinHttpConnect(
            HINTERNET hSession,
            LPCWSTR pswzServerName,
            INTERNET_PORT nServerPort,
            DWORD dwReserved
        );
        """
        pswzServerName: int | str
        hSession, pswzServerName, nServerPort, dwReserved = argv
        nServerPort &= 0xFFFF

        if pswzServerName:
            pswzServerName = self.read_mem_string(pswzServerName, 2)
            ctx.args["pswzServerName"].display = pswzServerName

        wini = self.netman.get_wininet_object(hSession)

        if not wini:
            return 0

        sess = wini.new_session(pswzServerName, nServerPort, None, None, 0, 0, None)
        hdl = sess.get_handle()
        return hdl

    @apihook("WinHttpOpenRequest", argc=7, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpOpenRequest(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HINTERNET WinHttpOpenRequest(
            HINTERNET hConnect,
            LPCWSTR pwszVerb,
            LPCWSTR pwszObjectName,
            LPCWSTR pwszVersion,
            LPCWSTR pwszReferrer,
            LPCWSTR *ppwszAcceptTypes,
            DWORD dwFlags
        );
        """
        pwszVerb: int | str
        pwszObjectName: int | str
        pwszVersion: int | str
        pwszReferrer: int | str
        ppwszAcceptTypes: int | str
        hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags = argv

        if pwszVerb:
            pwszVerb = self.read_mem_string(pwszVerb, 2)
            ctx.args["pwszVerb"].display = pwszVerb
        if pwszObjectName:
            pwszObjectName = self.read_mem_string(pwszObjectName, 2)
            ctx.args["pwszObjectName"].display = pwszObjectName
        if pwszVersion:
            pwszVersion = self.read_mem_string(pwszVersion, 2)
            ctx.args["pwszVersion"].display = pwszVersion
        if pwszReferrer:
            pwszReferrer = self.read_mem_string(pwszReferrer, 2)
            ctx.args["pwszReferrer"].display = pwszReferrer
        if ppwszAcceptTypes:
            ppwszAcceptTypes = self.read_mem_string(ppwszAcceptTypes, 2)
            ctx.args["ppwszAcceptTypes"].display = ppwszAcceptTypes

        ctx.args["dwFlags"].display = decode(WINHTTP_OPEN_REQUEST_FLAGS, dwFlags)

        sess = self.netman.get_wininet_object(hConnect)
        req = sess.new_request(pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags, None)
        hdl = req.get_handle()

        return hdl

    @apihook("WinHttpGetIEProxyConfigForCurrentUser", argc=1, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpGetIEProxyConfigForCurrentUser(
        self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        BOOL WinHttpGetIEProxyConfigForCurrentUser(
            WINHTTP_CURRENT_USER_IE_PROXY_CONFIG *pProxyConfig
        );
        """
        (pProxyConfig,) = argv

        if pProxyConfig:
            ps = self.get_ptr_size()
            self.mem_write(pProxyConfig, (1).to_bytes(ps, "little") + b"\0" * (3 * ps))

        return True

    @apihook("WinHttpGetProxyForUrl", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpGetProxyForUrl(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL WinHttpGetProxyForUrl(
            HINTERNET hSession,
            LPCWSTR lpcwszUrl,
            WINHTTP_AUTOPROXY_OPTIONS *pAutoProxyOptions,
            WINHTTP_PROXY_INFO *pProxyInfo
        );
        """
        hSession, lpcwszUrl, pAutoProxyOptions, pProxyInfo = argv

        if lpcwszUrl:
            ctx.args["lpcwszUrl"].display = self.read_mem_string(lpcwszUrl, 2)

        if pProxyInfo:
            ps = self.get_ptr_size()
            self.mem_write(pProxyInfo, windefs.WINHTTP_ACCESS_TYPE_NO_PROXY.to_bytes(ps, "little") + b"\0" * (2 * ps))

        return True

    @apihook("WinHttpSetOption", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpSetOption(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL WinHttpSetOption(
            HINTERNET hInternet,
            DWORD dwOption,
            LPVOID lpBuffer,
            DWORD dwBufferLength
        );
        """
        hInternet, dwOption, lpBuffer, dwBufferLength = argv

        return True

    @apihook("WinHttpSendRequest", argc=7, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpSendRequest(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL WinHttpSendRequest(
            HINTERNET hRequest,
            LPCWSTR lpszHeaders,
            DWORD dwHeadersLength,
            LPVOID lpOptional,
            DWORD dwOptionalLength,
            DWORD dwTotalLength,
            DWORD_PTR dwContext
        );
        """
        lpszHeaders: int | str
        hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext = argv

        body = b""

        if lpszHeaders:
            lpszHeaders = self.read_mem_string(lpszHeaders, 2)
            ctx.args["lpszHeaders"].display = lpszHeaders

        if lpOptional and dwOptionalLength:
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

    @apihook("WinHttpReceiveResponse", argc=2, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpReceiveResponse(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL WinHttpReceiveResponse(
            HINTERNET hRequest,
            LPVOID lpReserved
        );
        """
        hRequest, lpReserved = argv

        return True

    @apihook("WinHttpReadData", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpReadData(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL WinHttpReadData(
            HINTERNET hRequest,
            LPVOID lpBuffer,
            DWORD dwNumberOfBytesToRead,
            LPDWORD lpdwNumberOfBytesRead
        );
        """
        hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead = argv

        rv = 1

        req = self.netman.get_wininet_object(hRequest)
        resp = req.get_response()
        data = resp.read(dwNumberOfBytesToRead)

        if lpBuffer:
            self.mem_write(lpBuffer, data)

        if lpdwNumberOfBytesRead:
            self.write_dword(lpdwNumberOfBytesRead, len(data))

        return rv

    @apihook("WinHttpQueryDataAvailable", argc=2, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpQueryDataAvailable(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL WinHttpQueryDataAvailable(
            HINTERNET hRequest,
            LPDWORD lpdwNumberOfBytesAvailable
        );
        """
        hRequest, lpdwNumberOfBytesAvailable = argv

        req = self.netman.get_wininet_object(hRequest)
        avail = req.get_response_size()

        if lpdwNumberOfBytesAvailable:
            self.write_dword(lpdwNumberOfBytesAvailable, avail)

        return True

    @apihook("WinHttpCrackUrl", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpCrackUrl(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL WinHttpCrackUrl(
            LPCWSTR pwszUrl,
            DWORD dwUrlLength,
            DWORD dwFlags,
            LPURL_COMPONENTS lpUrlComponents
        );
        """
        pwszUrl, dwUrlLength, dwFlags, lpUrlComponents = argv
        cw = 2  # Wide
        rv = False
        # TODO : implement flags
        # url = self.read_mem_string(pwszUrl, dwUrlLength)
        if pwszUrl and lpUrlComponents:
            url = self.read_mem_string(pwszUrl, cw)
            ctx.args["pwszUrl"].display = url
            rv = True

            uc = windefs.URL_COMPONENTS(emu.get_ptr_size())
            url_comp = self.mem_cast(uc, lpUrlComponents)

            crack = urlparse(url)
            if crack.scheme == "https":
                url_comp.nScheme = windefs.INTERNET_SCHEME_HTTPS
            elif crack.scheme == "http":
                url_comp.nScheme = windefs.INTERNET_SCHEME_HTTP
            port, parts = windefs.crack_url(url)
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
                    setattr(url_comp, f"lpsz{part}", pwszUrl + offset * cw)
                setattr(url_comp, f"dw{part}Length", len(text))

            self.mem_write(lpUrlComponents, url_comp.get_bytes())

        return rv

    @apihook("WinHttpAddRequestHeaders", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpAddRequestHeaders(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL WinHttpAddRequestHeaders(
            HINTERNET hRequest,
            LPCWSTR lpszHeaders,
            DWORD dwHeadersLength,
            DWORD dwModifiers
        );
        """
        hRequest, lpszHeaders, dwHeadersLength, dwModifiers = argv

        lpszHeaders = self.read_wide_string(lpszHeaders, dwHeadersLength)
        ctx.args["lpszHeaders"].display = lpszHeaders
        flags = windefs.get_header_info_winhttp(dwModifiers)
        ctx.args["dwModifiers"].display = " | ".join(flags)
        rv = 1

        return rv

    @apihook("WinHttpQueryHeaders", argc=6, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpQueryHeaders(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL WinHttpQueryHeaders(
            HINTERNET hRequest,
            DWORD dwInfoLevel,
            LPCWSTR pwszName,
            LPVOID lpBuffer,
            LPDWORD lpdwBufferLength,
            LPDWORD lpdwIndex
        );
        """
        hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwBufferLength, lpdwIndex = argv

        header_id = dwInfoLevel & windefs.HTTP_QUERY_HEADER_MASK
        as_number = bool(dwInfoLevel & windefs.WINHTTP_QUERY_FLAG_NUMBER)
        header_query = windefs.get_header_query(header_id)
        if header_query:
            if as_number:
                header_query += " | WINHTTP_QUERY_FLAG_NUMBER"
            ctx.args["dwInfoLevel"].display = header_query

        if header_id == windefs.WINHTTP_QUERY_STATUS_CODE:
            text = windefs.HTTP_STATUS_OK
        else:
            req = self.netman.get_wininet_object(hRequest)
            if not isinstance(req, netman.WininetRequest):
                emu.set_last_error(windefs.ERROR_INVALID_HANDLE)
                return 0
            text = windefs.get_header_text(header_id, req.get_response_headers())
            if text is None:
                emu.set_last_error(windefs.ERROR_HTTP_HEADER_NOT_FOUND)
                return 0

        if as_number:
            if not text.isdigit():
                emu.set_last_error(windefs.ERROR_HTTP_INVALID_QUERY_REQUEST)
                return 0
            out = int(text).to_bytes(4, "little")
            out_len = len(out)
        else:
            out = (text + "\x00").encode("utf-16le")
            out_len = len(out) - 2
        if lpBuffer == 0 or self.read_dword(lpdwBufferLength) < len(out):
            self.write_dword(lpdwBufferLength, len(out))
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
            return 0
        self.mem_write(lpBuffer, out)
        self.write_dword(lpdwBufferLength, out_len)
        return 1

    @apihook("WinHttpCloseHandle", argc=1, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpCloseHandle(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL WinHttpCloseHandle(
            HINTERNET hInternet
        );
        """
        rv = 1

        return rv
