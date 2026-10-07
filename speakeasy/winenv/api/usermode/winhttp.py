# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from socket import inet_aton
from typing import Any
from urllib.parse import urlparse

import speakeasy.windows.netman as netman
import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.wininet as windefs

from .. import api


def is_ip_address(ip):
    try:
        inet_aton(ip)
        return True
    except Exception:
        return False


class WinHttp(api.ApiHandler):
    """
    Implements HTTP functions from winhttp.dll
    """

    name = "winhttp"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs: dict[str, Any] = {}
        self.data: dict[str, Any] = {}
        self.win: Any | None = None
        self.netman = netman.NetworkManager(emu.handle_allocator, config=emu.config.network)
        super().__get_hook_attrs__(self)

    @apihook("WinHttpOpen", argc=5, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpOpen(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        WINHTTPAPI HINTERNET WinHttpOpen(
          LPCWSTR pszAgentW,
          DWORD   dwAccessType,
          LPCWSTR pszProxyW,
          LPCWSTR pszProxyBypassW,
          DWORD   dwFlags
        );
        """

        ua, access, proxy, bypass, flags = argv

        if ua:
            ua = self.read_mem_string(ua, 2)
            ctx.args["pszAgentW"].display = ua
        if proxy:
            proxy = self.read_mem_string(proxy, 2)
            ctx.args["pszProxyW"].display = proxy
        if bypass:
            bypass = self.read_mem_string(bypass, 2)
            ctx.args["pszProxyBypassW"].display = bypass

        conn = self.netman.new_wininet_inst(ua, access, proxy, bypass, flags)
        hnd = conn.get_handle()
        return hnd

    @apihook("WinHttpConnect", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpConnect(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        WINHTTPAPI HINTERNET WinHttpConnect(
          IN HINTERNET     hSession,
          IN LPCWSTR       pswzServerName,
          IN INTERNET_PORT nServerPort,
          IN DWORD         dwReserved
        );
        """
        hnd, server, port, reserve = argv

        if server:
            server = self.read_mem_string(server, 2)
            ctx.args["pswzServerName"].display = server

        wini = self.netman.get_wininet_object(hnd)

        if not wini:
            return 0

        sess = wini.new_session(server, port, None, None, 0, 0, None)
        hdl = sess.get_handle()
        return hdl

    @apihook("WinHttpOpenRequest", argc=7, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpOpenRequest(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        WINHTTPAPI HINTERNET WinHttpOpenRequest(
          IN HINTERNET hConnect,
          IN LPCWSTR   pwszVerb,
          IN LPCWSTR   pwszObjectName,
          IN LPCWSTR   pwszVersion,
          IN LPCWSTR   pwszReferrer,
          IN LPCWSTR   *ppwszAcceptTypes,
          IN DWORD     dwFlags
        );
        """
        hnd, verb, objname, ver, ref, accepts, flags = argv

        if verb:
            verb = self.read_mem_string(verb, 2)
            ctx.args["pwszVerb"].display = verb
        if objname:
            objname = self.read_mem_string(objname, 2)
            ctx.args["pwszObjectName"].display = objname
        if ver:
            ver = self.read_mem_string(ver, 2)
            ctx.args["pwszVersion"].display = ver
        if ref:
            ref = self.read_mem_string(ref, 2)
            ctx.args["pwszReferrer"].display = ref
        if accepts:
            accepts = self.read_mem_string(accepts, 2)
            ctx.args["ppwszAcceptTypes"].display = accepts

        defs = windefs.get_flag_defines(flags)
        ctx.args["dwFlags"].display = " | ".join(defs)

        sess = self.netman.get_wininet_object(hnd)
        req = sess.new_request(verb, objname, ver, ref, accepts, defs, None)
        hdl = req.get_handle()

        return hdl

    @apihook("WinHttpGetIEProxyConfigForCurrentUser", argc=1, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpGetIEProxyConfigForCurrentUser(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLAPI WinHttpGetIEProxyConfigForCurrentUser(
          IN OUT WINHTTP_CURRENT_USER_IE_PROXY_CONFIG *pProxyConfig
        );
        """

        (proxy_config,) = argv

        if proxy_config:
            self.mem_write(proxy_config, (1).to_bytes(4, "little"))

        return True

    @apihook("WinHttpGetProxyForUrl", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpGetProxyForUrl(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLAPI WinHttpGetProxyForUrl(
          IN HINTERNET                 hSession,
          IN LPCWSTR                   lpcwszUrl,
          IN WINHTTP_AUTOPROXY_OPTIONS *pAutoProxyOptions,
          OUT WINHTTP_PROXY_INFO       *pProxyInfo
        );
        """

        hnd, url, proxopts, proxinfo = argv

        if url:
            url = self.read_mem_string(url, 2)
            ctx.args["lpcwszUrl"].display = url

        return True

    @apihook("WinHttpSetOption", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpSetOption(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLAPI WinHttpSendRequest(
          IN HINTERNET hRequest,
          LPCWSTR      lpszHeaders,
          IN DWORD     dwHeadersLength,
          LPVOID       lpOptional,
          IN DWORD     dwOptionalLength,
          IN DWORD     dwTotalLength,
          IN DWORD_PTR dwContext
        );
        """
        hnd, option, buff, buflen = argv

        return True

    @apihook("WinHttpSendRequest", argc=7, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpSendRequest(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLAPI WinHttpSendRequest(
          IN HINTERNET hRequest,
          LPCWSTR      lpszHeaders,
          IN DWORD     dwHeadersLength,
          LPVOID       lpOptional,
          IN DWORD     dwOptionalLength,
          IN DWORD     dwTotalLength,
          IN DWORD_PTR dwContext
        );
        """
        hnd, headers, hdrlen, lpOptional, dwOptionalLength, totlen, context = argv

        body = b""

        if headers:
            headers = self.read_mem_string(headers, 2)
            ctx.args["lpszHeaders"].display = headers

        if lpOptional and dwOptionalLength:
            body = self.mem_read(lpOptional, dwOptionalLength)

        req = self.netman.get_wininet_object(hnd)
        srv = req.get_server()
        port = req.get_port()

        if not is_ip_address(srv):
            self.record_dns_event(srv)

        rv = 1
        req_str = req.format_http_request(headers=headers)

        self.record_http_event(srv, port, headers=req_str, body=body, secure=req.is_secure())
        return rv

    @apihook("WinHttpReceiveResponse", argc=2, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpReceiveResponse(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        WINHTTPAPI BOOL WinHttpReceiveResponse(
          IN HINTERNET hRequest,
          IN LPVOID    lpReserved
        );
        """
        hnd, lpReserved = argv

        return True

    @apihook("WinHttpReadData", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpReadData(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLAPI WinHttpReadData(
          IN HINTERNET hRequest,
          LPVOID       lpBuffer,
          IN DWORD     dwNumberOfBytesToRead,
          OUT LPDWORD  lpdwNumberOfBytesRead
        );
        """
        hnd, buf, size, bytes_read = argv

        rv = 1

        req = self.netman.get_wininet_object(hnd)
        resp = req.get_response()
        data = resp.read(size)

        if buf:
            self.mem_write(buf, data)

        if bytes_read:
            self.mem_write(bytes_read, (len(data)).to_bytes(4, "little"))

        return rv

    @apihook("WinHttpCrackUrl", argc=4, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpCrackUrl(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLAPI WinHttpCrackUrl(
            LPCWSTR          pwszUrl,
            DWORD            dwUrlLength,
            DWORD            dwFlags,
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
    def WinHttpAddRequestHeaders(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLAPI WinHttpAddRequestHeaders(
          HINTERNET hRequest,
          LPCWSTR   lpszHeaders,
          DWORD     dwHeadersLength,
          DWORD     dwModifiers
        );
        """
        hnd, headers, dwHeaderlen, dwModfier = argv

        headers = self.read_wide_string(headers, dwHeaderlen)
        ctx.args["lpszHeaders"].display = headers
        flags = windefs.get_header_info_winhttp(dwModfier)
        ctx.args["dwModifiers"].display = " | ".join(flags)
        rv = 1

        return rv

    @apihook("WinHttpQueryHeaders", argc=6, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpQueryHeaders(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLAPI WinHttpQueryHeaders(
           HINTERNET hRequest,
           DWORD     dwInfoLevel,
           LPCWSTR   pwszName,
           LPVOID    lpBuffer,
           LPDWORD   lpdwBufferLength,
           LPDWORD   lpdwIndex
         );
        """
        hnd, dwInfoLevel, name, buffer, bufferLen, index = argv

        header_id = dwInfoLevel & windefs.HTTP_QUERY_HEADER_MASK
        as_number = bool(dwInfoLevel & windefs.WINHTTP_QUERY_FLAG_NUMBER)
        header_query = windefs.get_header_query(header_id)
        if header_query:
            if as_number:
                header_query += " | WINHTTP_QUERY_FLAG_NUMBER"
            ctx.args["dwInfoLevel"].display = header_query

        if header_id == windefs.WINHTTP_QUERY_STATUS_CODE:
            if as_number:
                out = int(windefs.HTTP_STATUS_OK).to_bytes(4, "little")
                out_len = len(out)
            else:
                out = (windefs.HTTP_STATUS_OK + "\x00").encode("utf-16le")
                out_len = len(out) - 2
            if buffer == 0 or int.from_bytes(self.mem_read(bufferLen, 4), "little") < len(out):
                self.mem_write(bufferLen, len(out).to_bytes(4, "little"))
                emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
                return 0
            self.mem_write(buffer, out)
            self.mem_write(bufferLen, out_len.to_bytes(4, "little"))
            return 1

        if buffer == 0:
            emu.set_last_error(windefs.ERROR_INSUFFICIENT_BUFFER)
            return 0

        rv = 1

        return rv

    @apihook("WinHttpCloseHandle", argc=1, conv=_arch.CALL_CONV_STDCALL)
    def WinHttpCloseHandle(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOLAPI WinHttpCloseHandle(
          HINTERNET hInternet
        );
        """
        rv = 1

        return rv
