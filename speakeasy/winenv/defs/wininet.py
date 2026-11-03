# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from urllib.parse import urlsplit

from speakeasy.struct import EmuStruct, Ptr
from speakeasy.winenv.defs.enums import WINHTTP_QUERY

INTERNET_NO_CALLBACK = 0x00000000
INTERNET_CONNECTION_MODEM = 0x00000001
INTERNET_CONNECTION_LAN = 0x00000002
INTERNET_CONNECTION_PROXY = 0x00000004
INTERNET_CONNECTION_MODEM_BUSY = 0x00000008
INTERNET_RAS_INSTALLED = 0x00000010
INTERNET_CONNECTION_OFFLINE = 0x00000020
INTERNET_CONNECTION_CONFIGURED = 0x00000040
WININET_API_FLAG_ASYNC = 0x00000001
WININET_API_FLAG_SYNC = 0x00000004
WININET_API_FLAG_USE_CONTEXT = 0x00000008

INTERNET_SCHEME_PARTIAL = -2
INTERNET_SCHEME_UNKNOWN = -1
INTERNET_SCHEME_DEFAULT = 0
INTERNET_SCHEME_FTP = 1
INTERNET_SCHEME_GOPHER = 2
INTERNET_SCHEME_HTTP = 3
INTERNET_SCHEME_HTTPS = 4

HTTP_STATUS_OK = "200"

WINHTTP_ACCESS_TYPE_NO_PROXY = 1

WINHTTP_ADDREQ_INDEX_MASK = 0x0000FFFF
WINHTTP_ADDREQ_FLAGS_MASK = 0xFFFF0000

WINHTTP_QUERY_FLAG_NUMBER = 0x20000000
HTTP_QUERY_FLAG_NUMBER = 0x20000000
HTTP_QUERY_HEADER_MASK = 0xFFFF


SECURITY_FLAG_SECURE = 1

ERROR_HTTP_HEADER_NOT_FOUND = 12150
ERROR_HTTP_INVALID_QUERY_REQUEST = 12154

HEADER_NAMES = {WINHTTP_QUERY.WINHTTP_QUERY_CONTENT_LENGTH: "Content-Length"}


class URL_COMPONENTS(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.dwStructSize = ct.c_uint32
        self.lpszScheme = Ptr
        self.dwSchemeLength = ct.c_uint32
        self.nScheme = ct.c_uint32
        self.lpszHostName = Ptr
        self.dwHostNameLength = ct.c_uint32
        self.nPort = ct.c_uint16
        self.lpszUserName = Ptr
        self.dwUserNameLength = ct.c_uint32
        self.lpszPassword = Ptr
        self.dwPasswordLength = ct.c_uint32
        self.lpszUrlPath = Ptr
        self.dwUrlPathLength = ct.c_uint32
        self.lpszExtraInfo = Ptr
        self.dwExtraInfoLength = ct.c_uint32


def get_header_text(header_id, lines):
    """
    Get the text that a header query gives for a response with a status line and header lines.

    Returns ``None`` when the response does not have the header.
    """
    if header_id == WINHTTP_QUERY.WINHTTP_QUERY_RAW_HEADERS:
        return "".join(line + "\0" for line in lines) + "\0"
    if header_id == WINHTTP_QUERY.WINHTTP_QUERY_RAW_HEADERS_CRLF:
        return "".join(line + "\r\n" for line in lines) + "\r\n"
    name = HEADER_NAMES.get(header_id, "").lower()
    for line in lines[1:]:
        key, _, value = line.partition(":")
        if key.lower() == name:
            return value.strip()
    return None


def crack_url(url):
    """
    Split a URL into ``URL_COMPONENTS`` parts.

    Returns:
        The port and a mapping of component name (``Scheme``, ``HostName``, ``UrlPath``,
        ``ExtraInfo``) to the text and its character offset in ``url``.
    """
    crack = urlsplit(url)
    netloc_start = len(crack.scheme) + 1 if crack.scheme else 0
    if url.startswith("//", netloc_start):
        netloc_start += 2
    host_start = netloc_start + len(crack.netloc.rsplit("@", 1)[0]) + 1 if "@" in crack.netloc else netloc_start
    try:
        port = crack.port
    except ValueError:
        port = None
    host = url[host_start : netloc_start + len(crack.netloc)]
    if port is not None:
        host = host.rsplit(":", 1)[0]
    else:
        port = {"http": 80, "https": 443, "ftp": 21}.get(crack.scheme, 0)
    path_start = netloc_start + len(crack.netloc)
    extra_start = path_start + len(crack.path)
    parts = {
        "Scheme": (url[: len(crack.scheme)], 0),
        "HostName": (host, host_start),
        "UrlPath": (crack.path, path_start),
        "ExtraInfo": (url[extra_start:], extra_start),
    }
    return port, parts
