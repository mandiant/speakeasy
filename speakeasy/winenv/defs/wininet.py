# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct
from speakeasy.struct import EmuStruct, Ptr


INTERNET_FLAG_ASYNC = 0x10000000
INTERNET_FLAG_CACHE_ASYNC = 0x00000080
INTERNET_FLAG_CACHE_IF_NET_FAIL = 0x00010000
INTERNET_FLAG_DONT_CACHE = 0x04000000
INTERNET_FLAG_EXISTING_CONNECT = 0x20000000
INTERNET_FLAG_FORMS_SUBMIT = 0x00000040
INTERNET_FLAG_FROM_CACHE = 0x01000000
INTERNET_FLAG_FWD_BACK = 0x00000020
INTERNET_FLAG_HYPERLINK = 0x00000400
INTERNET_FLAG_IGNORE_CERT_CN_INVALID = 0x00001000
INTERNET_FLAG_IGNORE_CERT_DATE_INVALID = 0x00002000
INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP = 0x00008000
INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS = 0x00004000
INTERNET_FLAG_KEEP_CONNECTION = 0x00400000
INTERNET_FLAG_MAKE_PERSISTENT = 0x02000000
INTERNET_FLAG_MUST_CACHE_REQUEST = 0x00000010
INTERNET_FLAG_NEED_FILE = 0x00000010
INTERNET_FLAG_NO_AUTH = 0x00040000
INTERNET_FLAG_NO_AUTO_REDIRECT = 0x00200000
INTERNET_FLAG_NO_COOKIES = 0x00080000
INTERNET_FLAG_NO_UI = 0x00000200
INTERNET_FLAG_OFFLINE = 0x01000000
INTERNET_FLAG_PASSIVE = 0x08000000
INTERNET_FLAG_PRAGMA_NOCACHE = 0x00000100
INTERNET_FLAG_RAW_DATA = 0x40000000
INTERNET_FLAG_READ_PREFETCH = 0x00100000
INTERNET_FLAG_RELOAD = 0x80000000
INTERNET_FLAG_RESTRICTED_ZONE = 0x00020000
INTERNET_FLAG_RESYNCHRONIZE = 0x00000800
INTERNET_FLAG_SECURE = 0x00800000
INTERNET_FLAG_TRANSFER_ASCII = 0x00000001
INTERNET_FLAG_TRANSFER_BINARY = 0x00000002
INTERNET_NO_CALLBACK = 0x00000000
INTERNET_OPTION_SUPPRESS_SERVER_AUTH = 104
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

HTTP_QUERY_STATUS_CODE = 19
HTTP_STATUS_OK = "200"

INTERNET_OPTION_SECURITY_FLAGS = 31

SECURITY_FLAG_SECURE = 1


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


def get_const_defines(flags, prefix=''):
    defs = []
    for k, v in globals().items():
        if isinstance(v, int):
            if v & flags:
                if prefix:
                    if k.startswith(prefix):
                        defs.append(k)
                else:
                    defs.append(k)
    return defs


def get_flag_defines(flags):
    return get_const_defines(flags, prefix='INTERNET_FLAG')


def get_header_info(info):
    for k, v in globals().items():
        if k.startswith('HTTP_QUERY') and v == info:
            return k


def get_option_define(opt):
    for k, v in globals().items():
        if k.startswith('INTERNET_OPTION_') and v == opt:
            return k
