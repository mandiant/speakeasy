# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from enum import IntEnum


class ADDRESS_FAMILY(IntEnum):
    AF_INET = 2
    AF_INET6 = 23
    AF_UNSPEC = 0


class SOCKET_TYPE(IntEnum):
    """The socket types of the SOCK_* constants. The SDK has no enum type for them."""

    SOCK_STREAM = 1
    SOCK_DGRAM = 2
    SOCK_RAW = 3
    SOCK_RDM = 4
    SOCK_SEQPACKET = 5


class SOCKET_OPTION_LEVEL(IntEnum):
    """The option levels of getsockopt and setsockopt that the handlers know. The SDK has no enum type for them."""

    SOL_SOCKET = 0xFFFF


class SOCKET_OPTION(IntEnum):
    """The SOL_SOCKET options that the handlers know. The SDK has no enum type for them."""

    SO_SNDBUF = 0x1001
    SO_RCVBUF = 0x1002


# Protocol types
IPPROTO_ICMP = 1
IPPROTO_IGMP = 2
BTHPROTO_RFCOMM = 3
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58
IPPROTO_RM = 113

WSA_FLAG_OVERLAPPED = 1
WSA_FLAG_ACCESS_SYSTEM_SECURITY = 0x40
WSA_FLAG_NO_HANDLE_INHERIT = 0x80

HOST_NOT_FOUND = 11001
SOCKET_ERROR = 0xFFFFFFFF
WSAEFAULT = 10014
WSAENOTSOCK = 10038
WSAENOTCONN = 10057
WSATYPE_NOT_FOUND = 10109

MSG_PEEK = 0x2

INADDR_NONE = 0xFFFFFFFF

AI_NUMERICHOST = 4

# Incomplete mapping of services to ports
SERVICE_PORTS = dict(ftp=21, ssh=22, smtp=25, http=80, https=443)

SOCK_BUF_SIZE = 0x2000
