# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

# Address families
AF_UNSPEC = 0
AF_INET = 2
AF_IPX = 6
AF_APPLETALK = 16
AF_NETBIOS = 17
AF_INET6 = 23
AF_IRDA = 26
AF_BTH = 32

# Socket types
SOCK_STREAM = 1
SOCK_DGRAM = 2
SOCK_RAW = 3
SOCK_RDM = 4
SOCK_SEQPACKET = 5

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
WSAENOTSOCK = 10038

MSG_PEEK = 0x2

AI_NUMERICHOST = 4

# Incomplete mapping of services to ports
SERVICE_PORTS = dict(ftp=21, ssh=22, smtp=25, http=80, https=443)

SOL_SOCKET = 0xFFFF

SO_SNDBUF = 0x1001
SO_RCVBUF = 0x1002

SOCK_BUF_SIZE = 0x2000


def get_flag_defines(flags, prefix=''):
    defs = []
    for k, v in globals().items():
        if not isinstance(v, int):
            continue
        if v & flags:
            if prefix and k.startswith(prefix):
                defs.append(k)
    return defs


def get_define(define, prefix=''):
    for k, v in globals().items():
        if not isinstance(v, int) or v != define:
            continue
        if prefix:
            if k.startswith(prefix):
                return k
        else:
            return k


def get_addr_family(define):
    return get_define(define, prefix='AF_')


def get_sock_type(define):
    return get_define(define, prefix='SOCK_')


def get_proto_type(define):
    return get_define(define, prefix='IPPROTO_')
