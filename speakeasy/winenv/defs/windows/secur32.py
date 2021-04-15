# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

# EXTENDED_NAME_FORMAT
NameUnknown = 0
NameFullyQualifiedDN = 1
NameSamCompatible = 2
NameDisplay = 3
NameUniqueId = 6
NameCanonical = 7
NameUserPrincipal = 8
NameCanonicalEx = 9
NameServicePrincipal = 0xA
NameDnsDomain = 0xC
NameGivenName = 0xD
NameSurname = 0xE

SEC_E_INVALID_HANDLE = 0x80090301


def get_define(define, prefix=''):
    for k, v in globals().items():
        if not isinstance(v, int) or v != define:
            continue
        if prefix:
            if k.startswith(prefix):
                return k
        else:
            return k
