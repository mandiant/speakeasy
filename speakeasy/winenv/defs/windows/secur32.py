# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from enum import IntEnum


class EXTENDED_NAME_FORMAT(IntEnum):
    NameUnknown = 0
    NameFullyQualifiedDN = 1
    NameSamCompatible = 2
    NameDisplay = 3
    NameUniqueId = 6
    NameCanonical = 7
    NameUserPrincipal = 8
    NameCanonicalEx = 9
    NameServicePrincipal = 10
    NameDnsDomain = 12
    NameGivenName = 13
    NameSurname = 14


SEC_E_INVALID_HANDLE = 0x80090301
