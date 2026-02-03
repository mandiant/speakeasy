# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import ctypes as ct

from speakeasy.struct import EmuStruct, Ptr


EXPECTED_32BIT_BYTES = (
    b'\x01\x01\x02\x02\x03\x03\x03\x03\x04\x04\x04\x04\x05\x05'
    b'\x06\x06\x06\x06\x07\x07\x07\x07AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    b'\x08\x08\t\t\t\t\n\n\n\nBBBBBBBBBBBBBBBBBBBBBBBB'
)

EXPECTED_64BIT_BYTES = (
    b'\x01\x01\x02\x02\x03\x03\x03\x03\x04\x04\x04\x04\x04\x04\x04\x04\x05\x05'
    b'\x06\x06\x06\x06\x07\x07\x07\x07AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    b'\x08\x08\t\t\t\t\t\t\t\t\n\n\n\nBBBBBBBBBBBBBBBBBBBBBBBB'
)


class DEEP_NEST(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Field1 = ct.c_uint32
        self.Field2 = ct.c_uint32
        self.DeepData = ct.c_uint8 * 32


class SHALLOW_NEST(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size, pack=1)
        self.Field1 = ct.c_uint16
        self.DeepStruct = DEEP_NEST
        self.Field2 = ct.c_uint16


class TOP_OBJECT(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size=ptr_size, pack=1)
        self.Field1 = ct.c_uint16
        self.Field2 = ct.c_uint16
        self.Field3 = ct.c_uint32
        self.Field4 = Ptr
        self.NestedStruct = SHALLOW_NEST
        self.Field5 = Ptr
        self.Field6 = ct.c_uint32
        self.Field7 = ct.c_uint8 * 24


def test_32bit_emit():
    ptr_size = 4
    top = TOP_OBJECT(ptr_size)

    top.Field1 = 0x0101
    top.Field2 = 0x0202
    top.Field3 = 0x03030303
    top.Field4 = 0x04040404
    top.NestedStruct.Field1 = 0x0505
    top.NestedStruct.DeepStruct.Field1 = 0x06060606
    top.NestedStruct.DeepStruct.Field2 = 0x07070707
    top.NestedStruct.DeepStruct.DeepData = b'A' * 32
    top.NestedStruct.Field2 = 0x0808
    top.Field5 = 0x09090909
    top.Field6 = 0x0a0a0a0a
    top.Field7 = b'B' * 24

    bytez = top.get_bytes()
    assert bytez == EXPECTED_32BIT_BYTES


def test_32bit_cast():
    ptr_size = 4
    top = TOP_OBJECT(ptr_size)
    top.cast(EXPECTED_32BIT_BYTES)

    assert top.Field1 == 0x0101
    assert top.Field2 == 0x0202
    assert top.Field3 == 0x03030303
    assert top.Field4 == 0x04040404
    assert top.NestedStruct.Field1 == 0x0505
    assert top.NestedStruct.DeepStruct.Field1 == 0x06060606
    assert top.NestedStruct.DeepStruct.Field2 == 0x07070707
    assert bytes(top.NestedStruct.DeepStruct.DeepData[:]) == b'A' * 32
    assert top.NestedStruct.Field2 == 0x0808
    assert top.Field5 == 0x09090909
    assert top.Field6 == 0x0a0a0a0a
    assert bytes(top.Field7[:]) == b'B' * 24


def test_64bit_emit():
    ptr_size = 8
    top = TOP_OBJECT(ptr_size)

    top.Field1 = 0x0101
    top.Field2 = 0x0202
    top.Field3 = 0x03030303
    top.Field4 = 0x0404040404040404
    top.NestedStruct.Field1 = 0x0505
    top.NestedStruct.DeepStruct.Field1 = 0x06060606
    top.NestedStruct.DeepStruct.Field2 = 0x07070707
    top.NestedStruct.DeepStruct.DeepData = b'A' * 32
    top.NestedStruct.Field2 = 0x0808
    top.Field5 = 0x0909090909090909
    top.Field6 = 0x0a0a0a0a
    top.Field7 = b'B' * 24

    bytez = top.get_bytes()
    assert bytez == EXPECTED_64BIT_BYTES


def test_64bit_cast():
    ptr_size = 8
    top = TOP_OBJECT(ptr_size)
    top.cast(EXPECTED_64BIT_BYTES)

    assert top.Field1 == 0x0101
    assert top.Field2 == 0x0202
    assert top.Field3 == 0x03030303
    assert top.Field4 == 0x0404040404040404
    assert top.NestedStruct.Field1 == 0x0505
    assert top.NestedStruct.DeepStruct.Field1 == 0x06060606
    assert top.NestedStruct.DeepStruct.Field2 == 0x07070707
    assert bytes(top.NestedStruct.DeepStruct.DeepData[:]) == b'A' * 32
    assert top.NestedStruct.Field2 == 0x0808
    assert top.Field5 == 0x0909090909090909
    assert top.Field6 == 0x0a0a0a0a
    assert bytes(top.Field7[:]) == b'B' * 24
