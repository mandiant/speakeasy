# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import unittest
import ctypes as ct

from speakeasy.struct import EmuStruct, Ptr

# These are our ground truth test cases
EXPECTED_32BIT_BYTES = b'\x01\x01\x02\x02\x03\x03\x03\x03\x04\x04\x04\x04\x05\x05' \
                       b'\x06\x06\x06\x06\x07\x07\x07\x07AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
                       b'\x08\x08\t\t\t\t\n\n\n\nBBBBBBBBBBBBBBBBBBBBBBBB'

EXPECTED_64BIT_BYTES = b'\x01\x01\x02\x02\x03\x03\x03\x03\x04\x04\x04\x04\x04\x04\x04\x04\x05\x05'\
                       b'\x06\x06\x06\x06\x07\x07\x07\x07AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
                       b'\x08\x08\t\t\t\t\t\t\t\t\n\n\n\nBBBBBBBBBBBBBBBBBBBBBBBB'


class DEEP_NEST(EmuStruct):
    # Struct nested 2 levels deep
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Field1 = ct.c_uint32
        self.Field2 = ct.c_uint32
        self.DeepData = ct.c_uint8 * 32


class SHALLOW_NEST(EmuStruct):
    # Struct nested 1 level deep
    def __init__(self, ptr_size):
        super().__init__(ptr_size, pack=1)
        self.Field1 = ct.c_uint16
        self.DeepStruct = DEEP_NEST
        self.Field2 = ct.c_uint16


class TOP_OBJECT(EmuStruct):
    # Top level struct containing nested structs
    def __init__(self, ptr_size):
        super().__init__(ptr_size=ptr_size, pack=1)
        self.Field1 = ct.c_uint16
        self.Field2 = ct.c_uint16
        self.Field3 = ct.c_uint32
        self.Field4 = Ptr  # Ptr fields allow you to dynamically create pointer-sized fields
        self.NestedStruct = SHALLOW_NEST
        self.Field5 = Ptr
        self.Field6 = ct.c_uint32
        self.Field7 = ct.c_uint8 * 24


class TestStruct(unittest.TestCase):
    def test_32bit_emit(self):
        '''
        Make sure we can convert arbitrary bytes to a speakeasy emu struct and vice versa
        '''
        # Create a TOP_OBJECT struct with a 32-bit pointer size
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
        self.assertEqual(bytez, EXPECTED_32BIT_BYTES)

    def test_32bit_cast(self):
        '''
        Now lets flip the same test, bytes should be casted into an equally correct 32bit structure
        '''
        # Create a TOP_OBJECT struct with a 32-bit pointer size
        ptr_size = 4
        top = TOP_OBJECT(ptr_size)
        # "cast" raw bytes into a python structure for easy mutation
        top.cast(EXPECTED_32BIT_BYTES)

        # Make sure the struct fields are what we expect
        self.assertEqual(top.Field1, 0x0101)
        self.assertEqual(top.Field2, 0x0202)
        self.assertEqual(top.Field3, 0x03030303)
        self.assertEqual(top.Field4, 0x04040404)
        self.assertEqual(top.NestedStruct.Field1, 0x0505)
        self.assertEqual(top.NestedStruct.DeepStruct.Field1, 0x06060606)
        self.assertEqual(top.NestedStruct.DeepStruct.Field2, 0x07070707)
        self.assertEqual(bytes(top.NestedStruct.DeepStruct.DeepData[:]), b'A' * 32)
        self.assertEqual(top.NestedStruct.Field2, 0x0808)
        self.assertEqual(top.Field5, 0x09090909)
        self.assertEqual(top.Field6, 0x0a0a0a0a)
        self.assertEqual(bytes(top.Field7[:]), b'B' * 24)

    def test_64bit_emit(self):

        '''
        Make sure we can convert arbitrary bytes to a speakeasy emu struct and vice versa
        '''

        # Create a TOP_OBJECT struct with a 64-bit pointer size
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
        self.assertEqual(bytez, EXPECTED_64BIT_BYTES)

    def test_64bit_cast(self):
        '''
        Now lets flip the same test, bytes should be casted into an equally correct 64bit structure
        '''
        # Create a TOP_OBJECT struct with a 64-bit pointer size
        ptr_size = 8
        top = TOP_OBJECT(ptr_size)

        # "cast" raw bytes into a python structure for easy mutation
        top.cast(EXPECTED_64BIT_BYTES)

        # Make sure the struct fields are what we expect
        self.assertEqual(top.Field1, 0x0101)
        self.assertEqual(top.Field2, 0x0202)
        self.assertEqual(top.Field3, 0x03030303)
        self.assertEqual(top.Field4, 0x0404040404040404)
        self.assertEqual(top.NestedStruct.Field1, 0x0505)
        self.assertEqual(top.NestedStruct.DeepStruct.Field1, 0x06060606)
        self.assertEqual(top.NestedStruct.DeepStruct.Field2, 0x07070707)
        self.assertEqual(bytes(top.NestedStruct.DeepStruct.DeepData[:]), b'A' * 32)
        self.assertEqual(top.NestedStruct.Field2, 0x0808)
        self.assertEqual(top.Field5, 0x0909090909090909)
        self.assertEqual(top.Field6, 0x0a0a0a0a)
        self.assertEqual(bytes(top.Field7[:]), b'B' * 24)


if __name__ == '__main__':
    unittest.main()
