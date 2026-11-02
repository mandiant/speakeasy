from __future__ import annotations

import ctypes as ct
from typing import Annotated, Any

import pytest

import speakeasy.winenv.defs.nt.ntoskrnl as ntdefs
from speakeasy.struct import EmuStruct, Ptr

EXPECTED_32BIT_BYTES = (
    b"\x01\x01\x02\x02\x03\x03\x03\x03\x04\x04\x04\x04\x05\x05"
    b"\x06\x06\x06\x06\x07\x07\x07\x07AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    b"\x08\x08\t\t\t\t\n\n\n\nBBBBBBBBBBBBBBBBBBBBBBBB"
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
    top.NestedStruct.DeepStruct.DeepData = b"A" * 32
    top.NestedStruct.Field2 = 0x0808
    top.Field5 = 0x09090909
    top.Field6 = 0x0A0A0A0A
    top.Field7 = b"B" * 24

    bytez = top.get_bytes()
    assert bytez == EXPECTED_32BIT_BYTES


class WIDE_OR_NARROW(EmuStruct):
    def __init__(self, ptr_size, width):
        super().__init__(ptr_size)
        self.Size = ct.c_uint32
        self.Name = ct.c_uint8 * (4 * width)


def test_struct_layout_follows_constructor_arguments():
    assert WIDE_OR_NARROW(4, 1).sizeof() == 8
    assert WIDE_OR_NARROW(4, 2).sizeof() == 12
    assert WIDE_OR_NARROW(4, 1).sizeof() == 8


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_irp_cast_reads_nested_fields_after_padding(ptr_size: int) -> None:
    irp: Any = ntdefs.IRP(ptr_size)
    irp.IoStatus.Information = 0x1122
    irp.Tail.Overlay.CurrentStackLocation = 0x3344
    copy: Any = ntdefs.IRP(ptr_size).cast(irp.get_bytes())
    assert (copy.IoStatus.Information, copy.Tail.Overlay.CurrentStackLocation) == (0x1122, 0x3344)


class POINT_BY_INIT(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.x = ct.c_int32
        self.y = ct.c_int32


class RECORD_BY_INIT(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        self.Size = ct.c_uint16
        self.Buffer = Ptr
        self.Origin = POINT_BY_INIT
        self.Corners = POINT_BY_INIT * 2
        self.Slots = Ptr * 3
        self.Name = ct.c_uint8 * 6
        if ptr_size == 8:
            self.Padding = ct.c_uint32
        self.Flags = ct.c_uint32


class RECORD(EmuStruct):
    Size: Annotated[int, ct.c_uint16]
    Buffer: Annotated[int, Ptr]
    # POINT comes later in the module
    Origin: POINT
    Corners: Annotated[list[POINT], POINT * 2]
    Slots: Annotated[list[int], Ptr * 3]
    Name: Annotated[bytes, ct.c_uint8 * 6]

    def __init__(self, ptr_size):
        super().__init__(ptr_size)
        if ptr_size == 8:
            self.Padding = ct.c_uint32
        self.Flags = ct.c_uint32


class POINT(EmuStruct):
    x: Annotated[int, ct.c_int32]
    y: Annotated[int, ct.c_int32]


def fill(record: Any) -> bytes:
    record.Size = 0x1122
    record.Buffer = 0x33445566
    record.Origin.y = -2
    record.Corners[1].x = 7
    record.Slots[2] = 0x77
    record.Name = b"abcdef"
    record.Flags = 0x88
    return bytes(record.get_bytes())


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_class_level_fields_give_the_layout_of_init_fields(ptr_size: int) -> None:
    by_init = RECORD_BY_INIT(ptr_size)
    declared = RECORD(ptr_size)
    assert declared.sizeof() == by_init.sizeof()
    assert [name for name, _ in declared.get_cstruct()._fields_] == [name for name, _ in by_init.get_cstruct()._fields_]
    assert fill(declared) == fill(by_init)


class EXTENDED_POINT(POINT):
    z: Annotated[int, ct.c_int32]


def test_class_level_fields_of_a_base_class_come_first() -> None:
    assert [name for name, _ in EXTENDED_POINT(4).get_cstruct()._fields_] == ["x", "y", "z"]
