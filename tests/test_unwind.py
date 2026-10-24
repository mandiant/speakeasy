"""x64 unwinding of synthetic unwind data, following RtlVirtualUnwind."""

import struct

import pytest

import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.windows import unwind

BASE = 0x10000
STACK = BASE + 0x8000
HANDLER = 0x5000

# A primary function with an rbp frame: push rbp; mov rbp, rsp
PRIMARY = unwind.RuntimeFunction(BASE, 0, 0x1000, 0x1100, 0x3000)
PRIMARY_INFO = bytes([1 | unwind.UNW_FLAG_EHANDLER << 3, 4, 2, 5])  # prolog 4, two codes, frame register rbp
PRIMARY_INFO += bytes([4, unwind.UWOP_SET_FPREG, 1, 5 << 4 | unwind.UWOP_PUSH_NONVOL])
PRIMARY_INFO += struct.pack("<I", HANDLER)


def chained_info(parent: unwind.RuntimeFunction, frame_register: int = 5) -> bytes:
    """Unwind data of a fragment of parent, without codes of its own."""
    return bytes([1 | unwind.UNW_FLAG_CHAININFO << 3, 0, 0, frame_register]) + struct.pack(
        "<III", parent.begin, parent.end, parent.unwind_info
    )


def unwinding(*infos: tuple[int, bytes]):
    """A reader of memory holding infos at their RVAs, and a frame: rbp at STACK, saved rbp, return address."""
    memory = bytearray(0x10000)
    for rva, info in infos:
        memory[rva : rva + len(info)] = info
    memory[STACK - BASE : STACK - BASE + 16] = struct.pack("<QQ", 0x1234, 0x7777)
    ctx = windefs.CONTEXT64(8)
    ctx.Rsp, ctx.Rbp = STACK - 0x40, STACK
    return (lambda address, size: bytes(memory[address - BASE : address - BASE + size])), ctx


@pytest.mark.parametrize("frame_register", [5, 0])
def test_chained_fragment_unwinds_with_the_primary(frame_register):
    fragment = unwind.RuntimeFunction(BASE, 0, 0x2000, 0x2100, 0x3100)
    read, ctx = unwinding((0x3000, PRIMARY_INFO), (0x3100, chained_info(PRIMARY, frame_register)))

    info = unwind.virtual_unwind(read, fragment, BASE + 0x2010, ctx, unwind.UNW_FLAG_EHANDLER)

    assert (ctx.Rip, ctx.Rsp, ctx.Rbp) == (0x7777, STACK + 16, 0x1234)
    assert info.handler == BASE + HANDLER
    assert info.establisher_frame == (STACK if frame_register else STACK - 0x40)


def test_fragment_before_its_primary_unwinds_every_code():
    # An indirect entry resolves to the primary, whose begin is after pc
    read, ctx = unwinding((0x3000, PRIMARY_INFO))

    info = unwind.virtual_unwind(read, PRIMARY, BASE + 0x800, ctx, unwind.UNW_FLAG_EHANDLER)

    assert (ctx.Rip, ctx.Rsp, ctx.Rbp) == (0x7777, STACK + 16, 0x1234)
    assert info.handler == BASE + HANDLER


def test_prolog_has_no_handler():
    # After push rbp, before mov rbp, rsp
    read, ctx = unwinding((0x3000, PRIMARY_INFO))
    ctx.Rsp = STACK

    info = unwind.virtual_unwind(read, PRIMARY, BASE + 0x1001, ctx, unwind.UNW_FLAG_EHANDLER)

    assert (ctx.Rip, ctx.Rsp, ctx.Rbp) == (0x7777, STACK + 16, 0x1234)
    assert info.handler == 0


def test_cyclic_chain_is_an_error():
    fragment = unwind.RuntimeFunction(BASE, 0, 0x2000, 0x2100, 0x3100)
    read, ctx = unwinding((0x3100, chained_info(fragment)))

    with pytest.raises(unwind.UnwindError):
        unwind.virtual_unwind(read, fragment, BASE + 0x2010, ctx)
