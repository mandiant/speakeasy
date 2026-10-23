"""
x64 table-based unwinding: RtlLookupFunctionEntry and RtlVirtualUnwind.

These operate on guest memory through a ``read(address, size) -> bytes``
callable and on a CONTEXT64 struct that is unwound in place, so they serve
both the exception dispatcher and the API handlers of the same name.

See https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
"""

import bisect
import struct
from collections.abc import Callable
from dataclasses import dataclass

Reader = Callable[[int, int], bytes]

UNW_FLAG_EHANDLER = 1
UNW_FLAG_UHANDLER = 2
UNW_FLAG_CHAININFO = 4

UWOP_PUSH_NONVOL = 0
UWOP_ALLOC_LARGE = 1
UWOP_ALLOC_SMALL = 2
UWOP_SET_FPREG = 3
UWOP_SAVE_NONVOL = 4
UWOP_SAVE_NONVOL_FAR = 5
UWOP_SAVE_XMM128 = 8
UWOP_SAVE_XMM128_FAR = 9
UWOP_PUSH_MACHFRAME = 10

# CONTEXT64 field for each UNWIND_CODE register number
GPRS = ("Rax", "Rcx", "Rdx", "Rbx", "Rsp", "Rbp", "Rsi", "Rdi") + tuple(f"R{i}" for i in range(8, 16))

IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3


@dataclass(frozen=True)
class RuntimeFunction:
    image_base: int
    address: int  # VA of the RUNTIME_FUNCTION entry
    begin: int  # RVAs
    end: int
    unwind_info: int


@dataclass(frozen=True)
class FrameInfo:
    """What RtlVirtualUnwind reports about the frame it just unwound."""

    establisher_frame: int
    handler: int = 0  # VA of the language handler, 0 if none
    handler_data: int = 0  # VA of the handler's data (e.g. the C scope table)


def _u16(read: Reader, addr: int) -> int:
    return struct.unpack("<H", read(addr, 2))[0]


def _u32(read: Reader, addr: int) -> int:
    return struct.unpack("<I", read(addr, 4))[0]


def _u64(read: Reader, addr: int) -> int:
    return struct.unpack("<Q", read(addr, 8))[0]


def read_runtime_function(read: Reader, image_base: int, address: int) -> RuntimeFunction:
    begin, end, unwind_info = struct.unpack("<III", read(address, 12))
    return RuntimeFunction(image_base, address, begin, end, unwind_info)


@dataclass(frozen=True)
class FunctionTable:
    """
    A table of RUNTIME_FUNCTIONs registered at runtime, for code outside loaded images:
    from RtlAddFunctionTable, or with a callback from RtlInstallFunctionTableCallback.
    """

    identifier: int  # the table's address, or the callback table's identifier
    base: int
    begin: int  # the addresses it covers
    end: int
    count: int = 0
    callback: int = 0


def search_function_table(read: Reader, table: FunctionTable, pc: int) -> RuntimeFunction | None:
    """Find pc in a registered table, whose entries need not be sorted."""
    entries = read(table.identifier, 12 * table.count)
    for i, (begin, end, _) in enumerate(struct.iter_unpack("<III", entries)):
        if begin <= pc - table.base < end:
            return read_runtime_function(read, table.base, table.identifier + 12 * i)
    return None


def lookup_function_entry(read: Reader, image_base: int, pc: int) -> RuntimeFunction | None:
    """Binary search the image's .pdata for the function containing pc."""
    if read(image_base, 2) != b"MZ":
        return None
    nt = image_base + _u32(read, image_base + 0x3C)
    # PE32+ data directories start 0x70 bytes into the optional header (nt + 0x18)
    rva, size = struct.unpack("<II", read(nt + 0x18 + 0x70 + 8 * IMAGE_DIRECTORY_ENTRY_EXCEPTION, 8))
    if not rva:
        return None
    table = image_base + rva
    begins = [b for b, _, _ in struct.iter_unpack("<III", read(table, size - size % 12))]
    i = bisect.bisect_right(begins, pc - image_base) - 1
    if i < 0:
        return None
    fn = read_runtime_function(read, image_base, table + 12 * i)
    if not fn.begin <= pc - image_base < fn.end:
        return None
    if fn.unwind_info & 1:  # indirect entry: points at the primary RUNTIME_FUNCTION
        fn = read_runtime_function(read, image_base, image_base + (fn.unwind_info & ~1))
    return fn


@dataclass(frozen=True)
class UnwindCode:
    prolog_offset: int
    op: int
    info: int  # register number, or size class for UWOP_ALLOC_*
    operand: int  # the 16- or 32-bit value in the following slots, if any


@dataclass(frozen=True)
class UnwindInfo:
    flags: int
    prolog_size: int
    frame_reg: int
    frame_offset: int
    codes: list[UnwindCode]
    trailer: int  # VA after the codes: handler RVA + data, or a chained RUNTIME_FUNCTION


def _slots(op: int, info: int) -> int:
    """Number of 16-bit slots taken by an unwind code."""
    if op == UWOP_ALLOC_LARGE:
        return 3 if info else 2
    return {UWOP_SAVE_NONVOL: 2, UWOP_SAVE_NONVOL_FAR: 3, UWOP_SAVE_XMM128: 2, UWOP_SAVE_XMM128_FAR: 3}.get(op, 1)


def read_unwind_info(read: Reader, address: int) -> UnwindInfo:
    version_flags, prolog_size, count, frame = read(address, 4)
    raw = read(address + 4, 2 * count)
    codes = []
    i = 0
    while i < count:
        op, info = raw[2 * i + 1] & 0xF, raw[2 * i + 1] >> 4
        n = _slots(op, info)
        codes.append(UnwindCode(raw[2 * i], op, info, int.from_bytes(raw[2 * i + 2 : 2 * (i + n)], "little")))
        i += n
    trailer = address + 4 + 2 * ((count + 1) & ~1)
    return UnwindInfo(version_flags >> 3, prolog_size, frame & 0xF, frame >> 4, codes, trailer)


def virtual_unwind(read: Reader, fn: RuntimeFunction, pc: int, ctx, handler_type: int = 0) -> FrameInfo:
    """
    Unwind one frame: ctx is updated in place to the caller's state.

    Returns the establisher frame and, when the frame has a handler of
    ``handler_type`` (UNW_FLAG_EHANDLER or UNW_FLAG_UHANDLER), the handler.

    Not handled: a pc inside an epilogue, which Windows unwinds by simulating
    the remaining epilogue instructions.
    """
    base = fn.image_base
    info = read_unwind_info(read, base + fn.unwind_info)
    offset = pc - base - fn.begin
    # While pc is in the prolog, only codes for instructions that already ran are undone.
    in_prolog = offset < info.prolog_size

    frame = ctx.Rsp
    if info.frame_reg and any(
        c.op == UWOP_SET_FPREG and not (in_prolog and c.prolog_offset > offset) for c in info.codes
    ):
        frame = getattr(ctx, GPRS[info.frame_reg]) - 16 * info.frame_offset

    handler = handler_data = 0
    if info.flags & handler_type:
        handler, handler_data = base + _u32(read, info.trailer), info.trailer + 4

    machine_frame = False
    while True:
        for c in info.codes:
            if in_prolog and c.prolog_offset > offset:
                continue
            if c.op == UWOP_PUSH_NONVOL:
                setattr(ctx, GPRS[c.info], _u64(read, ctx.Rsp))
                ctx.Rsp += 8
            elif c.op == UWOP_ALLOC_LARGE:
                ctx.Rsp += c.operand if c.info else c.operand * 8
            elif c.op == UWOP_ALLOC_SMALL:
                ctx.Rsp += c.info * 8 + 8
            elif c.op == UWOP_SET_FPREG:
                ctx.Rsp = frame
            elif c.op == UWOP_SAVE_NONVOL:
                setattr(ctx, GPRS[c.info], _u64(read, frame + c.operand * 8))
            elif c.op == UWOP_SAVE_NONVOL_FAR:
                setattr(ctx, GPRS[c.info], _u64(read, frame + c.operand))
            elif c.op in (UWOP_SAVE_XMM128, UWOP_SAVE_XMM128_FAR):
                xmm = getattr(ctx, f"Xmm{c.info}")
                xmm.Low, xmm.High = struct.unpack(
                    "<QQ", read(frame + c.operand * (16 if c.op == UWOP_SAVE_XMM128 else 1), 16)
                )
            elif c.op == UWOP_PUSH_MACHFRAME:
                sp = ctx.Rsp + (8 if c.info else 0)
                ctx.Rip, ctx.Rsp = _u64(read, sp), _u64(read, sp + 24)
                machine_frame = True
        if not info.flags & UNW_FLAG_CHAININFO:
            break
        # The chained (parent) function's prolog has fully executed.
        info = read_unwind_info(read, base + read_runtime_function(read, base, info.trailer).unwind_info)
        in_prolog = False

    if not machine_frame:
        unwind_leaf(read, ctx)
    return FrameInfo(frame, handler, handler_data)


def unwind_leaf(read: Reader, ctx) -> None:
    """A function without unwind data is a leaf: its return address is at rsp."""
    ctx.Rip = _u64(read, ctx.Rsp)
    ctx.Rsp += 8
