"""
The sections of an x64 CONTEXT that ContextFlags selects.

GetThreadContext and SetThreadContext copy only the sections the caller asks
for; the debug registers in particular belong to the thread, not the CPU,
since Unicorn does not implement them.
"""

CONTEXT_AMD64 = 0x100000
CONTEXT_CONTROL = 0x1
CONTEXT_INTEGER = 0x2
CONTEXT_SEGMENTS = 0x4
CONTEXT_FLOATING_POINT = 0x8
CONTEXT_DEBUG_REGISTERS = 0x10
CONTEXT_FULL = CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT
CONTEXT_ALL = CONTEXT_FULL | CONTEXT_SEGMENTS | CONTEXT_DEBUG_REGISTERS

DEBUG_REGISTERS = ("Dr0", "Dr1", "Dr2", "Dr3", "Dr6", "Dr7")

SECTIONS = {
    CONTEXT_CONTROL: ("SegCs", "SegSs", "EFlags", "Rsp", "Rip"),
    CONTEXT_INTEGER: ("Rax", "Rcx", "Rdx", "Rbx", "Rbp", "Rsi", "Rdi") + tuple(f"R{i}" for i in range(8, 16)),
    CONTEXT_SEGMENTS: ("SegDs", "SegEs", "SegFs", "SegGs"),
    CONTEXT_FLOATING_POINT: ("MxCsr",),
    CONTEXT_DEBUG_REGISTERS: DEBUG_REGISTERS,
}


def has(flags: int, section: int) -> bool:
    return bool(flags & CONTEXT_AMD64 and flags & section)


def copy_sections(source, target, flags: int) -> None:
    """Copy the sections of a CONTEXT64 that flags select from source to target."""
    for section, names in SECTIONS.items():
        if has(flags, section):
            for name in names:
                setattr(target, name, getattr(source, name))
    if has(flags, CONTEXT_FLOATING_POINT):
        for i in range(16):
            xmm, other = getattr(target, f"Xmm{i}"), getattr(source, f"Xmm{i}")
            xmm.Low, xmm.High = other.Low, other.High


def get_debug_registers(thread, ctx) -> None:
    for name in DEBUG_REGISTERS:
        setattr(ctx, name, thread.debug_registers[name])


def set_debug_registers(thread, ctx) -> None:
    thread.debug_registers.update({name: getattr(ctx, name) for name in DEBUG_REGISTERS})
