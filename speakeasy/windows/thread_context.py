"""
Thread contexts: the sections of a CONTEXT that ContextFlags selects, and
access to a context of either architecture.

GetThreadContext and SetThreadContext copy only the sections the caller asks
for; the debug registers in particular belong to the thread, not the CPU,
since Unicorn does not implement them.
"""

CONTEXT_AMD64 = 0x100000
CONTEXT_i386 = 0x10000
CONTEXT_CONTROL = 0x1
CONTEXT_INTEGER = 0x2
CONTEXT_SEGMENTS = 0x4
CONTEXT_FLOATING_POINT = 0x8
CONTEXT_DEBUG_REGISTERS = 0x10
CONTEXT_EXTENDED_REGISTERS = 0x20  # x86 only

DEBUG_REGISTERS = ("Dr0", "Dr1", "Dr2", "Dr3", "Dr6", "Dr7")

SECTIONS_AMD64 = {
    CONTEXT_CONTROL: ("SegCs", "SegSs", "EFlags", "Rsp", "Rip"),
    CONTEXT_INTEGER: ("Rax", "Rcx", "Rdx", "Rbx", "Rbp", "Rsi", "Rdi") + tuple(f"R{i}" for i in range(8, 16)),
    CONTEXT_SEGMENTS: ("SegDs", "SegEs", "SegFs", "SegGs"),
    CONTEXT_FLOATING_POINT: ("MxCsr",),
    CONTEXT_DEBUG_REGISTERS: DEBUG_REGISTERS,
}
SECTIONS_I386 = {
    CONTEXT_CONTROL: ("Ebp", "Eip", "SegCs", "EFlags", "Esp", "SegSs"),
    CONTEXT_INTEGER: ("Edi", "Esi", "Ebx", "Edx", "Ecx", "Eax"),
    CONTEXT_SEGMENTS: ("SegGs", "SegFs", "SegEs", "SegDs"),
    CONTEXT_DEBUG_REGISTERS: DEBUG_REGISTERS,
}


def is_amd64(ctx) -> bool:
    return hasattr(ctx, "Rip")


# CONTEXT_FULL and CONTEXT_ALL of winnt.h, which differ by architecture
CONTEXT_FULL_AMD64 = CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT
CONTEXT_ALL_AMD64 = CONTEXT_FULL_AMD64 | CONTEXT_SEGMENTS | CONTEXT_DEBUG_REGISTERS
CONTEXT_FULL_I386 = CONTEXT_i386 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS
CONTEXT_ALL_I386 = CONTEXT_FULL_I386 | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS


def has(flags: int, section: int) -> bool:
    return bool(flags & (CONTEXT_AMD64 | CONTEXT_i386) and flags & section)


def instruction_pointer(ctx) -> int:
    return ctx.Rip if is_amd64(ctx) else ctx.Eip


def stack_pointer(ctx) -> int:
    return ctx.Rsp if is_amd64(ctx) else ctx.Esp


def set_control(ctx, ip: int, sp: int) -> None:
    if is_amd64(ctx):
        ctx.Rip, ctx.Rsp = ip, sp
    else:
        ctx.Eip, ctx.Esp = ip, sp


def register_state(ctx) -> dict[str, str]:
    """The general purpose registers of ctx, formatted like the emulator's register state."""
    if is_amd64(ctx):
        names = ("Rsp", "Rbp", "Rip", "Rsi", "Rdi", "Rax", "Rbx", "Rcx", "Rdx") + tuple(f"R{i}" for i in range(8, 16))
        width = 18
    else:
        names = ("Esp", "Ebp", "Eip", "Esi", "Edi", "Eax", "Ebx", "Ecx", "Edx")
        width = 10
    return {name.lower(): f"{getattr(ctx, name):#0{width}x}" for name in names}


def copy_sections(source, target, flags: int) -> None:
    """Copy the sections of a CONTEXT that flags select from source to target."""
    amd64 = is_amd64(target)
    for section, names in (SECTIONS_AMD64 if amd64 else SECTIONS_I386).items():
        if has(flags, section):
            for name in names:
                setattr(target, name, getattr(source, name))
    if amd64 and has(flags, CONTEXT_FLOATING_POINT):
        for i in range(16):
            xmm, other = getattr(target, f"Xmm{i}"), getattr(source, f"Xmm{i}")
            xmm.Low, xmm.High = other.Low, other.High


def get_debug_registers(thread, ctx) -> None:
    for name in DEBUG_REGISTERS:
        setattr(ctx, name, thread.debug_registers[name])


def set_debug_registers(thread, ctx) -> None:
    thread.debug_registers.update({name: getattr(ctx, name) for name in DEBUG_REGISTERS})
