"""
Thread contexts: the sections of a CONTEXT that ContextFlags selects, and
access to a context of either architecture.

GetThreadContext and SetThreadContext copy only the sections the caller asks
for; the debug registers in particular belong to the thread, not the CPU,
since Unicorn does not implement them.
"""

import speakeasy.winenv.arch as _arch

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

_FLAGS_AND_SEGMENT_REGISTERS = {
    "EFlags": _arch.X86_REG_EFLAGS,
    "SegCs": _arch.X86_REG_CS,
    "SegSs": _arch.X86_REG_SS,
    "SegDs": _arch.X86_REG_DS,
    "SegFs": _arch.X86_REG_FS,
    "SegGs": _arch.X86_REG_GS,
    "SegEs": _arch.X86_REG_ES,
}

# CONTEXT fields and the CPU registers they map to
CPU_REGISTERS_I386 = {
    "Edi": _arch.X86_REG_EDI,
    "Esi": _arch.X86_REG_ESI,
    "Eax": _arch.X86_REG_EAX,
    "Ebp": _arch.X86_REG_EBP,
    "Edx": _arch.X86_REG_EDX,
    "Ecx": _arch.X86_REG_ECX,
    "Ebx": _arch.X86_REG_EBX,
    "Esp": _arch.X86_REG_ESP,
    "Eip": _arch.X86_REG_EIP,
    **_FLAGS_AND_SEGMENT_REGISTERS,
}
CPU_REGISTERS_AMD64 = {
    "Rax": _arch.AMD64_REG_RAX,
    "Rbx": _arch.AMD64_REG_RBX,
    "Rcx": _arch.AMD64_REG_RCX,
    "Rdx": _arch.AMD64_REG_RDX,
    "Rsi": _arch.AMD64_REG_RSI,
    "Rdi": _arch.AMD64_REG_RDI,
    "Rbp": _arch.AMD64_REG_RBP,
    "Rsp": _arch.AMD64_REG_RSP,
    "Rip": _arch.AMD64_REG_RIP,
    "R8": _arch.AMD64_REG_R8,
    "R9": _arch.AMD64_REG_R9,
    "R10": _arch.AMD64_REG_R10,
    "R11": _arch.AMD64_REG_R11,
    "R12": _arch.AMD64_REG_R12,
    "R13": _arch.AMD64_REG_R13,
    "R14": _arch.AMD64_REG_R14,
    "R15": _arch.AMD64_REG_R15,
    **_FLAGS_AND_SEGMENT_REGISTERS,
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
    ip: int = ctx.Rip if is_amd64(ctx) else ctx.Eip
    return ip


def stack_pointer(ctx) -> int:
    sp: int = ctx.Rsp if is_amd64(ctx) else ctx.Esp
    return sp


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
