"""
Hardware execute breakpoints, from the debug registers of the current thread.

Unicorn has no debug registers. While the current thread's Dr7 enables an
execute breakpoint, a code hook at its address raises STATUS_SINGLE_STEP before
the instruction runs, as the CPU's debug exception does, and sets the
breakpoint's bit in Dr6. A handler that continues at the breakpoint with the
resume flag set runs the instruction once without breaking again.

Data breakpoints (a Dr7 R/W field other than execute) are not implemented.
"""

import speakeasy.winenv.defs.nt.ddk as ddk
from speakeasy.windows.cpu_exceptions import CpuException

RESUME_FLAG = 0x10000


def execute_breakpoints(debug_registers: dict[str, int]) -> dict[int, int]:
    """Address to index of each execute breakpoint that Dr7 enables."""
    dr7 = debug_registers["Dr7"]
    breakpoints: dict[int, int] = {}
    for i in range(4):
        enabled = dr7 >> (2 * i) & 3  # local and global enable
        rw = dr7 >> (16 + 4 * i) & 3  # 0: break on execution
        if enabled and rw == 0:
            breakpoints.setdefault(debug_registers[f"Dr{i}"], i)
    return breakpoints


class HardwareBreakpoints:
    def __init__(self, emu):
        self.emu = emu
        self.hooks: dict[int, object] = {}
        self.resume: tuple[object, int] | None = None  # a thread and the breakpoint the resume flag skips

    def update(self) -> None:
        """Hook the current thread's enabled execute breakpoints, and unhook the rest."""
        thread = self.emu.get_current_thread()
        wanted = {}
        if thread is not None and not self.emu.kernel_mode:
            wanted = execute_breakpoints(thread.debug_registers)
        for address in self.hooks.keys() - wanted.keys():
            self.emu.remove_code_hook(self.hooks.pop(address))
        for address in wanted.keys() - self.hooks.keys():
            self.hooks[address] = self.emu.add_code_hook(self._hit, begin=address, end=address)
            # Code that already ran was translated without the hook
            self.emu.emu_eng.invalidate_translations(address, address + 1)

    def resume_at(self, address: int) -> None:
        """The current thread continues at address with the resume flag: run it without breaking."""
        self.resume = None
        if address in self.hooks:
            self.resume = (self.emu.get_current_thread(), address)

    def _hit(self, emu, address, size, ctx=None):
        thread = self.emu.get_current_thread()
        if self.resume is not None:
            resume, self.resume = self.resume, None
            if resume == (thread, address):
                return
        index = execute_breakpoints(thread.debug_registers).get(address) if thread is not None else None
        if index is None:
            return
        thread.debug_registers["Dr6"] |= 1 << index
        exception = CpuException(ddk.STATUS_SINGLE_STEP, address, address)
        self.emu.raise_cpu_exception(exception, "hardware_breakpoint")
