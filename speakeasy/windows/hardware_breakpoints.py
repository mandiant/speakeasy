"""
Hardware execute breakpoints, from the debug registers of the current thread.

Unicorn has no debug registers. When Dr7 of the current thread enables an
execute breakpoint, the emulator adds a code hook at the breakpoint address.
The hook raises STATUS_SINGLE_STEP before the instruction runs, as the debug
exception of the CPU does, and sets the bit of the breakpoint in Dr6. If a
handler continues at the breakpoint with the resume flag set, the instruction
runs one time and does not break again.

Data breakpoints (a Dr7 R/W field other than execute) have no effect.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from speakeasy.report import ErrorType
from speakeasy.windows.cpu_exceptions import CpuException
from speakeasy.winenv.defs.nt import ddk

if TYPE_CHECKING:
    from speakeasy.common import CodeHook
    from speakeasy.windows.objman import Thread
    from speakeasy.windows.winemu import WindowsEmulator

RESUME_FLAG = 0x10000


def execute_breakpoints(debug_registers: dict[str, int]) -> dict[int, int]:
    """Get the index of each execute breakpoint that Dr7 enables, by address."""
    dr7 = debug_registers["Dr7"]
    breakpoints: dict[int, int] = {}
    for i in range(4):
        enabled = dr7 >> (2 * i) & 3  # local and global enable
        rw = dr7 >> (16 + 4 * i) & 3  # 0: break on execution
        if enabled and rw == 0:
            breakpoints.setdefault(debug_registers[f"Dr{i}"], i)
    return breakpoints


class HardwareBreakpoints:
    def __init__(self, emu: WindowsEmulator):
        self.emu: WindowsEmulator = emu
        self.hooks: dict[int, CodeHook] = {}
        self.resume: tuple[Thread | None, int] | None = None  # a thread and the breakpoint the resume flag skips

    def update(self) -> None:
        """Hook the current thread's enabled execute breakpoints, and unhook the rest."""
        thread = self.emu.get_current_thread()
        wanted = {}
        if thread is not None and not self.emu.is_kernel_mode:
            wanted = execute_breakpoints(thread.debug_registers)
        for address in self.hooks.keys() - wanted.keys():
            self.emu.remove_hook(self.hooks.pop(address))
        for address in wanted.keys() - self.hooks.keys():
            self.hooks[address] = self.emu.add_code_hook(self._hit, begin=address, end=address)
            # Unicorn translated the code that already ran without the hook
            self.emu.emu_eng.invalidate_translations(address, address + 1)

    def resume_at(self, address: int) -> None:
        """Let the current thread run the instruction at address one time without a break, as the resume flag does."""
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
        self.emu.raise_cpu_exception(exception, ErrorType.HARDWARE_BREAKPOINT)
