# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from typing import TYPE_CHECKING

import speakeasy.winenv.arch as _arch
from speakeasy.winenv.api import api

if TYPE_CHECKING:
    from speakeasy.windows.kernel import WinKernelEmulator

PERF_FREQUENCY = 10_000_000


class Hal(api.ApiHandler):
    """
    Implements the hardware abstraction layer (hal.dll) that allows
    Windows to interact with hardware at a high level.
    """

    name = "hal"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs = {}
        self.data = {}
        self.emu = emu
        self.perf_counter: int = 0x5FD27D571F

        super().__get_hook_attrs__(self)

    @apihook("KeGetCurrentIrql", argc=0)
    def KeGetCurrentIrql(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        KIRQL KeGetCurrentIrql();
        """
        irql = emu.get_current_irql()
        return irql

    @apihook("KeQueryPerformanceCounter", argc=1)
    def KeQueryPerformanceCounter(
        self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT
    ):
        """
        LARGE_INTEGER KeQueryPerformanceCounter(
            PLARGE_INTEGER PerformanceFrequency
        );

        The counter runs at 10 MHz and advances by one millisecond on each call.
        """
        (freq,) = argv
        if freq:
            self.mem_write(freq, PERF_FREQUENCY.to_bytes(8, "little"))
        self.perf_counter += PERF_FREQUENCY // 1000
        if emu.get_ptr_size() == 4:
            emu.reg_write(_arch.X86_REG_EDX, self.perf_counter >> 32)
            return self.perf_counter & 0xFFFFFFFF
        return self.perf_counter

    @apihook("ExAcquireFastMutex", argc=1, conv=_arch.CALL_CONV_FASTCALL)
    def ExAcquireFastMutex(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID ExAcquireFastMutex(
            PFAST_MUTEX FastMutex
        );
        """
        return

    @apihook("ExReleaseFastMutex", argc=1, conv=_arch.CALL_CONV_FASTCALL)
    def ExReleaseFastMutex(self, emu: "WinKernelEmulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID ExReleaseFastMutex(
            PFAST_MUTEX FastMutex
        );
        """
        return
