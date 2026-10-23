# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.arch as _arch
from speakeasy.winenv.api import api

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
        self.perf_counter = 0x5FD27D571F

        super().__get_hook_attrs__(self)

    @apihook("KeGetCurrentIrql", argc=0)
    def KeGetCurrentIrql(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTHALAPI KIRQL KeGetCurrentIrql();
        """
        irql = emu.get_current_irql()
        return irql

    @apihook("KeQueryPerformanceCounter", argc=1)
    def KeQueryPerformanceCounter(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
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
    def ExAcquireFastMutex(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID ExAcquireFastMutex(
            _Inout_ PFAST_MUTEX FastMutex
        );
        """
        return

    @apihook("ExReleaseFastMutex", argc=1, conv=_arch.CALL_CONV_FASTCALL)
    def ExReleaseFastMutex(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID ExReleaseFastMutex(
            _Inout_ PFAST_MUTEX FastMutex
        );
        """
        return
