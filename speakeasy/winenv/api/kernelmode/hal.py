# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.nt.ntoskrnl as w
from speakeasy.winenv.api import api


class Hal(api.ApiHandler):
    """
    Implements the hardware abstraction layer (hal.dll) that allows
    Windows to interact with hardware at a high level.
    """

    name = 'hal'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Hal, self).__init__(emu)

        self.funcs = {}
        self.data = {}
        self.emu = emu

        self.win = w

        super(Hal, self).__get_hook_attrs__(self)

    @apihook('KeGetCurrentIrql', argc=0)
    def KeGetCurrentIrql(self, emu, argv, ctx={}):
        """
        NTHALAPI KIRQL KeGetCurrentIrql();
        """
        irql = emu.get_current_irql()
        return irql

    @apihook('ExAcquireFastMutex', argc=1, conv=_arch.CALL_CONV_FASTCALL)
    def ExAcquireFastMutex(self, emu, argv, ctx={}):
        """
        VOID ExAcquireFastMutex(
            _Inout_ PFAST_MUTEX FastMutex
        );
        """
        return

    @apihook('ExReleaseFastMutex', argc=1, conv=_arch.CALL_CONV_FASTCALL)
    def ExReleaseFastMutex(self, emu, argv, ctx={}):
        """
        VOID ExReleaseFastMutex(
            _Inout_ PFAST_MUTEX FastMutex
        );
        """
        return
