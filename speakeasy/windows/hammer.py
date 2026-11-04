# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

import collections
import logging
from typing import TYPE_CHECKING

import speakeasy.winenv.arch as e_arch

if TYPE_CHECKING:
    from speakeasy.config import ApiHammeringConfig
    from speakeasy.windows.winemu import WindowsEmulator

logger = logging.getLogger(__name__)


# The mitigation does not patch calls to these APIs, unless the config gives its own allow list.
_default_api_hammer_allowlist = [
    "kernel32.WriteProcessMemory",
    "kernel32.WriteFile",
    "kernel32.ReadFile",
]


def _lowercase_set(tt):
    return set([bb.lower() for bb in tt])


class ApiHammer:
    """
    Find API hammering and patch the call sites.

    Malware calls an API many times in a loop to use up the time of a sandbox or an emulator.
    """

    def __init__(self, emu):
        super().__init__()
        self.emu: WindowsEmulator = emu
        self.api_stats: collections.defaultdict[str, int] = collections.defaultdict(int)
        self.hammer_memregion: int | None = None
        self.hammer_offset: int = 0

        self.config: ApiHammeringConfig | None = self.emu.config.api_hammering
        self.api_threshold: int
        self.enabled: bool
        self.allow_list: set[str]
        if self.config:
            self.api_threshold = self.config.threshold
            self.enabled = self.config.enabled
            self.allow_list = _lowercase_set(self.config.allow_list or _default_api_hammer_allowlist)
        else:
            self.api_threshold = 1000
            self.enabled = False
            self.allow_list = _lowercase_set(_default_api_hammer_allowlist)

    def is_allowed_api(self, apiname):
        """Return ``True`` if the API is one that the hammering mitigation skips."""
        return apiname.lower() in self.allow_list

    def handle_import_func(self, imp_api, conv, argc):
        """
        Count the calls to an API from one return address.

        When the count gets to the threshold, patch the call site on x86, so that the call returns 0
        without a call to the API.
        """
        if not self.enabled:
            return
        if self.is_allowed_api(imp_api):
            return
        hammer_key = imp_api + f"{self.emu.get_ret_address():x}"
        self.api_stats[hammer_key] += 1
        if self.api_stats[hammer_key] < self.api_threshold:
            return
        # TODO: reuse the stubs in hammer_memregion.
        if self.emu.get_arch() == e_arch.ARCH_X86:
            try:
                eip = self.emu.get_ret_address() - 6
                mnem, op, instr = self.emu.get_disasm(eip, e_arch.DISASM_SIZE)
                logger.info(f"api hammering at: {imp_api} 0x{self.emu.get_pc():x} {mnem!r} {op!r} {instr!r}")
                if (mnem == "call") and "dword ptr" in instr:
                    if conv == e_arch.CALL_CONV_CDECL:
                        patch = b"\x31\xc0\x90\x90\x90\x90\x90"
                        self.emu.mem_write(eip, patch)
                        logger.info(f"API HAMMERING DETECTED - patching 1 cdecl at {eip:x}")
                    elif conv == e_arch.CALL_CONV_STDCALL:
                        patch = b"\x31\xc0\x83\xc4" + (4 * argc).to_bytes(1, "little") + b"\x90"
                        self.emu.mem_write(eip, patch)
                        logger.info(f"API HAMMERING DETECTED - patching 1 stdcall at {eip:x}")
                else:
                    eip = self.emu.get_ret_address() - 2
                    mnem, op, instr = self.emu.get_disasm(eip, e_arch.DISASM_SIZE)
                    logger.info(f"api hammering at: 0x{self.emu.get_pc():x} {mnem!r} {op!r} {instr!r}")
                    if (mnem == "call") and op in e_arch.REG_LOOKUP.keys():
                        if self.hammer_memregion is None:
                            self.hammer_memregion = self.emu.mem_map(0x1024 * 4, tag="speakeasy.hammerpatch")
                        if conv == e_arch.CALL_CONV_CDECL:
                            patch = b"\x31\xc0\xc3"
                            self.emu.mem_write(eip, patch)
                            logger.info("API HAMMERING DETECTED - patching 2 cdecl at %x" % (eip,))  # noqa
                        elif conv == e_arch.CALL_CONV_STDCALL:
                            patch = b"\x31\xc0\xc2" + (4 * argc).to_bytes(2, "little") + b"\x90"
                            loc = self.hammer_memregion + self.hammer_offset
                            if (self.hammer_offset + len(patch)) < 0x1024 * 4:
                                self.emu.mem_write(loc, patch)
                                self.hammer_offset += len(patch)
                                reg = e_arch.REG_LOOKUP[op]
                                self.emu.reg_write(reg, loc)
                                logger.info("API HAMMERING DETECTED - patching 2 stdcall at %x" % (eip,))  # noqa
                    else:
                        logger.info(f"API HAMMERING DETECTED - unable to patch {eip:x}")
            except Exception:
                logger.debug("api hammering disassembly failed at return address 0x%x", self.emu.get_ret_address())
                return

        if self.emu.get_arch() == e_arch.ARCH_AMD64:
            # TODO: patch the call sites on x64.
            pass
