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
        self.unpatchable: set[str] = set()

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
        without a call to the API. If the emulator cannot patch the call site, it logs this one time and
        then does not count the calls from that site.
        """
        if not self.enabled:
            return
        if self.is_allowed_api(imp_api):
            return
        ret = self.emu.get_ret_address()
        hammer_key = imp_api + f"{ret:x}"
        if hammer_key in self.unpatchable:
            return
        self.api_stats[hammer_key] += 1
        if self.api_stats[hammer_key] < self.api_threshold:
            return
        del self.api_stats[hammer_key]
        if self.emu.get_arch() == e_arch.ARCH_X86:
            try:
                patched = self._patch_x86_call(ret, conv, argc)
            except Exception:
                logger.debug("api hammering disassembly failed at return address 0x%x", ret, exc_info=True)
                patched = False
        else:
            # TODO: patch the call sites on x64.
            patched = False
        if patched:
            logger.info("API HAMMERING DETECTED - patched the call to %s that returns to 0x%x", imp_api, ret)
        else:
            logger.info("API HAMMERING DETECTED - unable to patch the call to %s that returns to 0x%x", imp_api, ret)
            self.unpatchable.add(hammer_key)

    def _is_api_or_thunk(self, address: int) -> bool:
        """Return ``True`` if ``address`` is an API, or a ``jmp [mem]`` thunk that goes to an API."""
        if self.emu.get_symbol_from_address(address) is not None:
            return True
        if not self.emu.is_address_valid(address):
            return False
        thunk = self.emu.mem_read(address, 6)
        if thunk[:2] != b"\xff\x25":
            return False
        ptr = int.from_bytes(thunk[2:], "little")
        return self.emu.is_address_valid(ptr) and self.emu.get_symbol_from_address(self.emu.read_ptr(ptr)) is not None

    def _patch_x86_call(self, ret: int, conv: int, argc: int) -> bool:
        """Patch the x86 call that returns to ``ret``, so that it returns 0. Return ``False`` for an unknown form."""
        # xor eax, eax, then remove the arguments of a stdcall API.
        patch = None
        if conv == e_arch.CALL_CONV_CDECL:
            patch = b"\x31\xc0"
        elif conv == e_arch.CALL_CONV_STDCALL and 4 * argc <= 0x7F:
            patch = b"\x31\xc0\x83\xc4" + (4 * argc).to_bytes(1, "little")

        call = self.emu.mem_read(ret - 5, 5)
        if patch and call[0] == 0xE8:
            target = (ret + int.from_bytes(call[1:], "little", signed=True)) & 0xFFFFFFFF
            if self._is_api_or_thunk(target):
                self.emu.mem_write(ret - 5, patch.ljust(5, b"\x90"))
                return True

        eip = ret - 6
        mnem, op, instr = self.emu.get_disasm(eip, e_arch.DISASM_SIZE)
        if patch and (mnem == "call") and "dword ptr" in instr:
            self.emu.mem_write(eip, patch.ljust(6, b"\x90"))
            return True

        eip = ret - 2
        mnem, op, instr = self.emu.get_disasm(eip, e_arch.DISASM_SIZE)
        if (mnem == "call") and op in e_arch.REG_LOOKUP.keys():
            if self.hammer_memregion is None:
                self.hammer_memregion = self.emu.mem_map(0x1024 * 4, tag="speakeasy.hammerpatch")
            # The 2-byte call has no room for a patch, so point the register at a stub that
            # returns 0. The caller code stays as it is.
            # TODO: reuse the stubs in hammer_memregion.
            if conv == e_arch.CALL_CONV_CDECL:
                stub = b"\x31\xc0\xc3"
            elif conv == e_arch.CALL_CONV_STDCALL:
                stub = b"\x31\xc0\xc2" + (4 * argc).to_bytes(2, "little") + b"\x90"
            else:
                return False
            loc = self.hammer_memregion + self.hammer_offset
            if (self.hammer_offset + len(stub)) >= 0x1024 * 4:
                return False
            self.emu.mem_write(loc, stub)
            self.hammer_offset += len(stub)
            self.emu.reg_write(e_arch.REG_LOOKUP[op], loc)
            return True

        return False
