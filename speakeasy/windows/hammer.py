# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.


import collections

import speakeasy.winenv.arch as e_arch

# When disassembling, a minimum instruction size needs to be supplied
# This number is arbitrary and just needs to be large enough to cover
# the size of the current disasm target
DISASM_SIZE = 0x20


# default list of APIs to always allow despite triggering API hammering detection
_default_api_hammer_allowlist = [
    'kernel32.WriteProcessMemory',
    'kernel32.WriteFile',
    'kernel32.ReadFile',
]


def _lowercase_set(tt):
    return set([bb.lower() for bb in tt])


class ApiHammer():
    """
    Detect and attempt to mitigate API hammering as part of anti-sandbox or
    anti-emulation in malware samples
    """

    def __init__(self, emu):
        super(ApiHammer, self).__init__()
        self.emu = emu
        self.api_stats = collections.defaultdict(int)
        self.hammer_memregion = None
        self.hammer_offset = 0

        self.config = self.emu.config.get('api_hammering', {})
        self.api_threshold = self.config.get('threshold', 1000)
        self.enabled = self.config.get('enabled', False)
        self.allow_list = _lowercase_set(self.config.get('allow_list',
                                                         _default_api_hammer_allowlist))

    def is_allowed_api(self, apiname):
        '''
        Returns true if the given apiname is one we don't want to use api hammering
        mitigation for
        '''
        return apiname.lower() in self.allow_list

    def handle_import_func(self, imp_api, conv, argc):
        '''
        Identifies possible API hammering and attempts to patch in mitigations.
        '''
        if not self.enabled:
            # api hammering mitigation not enabled, so exit
            return
        if self.is_allowed_api(imp_api):
            # this is an api that we always want to allow, don't bother trying to
            # prevent api hammering
            return
        hammer_key = imp_api + '%x' % self.emu.get_ret_address()
        self.api_stats[hammer_key] += 1
        if self.api_stats[hammer_key] < self.api_threshold:
            return
        # TODO: better parameterize the checking & dispatch of the types of calls/jmps to imports
        # so we can more easily loop through them & clean up the the logic below
        # TODO: track patches in the hammer_memregion & reuse when possible
        if self.emu.get_arch() == e_arch.ARCH_X86:
            eip = self.emu.get_ret_address() - 6
            mnem, op, instr = self.emu.get_disasm(eip, DISASM_SIZE)
            self.emu.log_info('api hammering at: %s 0x%x %r %r %r' % (imp_api, self.emu.get_pc(),
                                                                      mnem, op, instr))
            if (mnem == 'call') and 'dword ptr' in instr:
                if conv == e_arch.CALL_CONV_CDECL:
                    # If cdecl, the emu engine will clean the stack
                    # just xor eax,eax & 4 bytes of nop
                    patch = b'\x31\xc0\x90\x90\x90\x90\x90'
                    self.emu.mem_write(eip, patch)
                    self.emu.log_info('API HAMMERING DETECTED - patching 1 cdecl at %x' % (eip, ))
                elif conv == e_arch.CALL_CONV_STDCALL:
                    # If stdcall, we need to clean the stack
                    # patch is xor eax, eax; add esp, <count>
                    patch = b'\x31\xc0\x83\xc4' + (4*argc).to_bytes(1, 'little') + b'\x90'
                    self.emu.mem_write(eip, patch)
                    self.emu.log_info('API HAMMERING DETECTED - patching 1 stdcall at %x' % (eip,))
            else:
                eip = self.emu.get_ret_address() - 2
                mnem, op, instr = self.emu.get_disasm(eip, DISASM_SIZE)
                self.emu.log_info('api hammering at: 0x%x %r %r %r' % (self.emu.get_pc(), mnem,
                                                                       op, instr))
                if (mnem == 'call') and op in e_arch.REG_LOOKUP.keys():
                    # not enough space to clean up stack inline, so write stack cleanup code to a
                    # hammerpatch region & change the register to point to this cleanup code
                    # instead the hope is that we're in a tight loop, so this will prevent exiting
                    # the emulator the majority of the time.
                    if self.hammer_memregion is None:
                        self.hammer_memregion = self.emu.mem_map(0x1024*4,
                                                                 tag='speakeasy.hammerpatch')
                    if conv == e_arch.CALL_CONV_CDECL:
                        # If cdecl, the emu engine will clean the stack
                        # just xor eax,eax; retn
                        patch = b'\x31\xc0\xc3'
                        self.emu.mem_write(eip, patch)
                        self.emu.log_info('API HAMMERING DETECTED - patching 2 cdecl at %x' % (eip,)) # noqa
                    elif conv == e_arch.CALL_CONV_STDCALL:
                        # patch is xor eax, eax; retn <count>
                        patch = b'\x31\xc0\xc2' + (4*argc).to_bytes(2, 'little') + b'\x90'
                        loc = self.hammer_memregion + self.hammer_offset
                        if (self.hammer_offset + len(patch)) < 0x1024*4:
                            self.emu.mem_write(loc, patch)
                            self.hammer_offset += len(patch)
                            # now change the the register
                            reg = e_arch.REG_LOOKUP[op]
                            self.emu.reg_write(reg, loc)
                            self.emu.log_info('API HAMMERING DETECTED - patching 2 stdcall at %x' % (eip,)) # noqa
                else:
                    self.emu.log_info('API HAMMERING DETECTED - unable to patch %x' % (eip, ))

        if self.emu.get_arch() == e_arch.ARCH_AMD64:
            # TODO
            pass
