# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from itertools import groupby
from operator import itemgetter

import speakeasy.common as common


class MemMap(object):
    """
    Class that defines a memory mapping (e.g. heap/pool alloc, binary image, etc.)
    """
    def __init__(self, base, size, tag, prot, flags, block_base, block_size,
                 shared=False, process=None):
        self.base = base
        self.size = size

        base_addr_tag = '.0x%x' % (base)
        if tag and base_addr_tag not in tag:
            tag += base_addr_tag

        if tag:
            tag = list(tag)
            bad_chars = '\\?[]:]'
            [tag.__setitem__(j, '_') for j in [i for i, e in enumerate(tag) if e in bad_chars]]
            tag = ''.join(tag)

        self.tag = tag
        self.prot = prot
        self.flags = flags
        self.shared = shared
        self.free = False
        self.process = process
        self.block_base = block_base
        self.block_size = block_size

    def update_tag(self, new_tag):
        """
        Set the tag for the memory mapping
        """
        self.tag = new_tag

    def get_process(self):
        """
        Get the process object associated with a memory map
        """
        return self.process

    def set_process(self, process):
        """
        Set the process object associated with a memory map
        """
        self.process = process

    def get_tag(self):
        """
        Get the tag for the memory mapping
        """
        return self.tag

    def get_prot(self):
        """
        Get the memory permissions for a map
        """
        return self.prot

    def get_flags(self):
        """
        Get the memory flags for a map
        """
        return self.flags

    def get_size(self):
        """
        Get the byte size for the current memory mapping
        """
        return self.size

    def get_base(self):
        """
        Get the base address (lowest possible address) of the current memory map
        """
        return self.base

    def set_alloc(self):
        """
        Set the current mapping to be in an allocated state
        """
        self.free = False

    def set_free(self):
        """
        Set the current mapping to be in a free state
        """
        self.free = True

    def is_free(self):
        """
        Return the alloc state of a memory block
        """
        return self.free

    def __hash__(self):
        return hash(self.base)

    def __eq__(self, other):
        if other is not None:
            return self.base == other.base

    def __ne__(self, other):
        return not(self == other)


class MemoryManager(object):

    """
    Primitive memory manager used to block OS sized allocation units into something more practical
    """

    def __init__(self, *args, **kwargs):
        super(MemoryManager, self).__init__()
        self.maps = []
        self.emu_eng = None
        self.mem_reserves = []
        self.block_base = 0
        self.block_size = 0
        self.block_offset = 0
        self.page_size = 0x1000

    def _hook_mem_map_dispatch(self, mm):
        hl = self.hooks.get(common.HOOK_MEM_MAP, [])
        ctx = {}
        for mem_map_hook in hl:
            if mem_map_hook.enabled:
                # the mapped memory region's base address falls within the hook's bounds
                if mem_map_hook.begin <= mm.get_base():
                    if not mem_map_hook.end or mem_map_hook.end > mm.get_base():
                        mem_map_hook.cb(self, mm.get_base(), mm.get_size(),
                                        mm.get_tag(), mm.get_prot(), mm.get_flags(), ctx)

    def mem_map(self, size, base=None, perms=common.PERM_MEM_RWX,
                tag=None, flags=0, shared=False, process=None):
        """
        Map a block of memory with specified permissions and a tag
        """
        if not process and tag and not tag.startswith('emu'):
            process = self.get_current_process()

        if base is None:
            if size < self.page_size and size % self.page_size:
                addr = self.block_base + self.block_offset
                pad_size = 0x10 - (size % 0x10)
                size += pad_size
                if not self.block_base or ((addr + size) > self.block_base + self.page_size):
                    block = self.get_valid_ranges(self.page_size)
                    self.block_base, self.block_size = block

                    self.emu_eng.mem_map(self.block_base, self.block_size)
                    self.block_offset = 0
                    addr = self.block_base + self.block_offset

                self.block_offset += size
                base = addr

                mm = MemMap(base, size, tag, perms, flags, self.block_base, self.block_size,
                            shared, process)

                self.maps.append(mm)
                self._hook_mem_map_dispatch(mm)
                return base

        block = self.get_valid_ranges(size, addr=base)
        base, size = block

        block_size = self.block_size
        if size > self.block_size:
            block_size = size
        mm = MemMap(base, size, tag, perms, flags, base, block_size, shared, process)
        self.emu_eng.mem_map(base, size, perms=perms)
        self.maps.append(mm)
        self._hook_mem_map_dispatch(mm)
        return base

    def mem_free(self, base):
        """
        Free a block of memory, if all blocks in a block are set to free, unmap the entire block
        """
        mm = self.get_address_map(base)
        if mm:
            mm.set_free()

            # If we want to freeze memory, just return
            if self.keep_memory_on_free:
                return

            ml = [m for m in self.get_mem_maps() if m.block_base == mm.block_base]
            # if all blocks are free in the current block, free it from the emu engine
            if all([m.free for m in ml]):
                self.block_base = 0
                self.mem_unmap(mm.block_base, mm.block_size)
                [self.maps.remove(mm) for mm in ml]

    def mem_remap(self, frm, to):
        """
        Remap a block of emulated memory, and return the new address,
        or -1 on error
        Protections remain the same
        """
        map = self.get_address_map(frm)

        if not map:
            return -1

        prot = map.prot
        size = map.size

        # Exclude old memory region in tag name
        tag = map.tag[:map.tag.rfind(".")]

        contents = self.mem_read(map.base, size)

        # Will unmap as well
        self.mem_free(map.base)

        newmem = self.mem_map(size, base=to, perms=prot, tag=tag)
        
        if newmem != to:
            return -1

        self.mem_write(newmem, contents)

        return newmem

    def mem_unmap(self, base, size):
        """
        Free a block of emulated memory
        """
        self.emu_eng.mem_unmap(base, size)

    def mem_write(self, addr, data):
        """
        Write bytes into the emulated address space
        """
        self.emu_eng.mem_write(addr, data)

    def mem_read(self, addr, size):
        """
        Read bytes from the emulated address space
        """
        return bytes(self.emu_eng.mem_read(addr, size))

    def mem_protect(self, addr, size, perms):
        """
        Change memory protections
        """
        self.emu_eng.mem_protect(addr, size, perms)

    def _mem_unmap_region(self, base, size):
        """
        Remove an entire memory region that may not have blocks allocated within it
        """
        self.emu_eng.mem_unmap(base, size)

    def get_address_map(self, address):
        """
        Get the "MemMap" object associated with a specific address
        """
        for m in self.maps:
            if m.base <= address <= (m.base + m.size) - 1:
                return m

    def get_reserve_map(self, address):
        """
        Get the "MemMap" object that was only reserved for a specific address
        """
        for m in self.mem_reserves:
            if m.base <= address <= (m.base + m.size) - 1:
                return m

    def is_address_valid(self, address):
        """
        Was this address previously reserved or mapped?
        """
        if self.get_address_map(address):
            return True
        if self.get_reserve_map(address):
            return True
        return False

    def get_address_tag(self, address):
        """
        Get the tag for a supplied memory address
        """
        for m in self.maps:
            if address >= m.base and address <= (m.base + m.size) - 1:
                return m.tag

    def mem_reserve(self, size, base=None, perms=None, tag=None, flags=0, shared=False):
        """
        Reserve (but do not map) a block of memory
        """
        if base is None:
            block = self.get_valid_ranges(size)
            base, size = block

        mm = MemMap(base, size, tag, perms, flags, base, self.block_size, shared)

        self.mem_reserves.append(mm)
        return base

    def purge_memory(self):
        """
        Unmap all current blocks of mapped memory
        """
        for region in self.get_mem_regions():
            base, end, perms = region
            size = (end - base) + 1
            self._mem_unmap_region(base, size)

    def get_mem_maps(self):
        """
        Get the listing of current memory maps
        """
        return self.maps

    def mem_map_reserve(self, mapped_base):
        """
        Map a previously reserved block of memory
        """
        for r in self.mem_reserves:
            if mapped_base == r.base:
                self.mem_reserves.remove(r)
                return self.mem_map(r.size, base=r.base, perms=r.prot, tag=r.tag)
        return None

    def get_mem_regions(self):
        """
        Get the current regions of mapped memory
        """
        return self.emu_eng.mem_regions()

    def get_valid_ranges(self, size, addr=None):
        """
        Retrieve a valid address range that can satisfy the requested size.
        Optionally, a base address can be specified to test if it can be used
        """

        def get_runs(i):
            for k, g in groupby(enumerate(i),
                                lambda ix: ix[0] - (ix[1] >> 12)):
                yield tuple(map(itemgetter(1), g))

        page_size = self.page_size

        # mem_map needs to be page aligned
        total = size

        # alloced address needs to also be on a page boundary
        if addr is None:
            addr = page_size
        base = addr - (addr % page_size)

        if total < page_size:
            total = page_size
        elif total % page_size:
            total += (page_size - (total % page_size))

        curr = []
        for m in self.get_mem_regions():
            curr += range(m[0], m[1], page_size)

        # Add reserved memory so we don't accidentally allocate it
        for res in self.mem_reserves:
            curr += range(res.base, (res.base + res.size), page_size)

        curr = sorted(set(curr))

        attempts = 9999
        while attempts:
            req = set(range(base, base + total, page_size))

            diffs = sorted(req.difference(curr))

            if len(diffs) == len(req):
                break

            if not attempts % 10:
                base += (page_size * 1000)
            else:
                base += total
            attempts -= 1

        if attempts == 0:
            raise Exception('Failed to allocate emulator memory')

        a = [r for r in get_runs(diffs)][0]

        return (min(a), total)
