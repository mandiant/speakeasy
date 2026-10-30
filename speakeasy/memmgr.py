# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

import speakeasy.common as common
from speakeasy.errors import OutOfMemoryError

if TYPE_CHECKING:
    from speakeasy.config import SpeakeasyConfig
    from speakeasy.engines.unicorn_eng import EmuEngine


class MemMap:
    """
    Class that defines a memory mapping (e.g. heap/pool alloc, binary image, etc.)
    """

    def __init__(self, base, size, tag, prot, flags, block_base, block_size, shared=False, process=None):
        self.base: int = base
        self.size: int = size

        base_addr_tag = f".0x{base:x}"
        if tag and base_addr_tag not in tag:
            tag += base_addr_tag

        if tag:
            tag = list(tag)
            bad_chars = "\\?[]:]"
            [tag.__setitem__(j, "_") for j in [i for i, e in enumerate(tag) if e in bad_chars]]
            tag = "".join(tag)

        self.tag: str | None = tag
        self.prot: int = prot
        self.flags: int = flags
        self.shared: bool = shared
        self.free: bool = False
        self.process: Any = process
        self.block_base: int = block_base
        self.block_size: int = block_size

    def __hash__(self):
        return hash(self.base)

    def __eq__(self, other):
        if other is not None:
            return self.base == other.base

    def __ne__(self, other):
        return not (self == other)


# Windows never maps the first 64 KB, so a null pointer plus a small offset faults
ALLOCATION_GRANULARITY = 0x10000


class MemoryManager:
    """
    Primitive memory manager used to block OS sized allocation units into something more practical

    Subclasses must define the following attributes:
        hooks: Dictionary of hooks
        config: Emulation configuration
    """

    hooks: dict[int, Any]
    emu_eng: EmuEngine
    config: SpeakeasyConfig

    def get_current_process(self) -> Any:
        return None

    def get_address_limit(self) -> int | None:
        """
        Return the end of the address space that allocations which start below it must fit in
        """
        return None

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.maps: list[MemMap] = []
        self.mem_reserves: list[MemMap] = []
        self.block_base: int = 0
        self.block_size: int = 0
        self.block_offset: int = 0
        self.page_size: int = 0x1000
        self.alloc_base: int = ALLOCATION_GRANULARITY

    @contextmanager
    def allocations_from(self, base: int) -> Iterator[None]:
        """
        Start the search for free memory at base, for the allocations in this block
        that do not give an address
        """
        previous = self.alloc_base
        self.alloc_base = base
        # Start a new shared block for small allocations, here and after the block,
        # so that small allocations also come from the current search base
        self.block_base = self.block_offset = 0
        try:
            yield
        finally:
            self.alloc_base = previous
            self.block_base = self.block_offset = 0

    def _hook_mem_map_dispatch(self, mm):
        hl = self.hooks.get(common.HOOK_MEM_MAP, [])
        for mem_map_hook in hl:
            if mem_map_hook.enabled:
                # the mapped memory region's base address falls within the hook's bounds
                if mem_map_hook.begin <= mm.base:
                    if not mem_map_hook.end or mem_map_hook.end > mm.base:
                        mem_map_hook.cb(self, mm.base, mm.size, mm.tag, mm.prot, mm.flags)

    def mem_map(
        self,
        size: int,
        base: int | None = None,
        perms: int = common.PERM_MEM_RWX,
        tag: str | None = None,
        flags: int = 0,
        shared: bool = False,
        process: Any = None,
    ) -> int:
        """
        Map a block of memory with specified permissions and a tag
        """
        if not process and tag and not tag.startswith("emu"):
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

                mm = MemMap(base, size, tag, perms, flags, self.block_base, self.block_size, shared, process)

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

    def mem_free(self, base) -> None:
        """
        Free a block of memory, if all blocks in a block are set to free, unmap the entire block
        """
        mm = self.get_address_map(base)
        if mm:
            mm.free = True

            # If we want to freeze memory, just return
            if self.config.keep_memory_on_free:
                return

            ml = [m for m in self.get_mem_maps() if m.block_base == mm.block_base]
            # if all blocks are free in the current block, free it from the emu engine
            if all([m.free for m in ml]):
                self.block_base = 0
                self.mem_unmap(mm.block_base, mm.block_size)
                for m in ml:
                    self.maps.remove(m)

    def mem_unmap(self, base, size):
        """
        Free a block of emulated memory
        """
        self.emu_eng.mem_unmap(base, size)

    def mem_write(self, addr, data) -> None:
        """
        Write bytes into the emulated address space
        """
        self.emu_eng.mem_write(addr, data)

    def mem_read(self, addr, size) -> bytes:
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

    def is_address_valid(self, address) -> bool:
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

    def mem_unreserve(self, base):
        """
        Release a reserved block of memory without mapping it
        """
        self.mem_reserves = [r for r in self.mem_reserves if r.base != base]

    def get_mem_maps(self) -> list[MemMap]:
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
                perms = common.PERM_MEM_RWX if r.prot is None else r.prot
                return self.mem_map(r.size, base=r.base, perms=perms, tag=r.tag)
        return None

    def get_mem_regions(self):
        """
        Get the current regions of mapped memory
        """
        return self.emu_eng.mem_regions()

    def get_valid_ranges(self, size: int, addr: int | None = None) -> tuple[int, int]:
        """
        Retrieve a valid address range that can satisfy the requested size.
        Optionally, a base address can be specified to test if it can be used
        """

        page_size = self.page_size

        # mem_map needs to be page aligned
        total = size

        # alloced address needs to also be on a page boundary
        if addr is None:
            addr = self.alloc_base
        base = addr - (addr % page_size)

        if total < page_size:
            total = page_size
        elif total % page_size:
            total += page_size - (total % page_size)

        curr: list[int] = []
        for m in self.get_mem_regions():
            curr += range(m[0], m[1], page_size)

        # Add reserved memory so we don't accidentally allocate it
        for res in self.mem_reserves:
            curr += range(res.base, (res.base + res.size), page_size)

        curr = sorted(set(curr))

        for page in curr:
            if page >= base + total:
                break
            if page >= base:
                base = page + page_size

        limit = self.get_address_limit()
        if limit is not None and addr < limit < base + total:
            raise OutOfMemoryError(f"no free range of 0x{total:x} bytes below 0x{limit:x}")

        return (base, total)
