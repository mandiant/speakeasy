"""Session-local ownership of public API entries and private dispatch traps."""

from __future__ import annotations

import ntpath
from bisect import bisect_right, insort
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import speakeasy.common as common
from speakeasy.errors import WindowsEmuError
from speakeasy.windows.loaders import ExportEntry, RuntimeModule

if TYPE_CHECKING:
    from speakeasy.windows.winemu import WindowsEmulator


def module_name(value: str) -> str:
    return ntpath.splitext(ntpath.basename(value))[0].lower()


def symbol_ref(value: str | int) -> str | int:
    if isinstance(value, str) and value.startswith("ordinal_") and value[8:].isdigit():
        return int(value[8:])
    return value


@dataclass
class ApiEntry:
    module: RuntimeModule
    export: ExportEntry
    names: list[str] = field(default_factory=list)
    trap: int | None = None
    initialized: bool = False
    callback: bool = False
    binding_module: str | None = None
    binding_name: str | None = None

    @property
    def address(self) -> int:
        return self.export.address

    @property
    def name(self) -> str:
        return self.binding_name or (self.names[0] if self.names else f"ordinal_{self.export.ordinal}")

    @property
    def dll(self) -> str:
        return self.binding_module or self.module.name

    @property
    def symbol(self) -> str:
        return f"{self.dll}.{self.name}"


class ApiRegistry:
    TRAP_SIZE = 0x100000
    TRAP_STRIDE = 16

    def __init__(self, emu: WindowsEmulator):
        self.emu = emu
        self.entries: dict[int, ApiEntry] = {}
        self.traps: dict[int, ApiEntry] = {}
        self.names: dict[int, dict[str, ApiEntry]] = {}
        self.ordinals: dict[int, dict[int, ApiEntry]] = {}
        self.dynamic_offsets: dict[int, int] = {}
        self.trap_base: int | None = None
        self._addresses: list[int] = []
        self._trap_count = 0

    def _allocate_trap(self) -> int:
        if self.trap_base is None:
            base, size = self.emu.get_valid_ranges(self.TRAP_SIZE, addr=0xF0000000)
            if base + size > 0x100000000:
                raise WindowsEmuError("no address space available for API trap reservation")
            self.emu.mem_reserve(size, base=base, tag="emu.api_traps")
            self.trap_base = base
        offset = self._trap_count * self.TRAP_STRIDE
        if offset >= self.TRAP_SIZE:
            raise WindowsEmuError("API trap reservation exhausted")
        self._trap_count += 1
        return self.trap_base + offset

    def unregister_module(self, module: RuntimeModule) -> None:
        """Discard an unsuccessful load without reusing published trap tokens."""
        addresses = [address for address, entry in self.entries.items() if entry.module is module]
        for address in addresses:
            entry = self.entries.pop(address)
            if entry.trap is not None:
                self.traps.pop(entry.trap, None)
        self._addresses = sorted(self.entries)
        self.names.pop(id(module), None)
        self.ordinals.pop(id(module), None)
        self.dynamic_offsets.pop(id(module), None)

    def overlaps_traps(self, address: int, size: int = 1) -> bool:
        return (
            self.trap_base is not None
            and address < self.trap_base + self.TRAP_SIZE
            and address + max(size, 1) > self.trap_base
        )

    def register_module(self, module: RuntimeModule) -> None:
        by_name = self.names.setdefault(id(module), {})
        by_ordinal = self.ordinals.setdefault(id(module), {})
        synthetic = module._image.source == "synthetic"
        for export in module.get_exports():
            if not export.address:
                continue
            entry = self.entries.get(export.address)
            if entry is None:
                entry = ApiEntry(module, export)
                if synthetic and export.kind == "function" and not export.forwarder:
                    from speakeasy.windows.api_image import encode_api_stub

                    entry.trap = self._allocate_trap()
                    code = encode_api_stub(module.arch, export.address, entry.trap)
                    self.emu.mem_write(export.address, code)
                    self.traps[entry.trap] = entry
                self.entries[export.address] = entry
                insort(self._addresses, export.address)
            if export.name:
                if export.name not in entry.names:
                    entry.names.append(export.name)
                by_name[export.name] = entry
            by_ordinal[export.ordinal] = entry

    def lookup(self, module: RuntimeModule, reference: str | int) -> ApiEntry | None:
        reference = symbol_ref(reference)
        if isinstance(reference, int):
            return self.ordinals.get(id(module), {}).get(reference)
        return self.names.get(id(module), {}).get(reference)

    def dynamic(self, module: RuntimeModule, reference: str | int) -> ApiEntry:
        existing = self.lookup(module, reference)
        if existing is not None:
            return existing
        if module._image.source != "synthetic":
            raise WindowsEmuError("cannot synthesize an export in a guest PE")
        reference = symbol_ref(reference)
        arena = next((s for s in module.sections if s.name == ".dyn"), None)
        offset = self.dynamic_offsets.get(id(module), 0)
        if arena is None or offset + 32 > arena.virtual_size:
            raise WindowsEmuError(f"dynamic API arena exhausted for {module.name}")
        slot = module.base + arena.virtual_address + offset
        # Never overwrite guest patches or restore guest-changed page protections.
        perms = next((p for start, end, p in self.emu.get_mem_regions() if start <= slot and slot + 32 <= end + 1), 0)
        if not perms & self.emu.emu_eng.perms[common.PERM_MEM_EXEC] or self.emu.mem_read(slot, 32) != b"\xcc" * 32:
            raise WindowsEmuError(f"dynamic API arena modified by guest for {module.name}")
        address = slot + 16
        export = ExportEntry(
            name=reference if isinstance(reference, str) else None,
            address=address,
            ordinal=reference if isinstance(reference, int) else 0,
            execution_mode="intercepted",
            kind="function",
        )
        from speakeasy.windows.api_image import encode_api_stub

        trap = self._allocate_trap()
        entry = ApiEntry(module, export, [reference] if isinstance(reference, str) else [], trap)
        self.emu.mem_write(slot, b"\x90" * 16 + encode_api_stub(module.arch, address, trap).ljust(16, b"\xcc"))
        self.entries[address] = entry
        insort(self._addresses, address)
        self.traps[trap] = entry
        if isinstance(reference, str):
            self.names.setdefault(id(module), {})[reference] = entry
        else:
            self.ordinals.setdefault(id(module), {})[reference] = entry
        self.dynamic_offsets[id(module)] = offset + 32
        return entry

    def symbol(self, address: int) -> str | None:
        entry = self.entries.get(address)
        if entry is not None:
            return entry.symbol
        # Interior lookup is for presentation only; it never controls dispatch.
        index = bisect_right(self._addresses, address) - 1
        if index >= 0:
            start = self._addresses[index]
            record = self.entries[start]
            extent = 16 if record.export.kind == "function" and record.trap is not None else 1
            if start < address < start + extent:
                return f"{record.symbol}+0x{address - start:x}"
        return None
