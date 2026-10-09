"""API capacity failures preserve publication and never reuse retired tokens."""

import pytest

from speakeasy.errors import WindowsEmuError
from speakeasy.windows.api_image import ApiExportSpec, build_api_image
from tests.test_module_load_rollback import (
    assert_image_unmapped,
    assert_restored,
    snapshot,
)
from tests.test_module_load_rollback import (
    warm_emu as warm_emu,
)


def test_trap_exhaustion_rolls_back_partial_module_and_retires_token(warm_emu, monkeypatch):
    emu = warm_emu
    survivor_address = emu.get_proc("kernel32", "GetTickCount")
    registry = emu.api_registry
    survivor = registry.entries[survivor_address]
    before = snapshot(emu)
    original_count = registry._trap_count
    original_size = registry.TRAP_SIZE
    base, _ = emu.get_valid_ranges(0x20000, addr=0x68000000)
    image = build_api_image(
        name="trap_capacity",
        arch=emu.arch,
        base=base,
        emu_path=r"C:\test\trap_capacity.dll",
        exports=[ApiExportSpec("Alias", 7), ApiExportSpec("First", 7), ApiExportSpec("Second", 8)],
    )
    # Leave one token available: aliases publish once, then the second target fails.
    monkeypatch.setattr(registry, "TRAP_SIZE", (original_count + 1) * registry.TRAP_STRIDE)
    published = []
    original_allocate = registry._allocate_trap

    def allocate():
        if registry._trap_count > original_count:
            published.extend(entry for entry in registry.traps.values() if entry.module.name == image.name)
        return original_allocate()

    monkeypatch.setattr(registry, "_allocate_trap", allocate)
    with pytest.raises(WindowsEmuError, match="API trap reservation exhausted"):
        emu.load_image(image)
    assert len(published) == 1
    retired = published[0].trap
    assert registry._trap_count == original_count + 1
    assert retired not in registry.traps
    assert_restored(emu, before, [published[0].module])
    assert_image_unmapped(emu, base, image.image_size)
    assert registry.entries[survivor_address] is survivor
    assert registry.traps[survivor.trap] is survivor

    monkeypatch.setattr(registry, "TRAP_SIZE", original_size)
    monkeypatch.setattr(registry, "_allocate_trap", original_allocate)
    replacement = emu.load_image(image)
    first = registry.lookup(replacement, "First")
    assert registry.lookup(replacement, "Alias") is first
    assert registry.lookup(replacement, 7) is first
    assert first.address == published[0].address  # Same public slot, fresh private identity.
    second = registry.lookup(replacement, "Second")
    assert first.trap != second.trap
    assert first.trap > retired and second.trap > retired
    assert registry.traps[first.trap] is first
    assert registry.traps[second.trap] is second
    assert registry._trap_count == original_count + 3


def test_dynamic_trap_exhaustion_preserves_arena_and_existing_identity(warm_emu, monkeypatch):
    emu = warm_emu
    module = emu.load_module_by_name("dynamic_trap_capacity")
    registry = emu.api_registry
    first = registry.dynamic(module, "First")
    arena = next(section for section in module.sections if section.name == ".dyn")
    bytes_before = emu.mem_read(module.base + arena.virtual_address, arena.virtual_size)
    before = snapshot(emu)
    offset = registry.dynamic_offsets[id(module)]
    original_count = registry._trap_count
    original_size = registry.TRAP_SIZE
    monkeypatch.setattr(registry, "TRAP_SIZE", original_count * registry.TRAP_STRIDE)

    with pytest.raises(WindowsEmuError, match="API trap reservation exhausted"):
        registry.dynamic(module, "Rejected")
    assert snapshot(emu) == before
    assert registry.dynamic_offsets[id(module)] == offset
    assert registry._trap_count == original_count
    assert emu.mem_read(module.base + arena.virtual_address, arena.virtual_size) == bytes_before
    assert registry.lookup(module, "Rejected") is None
    assert registry.dynamic(module, "First") is first
    assert registry.traps[first.trap] is first

    monkeypatch.setattr(registry, "TRAP_SIZE", original_size)
    following = registry.dynamic(module, "Following")
    assert following.address == module.base + arena.virtual_address + offset + 16
    assert following.trap == registry.trap_base + original_count * registry.TRAP_STRIDE
    assert registry.lookup(module, "Following") is following
    assert following.trap != first.trap


def test_last_dynamic_arena_slot_then_exhaustion_is_atomic(warm_emu):
    emu = warm_emu
    module = emu.load_module_by_name("dynamic_arena_capacity")
    registry = emu.api_registry
    first = registry.dynamic(module, "First")
    first_bytes = emu.mem_read(first.address, 16)
    arena = next(section for section in module.sections if section.name == ".dyn")
    registry.dynamic_offsets[id(module)] = arena.virtual_size - 32
    last = registry.dynamic(module, 65535)
    assert last.address == module.base + arena.virtual_address + arena.virtual_size - 16
    assert registry.dynamic_offsets[id(module)] == arena.virtual_size
    assert registry.dynamic(module, "ordinal_65535") is last
    last_bytes = emu.mem_read(last.address - 16, 32)
    before = snapshot(emu)
    count = registry._trap_count

    with pytest.raises(WindowsEmuError, match="dynamic API arena exhausted"):
        registry.dynamic(module, "Overflow")
    assert snapshot(emu) == before
    assert registry._trap_count == count
    assert registry.lookup(module, "Overflow") is None
    assert registry.dynamic(module, "First") is first
    assert registry.traps[first.trap] is first
    assert registry.traps[last.trap] is last
    assert emu.mem_read(first.address, 16) == first_bytes
    assert emu.mem_read(last.address - 16, 32) == last_bytes
