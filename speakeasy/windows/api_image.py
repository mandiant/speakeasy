"""Deterministic, mapped PE images for synthetic API modules.

Raw section offsets equal RVAs, so the regions also form a parseable PE file.
The registry patches the faulting public entries after allocating private traps.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

import speakeasy.common as common
import speakeasy.winenv.arch as _arch

if TYPE_CHECKING:
    from speakeasy.windows.loaders import LoadedImage

API_SLOT_SIZE = 32
API_ENTRY_OFFSET = 16
API_DATA_SIZE = 0x100
API_DYNAMIC_SIZE = 0x10000


@dataclass(frozen=True)
class ApiExportSpec:
    name: str | None
    ordinal: int | None = None
    kind: str = "function"
    forwarder: str | None = None


def encode_api_stub(arch: int, entry_address: int, trap_address: int) -> bytes:
    """Encode a stack/flags-neutral jump from a public entry to its private trap."""
    if arch == _arch.ARCH_X86:
        # Keep a complete five-byte prologue for ordinary inline-hook trampolines.
        return b"\x8b\xff\x0f\x1f\x00\xe9" + struct.pack("<I", (trap_address - entry_address - 10) & 0xFFFFFFFF)
    return b"\x66\x90\xff\x25\x00\x00\x00\x00" + struct.pack("<Q", trap_address)


def _ascii_string(value: str, label: str) -> None:
    if not value or "\0" in value:
        raise ValueError(f"Invalid {label}")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"Non-ASCII {label}") from exc


def validate_forwarder(value: str) -> None:
    """Validate DLL.name / DLL.#ordinal syntax without resolving its target."""
    _ascii_string(value, "forwarder")
    dll, separator, symbol = value.rpartition(".")
    if not separator or not dll or not symbol or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Invalid forwarder target")
    if any(c in dll for c in "\\/:") or dll.startswith(".") or dll.endswith("."):
        raise ValueError("Invalid forwarder module")
    if symbol.startswith("#"):
        digits = symbol[1:]
        if not digits.isascii() or not digits.isdecimal() or not 0 < int(digits) <= 0xFFFF:
            raise ValueError("Invalid forwarder ordinal")


def _align(value: int) -> int:
    return (value + 0xFFF) & ~0xFFF


def build_api_image(
    *,
    name: str,
    arch: int,
    base: int,
    emu_path: str,
    exports: list[ApiExportSpec],
) -> LoadedImage:
    """Build a valid PE with sparse EAT ordinals and independently sorted names.

    Explicit ordinal aliases share a target. Unknown ordinals use the lowest
    available positive value in byte-sorted name order. Export spans are bounded
    by the WORD indices in the export name ordinal table.
    """
    from speakeasy.windows.loaders import ExportEntry, LoadedImage, MemoryRegion, PeMetadata, SectionEntry

    _ascii_string(name, "module name")
    specs = sorted(exports, key=lambda e: (e.name is None, (e.name or "").encode("ascii"), e.ordinal or 0))
    names = {spec.name for spec in specs if spec.name is not None}
    used = {spec.ordinal for spec in specs if spec.ordinal is not None}
    assigned: list[tuple[ApiExportSpec, int]] = []
    candidate = 1
    for spec in specs:
        ordinal = spec.ordinal
        if ordinal is None:
            while candidate in used:
                candidate += 1
            ordinal = candidate
            used.add(ordinal)
        assigned.append((spec, ordinal))
    ordinal_base = min(used, default=1)
    span = max(used, default=0) - ordinal_base + 1 if used else 0
    if span > 0x10000 or len(names) > 0x10000:
        raise ValueError("Export table exceeds WORD ordinal index capacity")
    targets: dict[int, ApiExportSpec] = {}
    for spec, ordinal in assigned:
        previous = targets.get(ordinal)
        if previous and (previous.kind, previous.forwarder) != (spec.kind, spec.forwarder):
            raise ValueError("Conflicting exports for one ordinal")
        targets[ordinal] = spec

    text_size = _align(
        max(1, sum(s.kind == "function" and s.forwarder is None for s in targets.values()) * API_SLOT_SIZE)
    )
    data_size = _align(max(1, sum(s.kind == "data" and s.forwarder is None for s in targets.values()) * API_DATA_SIZE))
    text = bytearray(b"\xcc" * text_size)
    data = bytearray(data_size)
    text_rva = 0x1000
    edata_rva = text_rva + len(text)
    edata = bytearray(40 + span * 4 + len(names) * 6) if assigned else bytearray()

    def string_rva(value: str) -> int:
        rva = edata_rva + len(edata)
        edata.extend(value.encode("ascii") + b"\0")
        return rva

    dll_name = name + ("" if name.lower().endswith(".dll") else ".dll")
    dll_rva = string_rva(dll_name) if assigned else 0
    name_rvas = {s.name: string_rva(s.name) for s, _ in assigned if s.name is not None}
    forward_rvas = {o: string_rva(s.forwarder) for o, s in sorted(targets.items()) if s.forwarder is not None}
    export_size = len(edata)
    edata.extend(b"\0" * (_align(max(1, export_size)) - export_size))
    data_rva = edata_rva + len(edata)
    dyn_rva = data_rva + len(data)
    image_size = dyn_rva + API_DYNAMIC_SIZE
    if base < 0 or base + image_size > 1 << arch:
        raise ValueError("Image exceeds the architecture address space")
    rvas: dict[int, int] = {}
    function_index = data_index = 0
    for ordinal, spec in sorted(targets.items()):
        if spec.forwarder is not None:
            rvas[ordinal] = forward_rvas[ordinal]
        elif spec.kind == "data":
            rvas[ordinal] = data_rva + data_index * API_DATA_SIZE
            data_index += 1
        else:
            slot = function_index * API_SLOT_SIZE
            text[slot : slot + API_ENTRY_OFFSET] = b"\x90" * API_ENTRY_OFFSET
            rvas[ordinal] = text_rva + slot + API_ENTRY_OFFSET
            function_index += 1
    if assigned:
        eat_offset = 40
        name_offset = eat_offset + span * 4
        ordinal_offset = name_offset + len(names) * 4
        struct.pack_into(
            "<IIHHIIIIIII",
            edata,
            0,
            0,
            0,
            0,
            0,
            dll_rva,
            ordinal_base,
            span,
            len(names),
            edata_rva + eat_offset,
            edata_rva + name_offset,
            edata_rva + ordinal_offset,
        )
        for ordinal, rva in rvas.items():
            struct.pack_into("<I", edata, eat_offset + (ordinal - ordinal_base) * 4, rva)
        for i, (spec, ordinal) in enumerate((s, o) for s, o in assigned if s.name is not None):
            assert spec.name is not None
            struct.pack_into("<I", edata, name_offset + i * 4, name_rvas[spec.name])
            struct.pack_into("<H", edata, ordinal_offset + i * 2, ordinal - ordinal_base)

    headers = bytearray(0x1000)
    headers[:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x80)
    headers[0x80:0x84] = b"PE\0\0"
    is64 = arch == _arch.ARCH_AMD64
    machine, magic, opt_size = (0x8664, 0x20B, 240) if is64 else (0x14C, 0x10B, 224)
    struct.pack_into("<HHIIIHH", headers, 0x84, machine, 4, 0, 0, 0, opt_size, 0x2022 if is64 else 0x2102)
    opt = 0x98
    struct.pack_into(
        "<HBBIIIII", headers, opt, magic, 0, 0, len(text) + API_DYNAMIC_SIZE, len(edata) + len(data), 0, 0, text_rva
    )
    if is64:
        struct.pack_into("<Q", headers, opt + 24, base)
    else:
        struct.pack_into("<II", headers, opt + 24, data_rva, base)
    struct.pack_into("<IIHHHHHH", headers, opt + 32, 0x1000, 0x200, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<IIIIHH", headers, opt + 52, 0, image_size, len(headers), 0, 2, 0x100)
    if is64:
        struct.pack_into("<QQQQII", headers, opt + 72, 0x12000, 0x1000, 0x100000, 0x1000, 0, 16)
    else:
        struct.pack_into("<IIIIII", headers, opt + 72, 0x12000, 0x1000, 0x100000, 0x1000, 0, 16)
    directory_offset = opt + (112 if is64 else 96)
    if assigned:
        struct.pack_into("<II", headers, directory_offset, edata_rva, export_size)
    rx = common.PERM_MEM_READ | common.PERM_MEM_EXEC
    rw = common.PERM_MEM_READ | common.PERM_MEM_WRITE
    contents = [
        (".text", text_rva, text, rx, 0x60000020),
        (".edata", edata_rva, edata, common.PERM_MEM_READ, 0x40000040),
        (".data", data_rva, data, rw, 0xC0000040),
        (".dyn", dyn_rva, b"\xcc" * API_DYNAMIC_SIZE, rx, 0x60000020),
    ]
    sections = []
    regions = [MemoryRegion(base, bytes(headers), "headers", common.PERM_MEM_READ)]
    for i, (section_name, rva, content, perms, chars) in enumerate(contents):
        struct.pack_into(
            "<8sIIIIIIHHI",
            headers,
            opt + opt_size + i * 40,
            section_name.encode(),
            len(content),
            rva,
            len(content),
            rva,
            0,
            0,
            0,
            0,
            chars,
        )
        sections.append(SectionEntry(section_name, rva, len(content), perms))
        regions.append(MemoryRegion(base + rva, bytes(content), section_name, perms))
    regions[0].data = bytes(headers)
    return LoadedImage(
        arch=arch,
        module_type="dll",
        name=name,
        emu_path=emu_path,
        image_base=base,
        image_size=image_size,
        regions=regions,
        imports=[],
        exports=[
            ExportEntry(s.name, base + rvas[o], o, "intercepted", kind=s.kind, forwarder=s.forwarder)
            for s, o in assigned
        ],
        default_export_mode="intercepted",
        entry_points=[],
        loader=None,
        sections=sections,
        pe_metadata=PeMetadata(2, 0, machine, magic),
        source="synthetic",
    )
