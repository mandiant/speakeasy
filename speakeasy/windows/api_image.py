"""Deterministic, mapped PE images for synthetic API modules.

Raw section offsets equal RVAs, so the regions also form a parseable PE file.
The registry patches the faulting public entries after allocating private traps.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

import speakeasy.common as common
import speakeasy.winenv.arch as _arch
from speakeasy.windows.export_manifest import get_export_manifest
from speakeasy.windows.loaders import ExportEntry, LoadedImage, MemoryRegion, PeMetadata, SectionEntry
from speakeasy.winenv.api.sigdb import SignatureDatabase

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
        exports=[ExportEntry(s.name, base + rvas[o], o, kind=s.kind, forwarder=s.forwarder) for s, o in assigned],
        entry_points=[],
        loader=None,
        sections=sections,
        pe_metadata=PeMetadata(2, 0, machine, magic),
        source="synthetic",
    )


class ApiModuleLoader:
    def __init__(
        self,
        *,
        name: str,
        arch: int,
        base: int,
        emu_path: str,
        signature_db: SignatureDatabase,
        api: Any = None,
    ) -> None:
        self._name = name
        self._api = api
        self._arch = arch
        self._base = base
        self._emu_path = emu_path
        self._signature_db = signature_db

    def make_image(self) -> LoadedImage:
        arch_name = "x86" if self._arch == _arch.ARCH_X86 else "x64"
        handler_ordinals: dict[str, int | None] = {}
        data_names: set[str] = set()
        nt_handler = getattr(self._api, "_nt_handler", None)
        for handler in (self._api, nt_handler):
            if handler is None:
                continue
            for key, func in handler.funcs.items():
                # Handlers register each ordinal under its name as well.
                if isinstance(key, int) or (handler is nt_handler and not key.startswith(("Nt", "Zw"))):
                    continue
                handler_ordinals[key] = func[4]
            if handler is self._api:
                data_names.update(handler.data)

        def kind(name: str | None, physical_kind: str = "function") -> str:
            return "data" if physical_kind == "data" or name in data_names else "function"

        manifest = get_export_manifest(self._name.lower(), arch_name)
        if manifest is not None:
            # The physical table owns names and ordinals. Handler-only names
            # follow the highest physical ordinal so that they never take an
            # ordinal that the real module leaves unused. A handler name whose
            # A or W variant is physical only serves dispatch of that variant.
            exports = [ApiExportSpec(e.name, e.ordinal, kind(e.name, e.kind)) for e in manifest.exports]
            physical = {e.name for e in manifest.exports}
            next_ordinal = max((e.ordinal for e in manifest.exports), default=0) + 1
            extras = (handler_ordinals.keys() | data_names) - physical
            for name in sorted(n for n in extras if not {n + "A", n + "W"} & physical):
                exports.append(ApiExportSpec(name, next_ordinal, kind(name)))
                next_ordinal += 1
        else:
            # The catalog owns surface membership. Permissive lookup serves
            # ABI reuse and must never determine exported names.
            specs = {name: ApiExportSpec(name) for name in self._signature_db.get_functions(self._name, arch_name)}
            specs.update({name: ApiExportSpec(name, ordinal) for name, ordinal in handler_ordinals.items()})
            if self._name == "ntoskrnl":
                # The kernel exports native services under both prefixes, and
                # dispatch folds each pair onto one handler.
                for name in list(handler_ordinals):
                    if name.startswith(("Nt", "Zw")):
                        alias = ("Zw" if name.startswith("Nt") else "Nt") + name[2:]
                        specs.setdefault(alias, ApiExportSpec(alias))
            specs.update({name: ApiExportSpec(name, kind="data") for name in data_names})
            exports = list(specs.values())
        image_name = self._name
        try:
            image_name.encode("ascii")
        except UnicodeEncodeError:
            # The PE export-directory label need not be the loaded filename.
            # Keep that label ASCII while retaining the actual Unicode module
            # identity in the registry, loader lists and emulated path.
            image_name = "speakeasy"
        image = build_api_image(
            name=image_name,
            arch=self._arch,
            base=self._base,
            emu_path=self._emu_path,
            exports=exports,
        )
        image.name = self._name
        image.loader = self
        return image
