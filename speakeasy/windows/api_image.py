"""
The PE images of the synthetic API modules.

The raw offset of each section is equal to its RVA, so the regions are also a valid PE file.
The API registry writes the entry code of each function export when it gives the export an API token.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

import speakeasy.winenv.arch as _arch
from speakeasy import common
from speakeasy.windows.export_manifest import get_export_manifest, get_ordinal_names
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


def encode_jump(arch: int, address: int, target: int) -> bytes:
    """Encode a jump at address to target. The jump does not change the registers, the stack or the flags."""
    if arch == _arch.ARCH_X86:
        return b"\xe9" + struct.pack("<I", (target - address - 5) & 0xFFFFFFFF)
    return b"\xff\x25\x00\x00\x00\x00" + struct.pack("<Q", target)


def encode_api_stub(arch: int, entry_address: int, trap_address: int) -> bytes:
    """Encode the entry code that jumps to the API token. The code does not change the stack or the flags."""
    if arch == _arch.ARCH_X86:
        # Inline hooks look for the Windows hot-patch prologue. pop ebp undoes it before the jump.
        return b"\x8b\xff\x55\x8b\xec\x5d" + encode_jump(arch, entry_address + 6, trap_address)
    return b"\x66\x90" + encode_jump(arch, entry_address + 2, trap_address)


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
    """
    Build a valid PE image with the given exports.

    ``base`` is the preferred base. The image has no absolute addresses, so it can load at any base.
    Exports with the same explicit ordinal share one EAT entry. An export without an
    ordinal gets the lowest free ordinal, in the byte order of the names. The EAT can
    have gaps between the ordinals.

    Raises:
        ValueError: if a name is not ASCII, the exports do not fit the WORD indices of the
            export directory, two exports with one ordinal are different, or the image
            does not fit the address space.
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
    regions = [MemoryRegion(0, bytes(headers), "headers", common.PERM_MEM_READ)]
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
        regions.append(MemoryRegion(rva, bytes(content), section_name, perms))
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
        exports=[ExportEntry(s.name, rvas[o], o, kind=s.kind, forwarder=s.forwarder) for s, o in assigned],
        entry_points=[],
        sections=sections,
        pe_metadata=PeMetadata(2, 0, machine, magic),
        source="synthetic",
        relocations=[],
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
        self._name: str = name
        self._api: Any = api
        self._arch: int = arch
        self._base: int = base
        self._emu_path: str = emu_path
        self._signature_db: SignatureDatabase = signature_db

    def make_image(self) -> LoadedImage:
        arch_name = "x86" if self._arch == _arch.ARCH_X86 else "x64"
        handler_ordinals: dict[str, int | None] = {}
        data_names: set[str] = set()
        nt_handler = getattr(self._api, "_nt_handler", None)
        for handler in (self._api, nt_handler):
            if handler is None:
                continue
            for key, func in handler.funcs.items():
                # Handlers register each ordinal under its name too. ntdll exports only the Nt and Zw
                # handlers of ntoskrnl.
                if isinstance(key, int) or (handler is nt_handler and not key.startswith(("Nt", "Zw"))):
                    continue
                handler_ordinals[key] = func[4]
            if handler is self._api:
                data_names.update(handler.data)

        def kind(name: str | None, physical_kind: str = "function") -> str:
            return "data" if physical_kind == "data" or name in data_names else "function"

        manifest = get_export_manifest(self._name.lower(), arch_name)
        physical_exports: list[ApiExportSpec] | None = None
        if manifest is not None:
            physical_exports = [ApiExportSpec(e.name, e.ordinal, kind(e.name, e.kind)) for e in manifest.exports]
        elif (ordinal_names := get_ordinal_names(self._name.lower(), arch_name)) is not None:
            physical_exports = [ApiExportSpec(e.name, e.ordinal, kind(e.name, e.kind)) for e in ordinal_names.names]
        if physical_exports is not None:
            # The manifest or the ordinal names define the names and ordinals. A handler name that
            # is not in them gets an ordinal after the highest ordinal, so that it does not take an
            # ordinal that the real module does not use. If they have the A or W variant of a
            # handler name, the emulator uses the handler name only to find the handler.
            exports = physical_exports
            physical = {e.name for e in exports}
            next_ordinal = max((e.ordinal or 0 for e in exports), default=0) + 1
            extras = (handler_ordinals.keys() | data_names) - physical
            for name in sorted(n for n in extras if not {n + "A", n + "W"} & physical):
                exports.append(ApiExportSpec(name, next_ordinal, kind(name)))
                next_ordinal += 1
        else:
            # The declarations of this DLL and the handlers give the export names. A declaration
            # of the name in a different DLL can give the arguments of a call, but not an export.
            specs = {name: ApiExportSpec(name) for name in self._signature_db.get_functions(self._name, arch_name)}
            specs.update({name: ApiExportSpec(name, ordinal) for name, ordinal in handler_ordinals.items()})
            if self._name == "ntoskrnl":
                # ntoskrnl exports the system services with the Nt and the Zw prefix, and one
                # handler serves both names.
                for name in list(handler_ordinals):
                    if name.startswith(("Nt", "Zw")):
                        alias = ("Zw" if name.startswith("Nt") else "Nt") + name[2:]
                        specs.setdefault(alias, ApiExportSpec(alias))
            specs.update({name: ApiExportSpec(name, kind="data") for name in data_names})
            exports = list(specs.values())
        image_name = manifest.export_name if manifest is not None else self._name
        try:
            image_name.encode("ascii")
        except UnicodeEncodeError:
            # The name in the export directory can differ from the module name. Use an ASCII
            # name there, and keep the real name for the registry, the loader lists and the path.
            image_name = "speakeasy"
        image = build_api_image(
            name=image_name,
            arch=self._arch,
            base=self._base,
            emu_path=self._emu_path,
            exports=exports,
        )
        image.name = self._name
        return image
