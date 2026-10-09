from __future__ import annotations

import logging
import ntpath
import os
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

import speakeasy.common as common
import speakeasy.winenv.arch as _arch

if TYPE_CHECKING:
    from speakeasy.winenv.api.sigdb import SignatureDatabase

logger = logging.getLogger(__name__)


@dataclass
class ResourceEntry:
    id: int | str
    data_rva: int
    size: int
    type_id: int | str
    entry_rva: int  # RVA of the IMAGE_RESOURCE_DATA_ENTRY structure
    lang_id: int = 0


@dataclass
class PeMetadata:
    subsystem: int
    timestamp: int
    machine: int
    magic: int
    resources: list[ResourceEntry] = field(default_factory=list)
    string_table: dict[int, str] = field(default_factory=dict)  # For LoadString


@dataclass
class MemoryRegion:
    base: int
    data: bytes
    name: str
    perms: int


@dataclass
class SectionEntry:
    name: str
    virtual_address: int
    virtual_size: int
    perms: int


def perms_from_section_chars(chars: int) -> int:
    from speakeasy.windows.common import ImageSectionCharacteristics

    perms = common.PERM_MEM_NONE
    if chars & ImageSectionCharacteristics.IMAGE_SCN_MEM_READ:
        perms |= common.PERM_MEM_READ
    if chars & ImageSectionCharacteristics.IMAGE_SCN_MEM_WRITE:
        perms |= common.PERM_MEM_WRITE
    if chars & ImageSectionCharacteristics.IMAGE_SCN_MEM_EXECUTE:
        perms |= common.PERM_MEM_EXEC
    return int(perms)


def get_prot_string(perms: int) -> str:
    r = "r" if perms & common.PERM_MEM_READ else "-"
    w = "w" if perms & common.PERM_MEM_WRITE else "-"
    x = "x" if perms & common.PERM_MEM_EXEC else "-"
    return r + w + x


@dataclass
class ImportEntry:
    iat_address: int
    dll_name: str
    func_name: str
    source: str = "static"


@dataclass
class ExportEntry:
    name: str | None
    address: int
    ordinal: int
    execution_mode: str
    kind: str = "function"
    forwarder: str | None = None


@dataclass
class LoadedImage:
    arch: int
    module_type: str
    name: str
    emu_path: str
    image_base: int
    image_size: int
    regions: list[MemoryRegion]
    imports: list[ImportEntry]
    exports: list[ExportEntry]
    default_export_mode: str
    entry_points: list[int]
    visible_in_peb: bool = True
    stack_size: int = 0x12000
    tls_callbacks: list[int] = field(default_factory=list)
    tls_directory_va: int | None = None
    loader: Loader | None = None
    sections: list[SectionEntry] = field(default_factory=list)
    pe_metadata: PeMetadata | None = None
    source: str = "guest_pe"


class Loader(Protocol):
    def make_image(self) -> LoadedImage: ...


class RuntimeModule:
    def __init__(self, image: LoadedImage) -> None:
        self._image = image
        self.base = image.image_base
        self.image_size = image.image_size
        self.ep = (image.entry_points[0] - image.image_base) if image.entry_points else 0
        self.arch = image.arch
        self.emu_path = image.emu_path
        self.path = image.emu_path
        self.module_type = image.module_type
        self.stack_commit = image.stack_size
        self.visible_in_peb = image.visible_in_peb
        self.loader = image.loader
        self.name = image.name
        self.sections = image.sections

    def __repr__(self) -> str:
        loader_type = type(self.loader).__name__ if self.loader is not None else "None"
        return f"RuntimeModule({self._image.name!r} at {self.base:#x}, via {loader_type})"

    def is_exe(self) -> bool:
        return self._image.module_type == "exe"

    def is_dll(self) -> bool:
        return self._image.module_type == "dll"

    def is_driver(self) -> bool:
        return self._image.module_type == "driver"

    def get_base_name(self) -> str:
        return ntpath.basename(self.emu_path)

    def get_ep(self) -> int:
        return self.base + self.ep

    def get_exports(self) -> list[ExportEntry]:
        return self._image.exports

    def get_export_by_name(self, name: str) -> ExportEntry | None:
        for exp in self._image.exports:
            if exp.name == name:
                return exp
        return None

    def get_section_for_addr(self, addr: int) -> SectionEntry | None:
        offset = addr - self.base
        for sect in self.sections:
            if sect.virtual_address <= offset < sect.virtual_address + sect.virtual_size:
                return sect
        return None

    def get_tls_callbacks(self) -> list[int]:
        return self._image.tls_callbacks

    def get_pe_metadata(self) -> PeMetadata | None:
        return self._image.pe_metadata


def _delay_import_directory(pe: Any) -> tuple[int, bytes, list[int]]:
    """Check raw delay descriptors before trusting pefile's permissive parser.

    Legacy x86 descriptors contain VAs. pefile normalizes their struct fields
    in place; retain the raw bytes so mapping does not rewrite the guest table.
    """
    if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 13:
        return 0, b"", []
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[13]
    rva, size = directory.VirtualAddress, directory.Size
    if not rva and not size:
        return 0, b"", []
    if not rva or size < 32 or rva + size > pe.image_size:
        raise ValueError("Delay import directory lies outside the image or is truncated")
    raw = pe.get_data(rva, size)
    if len(raw) != size:
        raise ValueError("Truncated delay import directory")
    counts: list[int] = []
    for offset in range(0, size - 31, 32):
        fields = struct.unpack_from("<8I", raw, offset)
        if not any(fields):
            return rva, raw, counts
        attrs, name, _handle, iat, names, _bound, _unload, _timestamp = fields
        if attrs not in (0, 1) or (pe.arch == _arch.ARCH_AMD64 and attrs != 1):
            raise ValueError("Invalid delay import attributes for PE architecture")
        if not attrs:
            name, iat, names = name - pe.base, iat - pe.base, names - pe.base
        if not 0 < name < pe.image_size:
            raise ValueError("Delay import DLL name lies outside the image")
        if not 0 < iat <= pe.image_size - pe.arch // 8:
            raise ValueError("Delay import IAT slot lies outside the image")
        if not 0 < names <= pe.image_size - pe.arch // 8:
            raise ValueError("Delay import name table lies outside the image")
        width = pe.arch // 8
        count = 0
        while True:
            slot = names + count * width
            if slot > pe.image_size - width:
                raise ValueError("Unterminated delay import name table")
            if iat + count * width > pe.image_size - width:
                raise ValueError("Delay import IAT slot lies outside the image")
            thunk = pe.get_data(slot, width)
            if len(thunk) != width:
                raise ValueError("Truncated delay import name table")
            if not int.from_bytes(thunk, "little"):
                break
            count += 1
        counts.append(count)
    raise ValueError("Unterminated delay import descriptor table")


class PeLoader:
    """Load guest PEs, tolerating malformed optional inventories by default.

    strict=True rejects malformed import/export metadata. Image mapping and
    architecture validation are mandatory in either mode.
    """

    def __init__(
        self,
        *,
        path: str | None = None,
        data: bytes | None = None,
        base_override: int | None = None,
        emu_path: str = "",
        strict: bool = False,
    ) -> None:
        self._strict = strict
        self._path = path
        self._data = data
        self._base_override = base_override
        self._emu_path = emu_path

    def _optional_error(self, context: str, error: Exception) -> None:
        if self._strict:
            raise error
        logger.warning("Skipping malformed PE %s: %s", context, error)

    def _import_dll_name(self, pe: Any, entry: Any, source: str) -> str:
        import pefile

        # pefile replaces non-ASCII names with *invalid*. Read the original
        # bounded string so accepting Latin-1 does not lose the name's bytes.
        rva = entry.struct.Name if source == "static" else entry.struct.szName
        if not 0 < rva < pe.image_size:
            raise ValueError("Import DLL name lies outside the image")
        try:
            raw = pe.get_data(rva, min(pefile.MAX_DLL_LENGTH, pe.image_size - rva))
        except pefile.PEFormatError as error:
            raise ValueError("Unreadable imported DLL name") from error
        terminator = raw.find(b"\0")
        if terminator < 0:
            raise ValueError("Unterminated imported DLL name")
        raw = raw[:terminator]
        # Retain pefile's filename rules for ASCII, allowing high bytes only
        # through the explicit lossless decoding policy.
        ascii_name = bytes(c if c < 128 else ord("x") for c in raw)
        if not raw or not pefile.is_valid_dos_filename(ascii_name):
            raise ValueError("Invalid imported DLL name")
        try:
            dll = raw.decode("ascii")
        except UnicodeDecodeError:
            if self._strict:
                raise
            dll = raw.decode("latin-1")
            logger.warning("Non-ASCII imported DLL name decoded as Latin-1: %r", dll)
        dll = ntpath.splitext(dll)[0]
        if not dll:
            raise ValueError("Invalid imported DLL name")
        return dll

    def _static_import_slots(self, pe: Any, entry: Any, parsed: Any, budget: list[int]):
        """Retain raw thunk positions when pefile filters malformed names."""
        from types import SimpleNamespace

        import pefile

        width = pe.arch // 8
        table_rva = entry.struct.OriginalFirstThunk or entry.struct.FirstThunk
        if table_rva != entry.struct.FirstThunk:
            # pefile falls back to the IAT when the preferred table is empty
            # or unreadable. Static symbol addresses track relocation; validate
            # their slot offsets before using thunk_rva as table-choice evidence.
            for symbol in parsed:
                address = getattr(symbol, "address", None)
                thunk_rva = getattr(symbol, "thunk_rva", None)
                if address is None or thunk_rva is None:
                    continue
                offset = address - pe.base - entry.struct.FirstThunk
                if (
                    offset >= 0
                    and offset % width == 0
                    and 0 < entry.struct.FirstThunk <= pe.image_size - width - offset
                    and thunk_rva == entry.struct.FirstThunk + offset
                ):
                    table_rva = entry.struct.FirstThunk
                    break
        symbols = {symbol.thunk_rva: symbol for symbol in parsed if getattr(symbol, "thunk_rva", None) is not None}
        index = 0
        while True:
            thunk_rva = table_rva + index * width
            try:
                if not table_rva or not 0 <= thunk_rva <= pe.image_size - width:
                    raise ValueError("Import name table lies outside the image")
                raw = pe.get_data(thunk_rva, width)
                if len(raw) != width:
                    raise ValueError("Truncated import name table")
                value = int.from_bytes(raw, "little")
            except (ValueError, pefile.PEFormatError) as error:
                self._optional_error("static import name table", error)
                return
            if not value:
                return
            # Allow a terminator after exhaustion, but stop on the first
            # further nonzero thunk: at most one lookahead per descriptor.
            if not budget[0]:
                self._optional_error("static import name table", ValueError("Import symbol limit exceeded"))
                return
            budget[0] -= 1
            slot_rva = entry.struct.FirstThunk + index * width
            index += 1
            ordinal_flag = 1 << (pe.arch - 1)
            ordinal = bool(value & ordinal_flag)
            if ordinal and value & ~(ordinal_flag | 0xFFFF):
                self._optional_error("static import entry", ValueError("Invalid ordinal import reserved bits"))
                continue
            symbol = symbols.get(thunk_rva)
            if symbol is None:
                # Recover metadata only; never rewrite guest thunks or IAT bytes.
                name = None
                if not ordinal:
                    try:
                        if not 0 < value <= pe.image_size - 3:
                            raise ValueError("Import function name lies outside the image")
                        raw = pe.get_data(value + 2, min(pefile.MAX_IMPORT_NAME_LENGTH, pe.image_size - value - 2))
                        terminator = raw.find(b"\0")
                        if terminator < 0:
                            raise ValueError("Unterminated imported function name")
                        name = raw[:terminator]
                    except (ValueError, pefile.PEFormatError) as error:
                        self._optional_error("static import entry", error)
                        continue
                symbol = SimpleNamespace(import_by_ordinal=ordinal, ordinal=value & 0xFFFF, name=name)
            yield slot_rva, symbol

    def make_image(self) -> LoadedImage:
        import pefile

        from speakeasy.windows.common import _PeParser

        class InventoryParser(_PeParser):
            # PeLoader builds these inventories from the raw pefile entries.
            # Avoid legacy eager UTF-8 decoding before our policy can run.
            def _get_pe_imports(self):
                return {}

            def _get_pe_exports(self):
                return []

        pe = InventoryParser(path=self._path, data=self._data)
        supported = {(0x14C, 0x10B): _arch.ARCH_X86, (0x8664, 0x20B): _arch.ARCH_AMD64}
        if (pe.FILE_HEADER.Machine, pe.OPTIONAL_HEADER.Magic) not in supported:
            raise ValueError("Unsupported or inconsistent PE machine and optional-header magic")

        if pe.base + pe.image_size > 1 << pe.arch:
            raise ValueError("PE exceeds architecture address space")
        if pe.OPTIONAL_HEADER.SizeOfHeaders > pe.image_size:
            raise ValueError("PE headers extend beyond the image")
        for section in pe.sections:
            # Raw file-alignment padding is not a declared virtual allocation.
            # Malware images may put that padding beyond SizeOfImage.
            if section.Misc_VirtualSize and section.VirtualAddress + section.Misc_VirtualSize > pe.image_size:
                raise ValueError("PE section extends beyond the image")

        if self._base_override is not None:
            if type(self._base_override) is not int or not 0 <= self._base_override < (1 << pe.arch):
                raise ValueError("Invalid PE base override")
            if self._base_override + pe.image_size > 1 << pe.arch:
                raise ValueError("Rebased PE exceeds architecture address space")
        if self._base_override is not None and self._base_override != pe.base:
            if not getattr(pe, "DIRECTORY_ENTRY_BASERELOC", None):
                raise ValueError("Cannot rebase a guest PE without valid relocation data")
            pe.rebase(self._base_override)

        module_type = "exe"
        if pe.is_driver():
            module_type = "driver"
        elif pe.is_dll():
            module_type = "dll"

        base = pe.base
        parsed_delay = getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", ())
        delay_rva, delay_raw = 0, b""
        try:
            delay_rva, delay_raw, delay_counts = _delay_import_directory(pe)
            if delay_counts != [len(entry.imports) for entry in parsed_delay]:
                raise ValueError("Delay import descriptors could not be parsed completely")
        except (ValueError, pefile.PEFormatError) as error:
            self._optional_error("delay import directory", error)
            parsed_delay = ()
            # Restore bounded raw descriptors even if their inventory is bad:
            # pefile may have normalized legacy VA fields in place.
            directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[13]
            delay_rva, size = directory.VirtualAddress, directory.Size
            delay_raw = b""
            if 0 < delay_rva and delay_rva + size <= pe.image_size:
                try:
                    raw = pe.get_data(delay_rva, size)
                except pefile.PEFormatError:
                    raw = b""
                if len(raw) == size:
                    delay_raw = raw
        mapped_image = pe.get_memory_mapped_image(max_virtual_address=0xF0000000)[: pe.image_size]
        if delay_raw:
            mapped_image = bytearray(mapped_image)
            mapped_image[delay_rva : delay_rva + len(delay_raw)] = delay_raw

        imports: list[ImportEntry] = []
        ptr_size = pe.arch // 8
        # Eager delay binding uses exactly the same inventory as ordinary imports.
        # pefile normalizes legacy x86 VA-based delay descriptors to RVAs, but
        # does not relocate delay symbol.address when the image is rebased.
        parsed_static = {
            entry.struct.get_file_offset(): entry.imports for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ())
        }
        static_entries = ()
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 1:
            directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]
            if directory.VirtualAddress:
                # The names-only pass retains descriptors whose entire symbol
                # inventory was discarded by pefile's permissive parser.
                try:
                    static_entries = (
                        pe.parse_import_directory(directory.VirtualAddress, directory.Size, dllnames_only=True) or ()
                    )
                except pefile.PEFormatError as error:
                    self._optional_error("static import directory", error)
        # pefile's > MAX_IMPORT_SYMBOLS guard can retain MAX + 1 symbols.
        # Preserve that surface with a shared nonzero-slot cap, including
        # malformed entries. Terminators do not consume it. This bounds our
        # single-table walk without duplicating pefile's ILT/IAT read counter.
        static_budget = [pefile.MAX_IMPORT_SYMBOLS + 1]
        for entries, source in ((static_entries, "static"), (parsed_delay, "delay")):
            for entry in entries:
                try:
                    dll = self._import_dll_name(pe, entry, source)
                    # _delay_import_directory already validated delay attributes.
                    iat_rva = entry.struct.pIAT if source == "delay" else entry.struct.FirstThunk
                except ValueError as error:
                    self._optional_error(f"{source} import descriptor", error)
                    continue
                if source == "static":
                    slots = self._static_import_slots(
                        pe, entry, parsed_static.get(entry.struct.get_file_offset(), ()), static_budget
                    )
                else:
                    slots = ((iat_rva + index * ptr_size, imp) for index, imp in enumerate(entry.imports))
                for slot_rva, imp in slots:
                    try:
                        if iat_rva == 0 or not 0 <= slot_rva <= pe.image_size - ptr_size:
                            raise ValueError("Import IAT slot lies outside the image")
                        if imp.import_by_ordinal:
                            func_name = f"ordinal_{imp.ordinal}"
                        else:
                            if not imp.name:
                                raise ValueError("Missing imported function name")
                            func_name = imp.name.decode("ascii")
                            if not pefile.is_valid_function_name(imp.name):
                                raise ValueError("Invalid imported function name")
                        imports.append(ImportEntry(base + slot_rva, dll, func_name, source))
                    except ValueError as error:
                        self._optional_error(f"{source} import entry", error)

        exports: list[ExportEntry] = []
        parsed_exports = getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", ())
        if pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0]
            directory_end = directory.VirtualAddress + directory.Size
            if (directory.VirtualAddress or directory.Size) and (
                not directory.VirtualAddress or directory.Size < 40 or directory_end > pe.image_size
            ):
                self._optional_error("export directory", ValueError("Export directory extends beyond the image"))
                parsed_exports = ()
            directory_bytes = b""
            if directory.VirtualAddress and directory.Size >= 40 and directory_end <= pe.image_size:
                try:
                    directory_bytes = pe.get_data(directory.VirtualAddress, directory.Size)
                    if len(directory_bytes) != directory.Size:
                        raise ValueError("Truncated export directory")
                except (ValueError, pefile.PEFormatError) as error:
                    self._optional_error("export directory", error)
                    parsed_exports = ()
            from speakeasy.windows.api_image import validate_forwarder

            for exp in parsed_exports:
                try:
                    if not exp.address:
                        continue
                    if not 0 < exp.address < pe.image_size:
                        raise ValueError("Export target lies outside the image")
                    forwarder = None
                    if directory.VirtualAddress <= exp.address < directory_end:
                        offset = exp.address - directory.VirtualAddress
                        terminator = directory_bytes.find(b"\0", offset)
                        if terminator < 0:
                            raise ValueError("Unterminated forwarder within export directory")
                        forwarder = directory_bytes[offset:terminator].decode("ascii")
                        validate_forwarder(forwarder)
                    section = pe.get_section_by_rva(exp.address)
                    kind = "function"
                    if forwarder is None and section is not None:
                        if not section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                            kind = "data"
                    name = exp.name.decode("utf-8") if exp.name else None
                    exports.append(
                        ExportEntry(
                            name=name,
                            address=exp.address + base,
                            ordinal=exp.ordinal,
                            execution_mode="guest",
                            kind=kind,
                            forwarder=forwarder,
                        )
                    )

                except ValueError as error:
                    self._optional_error("export entry", error)

        tls_callbacks: list[int] = []
        tls_directory_va: int | None = None
        ptr_size = 4 if pe.arch == _arch.ARCH_X86 else 8
        if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
            tls_directory_va = pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress + base
            rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - base
            for i in range(100):
                ptr = pe.get_data(rva + ptr_size * i, ptr_size)
                ptr = int.from_bytes(ptr, "little")
                if ptr == 0:
                    break
                tls_callbacks.append(ptr)

        sections = []
        for sect in pe.sections:
            available = max(0, pe.image_size - sect.VirtualAddress)
            extent = min(max(sect.Misc_VirtualSize, sect.SizeOfRawData), available)
            if not extent:
                continue
            sect_name = sect.Name.decode("utf-8", errors="ignore").rstrip("\x00")
            sections.append(
                SectionEntry(
                    name=sect_name,
                    virtual_address=sect.VirtualAddress,
                    virtual_size=extent,
                    perms=perms_from_section_chars(sect.Characteristics),
                )
            )

        region = MemoryRegion(
            base=base,
            data=bytes(mapped_image),
            name="pe_image",
            perms=common.PERM_MEM_RWX,
        )

        entry_points = []
        ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if ep_rva:
            entry_points.append(base + ep_rva)

        name = ""
        if self._path:
            name = os.path.splitext(os.path.basename(self._path))[0]

        pe_metadata = PeMetadata(
            subsystem=pe.OPTIONAL_HEADER.Subsystem,
            timestamp=pe.FILE_HEADER.TimeDateStamp,
            machine=pe.FILE_HEADER.Machine,
            magic=pe.OPTIONAL_HEADER.Magic,
        )

        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.name is not None:
                    type_id = str(resource_type.name)
                else:
                    type_id = resource_type.struct.Id

                if not hasattr(resource_type, "directory"):
                    continue

                for resource_id in resource_type.directory.entries:
                    if resource_id.name is not None:
                        res_id = str(resource_id.name)
                    else:
                        res_id = resource_id.struct.Id

                    # Handle string table specifically for LoadString
                    if type_id == 6:  # RT_STRING
                        if hasattr(resource_id, "directory"):
                            for str_entry in resource_id.directory.entries:
                                directory = getattr(str_entry, "directory", None)
                                if directory is not None and hasattr(directory, "strings"):
                                    for s_id, s_val in directory.strings.items():
                                        pe_metadata.string_table[s_id] = s_val

                    # Regular resource entry
                    if hasattr(resource_id, "directory"):
                        for resource_lang in resource_id.directory.entries:
                            if hasattr(resource_lang, "data"):
                                data_rva = resource_lang.data.struct.OffsetToData
                                size = resource_lang.data.struct.Size
                                lang_id = 0
                                if hasattr(resource_lang.data.struct, "Id"):
                                    lang_id = resource_lang.data.struct.Id
                                # Calculate RVA of the entry structure for HRSRC compatibility
                                entry_offset = resource_lang.data.struct.get_file_offset()
                                entry_rva = pe.get_rva_from_offset(entry_offset)

                                pe_metadata.resources.append(
                                    ResourceEntry(
                                        id=res_id,
                                        type_id=type_id,
                                        data_rva=data_rva,
                                        size=size,
                                        lang_id=lang_id,
                                        entry_rva=entry_rva,
                                    )
                                )

        return LoadedImage(
            arch=pe.arch,
            module_type=module_type,
            name=name,
            emu_path=self._emu_path,
            image_base=base,
            image_size=pe.image_size,
            regions=[region],
            imports=imports,
            exports=exports,
            default_export_mode="guest",
            entry_points=entry_points,
            visible_in_peb=True,
            stack_size=max(pe.OPTIONAL_HEADER.SizeOfStackReserve or 0, 0x12000),
            tls_callbacks=tls_callbacks,
            tls_directory_va=tls_directory_va,
            loader=self,
            sections=sections,
            pe_metadata=pe_metadata,
        )


class ShellcodeLoader:
    def __init__(self, *, data: bytes, arch: int) -> None:
        self._data = data
        self._arch = arch

    def make_image(self) -> LoadedImage:
        region = MemoryRegion(
            base=0,
            data=self._data,
            name="shellcode",
            perms=common.PERM_MEM_RWX,
        )

        return LoadedImage(
            arch=self._arch,
            module_type="shellcode",
            source="guest_shellcode",
            name="shellcode",
            emu_path="",
            image_base=0,
            image_size=len(self._data),
            regions=[region],
            imports=[],
            exports=[],
            default_export_mode="intercepted",
            entry_points=[],
            visible_in_peb=False,
            loader=self,
            sections=[
                SectionEntry(
                    name="shellcode",
                    virtual_address=0,
                    virtual_size=len(self._data),
                    perms=common.PERM_MEM_RWX,
                )
            ],
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
        from speakeasy.windows.api_image import ApiExportSpec, build_api_image
        from speakeasy.windows.export_manifest import get_export_manifest

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

        def kind(name: str | None) -> str:
            return "data" if name in data_names else "function"

        manifest = get_export_manifest(self._name.lower(), arch_name)
        if manifest is not None:
            # The physical table owns names and ordinals. Handler-only names
            # follow the highest physical ordinal so that they never take an
            # ordinal that the real module leaves unused. A handler name whose
            # A or W variant is physical only serves dispatch of that variant.
            exports = [ApiExportSpec(e.name, e.ordinal, kind(e.name)) for e in manifest.exports]
            physical = {e.name for e in manifest.exports}
            next_ordinal = max((e.ordinal for e in manifest.exports), default=0) + 1
            extras = (handler_ordinals.keys() | data_names) - physical
            for name in sorted(n for n in extras if not {n + "A", n + "W"} & physical):
                exports.append(ApiExportSpec(name, next_ordinal, kind(name)))
                next_ordinal += 1
        else:
            # Strict enumeration owns surface membership. Lookup is intentionally
            # permissive for ABI reuse and must never determine exported names.
            specs = {
                sig.name: ApiExportSpec(sig.name) for sig in self._signature_db.iter_functions(self._name, arch_name)
            }
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
