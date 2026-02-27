from __future__ import annotations

import ntpath
import os
from dataclasses import dataclass, field
from typing import Any, Protocol

import speakeasy.common as common
import speakeasy.winenv.arch as _arch


@dataclass
class ResourceEntry:
    id: int | str
    data_rva: int
    size: int
    type_id: int | str
    entry_rva: int # RVA of the IMAGE_RESOURCE_DATA_ENTRY structure
    lang_id: int = 0


@dataclass
class PeMetadata:
    subsystem: int
    timestamp: int
    machine: int
    magic: int
    resources: list[ResourceEntry] = field(default_factory=list)
    string_table: dict[int, str] = field(default_factory=dict) # For LoadString


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
    return perms


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


@dataclass
class ExportEntry:
    name: str | None
    address: int
    ordinal: int
    execution_mode: str


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


class Loader(Protocol):
    def make_image(self) -> LoadedImage: ...


class RuntimeModule:
    def __init__(self, image: LoadedImage) -> None:
        self._image = image
        self._pe: Any = None
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

    def is_decoy(self) -> bool:
        return self._image.module_type == "decoy"

    def get_base(self) -> int:
        return self.base

    def get_image_size(self) -> int:
        return self.image_size

    def get_emu_path(self) -> str:
        return self.emu_path

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


class PeLoader:
    def __init__(self, *, path: str | None = None, data: bytes | None = None) -> None:
        self._path = path
        self._data = data
        self._pe_obj: Any = None

    def make_image(self) -> LoadedImage:
        from speakeasy.windows.common import _PeParser

        pe = _PeParser(path=self._path, data=self._data, imp_id=0xFEEDF00C, imp_step=4)
        self._pe_obj = pe

        module_type = "exe"
        if pe.is_driver():
            module_type = "driver"
        elif pe.is_dll():
            module_type = "dll"

        base = pe.base
        mapped_image = pe.get_memory_mapped_image(max_virtual_address=0xF0000000)

        imports: list[ImportEntry] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8")
                dll = os.path.splitext(dll)[0]
                for imp in entry.imports:
                    if imp.import_by_ordinal:
                        func_name = f"ordinal_{imp.ordinal}"
                    else:
                        func_name = imp.name.decode("utf-8")
                    imports.append(
                        ImportEntry(
                            iat_address=imp.address,
                            dll_name=dll,
                            func_name=func_name,
                        )
                    )

        exports: list[ExportEntry] = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode("utf-8") if exp.name else None
                exports.append(
                    ExportEntry(
                        name=name,
                        address=exp.address + base,
                        ordinal=exp.ordinal,
                        execution_mode="intercepted",
                    )
                )

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
            sect_name = sect.Name.decode("utf-8", errors="ignore").rstrip("\x00")
            sections.append(
                SectionEntry(
                    name=sect_name,
                    virtual_address=sect.VirtualAddress,
                    virtual_size=sect.Misc_VirtualSize,
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
            magic=pe.OPTIONAL_HEADER.Magic
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
                    if type_id == 6: # RT_STRING
                         if hasattr(resource_id, "directory"):
                            for str_entry in resource_id.directory.entries:
                                # pefile handles strings as a dict {id: string}
                                if hasattr(str_entry.directory, "strings"):
                                    for s_id, s_val in str_entry.directory.strings.items():
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
                                
                                pe_metadata.resources.append(ResourceEntry(
                                    id=res_id,
                                    type_id=type_id,
                                    data_rva=data_rva,
                                    size=size,
                                    lang_id=lang_id,
                                    entry_rva=entry_rva
                                ))

        return LoadedImage(
            arch=pe.arch,
            module_type=module_type,
            name=name,
            emu_path="",
            image_base=base,
            image_size=pe.image_size,
            regions=[region],
            imports=imports,
            exports=exports,
            default_export_mode="intercepted",
            entry_points=entry_points,
            visible_in_peb=True,
            stack_size=pe.OPTIONAL_HEADER.SizeOfStackReserve or 0x12000,
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


class IdaLoader:
    def __init__(self) -> None:
        pass

    def make_image(self) -> LoadedImage:
        raise NotImplementedError


class ApiModuleLoader:
    def __init__(self, *, name: str, api: Any, arch: int, base: int, emu_path: str) -> None:
        self._name = name
        self._api = api
        self._arch = arch
        self._base = base
        self._emu_path = emu_path

    def make_image(self) -> LoadedImage:
        from speakeasy.windows.common import EXPORTED_FUNCTION, JitPeFile

        funcs = [(f[4], f[0]) for k, f in self._api.funcs.items() if isinstance(k, str)]
        data_exports = [k for k, d in self._api.data.items() if isinstance(k, str)]

        new = funcs.copy()

        if self._name == "ntdll":
            nt_handler = getattr(self._api, "_nt_handler", None)
            if nt_handler:
                nt_funcs = [(f[4], f[0]) for k, f in nt_handler.funcs.items() if isinstance(k, str)]
                new = funcs + nt_funcs

        if self._name in ("ntdll", "ntoskrnl"):
            extra = []
            for _o, fn in new:
                if fn.startswith("Nt"):
                    extra.append((None, "Zw" + fn[2:]))
                elif fn.startswith("Zw"):
                    extra.append((None, "Nt" + fn[2:]))
            new = new + extra
        else:
            extra = []
            for _o, fn in new:
                extra.append((None, fn + "A"))
                extra.append((None, fn + "W"))
            new = new + extra

        func_names = [fn for _o, fn in new]
        func_names.sort()

        all_exports: list[str] = []
        ords = [o for o, _fn in funcs if o is not None]
        if ords:
            num_exports = max(max(ords) + 1, len(all_exports) + 1)
            all_exports = [f"ordinal_{i}" for i in range(num_exports)]
            for o, fn in funcs:
                if o is not None:
                    all_exports[o - 1] = fn
            for fn in func_names:
                if fn not in all_exports:
                    all_exports.append(fn)
        if not all_exports:
            all_exports = func_names
        all_exports += data_exports

        jit = JitPeFile(self._arch, base=self._base)
        img_data = jit.get_decoy_pe_image(self._name, all_exports)
        image_size = jit.basepe.OPTIONAL_HEADER.SizeOfImage

        text_sect = jit.get_section_by_name(jit.basepe, ".text")
        text_va = text_sect.VirtualAddress
        stub_size = len(EXPORTED_FUNCTION[self._arch])

        pe_exports: list[ExportEntry] = []
        for i, name in enumerate(all_exports):
            pe_exports.append(
                ExportEntry(
                    name=name,
                    address=self._base + text_va + i * stub_size,
                    ordinal=i + 1,
                    execution_mode="intercepted",
                )
            )

        sections = []
        for sect in jit.basepe.sections:
            sect_name = sect.Name.decode("utf-8", errors="ignore").rstrip("\x00")
            vs = sect.Misc_VirtualSize
            sections.append(
                SectionEntry(
                    name=sect_name,
                    virtual_address=sect.VirtualAddress,
                    virtual_size=vs,
                    perms=perms_from_section_chars(sect.Characteristics),
                )
            )

        region = MemoryRegion(
            base=self._base,
            data=bytes(img_data),
            name="api_module",
            perms=common.PERM_MEM_RWX,
        )

        pe_metadata = PeMetadata(
            subsystem=jit.basepe.OPTIONAL_HEADER.Subsystem,
            timestamp=jit.basepe.FILE_HEADER.TimeDateStamp,
            machine=jit.basepe.FILE_HEADER.Machine,
            magic=jit.basepe.OPTIONAL_HEADER.Magic
        )
        
        return LoadedImage(
            arch=self._arch,
            module_type="dll",
            name=self._name,
            emu_path=self._emu_path,
            image_base=self._base,
            image_size=image_size,
            regions=[region],
            imports=[],
            exports=pe_exports,
            default_export_mode="intercepted",
            entry_points=[],
            visible_in_peb=True,
            loader=self,
            sections=sections,
            pe_metadata=pe_metadata,
        )


class DecoyLoader:
    def __init__(self, *, name: str, base: int, emu_path: str, image_size: int) -> None:
        self._name = name
        self._base = base
        self._emu_path = emu_path
        self._image_size = image_size

    def make_image(self) -> LoadedImage:
        pe_metadata = PeMetadata(
            subsystem=2, # IMAGE_SUBSYSTEM_WINDOWS_GUI
            timestamp=0,
            machine=0,
            magic=0
        )
        return LoadedImage(
            arch=0,
            module_type="decoy",
            name=self._name,
            emu_path=self._emu_path,
            image_base=self._base,
            image_size=self._image_size,
            regions=[],
            imports=[],
            exports=[],
            default_export_mode="intercepted",
            entry_points=[],
            visible_in_peb=True,
            loader=self,
            pe_metadata=pe_metadata,
        )
