# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import hashlib
import os
from collections import namedtuple
from enum import IntFlag

import pefile

import speakeasy.winenv.arch as _arch
import speakeasy.winenv.defs.nt.ddk as ddk
from speakeasy.struct import Enum

# GDT Constants needed to set our emulator into protected mode
# Access bits
GDT_ACCESS_BITS = Enum()
GDT_ACCESS_BITS.ProtMode32 = 0x4
GDT_ACCESS_BITS.PresentBit = 0x80
GDT_ACCESS_BITS.Ring3 = 0x60
GDT_ACCESS_BITS.Ring0 = 0
GDT_ACCESS_BITS.DataWritable = 0x2
GDT_ACCESS_BITS.CodeReadable = 0x2
GDT_ACCESS_BITS.DirectionConformingBit = 0x4
GDT_ACCESS_BITS.Code = 0x18
GDT_ACCESS_BITS.Data = 0x10

GDT_FLAGS = Enum()
GDT_FLAGS.Ring3 = 0x3
GDT_FLAGS.Ring0 = 0

DEFAULT_LOAD_ADDR = 0x40000

PAGE_SIZE = 0x1000

EMU_RESERVED = 0xFEEDF000
EMU_RESERVE_SIZE = 0x4000

EMU_RESERVED_END = EMU_RESERVED + EMU_RESERVE_SIZE
EMU_RETURN_ADDR = EMU_RESERVED
EXIT_RETURN_ADDR = EMU_RETURN_ADDR + 1
SEH_RETURN_ADDR = EMU_RETURN_ADDR + 4
API_CALLBACK_HANDLER_ADDR = EMU_RETURN_ADDR + 8


class ImageSectionCharacteristics(IntFlag):
    IMAGE_SCN_TYPE_NO_PAD = 0x00000008

    IMAGE_SCN_CNT_CODE = 0x00000020
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080

    IMAGE_SCN_LNK_OTHER = 0x00000100
    IMAGE_SCN_LNK_INFO = 0x00000200
    IMAGE_SCN_LNK_REMOVE = 0x00000800
    IMAGE_SCN_LNK_COMDAT = 0x00001000
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000

    IMAGE_SCN_GPREL = 0x00008000

    IMAGE_SCN_MEM_PURGEABLE = 0x00020000
    IMAGE_SCN_MEM_16BIT = 0x00020000  # IMAGE_SCN_MEM_PURGEABLE alias
    IMAGE_SCN_MEM_LOCKED = 0x00040000
    IMAGE_SCN_MEM_PRELOAD = 0x00080000

    # Alignment (object files only)
    IMAGE_SCN_ALIGN_1BYTES = 0x00100000
    IMAGE_SCN_ALIGN_2BYTES = 0x00200000
    IMAGE_SCN_ALIGN_4BYTES = 0x00300000
    IMAGE_SCN_ALIGN_8BYTES = 0x00400000
    IMAGE_SCN_ALIGN_16BYTES = 0x00500000
    IMAGE_SCN_ALIGN_32BYTES = 0x00600000
    IMAGE_SCN_ALIGN_64BYTES = 0x00700000
    IMAGE_SCN_ALIGN_128BYTES = 0x00800000
    IMAGE_SCN_ALIGN_256BYTES = 0x00900000
    IMAGE_SCN_ALIGN_512BYTES = 0x00A00000
    IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000
    IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000
    IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000
    IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000

    # Memory flags
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
    IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
    IMAGE_SCN_MEM_NOT_PAGED = 0x08000000
    IMAGE_SCN_MEM_SHARED = 0x10000000
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000


def normalize_dll_name(name):
    ret = name

    # Funnel CRTs into a single handler
    if name.lower().startswith(("api-ms-win-crt", "vcruntime", "ucrtbased", "ucrtbase", "msvcr", "msvcp")):
        ret = "msvcrt"

    # Redirect windows sockets 1.0 to windows sockets 2.0
    elif name.lower().startswith(("winsock", "wsock32")):
        ret = "ws2_32"

    elif name.lower().startswith("api-ms-win-core"):
        ret = "kernel32"

    return ret


class PeParseException(Exception):
    pass


class _PeParser(pefile.PE):
    """
    Represents PE files loaded into the emulator
    """

    def __init__(self, path=None, data=None, emu_path="", fast_load=False):
        super().__init__(name=path, data=data, fast_load=fast_load)

        if 0 == self.OPTIONAL_HEADER.ImageBase:
            self.relocate_image(DEFAULT_LOAD_ADDR)
            super().__init__(name=None, data=self.write())

        self.file_size = 0
        self.base = self.OPTIONAL_HEADER.ImageBase
        self.hash = self._hash_pe(path=path, data=data)
        self.imports = self._get_pe_imports()
        self.exports = self._get_pe_exports()
        self.mapped_image = self.get_memory_mapped_image(max_virtual_address=0xF0000000)
        # self.mapped_image = None
        self.image_size = self.OPTIONAL_HEADER.SizeOfImage
        self.is_mapped = True
        self.pe_sections = self._get_pe_sections()
        self.ep = self.OPTIONAL_HEADER.AddressOfEntryPoint
        self.stack_commit = self.OPTIONAL_HEADER.SizeOfStackCommit
        self.path = ""
        self.name = ""
        if path:
            self.path = os.path.abspath(path)
        self.emu_path = emu_path
        self.arch = self._get_architecture()
        if self.arch == _arch.ARCH_X86:
            self.ptr_size = 4
        else:
            self.ptr_size = 8

    def get_tls_callbacks(self):
        """
        Get the TLS callbacks for a PE (if any)
        """
        max_tls_callbacks = 100
        callbacks = []
        if hasattr(self, "DIRECTORY_ENTRY_TLS"):
            rva = self.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - self.OPTIONAL_HEADER.ImageBase

            for i in range(max_tls_callbacks):
                ptr = self.get_data(rva + self.ptr_size * i, self.ptr_size)
                ptr = int.from_bytes(ptr, "little")
                if ptr == 0:
                    break
                callbacks.append(ptr)
        return callbacks

    def get_resource_dir_rva(self):
        res_dir_rva = 0
        for dd in self.OPTIONAL_HEADER.DATA_DIRECTORY:
            if dd.name == "IMAGE_DIRECTORY_ENTRY_RESOURCE":
                res_dir_rva = dd.VirtualAddress
                break

        return res_dir_rva

    def _hash_pe(self, path=None, data=None):
        hasher = hashlib.sha256()
        buf = b""
        if path:
            with open(path, "rb") as f:
                buf = f.read()
        elif data:
            buf = data

        hasher.update(buf)
        self.file_size = len(buf)
        return hasher.hexdigest()

    def _get_pe_imports(self):
        pe = self
        imports: dict[int, tuple[str, str]] = {}

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return imports

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll
            dll = dll.decode("utf-8")
            dll = os.path.splitext(dll)[0]
            for imp in entry.imports:
                if imp.import_by_ordinal:
                    func_name = f"ordinal_{imp.ordinal}"
                    imports.update({imp.address: (dll, func_name)})
                else:
                    func_name = imp.name.decode("utf-8")
                    imports.update({imp.address: (dll, func_name)})
        return imports

    def get_exports(self):
        self.exports = self._get_pe_exports()

        return self.exports

    def _get_pe_exports(self):
        pe = self
        exports: list = []
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return exports

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            entry = namedtuple("export", ["name", "address", "forwarder", "ordinal"])  # type: ignore[name-match]  # legacy: namedtuple name differs from var
            entry.name = exp.name
            entry.address = exp.address + pe.base
            entry.forwarder = exp.forwarder
            entry.ordinal = exp.ordinal
            if entry.name:
                entry.name = entry.name.decode("utf-8")
            exports.append(entry)
        return exports

    def _get_pe_sections(self):
        pe = self
        sections = []
        for section in pe.sections:
            sect = (section.Name, section.VirtualAddress, section.Misc_VirtualSize, section.SizeOfRawData)
            sections.append(sect)
        return sections

    def get_section_by_name(self, name):
        sect = [s for s in self.sections if s.Name.decode("utf-8").strip("\x00") == name]
        if sect:
            return sect[0]

    def _get_architecture(self):
        # 0x010b: PE32, 0x020b: PE32+ (64 bit)
        magic = self.OPTIONAL_HEADER.Magic
        if magic & ddk.PE32_BIT:
            return _arch.ARCH_X86
        elif magic & ddk.PE32_PLUS_BIT:
            return _arch.ARCH_AMD64
        else:
            raise ValueError(f"Unsupported architecture: 0x{magic:x}")

    def get_export_by_name(self, name):
        for exp in self.get_exports():
            if name == exp.name:
                return exp.address

    def get_raw_data(self):
        return self.get_memory_mapped_image()

    def find_bytes(self, pattern, offset=0):
        return self.get_raw_data().find(pattern, offset)

    def set_bytes(self, offset, pattern):
        self.set_bytes_at_offset(offset, pattern)

    def get_base_name(self):
        fn = os.path.basename(self.path)
        bn = os.path.splitext(fn)[0]
        return bn

    def is_driver(self):
        rv = super().is_driver()
        if rv:
            return rv

        system_DLLs = set((b"ntoskrnl.exe", b"hal.dll", b"ndis.sys", b"bootvid.dll", b"kdcom.dll", b"win32k.sys"))

        if hasattr(self, "DIRECTORY_ENTRY_IMPORT"):
            if system_DLLs.intersection([imp.dll.lower() for imp in self.DIRECTORY_ENTRY_IMPORT]):
                return True

        if self.OPTIONAL_HEADER.Subsystem == pefile.SUBSYSTEM_TYPE["IMAGE_SUBSYSTEM_NATIVE"] and self.ep == 0:
            return True

    def is_dotnet(self):
        """
        Is the current PE file a .NET assembly?
        """
        for addr, imp in self.imports.items():
            dll, func = imp
            if dll == "mscoree" and func in ["_CorExeMain", "_CorDllMain"]:
                return True
        return False

    def has_reloc_table(self):
        return len(self.OPTIONAL_HEADER.DATA_DIRECTORY) >= 6 and self.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size > 0

    def rebase(self, to):
        self.relocate_image(to)

        self.base = to
        self.ep = self.OPTIONAL_HEADER.AddressOfEntryPoint

        # After relocation, generate a new memory mapped image
        self.mapped_image = self.get_memory_mapped_image(max_virtual_address=0xF0000000)

        self.pe_sections = self._get_pe_sections()
        self.imports = self._get_pe_imports()
        self.exports = self._get_pe_exports()

        return
