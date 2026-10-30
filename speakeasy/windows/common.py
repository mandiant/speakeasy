# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import datetime
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

# The machine setup allocates memory from this base, so that the input image can use its preferred base.
# On x86, the container image must fit between this base and TEB_ADDRESS.
MACHINE_BASE = 0x7D000000
# The user mode addresses of the first TEB and the first PEB in 32-bit Windows.
# x64 uses them too, because the GS base comes from a 32-bit GDT descriptor.
TEB_ADDRESS = 0x7FFDE000
PEB_ADDRESS = 0x7FFDF000

EMU_RESERVED = 0xFEEDF000
EMU_RESERVE_SIZE = 0x4000

EMU_RESERVED_END = EMU_RESERVED + EMU_RESERVE_SIZE
EMU_RETURN_ADDR = EMU_RESERVED
EXIT_RETURN_ADDR = EMU_RETURN_ADDR + 1
GUEST_CALLBACK_RETURN_ADDR = EMU_RETURN_ADDR + 8

# The emulated system booted one day before emulation starts.
START_TICK_COUNT = 24 * 60 * 60 * 1000

FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


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


def get_filetime(when: datetime.datetime) -> int:
    """
    Return a time with a time zone as a FILETIME value, in 100 ns units since 1601.
    """
    return (when - FILETIME_EPOCH) // datetime.timedelta(microseconds=1) * 10


# DLL and API set name prefixes, and the modules that have handlers for their
# functions. The first prefix that matches is used. When the functions of a set
# are in more than one module, the main module is first.
DLL_HOSTS: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (
        ("api-ms-win-crt", "api-ms-win-core-crt", "vcruntime", "ucrtbased", "ucrtbase", "msvcr", "msvcp", "crtdll"),
        ("msvcrt",),
    ),
    (("winsock", "wsock32"), ("ws2_32",)),
    (
        ("ext-ms-win-ntuser", "ext-ms-win-rtcore-ntuser", "api-ms-win-rtcore-ntuser", "api-ms-win-ntuser-"),
        ("user32",),
    ),
    (("ext-ms-win-gdi", "ext-ms-win-rtcore-gdi"), ("gdi32",)),
    (("api-ms-win-eventing", "api-ms-win-service", "api-ms-win-security"), ("advapi32",)),
    (("api-ms-win-shell-", "api-ms-win-core-commandlinetoargv", "ext-ms-win-shell32-"), ("shell32",)),
    (("api-ms-win-shcore-obsolete",), ("shell32", "shlwapi")),
    (("api-ms-win-core-shlwapi",), ("shlwapi",)),
    (("api-ms-win-core-com-l", "ext-ms-win-com-ole32", "ext-ms-win-ole32-"), ("ole32",)),
    (("api-ms-win-core-winrt",), ("combase",)),
    (("api-ms-win-core-string-l2",), ("user32",)),
    (("api-ms-win-mm-",), ("winmm",)),
    (("api-ms-win-core-version",), ("version",)),
    (("api-ms-win-core-processthreads",), ("kernel32", "advapi32")),
    (("api-ms-win-core-libraryloader", "api-ms-win-core-stringansi"), ("kernel32", "user32")),
    (("api-ms-win-core",), ("kernel32",)),
    (("ext-ms-win-session-wtsapi32",), ("wtsapi32",)),
    (("ext-ms-win-setupapi-",), ("setupapi",)),
    (("sspicli",), ("secur32",)),
    (("kernelbase",), ("kernelbase", "kernel32")),
    (("ntoskrnl",), ("ntoskrnl", "msvcrt")),
)


def get_dll_hosts(name: str) -> tuple[str, ...]:
    """
    Get the modules that have handlers for the functions of a DLL or API set.
    A DLL that is not in DLL_HOSTS has its own handlers.
    """
    lower = name.lower()
    for prefixes, hosts in DLL_HOSTS:
        if lower.startswith(prefixes):
            return hosts
    return (name,)


def normalize_dll_name(name: str) -> str:
    """Get the main module that has handlers for a DLL or API set."""
    return get_dll_hosts(name)[0]


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
        self.mapped_image = self.get_mapped_image()
        self.image_size = self.OPTIONAL_HEADER.SizeOfImage
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
        directories = self.OPTIONAL_HEADER.DATA_DIRECTORY
        return len(directories) > 14 and bool(directories[14].VirtualAddress and directories[14].Size)

    def get_mapped_image(self) -> bytes:
        """
        Return the image with each section at its virtual address.

        pefile leaves out a section whose raw data goes past the end of the file. Windows maps the
        bytes that the file has and fills the rest with zeros, so this keeps them.
        """
        data = self.__data__
        alignment = self.OPTIONAL_HEADER.SectionAlignment
        file_alignment = self.OPTIONAL_HEADER.FileAlignment
        mapped = bytearray(self.header)
        for section in self.sections:
            if section.Misc_VirtualSize == 0 and section.SizeOfRawData == 0:
                continue
            offset = self.adjust_PointerToRawData(section.PointerToRawData)
            address = self.adjust_SectionAlignment(section.VirtualAddress, alignment, file_alignment)
            if offset > len(data) or address >= 0xF0000000:
                continue
            if address > len(mapped):
                mapped.extend(bytes(address - len(mapped)))
            else:
                del mapped[address:]
            mapped += section.get_data()
        return bytes(mapped[: self.OPTIONAL_HEADER.SizeOfImage])

    def rebase(self, to):
        self.relocate_image(to)

        self.base = to
        self.ep = self.OPTIONAL_HEADER.AddressOfEntryPoint

        # After relocation, generate a new memory mapped image
        self.mapped_image = self.get_mapped_image()

        self.imports = self._get_pe_imports()
        self.exports = self._get_pe_exports()

        return
