# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import hashlib
import ntpath
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

IMPORT_HOOK_ADDR = 0xFEEDFACE
DEFAULT_LOAD_ADDR = 0x40000

PAGE_SIZE = 0x1000

EMU_RESERVED = 0xfeedf000
EMU_RESERVE_SIZE = 0x4000
DYM_IMP_RESERVE = EMU_RESERVED + 0x1000
EMU_CALLBACK_RESERVE = DYM_IMP_RESERVE + 0x1000
EMU_SYSCALL_RESERVE = EMU_CALLBACK_RESERVE + 0x1000

EMU_RESERVED_END = (EMU_RESERVED + EMU_RESERVE_SIZE)
EMU_RETURN_ADDR = EMU_RESERVED
EXIT_RETURN_ADDR = EMU_RETURN_ADDR + 1
SEH_RETURN_ADDR = EMU_RETURN_ADDR + 4
API_CALLBACK_HANDLER_ADDR = EMU_RETURN_ADDR + 8
IMPORT_HOOK_ADDR = EMU_RETURN_ADDR + 12

# Common blank DOS header
DOS_HEADER = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00' \
             b'\x00\x00\x00\x00@' + (b'\x00' * 35) + \
             b'\xb0\x00\x00\x00\x0e\x1f\xba\x0e\x00\xb4\t\xcd!\xb8\x01L\xcd!This program ' \
             b'cannot be run in DOS mode.\r\r\n$' + (b'\x00' * 39) + \
             b'Rich\xbeL\x1c\x41\x00\x00\x00\x00\x00\x00\x00\x00'

# Blank header used for a 32-bit PE header
EMPTY_PE_32 = DOS_HEADER + b'PE\x00\x00L\x01\x00\x00ABCD\x00\x00\x00\x00\x00\x00\x00\x00'   \
                           b'\xe0\x00\x03\x01\x0b\x01\x08\x00\x04\x00\x00\x00\x00\x00\x00'  \
                           b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd0\x01\x00\x00\xd4\x01'  \
                           b'\x00\x00\x00\x00@\x00\x01\x00\x00\x00\x01\x00\x00\x00\x04\x00' \
                           b'\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\xd4'  \
                           b'\x01\x00\x00\xd0\x01\x00\x00\x00\x00\x00\x00\x02\x00\x00\x04'  \
                           b'\x00\x00\x10\x00\x00\x10\x00\x00\x00\x00\x10\x00\x00\x10\x00'  \
                           b'\x00\x00\x00\x00\x00\x10' + (b'\x00' * 131)

# Blank header used for a 64-bit PE header
EMPTY_PE_64 = DOS_HEADER + b'PE\x00\x00d\x86\x00\x00ABCD\x00\x00\x00\x00\x00\x00\x00\x00'   \
                           b'\xf0\x00\x03\x10\x0b\x02\x08\x00\x04\x00\x00\x00\x00\x00\x00'  \
                           b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@' \
                           b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x06\x00'  \
                           b'\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xb8'  \
                           b'\x01\x00\x00\x00\x00\x00\x00AAAA\x02\x00\x00\x04\x00\x00\x10'  \
                           b'\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00'  \
                           b'\x10\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00'  \
                           b'\x00\x00\x00\x10' + (b'\x00' * 131)

# a 16-byte-aligned code used to implement exported functions in a 32-bit decoy module
X86_EXPORTED_FUNCTION = (
    b'\x8b\xff'                     # mov edi, edi
    b'\x55'                         # push ebp
    b'\x8b\xec'                     # mov ebp, esp
    b'\xb8\x00\x00\x00\x00'         # mov eax, 0
    b'\x8b\xe5'                     # mov esp, ebp
    b'\x5d'                         # pop ebp
    b'\xc3'                         # ret
    b'\xcc'                         # int3
    b'\xcc'                         # int3
    b'\xcc'                         # int3
)

# a 16-byte-aligned code used to implement exported functions in a 64-bit decoy module
X64_EXPORTED_FUNCTION = (
    b'\x48\x89\xff'                 # mov rdi, rdi
    b'\x90'                         # nop
    b'\x48\xc7\xc0\x00\x00\x00\x00' # mov rax, 0
    b'\xc3'                         # ret
    b'\xcc'                         # int3
    b'\xcc'                         # int3
    b'\xcc'                         # int3
    b'\xcc'                         # int3
)

EXPORTED_FUNCTION = {
    _arch.ARCH_X86: X86_EXPORTED_FUNCTION,
    _arch.ARCH_AMD64: X64_EXPORTED_FUNCTION
}

class ImageSectionCharacteristics(IntFlag):
    IMAGE_SCN_TYPE_NO_PAD            = 0x00000008

    IMAGE_SCN_CNT_CODE               = 0x00000020
    IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080

    IMAGE_SCN_LNK_OTHER              = 0x00000100
    IMAGE_SCN_LNK_INFO               = 0x00000200
    IMAGE_SCN_LNK_REMOVE             = 0x00000800
    IMAGE_SCN_LNK_COMDAT             = 0x00001000
    IMAGE_SCN_LNK_NRELOC_OVFL         = 0x01000000

    IMAGE_SCN_GPREL                  = 0x00008000

    IMAGE_SCN_MEM_PURGEABLE          = 0x00020000
    IMAGE_SCN_MEM_16BIT              = 0x00020000  # IMAGE_SCN_MEM_PURGEABLE alias
    IMAGE_SCN_MEM_LOCKED             = 0x00040000
    IMAGE_SCN_MEM_PRELOAD            = 0x00080000

    # Alignment (object files only)
    IMAGE_SCN_ALIGN_1BYTES           = 0x00100000
    IMAGE_SCN_ALIGN_2BYTES           = 0x00200000
    IMAGE_SCN_ALIGN_4BYTES           = 0x00300000
    IMAGE_SCN_ALIGN_8BYTES           = 0x00400000
    IMAGE_SCN_ALIGN_16BYTES          = 0x00500000
    IMAGE_SCN_ALIGN_32BYTES          = 0x00600000
    IMAGE_SCN_ALIGN_64BYTES          = 0x00700000
    IMAGE_SCN_ALIGN_128BYTES         = 0x00800000
    IMAGE_SCN_ALIGN_256BYTES         = 0x00900000
    IMAGE_SCN_ALIGN_512BYTES         = 0x00A00000
    IMAGE_SCN_ALIGN_1024BYTES        = 0x00B00000
    IMAGE_SCN_ALIGN_2048BYTES        = 0x00C00000
    IMAGE_SCN_ALIGN_4096BYTES        = 0x00D00000
    IMAGE_SCN_ALIGN_8192BYTES        = 0x00E00000

    # Memory flags
    IMAGE_SCN_MEM_DISCARDABLE        = 0x02000000
    IMAGE_SCN_MEM_NOT_CACHED         = 0x04000000
    IMAGE_SCN_MEM_NOT_PAGED          = 0x08000000
    IMAGE_SCN_MEM_SHARED             = 0x10000000
    IMAGE_SCN_MEM_EXECUTE            = 0x20000000
    IMAGE_SCN_MEM_READ               = 0x40000000
    IMAGE_SCN_MEM_WRITE              = 0x80000000

def normalize_dll_name(name):
    ret = name

    # Funnel CRTs into a single handler
    if name.lower().startswith(('api-ms-win-crt', 'vcruntime', 'ucrtbased', 'ucrtbase', 'msvcr', 'msvcp')):
        ret = 'msvcrt'

    # Redirect windows sockets 1.0 to windows sockets 2.0
    elif name.lower().startswith(('winsock', 'wsock32')):
        ret = 'ws2_32'

    elif name.lower().startswith('api-ms-win-core'):
        ret = 'kernel32'

    return ret


class PeParseException(Exception):
    pass


class PeFile(pefile.PE):
    """
    Represents PE files loaded into the emulator
    """
    def __init__(self, path=None, data=None, imp_id=IMPORT_HOOK_ADDR,
                 imp_step=4, emu_path='', fast_load=False):

        super().__init__(name=path, data=data, fast_load=fast_load)

        if 0 == self.OPTIONAL_HEADER.ImageBase:
            self.relocate_image(DEFAULT_LOAD_ADDR)
            super().__init__(name=None, data=self.write())

        self.imp_id = imp_id
        self.imp_step = imp_step
        self.file_size = 0
        self.base = self.OPTIONAL_HEADER.ImageBase
        self.hash = self._hash_pe(path=path, data=data)
        self.imports = self._get_pe_imports()
        self.exports = self._get_pe_exports()
        self.mapped_image = self.get_memory_mapped_image(max_virtual_address=0xf0000000)
        # self.mapped_image = None
        self.image_size = self.OPTIONAL_HEADER.SizeOfImage
        self.import_table = {}
        self.is_mapped = True
        self.pe_sections = self._get_pe_sections()
        self.ep = self.OPTIONAL_HEADER.AddressOfEntryPoint
        self.stack_commit = self.OPTIONAL_HEADER.SizeOfStackCommit
        self.path = ''
        self.name = ''
        if path:
            self.path = os.path.abspath(path)
        self.emu_path = emu_path
        self.arch = self._get_architecture()
        if self.arch == _arch.ARCH_X86:
            self.ptr_size = 4
        else:
            self.ptr_size = 8

        self._patch_imports()

    def get_tls_callbacks(self):
        """
        Get the TLS callbacks for a PE (if any)
        """
        max_tls_callbacks = 100
        callbacks = []
        if hasattr(self, 'DIRECTORY_ENTRY_TLS'):
            rva = (self.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks -
                   self.OPTIONAL_HEADER.ImageBase)

            for i in range(max_tls_callbacks):
                ptr = self.get_data(rva + self.ptr_size * i, self.ptr_size)
                ptr = int.from_bytes(ptr, 'little')
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

    def get_emu_path(self):
        """
        Get the path of the module (as it appears to the emulated binary)
        """
        return self.emu_path

    def set_emu_path(self, path):
        self.emu_path = path

    def _hash_pe(self, path=None, data=None):
        hasher = hashlib.sha256()
        buf = b''
        if path:
            with open(path, 'rb') as f:
                buf = f.read()
        elif data:
            buf = data

        hasher.update(buf)
        self.file_size = len(buf)
        return hasher.hexdigest()

    def _get_pe_imports(self):
        pe = self
        imports = {}

        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return imports

        for entry in pe.DIRECTORY_ENTRY_IMPORT:  # type: ignore[attr-defined]
            dll = entry.dll
            dll = dll.decode('utf-8')
            dll = os.path.splitext(dll)[0]
            for imp in entry.imports:
                if imp.import_by_ordinal:
                    func_name = f'ordinal_{imp.ordinal}'
                    imports.update({imp.address: (dll, func_name)})
                else:
                    func_name = imp.name.decode('utf-8')
                    imports.update({imp.address: (dll, func_name)})
        return imports

    def get_exports(self):
        self.exports = self._get_pe_exports()

        return self.exports

    def _get_pe_exports(self):
        pe = self
        exports = []
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return exports

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:  # type: ignore[attr-defined]
            entry = namedtuple('export', ['name', 'address', 'forwarder', 'ordinal'])
            entry.name = exp.name
            entry.address = exp.address + pe.get_base()
            entry.forwarder = exp.forwarder
            entry.ordinal = exp.ordinal
            if entry.name:
                entry.name = entry.name.decode('utf-8')
            exports.append(entry)
        return exports

    def _get_pe_sections(self):
        pe = self
        sections = []
        for section in pe.sections:
            sect = (section.Name, section.VirtualAddress,
                    section.Misc_VirtualSize, section.SizeOfRawData)
            sections.append(sect)
        return sections

    def get_sections(self):
        return self.sections

    def get_section_by_name(self, name):
        sect = [s for s in self.get_sections() if s.Name.decode('utf-8').strip('\x00') == name]
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
            raise ValueError(f'Unsupported architecture: 0x{magic:x}')

    def _patch_imports(self):
        """
        Imports are patched with invalid memory addresses. When the API is called
        by the emulated binary, the invalid memory fetch callback will trigger,
        allowing us to handle the Windows API within the emulator
        """
        if not self.imports:
            return

        if not self.mapped_image:
            raise ValueError('PE image has not been mapped yet')

        for addr, imp in self.imports.items():
            tmp = bytearray(self.mapped_image)
            offset = addr - self.base
            tmp[offset: offset + self.ptr_size] = \
                self.imp_id.to_bytes(self.ptr_size, 'little')
            self.mapped_image = bytes(tmp)

            self.import_table.update({self.imp_id: imp})
            self.imp_id += self.imp_step

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

    def get_ptr_size(self):
        return self.ptr_size

    def get_base(self):
        return self.base

    def get_base_name(self):
        fn = os.path.basename(self.path)
        bn = os.path.splitext(fn)[0]
        return bn

    def get_image_size(self):
        return self.image_size

    def is_decoy(self):
        return False

    def is_driver(self):
        rv = super().is_driver()
        if rv:
            return rv

        system_DLLs = set((b'ntoskrnl.exe', b'hal.dll', b'ndis.sys',
                           b'bootvid.dll', b'kdcom.dll', b'win32k.sys'))

        if hasattr(self, 'DIRECTORY_ENTRY_IMPORT'):
            if system_DLLs.intersection(
                    [imp.dll.lower() for imp in self.DIRECTORY_ENTRY_IMPORT]):
                return True

        if self.OPTIONAL_HEADER.Subsystem == pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_NATIVE'] \
           and self.ep == 0:
            return True

    def is_dotnet(self):
        """
        Is the current PE file a .NET assembly?
        """
        for addr, imp in self.imports.items():
            dll, func = imp
            if dll == 'mscoree' and func in ['_CorExeMain', '_CorDllMain']:
                return True
        return False

    def has_reloc_table(self):
        return len(self.OPTIONAL_HEADER.DATA_DIRECTORY) >= 6 and \
                self.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size > 0

    def rebase(self, to):
        self.relocate_image(to)

        self.base = to
        self.ep = self.OPTIONAL_HEADER.AddressOfEntryPoint

        # After relocation, generate a new memory mapped image
        self.mapped_image = self.get_memory_mapped_image(max_virtual_address=0xf0000000)

        self.pe_sections = self._get_pe_sections()
        self.imports = self._get_pe_imports()
        self.exports = self._get_pe_exports()
        self._patch_imports()

        return

class DecoyModule(PeFile):
    """
    Class that represents "decoy" modules that are loaded into emulated memory.
    We use decoy modules so that shellcode
    (or other modules) can parse the PE file to resolve exports.
    """
    def __init__(self, path=None, data=None, fast_load=True, base=0, emu_path='', is_jitted=False):
        self.image_size = 0
        self.ep = 0
        self.is_jitted = is_jitted
        self.decoy_base = base
        if path or data:
            super().__init__(path=path, data=data, fast_load=fast_load)

        if data:
            self.image_size = len(data)

        self.decoy_path = emu_path
        self.base_name = ''
        self.is_mapped = False
        self.data = b''

    def get_memory_mapped_image(self, max_virtual_address=0x10000000, base=None):
        mmi = super().get_memory_mapped_image(max_virtual_address, base)
        if self.is_jitted and len(mmi) < len(self.__data__):
            return self.__data__
        return mmi

    def get_base(self):
        return self.decoy_base

    def get_emu_path(self):
        return self.decoy_path

    def get_base_name(self):
        p = self.get_emu_path()
        img = ntpath.basename(p)
        bn = os.path.splitext(img)[0]
        return bn

    def get_ep(self):
        return self.get_base() + self.ep

    def is_decoy(self):
        return True


class JitPeFile:
    '''
    Class used to rapidly assemble a decoy PE that will only contain an export table
    so malware can parse it.
    '''
    def __init__(self, arch, base=0):

        if arch == _arch.ARCH_X86:
            husk = EMPTY_PE_32
        else:
            husk = EMPTY_PE_64

        self.arch = arch

        self.basepe = pefile.PE(data=husk, fast_load=True)

        self.basepe.OPTIONAL_HEADER.FileAlignment = 0x200
        self.basepe.OPTIONAL_HEADER.SectionAlignment = 0x1000

        if base > 0:            
            self.basepe.OPTIONAL_HEADER.ImageBase = base

    def get_section_by_name(self, pe, name):
        '''
        Get a PE section by name
        '''
        for sect in pe.sections:
            if sect.Name.decode('utf-8').strip('\x00') == name.strip('\x00'):
                return self.cast_section(sect.get_file_offset())

    def get_raw_pe(self):
        '''
        Get the raw data associated with a decoy PE
        '''
        return self.basepe.__data__

    def update(self):
        '''
        Update the raw data associated with a decoy PE
        '''
        self.basepe = pefile.PE(None, self.basepe.write(), fast_load=True)
        self.update_image_size()

    def cast_section(self, offset=None):
        '''
        Get a section from a given offset
        '''
        if offset is None:
            offset = self.get_current_offset()
            data = pefile.Structure(self.basepe.__IMAGE_SECTION_HEADER_format__).sizeof() * b'\x00'
        else:
            data = self.basepe.get_data(offset, pefile.Structure(self.basepe.__IMAGE_SECTION_HEADER_format__).sizeof()) # noqa

        sect = self.basepe.__unpack_data__(self.basepe.__IMAGE_SECTION_HEADER_format__, data,
                                           offset)
        return sect

    def update_image_size(self):
        '''
        Update the size of the image within the optional header
        '''
        self.basepe.OPTIONAL_HEADER.SizeOfImage = (len(self.basepe.get_memory_mapped_image()) +
                                                   PAGE_SIZE)

    def add_section(self, name, chars=0x40000040):
        '''
        Add a section to the decoy PE
        '''
        new_sect = self.cast_section()
        new_sect.Name = name.encode('utf-8')
        new_sect.Characteristics = chars

        hdr_size = pefile.Structure(self.basepe.__IMAGE_SECTION_HEADER_format__).sizeof()

        self.basepe.OPTIONAL_HEADER.SizeOfHeaders += hdr_size
        self.basepe.OPTIONAL_HEADER.SizeOfImage += hdr_size
        self.basepe.FILE_HEADER.NumberOfSections += 1

        self.update()
        return new_sect

    def get_current_offset(self):
        '''
        Get the current offset (or size) of the PE
        '''
        return len(self.basepe.__data__)

    def append_data(self, data):
        '''
        Append data to the decoy PE
        '''
        self.basepe.__data__ += data

    def get_exports_size(self, name, exports_info):
        '''
        Get the total size of the export directory
        '''
        # Get the total size needed for the new export section
        exp_size = pefile.Structure(self.basepe.__IMAGE_EXPORT_DIRECTORY_format__).sizeof()

        exp_size += (len(name) + 1)

        for (_, exp) in exports_info:
            exp_size += len(exp) + 1
            exp_size += (0x4 + 0x4 + 0x4)

        return exp_size
    
    def pad_file(self):
        cur_offset = self.get_current_offset()
        fa = self.basepe.OPTIONAL_HEADER.FileAlignment            
        aligned_offset = (cur_offset + fa - 1) &~ (fa - 1)
        padding = b'\x00' * (aligned_offset-cur_offset)
        self.append_data(padding)

    def get_decoy_pe_image(self, mod_name, exports):
        text_chars = \
            ImageSectionCharacteristics.IMAGE_SCN_MEM_READ |\
            ImageSectionCharacteristics.IMAGE_SCN_MEM_EXECUTE |\
            ImageSectionCharacteristics.IMAGE_SCN_CNT_CODE
        
        edata_chars = \
            ImageSectionCharacteristics.IMAGE_SCN_MEM_READ |\
            ImageSectionCharacteristics.IMAGE_SCN_CNT_INITIALIZED_DATA
        
        self.add_section(name='.text', chars=int(text_chars))
        self.add_section(name='.edata', chars=int(edata_chars))
        self.pad_file()        

        exports_info = self.init_text_section(exports)
        self.pad_file()

        # update header size
        text_sect = self.get_section_by_name(self.basepe, '.text')
        self.basepe.OPTIONAL_HEADER.SizeOfHeaders = text_sect.PointerToRawData

        self.init_export_section(mod_name.encode('utf-8'), exports_info)
        return self.get_raw_pe()

    def init_export_section(self, name, exports_info):
        '''
        Initialize and add the export table to the PE
        '''
        exports_size = self.get_exports_size(name, exports_info)

        dest_exp_sect = self.get_section_by_name(self.basepe, '.edata')

        cur_offset = self.get_current_offset()
        sa = self.basepe.OPTIONAL_HEADER.SectionAlignment
        text_sect = self.get_section_by_name(self.basepe, '.text')
        text_aligned_size = (text_sect.Misc_VirtualSize + sa - 1) & ~(sa - 1)
        sec_rva = text_sect.VirtualAddress + text_aligned_size

        dest_exp_sect.Misc_VirtualSize = exports_size
        dest_exp_sect.Misc_PhysicalAddress = 0
        dest_exp_sect.VirtualAddress = sec_rva
        dest_exp_sect.SizeOfRawData = exports_size
        dest_exp_sect.PointerToRawData = cur_offset

        self.basepe.OPTIONAL_HEADER.SizeOfInitializedData += exports_size

        export_dir = self.basepe.OPTIONAL_HEADER.DATA_DIRECTORY[0]

        export_dir.VirtualAddress = dest_exp_sect.VirtualAddress
        export_dir.Size = exports_size

        offset = self.get_current_offset()
        rva = sec_rva
        self.append_data(b'\x00' * exports_size)

        dest_export_dir = self.basepe.__unpack_data__(self.basepe.__IMAGE_EXPORT_DIRECTORY_format__, # noqa
                                                      pefile.Structure(self.basepe.__IMAGE_EXPORT_DIRECTORY_format__).sizeof() * b'\x00', # noqa
                                                      offset)
        offset += pefile.Structure(self.basepe.__IMAGE_EXPORT_DIRECTORY_format__).sizeof()
        rva += pefile.Structure(self.basepe.__IMAGE_EXPORT_DIRECTORY_format__).sizeof()

        dest_export_dir.Characteristics = 0
        dest_export_dir.TimeDateStamp = 0xD1234567
        dest_export_dir.MajorVersion = 0
        dest_export_dir.MinorVersion = 0
        dest_export_dir.Base = 1
        dest_export_dir.NumberOfFunctions = len(exports_info)
        dest_export_dir.NumberOfNames = len(exports_info)

        # Set the address of functions array
        num_funcs = dest_export_dir.NumberOfFunctions
        funcs_rva = rva
        names_rva = funcs_rva + (4 * num_funcs)
        ord_rva = names_rva + (4 * num_funcs)
        strings_rva = ord_rva + (2 * num_funcs)

        dest_export_dir.Name = strings_rva
        dest_export_dir.AddressOfFunctions = funcs_rva
        dest_export_dir.AddressOfNames = names_rva
        dest_export_dir.AddressOfNameOrdinals = ord_rva
        self.update()

        # Set the export name
        self.basepe.set_bytes_at_rva(strings_rva, name)
        strings_rva += len(name) + 1

        for i, (rva, exp) in enumerate(exports_info):
            exp = exp.encode('utf-8')

            # Add fluff to pass forwarded export checks
            self.append_data(b'\x00' * len(exports_info))

            # Add the function addresses
            self.basepe.set_dword_at_rva(funcs_rva, rva)
            funcs_rva += 4
            if funcs_rva > sec_rva + exports_size:
                raise Exception('Functions offset exceeds total PE size')

            # Add the ordinals
            self.basepe.set_dword_at_rva(ord_rva, (i + 1) - dest_export_dir.Base)
            ord_rva += 2
            if ord_rva > sec_rva + exports_size:
                raise Exception('Ordinals offset exceeds total PE size')

            # Add the function names in
            if strings_rva > sec_rva + exports_size:
                raise Exception('Export string offset exceeds total PE size')
            self.basepe.set_dword_at_rva(names_rva, strings_rva)
            names_rva += 4
            self.basepe.set_bytes_at_rva(strings_rva, exp)
            strings_rva += len(exp) + 1

        if strings_rva:
            strings_offset = self.basepe.get_offset_from_rva(strings_rva)
            self.basepe.__data__ = self.basepe.__data__[:strings_offset]
        self.update()

    def init_text_section(self, names):
        '''
        Initialize and add the text section to the PE
        '''
        pattern = b''
        exports_info = list()

        sect = self.get_section_by_name(self.basepe, '.text')
        cur_offset = self.get_current_offset()
        sa = self.basepe.OPTIONAL_HEADER.SectionAlignment            
        sec_rva = (cur_offset + sa - 1) &~ (sa - 1)
        
        # Add placeholder code in case emulated samples want to hook the function
        for (i, func_name) in enumerate(names):
            exports_info.append((sec_rva + len(pattern), func_name))
            # Using i + 1 to avoid using 0, since the Win32 convention is to return TRUE when the function succeeds
            pattern += EXPORTED_FUNCTION[self.arch].replace(b'\x00\x00\x00\x00', (i+1).to_bytes(4, 'little'))

        if pattern:
            sect.VirtualAddress = sec_rva
            sect.Misc_VirtualSize = len(pattern)
            sect.Misc_PhysicalAddress = 0
            sect.SizeOfRawData = len(pattern)
            sect.PointerToRawData = cur_offset
            self.basepe.OPTIONAL_HEADER.AddressOfEntryPoint = sect.VirtualAddress
            self.append_data(pattern)
        self.update()
        return exports_info
