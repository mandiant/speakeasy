"""
Read the imports of a PE image that the guest mapped itself, for example by process hollowing.
"""

import logging
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass

import pefile

logger = logging.getLogger(__name__)

# read(address, size) reads guest memory. It raises ValueError if the memory is not readable.
Reader = Callable[[int, int], bytes]

_PARSE_ERRORS = (ValueError, struct.error)


class _MappedImage:
    def __init__(self, read: Reader, base: int, image_size: int):
        self.read = read
        self.base = base
        self.image_size = image_size

    def read_rva(self, rva: int, size: int) -> bytes:
        if rva < 0 or size < 0 or rva + size > self.image_size:
            raise ValueError("import RVA outside image")
        return self.read(self.base + rva, size)

    def read_name(self, rva: int, *, dll: bool = False) -> str:
        # Read one byte at a time, so that a name at the end of a page does not fail.
        if not 0 <= rva < self.image_size:
            raise ValueError("import name RVA outside image")
        value = bytearray()
        for offset in range(min(4096, self.image_size - rva)):
            byte = self.read_rva(rva + offset, 1)
            if byte == b"\x00":
                if not value:
                    raise ValueError("invalid import name")
                if dll:
                    ascii_name = bytes(byte if byte < 128 else ord("x") for byte in value)
                    if not pefile.is_valid_dos_filename(ascii_name):
                        raise ValueError("invalid import DLL name")
                    try:
                        return value.decode("ascii")
                    except UnicodeError:
                        name = value.decode("latin-1")
                        logger.warning("non-ASCII injected import DLL name decoded as Latin-1: %r", name)
                        return name
                if not pefile.is_valid_function_name(bytes(value)):
                    raise ValueError("invalid import function name")
                return value.decode("ascii")
            value.extend(byte)
        raise ValueError("unterminated import name")


@dataclass(frozen=True)
class ImportSlot:
    """An entry in the IAT of a mapped image."""

    image: _MappedImage
    dll: str
    # address of the IAT entry
    iat: int
    # value from the ILT, or from the IAT if the image has no ILT
    thunk: int
    # value in the IAT now
    current: int
    has_ilt: bool
    ptr_size: int

    @property
    def is_ordinal(self) -> bool:
        return bool(self.thunk & (1 << (self.ptr_size * 8 - 1)))

    @property
    def is_bound_externally(self) -> bool:
        """The IAT entry already holds an address, and there is no ILT to get the name from."""
        return not self.has_ilt and not self.is_ordinal and self.thunk >= self.image.image_size

    def get_reference(self) -> str:
        """
        Get the import name, or "ordinal_N" for an import by ordinal.

        Raises:
            ValueError: if the name is outside the image or is not valid.
        """
        if self.is_ordinal:
            if self.thunk & ~((1 << (self.ptr_size * 8 - 1)) | 0xFFFF):
                raise ValueError("reserved bits in ordinal import")
            return f"ordinal_{self.thunk & 0xFFFF}"
        return self.image.read_name(self.thunk + 2)


def get_import_slots(read: Reader, base: int, ptr_size: int) -> Iterator[ImportSlot]:
    """
    Get the IAT entries of the PE image at base.

    Yield nothing if the memory at base is not a PE image for this pointer size,
    or if the image has no imports. Check each RVA against SizeOfImage, and limit
    the number of descriptors and thunks to read. Skip a descriptor or a thunk table
    that cannot be read, and log a warning.

    Raises:
        ValueError: if the headers cannot be read or the import directory is outside the image.
        struct.error: if a header is truncated.
    """
    dos = read(base, 0x40)
    if dos[:2] != b"MZ":
        return
    nt_rva = struct.unpack_from("<I", dos, 0x3C)[0]
    if nt_rva > 0x100000:
        return
    header = read(base + nt_rva, 24)
    if header[:4] != b"PE\x00\x00":
        return
    opt_size = struct.unpack_from("<H", header, 20)[0]
    if opt_size < (0x80 if ptr_size == 8 else 0x70) or opt_size > 0x1000:
        return
    opt = read(base + nt_rva + 24, opt_size)
    magic = struct.unpack_from("<H", opt)[0]
    if magic != (0x20B if ptr_size == 8 else 0x10B):
        return
    image_size = struct.unpack_from("<I", opt, 56)[0]
    directory_offset = 112 if ptr_size == 8 else 96
    if struct.unpack_from("<I", opt, directory_offset - 4)[0] < 2:
        return
    import_rva, import_size = struct.unpack_from("<II", opt, directory_offset + 8)
    if not import_rva and not import_size:
        return
    if not import_rva or not import_size or import_rva + import_size > image_size:
        raise ValueError("import directory outside image")

    image = _MappedImage(read, base, image_size)
    for index in range(min(import_size // 20, 4096)):
        try:
            descriptor = image.read_rva(import_rva + index * 20, 20)
        except _PARSE_ERRORS as error:
            logger.warning("unreadable injected PE import descriptor at %#x: %s", base, error)
            break
        if descriptor == b"\x00" * 20:
            break
        ilt_rva, _, _, name_rva, iat_rva = struct.unpack("<5I", descriptor)
        try:
            if not name_rva or not iat_rva:
                raise ValueError("incomplete import descriptor")
            dll_name = image.read_name(name_rva, dll=True)
        except _PARSE_ERRORS as error:
            logger.warning("skipping injected PE import descriptor %s at %#x: %s", index, base, error)
            continue
        thunk_rva = ilt_rva or iat_rva
        for offset in range(min(image_size // ptr_size, 65536)):
            iat = iat_rva + offset * ptr_size
            try:
                thunk = int.from_bytes(image.read_rva(thunk_rva + offset * ptr_size, ptr_size), "little")
                if not thunk:
                    break
                current = int.from_bytes(image.read_rva(iat, ptr_size), "little")
            except _PARSE_ERRORS as error:
                # The rest of this table cannot be read safely. The other descriptors do not depend on it.
                logger.warning("skipping injected PE import table %s at %#x: %s", dll_name, base, error)
                break
            yield ImportSlot(image, dll_name, base + iat, thunk, current, bool(ilt_rva), ptr_size)
        else:
            logger.warning("unterminated injected PE import thunk table at %#x", base)
    else:
        logger.warning("unterminated injected PE import descriptor table at %#x", base)
