# Copyright (C) 2026 Mandiant, Inc. All Rights Reserved.

import ntpath
import struct

import pefile

import speakeasy.winenv.defs.windows.windows as windefs

from .. import api

RT_VERSION = 16
VS_VERSION_SIGNATURE = b"FE2X"


def align4(offset: int) -> int:
    return (offset + 3) & ~3


def get_version_node(block: bytes, offset: int) -> tuple[int, str, int, int, bool]:
    """
    Decode the VS_VERSIONINFO node at ``offset``. Return its end, key, value
    offset, wValueLength, and whether the value is text.

    Raises:
        struct.error: the node header is outside the block.
    """
    length, value_length, value_type = struct.unpack_from("<HHH", block, offset)
    end = min(offset + length, len(block))
    key_end = offset + 6
    while key_end + 2 <= end and block[key_end : key_end + 2] != b"\0\0":
        key_end += 2
    key = block[offset + 6 : key_end].decode("utf-16le", "replace")
    return end, key, align4(key_end + 2), value_length, value_type == 1


def get_version_value(block: bytes, sub_block: str) -> tuple[int, int, bool] | None:
    """
    Find a value in a VS_VERSIONINFO block by its backslash separated path.
    Keys match without regard to case. Return the value offset, the
    wValueLength field, and whether the value is text, or None when the path
    does not exist.
    """
    try:
        end, _, value_offset, value_length, is_text = get_version_node(block, 0)
        for key in [part.lower() for part in sub_block.split("\\") if part]:
            child = align4(value_offset + value_length * (2 if is_text else 1))
            while child < end:
                child_end, child_key, value_offset, value_length, is_text = get_version_node(block, child)
                if child_end <= child:
                    return None
                if child_key.lower() == key:
                    end = child_end
                    break
                child = align4(child_end)
            else:
                return None
    except struct.error:
        return None
    return value_offset, value_length, is_text


class Version(api.ApiHandler):
    """
    Implements exported functions from version.dll

    The version resource of a file is the RT_VERSION resource of the loaded
    module with that path or file name, or else of the emulated PE file with
    that path. Other files report that they have no version resource.
    """

    name = "version"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        self.funcs = {}
        self.data = {}
        super().__get_hook_attrs__(self)

    def get_module_resource(self, emu, path):
        lowered = path.lower()
        for mod in emu.modules:
            emu_path = (mod.emu_path or "").lower()
            if lowered not in (emu_path, ntpath.basename(emu_path), (mod.name or "").lower()):
                continue
            metadata = mod.get_pe_metadata()
            for res in metadata.resources if metadata else []:
                if res.type_id == RT_VERSION:
                    return self.mem_read(mod.base + res.data_rva, res.size)
        return None

    def get_file_resource(self, emu, path):
        f = emu.get_file_manager().get_file_from_path(path)
        if not f:
            return None
        try:
            pe = pefile.PE(data=f.get_contents(), fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        except pefile.PEFormatError:
            return None
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return None
        for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if res_type.id != RT_VERSION or not hasattr(res_type, "directory"):
                continue
            for res_id in res_type.directory.entries:
                if hasattr(res_id, "directory") and res_id.directory.entries:
                    data = res_id.directory.entries[0].data.struct
                    return pe.get_data(data.OffsetToData, data.Size)
        return None

    def get_version_resource(self, emu, filename, arg, ctx):
        """
        Return the RT_VERSION resource of the named file, or None and set the
        last error.
        """
        resource = None
        if filename:
            path = self.read_mem_string(filename, self.get_char_width(ctx))
            ctx.args[arg].display = path
            resource = self.get_module_resource(emu, path) or self.get_file_resource(emu, path)
        if not resource:
            emu.set_last_error(windefs.ERROR_RESOURCE_TYPE_NOT_FOUND)
        return resource

    def get_size(self, emu, filename, arg, lpdwHandle, ctx):
        if lpdwHandle:
            self.mem_write(lpdwHandle, (0).to_bytes(4, "little"))
        resource = self.get_version_resource(emu, filename, arg, ctx)
        if not resource:
            return 0
        # The A functions convert text values into the space after the block.
        return len(resource) * 2 + len(VS_VERSION_SIGNATURE)

    def get_info(self, emu, filename, arg, dwLen, lpData, ctx):
        if not lpData:
            emu.set_last_error(windefs.ERROR_INVALID_DATA)
            return 0
        resource = self.get_version_resource(emu, filename, arg, ctx)
        if not resource:
            return 0
        self.mem_write(lpData, resource[:dwLen])
        length = struct.unpack_from("<H", resource)[0] if len(resource) >= 2 else 0
        if dwLen >= length + len(VS_VERSION_SIGNATURE):
            self.mem_write(lpData + length, VS_VERSION_SIGNATURE)
        return 1

    @apihook("GetFileVersionInfoSize", argc=2)
    def GetFileVersionInfoSize(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetFileVersionInfoSize(LPCSTR lptstrFilename, LPDWORD lpdwHandle);
        """
        lptstrFilename, lpdwHandle = argv
        return self.get_size(emu, lptstrFilename, 0, lpdwHandle, ctx)

    @apihook("GetFileVersionInfoSizeEx", argc=3)
    def GetFileVersionInfoSizeEx(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GetFileVersionInfoSizeEx(DWORD dwFlags, LPCSTR lpwstrFilename, LPDWORD lpdwHandle);
        """
        dwFlags, lpwstrFilename, lpdwHandle = argv
        return self.get_size(emu, lpwstrFilename, 1, lpdwHandle, ctx)

    @apihook("GetFileVersionInfo", argc=4)
    def GetFileVersionInfo(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetFileVersionInfo(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
        """
        lptstrFilename, dwHandle, dwLen, lpData = argv
        return self.get_info(emu, lptstrFilename, 0, dwLen, lpData, ctx)

    @apihook("GetFileVersionInfoEx", argc=5)
    def GetFileVersionInfoEx(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL GetFileVersionInfoEx(DWORD dwFlags, LPCSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
        """
        dwFlags, lpwstrFilename, dwHandle, dwLen, lpData = argv
        return self.get_info(emu, lpwstrFilename, 1, dwLen, lpData, ctx)

    @apihook("VerQueryValue", argc=4)
    def VerQueryValue(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL VerQueryValue(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen);
        """
        pBlock, lpSubBlock, lplpBuffer, puLen = argv
        if not pBlock or not lpSubBlock:
            return 0
        cw = self.get_char_width(ctx)
        sub_block = self.read_mem_string(lpSubBlock, cw)
        ctx.args[1].display = sub_block
        length = struct.unpack("<H", self.mem_read(pBlock, 2))[0]
        found = get_version_value(self.mem_read(pBlock, length), sub_block)
        if not found:
            emu.set_last_error(windefs.ERROR_RESOURCE_TYPE_NOT_FOUND)
            return 0
        offset, value_length, is_text = found
        value = pBlock + offset
        if is_text and cw == 1:
            text = self.mem_read(value, value_length * 2).decode("utf-16le", "replace")
            value = pBlock + length + len(VS_VERSION_SIGNATURE) + offset
            self.mem_write(value, text.encode("latin-1", "replace"))
        if lplpBuffer:
            self.mem_write(lplpBuffer, value.to_bytes(self.get_ptr_size(), "little"))
        if puLen:
            self.mem_write(puLen, value_length.to_bytes(4, "little"))
        return 1
