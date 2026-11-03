# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import struct
from typing import TYPE_CHECKING

from speakeasy.winenv.defs.nt import ddk

from .. import api

if TYPE_CHECKING:
    from speakeasy.windows.win32 import Win32Emulator

MAX_DIB_SIZE = 0x8000000

SYSTEM_FONT = 13
DC_PEN = 19
STOCK_OBJECT_BASE = 0x01900010

DEVICE_CAPS = {
    0: 0x4000,
    2: 1,
    4: 527,
    6: 296,
    8: 1920,
    10: 1080,
    12: 32,
    14: 1,
    24: -1,
    88: 96,
    90: 96,
    104: 32,
    116: 60,
    117: 1920,
    118: 1080,
}


class GDI32(api.ApiHandler):
    """
    Implements exported functions from gdi32.dll
    """

    name = "gdi32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)

        self.funcs = {}
        self.data = {}
        self.count: int = 0
        self.stock_objects: dict[int, int] = {}
        self.selected: dict[int, int] = {}
        self.handles: set[int] = set()
        super().__get_hook_attrs__(self)

    def new_handle(self, emu: "Win32Emulator") -> int:
        hnd = emu.handle_allocator.allocate_handle()
        self.handles.add(hnd)
        return hnd

    def is_gdi_object(self, hnd: int) -> bool:
        """
        Return True for a handle that gdi32 gave: from new_handle or a stock object.

        SelectObject gives the stock SYSTEM_FONT without a GetStockObject call,
        so the check accepts each handle in the stock object range.
        """
        if STOCK_OBJECT_BASE <= hnd <= STOCK_OBJECT_BASE + DC_PEN:
            return True
        return hnd in self.handles

    @apihook("CreateBitmap", argc=5)
    def CreateBitmap(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HBITMAP CreateBitmap(
            int nWidth,
            int nHeight,
            UINT nPlanes,
            UINT nBitCount,
            const VOID *lpBits
        );
        """
        return self.new_handle(emu)

    @apihook("MoveToEx", argc=4)
    def MoveToEx(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL MoveToEx(
            HDC hdc,
            int x,
            int y,
            LPPOINT lppt
        );
        """
        return 1

    @apihook("LineTo", argc=3)
    def LineTo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL LineTo(
            HDC hdc,
            int x,
            int y
        );
        """
        return 1

    @apihook("GetStockObject", argc=1)
    def GetStockObject(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HGDIOBJ GetStockObject(
            int i
        );
        """
        (i,) = argv
        if not 0 <= i <= DC_PEN:
            return 0
        return self.stock_objects.setdefault(i, STOCK_OBJECT_BASE + i)

    @apihook("GetMapMode", argc=1)
    def GetMapMode(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetMapMode(
            HDC hdc
        );
        """
        return 1

    @apihook("GetDeviceCaps", argc=2)
    def GetDeviceCaps(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetDeviceCaps(
            HDC hdc,
            int index
        );
        """
        hdc, index = argv
        return DEVICE_CAPS.get(index, 0) & 0xFFFFFFFF

    @apihook("GdiSetBatchLimit", argc=1)
    def GdiSetBatchLimit(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        DWORD GdiSetBatchLimit(
            DWORD dw
        );
        """
        return 0

    @apihook("MaskBlt", argc=12)
    def MaskBlt(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL MaskBlt(
            HDC hdcDest,
            int xDest,
            int yDest,
            int width,
            int height,
            HDC hdcSrc,
            int xSrc,
            int ySrc,
            HBITMAP hbmMask,
            int xMask,
            int yMask,
            DWORD rop
        );
        """
        return 1

    @apihook("BitBlt", argc=9)
    def BitBlt(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL BitBlt(
            HDC hdc,
            int x,
            int y,
            int cx,
            int cy,
            HDC hdcSrc,
            int x1,
            int y1,
            DWORD rop
        );
        """
        return 1

    @apihook("DeleteDC", argc=1)
    def DeleteDC(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL DeleteDC(
            HDC hdc
        );
        """
        return 1

    @apihook("SelectObject", argc=2)
    def SelectObject(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HGDIOBJ SelectObject(
            HDC hdc,
            HGDIOBJ h
        );
        """
        hdc, h = argv
        if not h:
            return 0
        previous = self.selected.get(hdc, STOCK_OBJECT_BASE + SYSTEM_FONT)
        self.selected[hdc] = h
        return previous

    @apihook("DeleteObject", argc=1)
    def DeleteObject(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL DeleteObject(
            HGDIOBJ ho
        );
        """
        return 1

    @apihook("CreateCompatibleBitmap", argc=3)
    def CreateCompatibleBitmap(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HBITMAP CreateCompatibleBitmap(
            HDC hdc,
            int cx,
            int cy
        );
        """
        return 0

    @apihook("CreateCompatibleDC", argc=1)
    def CreateCompatibleDC(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HDC CreateCompatibleDC(
            HDC hdc
        );
        """
        return self.new_handle(emu)

    @apihook("GetDIBits", argc=7)
    def GetDIBits(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetDIBits(
            HDC hdc,
            HBITMAP hbm,
            UINT start,
            UINT cLines,
            LPVOID lpvBits,
            LPBITMAPINFO lpbmi,
            UINT usage
        );
        """
        return 0

    @apihook("CreateDIBSection", argc=6)
    def CreateDIBSection(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HBITMAP CreateDIBSection(
            HDC hdc,
            const BITMAPINFO *pbmi,
            UINT usage,
            VOID **ppvBits,
            HANDLE hSection,
            DWORD offset
        );
        """
        hdc, pbmi, usage, ppvBits, hSection, offset = argv
        width, height, _, bit_count = struct.unpack("<iiHH", self.mem_read(pbmi + 4, 12))
        bits = 0
        hbm = 0
        size = (width * bit_count + 31) // 32 * 4 * abs(height)
        if width > 0 and height != 0 and bit_count in (1, 4, 8, 16, 24, 32) and size <= MAX_DIB_SIZE:
            bits = self.mem_alloc(size, tag="api.gdi32.CreateDIBSection")
            hbm = self.new_handle(emu)
        if ppvBits:
            self.write_ptr(ppvBits, bits)
        return hbm

    @apihook("CreateDCA", argc=4)
    def CreateDCA(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HDC CreateDCA(
            LPCSTR pwszDriver,
            LPCSTR pwszDevice,
            LPCSTR pszPort,
            const DEVMODEA *pdm
        );
        """
        return 0

    @apihook("GetTextCharacterExtra", argc=1)
    def GetTextCharacterExtra(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetTextCharacterExtra(
            HDC hdc
        );
        """
        return 0x8000000

    @apihook("StretchBlt", argc=11)
    def StretchBlt(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL StretchBlt(
            HDC hdcDest,
            int xDest,
            int yDest,
            int wDest,
            int hDest,
            HDC hdcSrc,
            int xSrc,
            int ySrc,
            int wSrc,
            int hSrc,
            DWORD rop
        );
        """
        return 0

    @apihook("CreateFontIndirectA", argc=1)
    def CreateFontIndirectA(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HFONT CreateFontIndirectA(
            const LOGFONTA *lplf
        );
        """
        (lplf,) = argv
        if not lplf:
            return 0
        return self.new_handle(emu)

    @apihook("GetObjectA", argc=3)
    def GetObjectA(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        int GetObjectA(
            HANDLE h,
            int c,
            LPVOID pv
        );
        """
        h, c, pv = argv
        if not self.is_gdi_object(h):
            return 0

        # The handler does not keep the object structures, so it writes zeros in their place.
        if pv and c:
            emu.mem_write(pv, b"\x00" * c)

        # Return number of bytes "written"
        return c

    @apihook("D3DKMTEnumAdapters2", argc=1)
    def D3DKMTEnumAdapters2(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS D3DKMTEnumAdapters2(
            const D3DKMT_ENUMADAPTERS2 *unnamedParam1
        );
        """
        (unnamedParam1,) = argv
        # No display adapters: NumAdapters is 0 and pAdapters is not touched
        if unnamedParam1:
            self.write_dword(unnamedParam1, 0)
        return ddk.STATUS_SUCCESS

    @apihook("D3DKMTEnumAdapters", argc=1)
    def D3DKMTEnumAdapters(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS D3DKMTEnumAdapters(
            const D3DKMT_ENUMADAPTERS *unnamedParam1
        );
        """
        (unnamedParam1,) = argv
        if unnamedParam1:
            self.write_dword(unnamedParam1, 0)
        return ddk.STATUS_SUCCESS

    @apihook("D3DKMTCloseAdapter", argc=1)
    def D3DKMTCloseAdapter(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS D3DKMTCloseAdapter(
            const D3DKMT_CLOSEADAPTER *unnamedParam1
        );
        """
        return ddk.STATUS_SUCCESS

    @apihook("D3DKMTQueryAdapterInfo", argc=1)
    def D3DKMTQueryAdapterInfo(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        NTSTATUS D3DKMTQueryAdapterInfo(
            const D3DKMT_QUERYADAPTERINFO *unnamedParam1
        );
        """
        return ddk.STATUS_INVALID_PARAMETER

    @apihook("WidenPath", argc=1)
    def WidenPath(self, emu: "Win32Emulator", argv: list[int], ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL WidenPath(
            HDC hdc
        );
        """
        # We don't emulate actual path widening; just report success.
        return 1
