# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from .. import api


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
        self.handle = 0
        self.count = 0
        super().__get_hook_attrs__(self)

    def get_handle(self):
        self.handle += 4
        hnd = self.handle
        return hnd

    @apihook("CreateBitmap", argc=5)
    def CreateBitmap(self, emu, argv, ctx: api.ApiContext = None):
        """
        HBITMAP CreateBitmap(
            int        nWidth,
            int        nHeight,
            UINT       nPlanes,
            UINT       nBitCount,
            const VOID *lpBits
        );
        """
        ctx = ctx or {}
        return self.get_handle()

    @apihook("MoveToEx", argc=1)
    def MoveToEx(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL MoveToEx(
          HDC     hdc,
          int     x,
          int     y,
          LPPOINT lppt
        );
        """
        ctx = ctx or {}
        return 1

    @apihook("LineTo", argc=1)
    def LineTo(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL LineTo(
          HDC hdc,
          int x,
          int y
        )
        """
        ctx = ctx or {}
        return 1

    @apihook("GetStockObject", argc=1)
    def GetStockObject(self, emu, argv, ctx: api.ApiContext = None):
        """
        HGDIOBJ GetStockObject(
            int i
        );
        """
        ctx = ctx or {}
        return 0

    @apihook("GetMapMode", argc=1)
    def GetMapMode(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetMapMode(
            HDC hdc
        );
        """
        ctx = ctx or {}
        return 1

    @apihook("GetDeviceCaps", argc=2)
    def GetDeviceCaps(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetDeviceCaps(
            HDC hdc,
            int index
        );
        """
        ctx = ctx or {}
        return 16

    @apihook("GdiSetBatchLimit", argc=1)
    def GdiSetBatchLimit(self, emu, argv, ctx: api.ApiContext = None):
        """
        DWORD GdiSetBatchLimit(
          DWORD dw
        );
        """
        ctx = ctx or {}
        return 0

    @apihook("MaskBlt", argc=12)
    def MaskBlt(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL MaskBlt(
          HDC     hdcDest,
          int     xDest,
          int     yDest,
          int     width,
          int     height,
          HDC     hdcSrc,
          int     xSrc,
          int     ySrc,
          HBITMAP hbmMask,
          int     xMask,
          int     yMask,
          DWORD   rop
        );
        """
        ctx = ctx or {}
        return 1

    @apihook("BitBlt", argc=9)
    def BitBlt(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL BitBlt(
        HDC   hdc,
        int   x,
        int   y,
        int   cx,
        int   cy,
        HDC   hdcSrc,
        int   x1,
        int   y1,
        DWORD rop
        """
        ctx = ctx or {}
        return 1

    @apihook("DeleteDC", argc=1)
    def DeleteDC(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL DeleteDC(
        HDC hdc
        );
        """
        ctx = ctx or {}
        return 1

    @apihook("SelectObject", argc=2)
    def SelectObject(self, emu, argv, ctx: api.ApiContext = None):
        """
        HGDIOBJ SelectObject(
          HDC     hdc,
          HGDIOBJ h
        );
        """
        ctx = ctx or {}
        return 0

    @apihook("DeleteObject", argc=1)
    def DeleteObject(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL DeleteObject(
        HGDIOBJ ho
        );
        """
        ctx = ctx or {}
        return 1

    @apihook("CreateCompatibleBitmap", argc=3)
    def CreateCompatibleBitmap(self, emu, argv, ctx: api.ApiContext = None):
        """
        HBITMAP CreateCompatibleBitmap(
        HDC hdc,
        int cx,
        int cy
        );
        """
        ctx = ctx or {}
        return 0

    @apihook("CreateCompatibleDC", argc=1)
    def CreateCompatibleDC(self, emu, argv, ctx: api.ApiContext = None):
        """
        HDC CreateCompatibleDC(
        HDC hdc
        );
        """
        ctx = ctx or {}
        return 0

    @apihook("GetDIBits", argc=7)
    def GetDIBits(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetDIBits(
        HDC          hdc,
        HBITMAP      hbm,
        UINT         start,
        UINT         cLines,
        LPVOID       lpvBits,
        LPBITMAPINFO lpbmi,
        UINT         usage
        );
        """
        ctx = ctx or {}
        return 0

    @apihook("CreateDIBSection", argc=6)
    def CreateDIBSection(self, emu, argv, ctx: api.ApiContext = None):
        """
        HBITMAP CreateDIBSection(
          [in]  HDC              hdc,
          [in]  const BITMAPINFO *pbmi,
          [in]  UINT             usage,
          [out] VOID             **ppvBits,
          [in]  HANDLE           hSection,
          [in]  DWORD            offset
        );
        """
        ctx = ctx or {}
        return 0

    @apihook("CreateDCA", argc=4)
    def CreateDCA(self, emu, argv, ctx: api.ApiContext = None):
        """
        HDC CreateDCA(
        LPCSTR         pwszDriver,
        LPCSTR         pwszDevice,
        LPCSTR         pszPort,
        const DEVMODEA *pdm
        );
        """
        ctx = ctx or {}
        return 0

    @apihook("GetTextCharacterExtra", argc=1)
    def GetTextCharacterExtra(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetTextCharacterExtra(
          HDC hdc
        );
        """
        ctx = ctx or {}
        return 0x8000000

    @apihook("StretchBlt", argc=11)
    def StretchBlt(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL StretchBlt(
          HDC   hdcDest,
          int   xDest,
          int   yDest,
          int   wDest,
          int   hDest,
          HDC   hdcSrc,
          int   xSrc,
          int   ySrc,
          int   wSrc,
          int   hSrc,
          DWORD rop
        );
        """
        ctx = ctx or {}
        return 0

    @apihook("CreateFontIndirectA", argc=1)
    def CreateFontIndirectA(self, emu, argv, ctx: api.ApiContext = None):
        """
        HFONT CreateFontIndirectA(
            const LOGFONTA *lplf
        );
        """
        ctx = ctx or {}
        # Return a fake HFONT handle.
        # Any non-zero value is treated as success.
        return 0x6000

    @apihook("GetObjectA", argc=3)
    def GetObjectA(self, emu, argv, ctx: api.ApiContext = None):
        """
        int GetObjectA(
            HANDLE h,
            int    c,
            LPVOID pv
        );
        """
        ctx = ctx or {}
        h, c, pv = argv

        # If caller provided a buffer, fill it with zeros.
        if pv and c:
            try:
                data = b"\x00" * c
                try:
                    emu.mem_write(pv, data)
                except Exception:
                    base_addr = pv & ~0xFFF
                    emu.mem_map(base_addr, 0x1000)
                    emu.mem_write(pv, data)
            except Exception:
                pass

        # Return number of bytes "written"
        return c

    @apihook("WidenPath", argc=1)
    def WidenPath(self, emu, argv, ctx: api.ApiContext = None):
        """
        BOOL WidenPath(
            HDC hdc
        );
        """
        ctx = ctx or {}
        # We don't emulate actual path widening; just report success.
        return 1
