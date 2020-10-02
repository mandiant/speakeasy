# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from .. import api


class GDI32(api.ApiHandler):

    """
    Implements exported functions from gdi32.dll
    """

    name = 'gdi32'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(GDI32, self).__init__(emu)

        self.funcs = {}
        self.data = {}
        self.handle = 0
        self.count = 0
        super(GDI32, self).__get_hook_attrs__(self)

    def get_handle(self):
        self.handle += 4
        hnd = self.handle
        return hnd

    @apihook('CreateBitmap', argc=5)
    def CreateBitmap(self, emu, argv, ctx={}):
        '''
        HBITMAP CreateBitmap(
            int        nWidth,
            int        nHeight,
            UINT       nPlanes,
            UINT       nBitCount,
            const VOID *lpBits
        );
        '''
        return self.get_handle()

    @apihook('MoveToEx', argc=1)
    def MoveToEx(self, emu, argv, ctx={}):
        """
        BOOL MoveToEx(
          HDC     hdc,
          int     x,
          int     y,
          LPPOINT lppt
        );
        """
        return 1

    @apihook('LineTo', argc=1)
    def LineTo(self, emu, argv, ctx={}):
        """
        BOOL LineTo(
          HDC hdc,
          int x,
          int y
        )
        """
        return 1

    @apihook('GetStockObject', argc=1)
    def GetStockObject(self, emu, argv, ctx={}):
        """
        HGDIOBJ GetStockObject(
            int i
        );
        """
        return 0

    @apihook('GetMapMode', argc=1)
    def GetMapMode(self, emu, argv, ctx={}):
        """
        int GetMapMode(
            HDC hdc
        );
        """
        return 1

    @apihook('GetDeviceCaps', argc=2)
    def GetDeviceCaps(self, emu, argv, ctx={}):
        """
        int GetDeviceCaps(
            HDC hdc,
            int index
        );
        """
        return 16

    @apihook('GdiSetBatchLimit', argc=1)
    def GdiSetBatchLimit(self, emu, argv, ctx={}):
        """
        DWORD GdiSetBatchLimit(
          DWORD dw
        );
        """
        return 0

    @apihook('MaskBlt', argc=12)
    def MaskBlt(self, emu, argv, ctx={}):
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
        return 1

    @apihook('SelectObject', argc=2)
    def SelectObject(self, emu, argv, ctx={}):
        """
        HGDIOBJ SelectObject(
          HDC     hdc,
          HGDIOBJ h
        );
        """
        return 0

    @apihook('GetTextCharacterExtra', argc=1)
    def GetTextCharacterExtra(self, emu, argv, ctx={}):
        """
        int GetTextCharacterExtra(
          HDC hdc
        );
        """
        return 0x8000000

    @apihook('StretchBlt', argc=11)
    def StretchBlt(self, emu, argv, ctx={}):
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
        return 0
