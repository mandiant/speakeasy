import ctypes as ct
from typing import Annotated

from speakeasy.struct import EmuStruct

LF_FACESIZE = 32
LF_FULLFACESIZE = 64

ANSI_CHARSET = 0
DEFAULT_CHARSET = 1

FW_NORMAL = 400
OUT_STROKE_PRECIS = 3
CLIP_STROKE_PRECIS = 2
DRAFT_QUALITY = 1

FIXED_PITCH = 1
VARIABLE_PITCH = 2
FF_ROMAN = 0x10
FF_SWISS = 0x20
FF_MODERN = 0x30

# TEXTMETRIC.tmPitchAndFamily
TMPF_FIXED_PITCH = 0x01  # set for a variable pitch font
TMPF_VECTOR = 0x02
TMPF_TRUETYPE = 0x04

TRUETYPE_FONTTYPE = 4
NTM_REGULAR = 0x40


class LOGFONT(EmuStruct):
    lfHeight: Annotated[int, ct.c_int32]
    lfWidth: Annotated[int, ct.c_int32]
    lfEscapement: Annotated[int, ct.c_int32]
    lfOrientation: Annotated[int, ct.c_int32]
    lfWeight: Annotated[int, ct.c_int32]
    lfItalic: Annotated[int, ct.c_uint8]
    lfUnderline: Annotated[int, ct.c_uint8]
    lfStrikeOut: Annotated[int, ct.c_uint8]
    lfCharSet: Annotated[int, ct.c_uint8]
    lfOutPrecision: Annotated[int, ct.c_uint8]
    lfClipPrecision: Annotated[int, ct.c_uint8]
    lfQuality: Annotated[int, ct.c_uint8]
    lfPitchAndFamily: Annotated[int, ct.c_uint8]
    lfFaceName: bytes

    def __init__(self, ptr_size, width):
        super().__init__(ptr_size)
        self.add_fields(lfFaceName=ct.c_uint8 * (LF_FACESIZE * width))


class ENUMLOGFONTEX(LOGFONT):
    elfFullName: bytes
    elfStyle: bytes
    elfScript: bytes

    def __init__(self, ptr_size, width):
        super().__init__(ptr_size, width)
        self.add_fields(
            elfFullName=ct.c_uint8 * (LF_FULLFACESIZE * width),
            elfStyle=ct.c_uint8 * (LF_FACESIZE * width),
            elfScript=ct.c_uint8 * (LF_FACESIZE * width),
        )


class NEWTEXTMETRICEX(EmuStruct):
    """NEWTEXTMETRICEXA or NEWTEXTMETRICEXW, which starts with a TEXTMETRIC."""

    tmHeight: Annotated[int, ct.c_int32]
    tmAscent: Annotated[int, ct.c_int32]
    tmDescent: Annotated[int, ct.c_int32]
    tmInternalLeading: Annotated[int, ct.c_int32]
    tmExternalLeading: Annotated[int, ct.c_int32]
    tmAveCharWidth: Annotated[int, ct.c_int32]
    tmMaxCharWidth: Annotated[int, ct.c_int32]
    tmWeight: Annotated[int, ct.c_int32]
    tmOverhang: Annotated[int, ct.c_int32]
    tmDigitizedAspectX: Annotated[int, ct.c_int32]
    tmDigitizedAspectY: Annotated[int, ct.c_int32]
    tmFirstChar: int
    tmLastChar: int
    tmDefaultChar: int
    tmBreakChar: int
    tmItalic: int
    tmUnderlined: int
    tmStruckOut: int
    tmPitchAndFamily: int
    tmCharSet: int
    ntmFlags: int
    ntmSizeEM: int
    ntmCellHeight: int
    ntmAvgWidth: int
    fsUsb: bytes
    fsCsb: bytes

    def __init__(self, ptr_size, width):
        super().__init__(ptr_size)
        char = ct.c_uint16 if width == 2 else ct.c_uint8
        self.add_fields(
            tmFirstChar=char,
            tmLastChar=char,
            tmDefaultChar=char,
            tmBreakChar=char,
            tmItalic=ct.c_uint8,
            tmUnderlined=ct.c_uint8,
            tmStruckOut=ct.c_uint8,
            tmPitchAndFamily=ct.c_uint8,
            tmCharSet=ct.c_uint8,
            ntmFlags=ct.c_uint32,
            ntmSizeEM=ct.c_uint32,
            ntmCellHeight=ct.c_uint32,
            ntmAvgWidth=ct.c_uint32,
            fsUsb=ct.c_uint32 * 4,
            fsCsb=ct.c_uint32 * 2,
        )
