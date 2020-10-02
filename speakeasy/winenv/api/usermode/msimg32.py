# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.


from .. import api


class Msimg32(api.ApiHandler):

    """
    Implements exported functions from msimg.dll
    """

    name = 'msimg32'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Msimg32, self).__init__(emu)
        super(Msimg32, self).__get_hook_attrs__(self)

    @apihook('TransparentBlt', argc=11)
    def TransparentBlt(self, emu, argv, ctx={}):
        '''
        BOOL TransparentBlt(
          HDC  hdcDest,
          int  xoriginDest,
          int  yoriginDest,
          int  wDest,
          int  hDest,
          HDC  hdcSrc,
          int  xoriginSrc,
          int  yoriginSrc,
          int  wSrc,
          int  hSrc,
          UINT crTransparent
        );
        '''
        return 1
