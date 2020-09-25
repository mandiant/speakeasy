# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from .. import api


class Advpack(api.ApiHandler):
    """
    Emulates functions from advpack.dll
    """

    name = 'advpack'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Advpack, self).__init__(emu)

        self.funcs = {}
        self.data = {}

        super(Advpack, self).__get_hook_attrs__(self)

    @apihook('IsNTAdmin', argc=2)
    def IsNTAdmin(self, emu, argv, ctx={}):
        """
        bool IsNTAdmin();
        """
        return emu.get_user().get('is_admin', False)
