# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.


from .. import api


class Comctl32(api.ApiHandler):

    name = 'comctl32'
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):

        super(Comctl32, self).__init__(emu)
        self.funcs = {}
        self.data = {}
        super(Comctl32, self).__get_hook_attrs__(self)
        self.netman = emu.get_network_manager()
        self.names = {}

    @apihook('InitCommonControlsEx', argc=1)
    def InitCommonControlsEx(self, emu, argv, ctx={}):
        """
        BOOL InitCommonControlsEx(
            const INITCOMMONCONTROLSEX *picce
        );
        """
        picce, = argv
        rv = True

        return rv
