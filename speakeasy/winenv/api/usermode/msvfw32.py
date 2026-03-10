from .. import api


class Msvfw32(api.ApiHandler):
    """Implements exported functions from msvfw32.dll."""

    name = "msvfw32"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        self.funcs = {}
        self.data = {}
        self.next_handle = 0x7000
        super().__get_hook_attrs__(self)

    def get_handle(self):
        handle = self.next_handle
        self.next_handle += 4
        return handle

    @apihook("ICOpen", argc=3)
    def ICOpen(self, emu, argv, ctx: api.ApiContext = None):
        """
        HIC ICOpen(
            DWORD fccType,
            DWORD fccHandler,
            UINT wMode
            );
        """
        ctx = ctx or {}
        _fcc_type, _fcc_handler, _mode = argv
        return self.get_handle()

    @apihook("ICSendMessage", argc=4)
    def ICSendMessage(self, emu, argv, ctx: api.ApiContext = None):
        """
        LRESULT ICSendMessage(
            HIC hic,
            UINT msg,
            DWORD_PTR dw1,
            DWORD_PTR dw2
            );
        """
        ctx = ctx or {}
        _hic, _msg, _dw1, _dw2 = argv
        return 1

    @apihook("ICClose", argc=1)
    def ICClose(self, emu, argv, ctx: api.ApiContext = None):
        """
        LRESULT ICClose(
            HIC hic
            );
        """
        ctx = ctx or {}
        return 1
