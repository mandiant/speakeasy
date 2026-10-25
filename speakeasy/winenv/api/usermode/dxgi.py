from .. import api

DXGI_ERROR_UNSUPPORTED = 0x887A0004


class Dxgi(api.ApiHandler):
    """
    Emulates functions from dxgi.dll. The emulator has no DXGI objects, so
    factory creation reports that DXGI is not supported.
    """

    name = "dxgi"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        super().__get_hook_attrs__(self)

    def clear_pointer(self, address):
        if address:
            self.mem_write(address, b"\x00" * self.get_ptr_size())

    @apihook("CreateDXGIFactory", argc=2)
    def CreateDXGIFactory(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CreateDXGIFactory(
          REFIID riid,
          void   **ppFactory
        );
        """
        _, ppFactory = argv
        self.clear_pointer(ppFactory)
        return DXGI_ERROR_UNSUPPORTED

    @apihook("CreateDXGIFactory1", argc=2)
    def CreateDXGIFactory1(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CreateDXGIFactory1(
          REFIID riid,
          void   **ppFactory
        );
        """
        _, ppFactory = argv
        self.clear_pointer(ppFactory)
        return DXGI_ERROR_UNSUPPORTED

    @apihook("CreateDXGIFactory2", argc=3)
    def CreateDXGIFactory2(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        HRESULT CreateDXGIFactory2(
          UINT   Flags,
          REFIID riid,
          void   **ppFactory
        );
        """
        _, _, ppFactory = argv
        self.clear_pointer(ppFactory)
        return DXGI_ERROR_UNSUPPORTED
