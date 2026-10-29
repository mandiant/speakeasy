from .. import api


class Bcryptprimitives(api.ApiHandler):
    """
    Implements exported functions from bcryptprimitives.dll
    """

    name = "bcryptprimitives"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        self.funcs = {}
        self.data = {}
        super().__get_hook_attrs__(self)

    @apihook("ProcessPrng", argc=2)
    def ProcessPrng(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        BOOL ProcessPrng(PBYTE pbData, SIZE_T cbData);
        """
        pbData, cbData = argv
        self.mem_write(pbData, emu.rng.randbytes(cbData))
        return 1
