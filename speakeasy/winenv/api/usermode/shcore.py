from .. import api


class Shcore(api.ApiHandler):
    name = "shcore"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        self.funcs = {}
        self.data = {}
        super().__get_hook_attrs__(self)
        self.task_pool_context = 0

    @apihook("SHTaskPoolGetUniqueContext", argc=0)
    def SHTaskPoolGetUniqueContext(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """DWORD SHTaskPoolGetUniqueContext();"""
        self.task_pool_context += 1
        return self.task_pool_context
