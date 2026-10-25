from .. import api


class kernelbase(api.ApiHandler):
    """
    Emulates functions from kernelbase.dll
    """

    name = "kernelbase"
    apihook = api.ApiHandler.apihook
    impdata = api.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        super().__get_hook_attrs__(self)

    @apihook("LogStagedFeatureUsage", argc=3)
    def LogStagedFeatureUsage(self, emu, argv, ctx: api.ApiContext = api.NO_CONTEXT):
        """
        VOID LogStagedFeatureUsage(
            UINT32 featureId,
            UINT32 kind,
            UINT32 addend
        );
        """
        return
